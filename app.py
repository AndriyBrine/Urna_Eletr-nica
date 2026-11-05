#!/usr/bin/env python3
"""
Urna eletrônica para eleição de Grêmio Estudantil.

- Roda 100% offline, só com a biblioteca padrão do Python (3.8+).
- Banco de dados: SQLite (arquivo eleicao.db ao lado deste script).
- Voto secreto: a tabela `votos` NÃO guarda matrícula, horário nem ordem
  (ID aleatório, tabela sem rowid). A tabela `eleitores` só guarda se já votou
  e a DATA (sem hora).
- Fluxo: mesário confere o aluno -> libera a urna -> aluno vota -> volta ao mesário.

Uso:  python app.py     (na primeira vez, as senhas são definidas no navegador)
"""
import csv
import hashlib
import hmac
import html
import io
import json
import os
import re
import secrets
import sqlite3
import sys
import threading
import time
import unicodedata
import uuid
import webbrowser
from datetime import date, datetime, timedelta, timezone
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

BASE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("URNA_DB", os.path.join(BASE, "eleicao.db"))
BACKUP_DIR = os.path.join(BASE, "backups")
PORT = int(os.environ.get("URNA_PORT", "8000"))

lock = threading.Lock()          # serializa gravações
SESSOES = {}                     # token -> papel ("admin" | "mesario")
LIBERADO = {"matricula": None}   # matrícula atualmente liberada na urna


# ------------------------------------------------------- horário de Brasília ----
try:
    from zoneinfo import ZoneInfo
    TZ_BRASILIA = ZoneInfo("America/Sao_Paulo")
    datetime.now(TZ_BRASILIA)          # falha se o sistema não tiver o banco de fusos (comum no Windows)
except Exception:
    TZ_BRASILIA = timezone(timedelta(hours=-3))   # Brasília = UTC-3 (sem horário de verão desde 2019)


def agora_br():
    """Data/hora atual no horário de Brasília, independente do fuso configurado no computador."""
    return datetime.now(TZ_BRASILIA)


# ----------------------------------------------------------------- banco ----
def db():
    conn = sqlite3.connect(DB_PATH, timeout=15, isolation_level=None)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = db()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS config(chave TEXT PRIMARY KEY, valor TEXT);
        CREATE TABLE IF NOT EXISTS eleitores(
            matricula TEXT PRIMARY KEY,
            nome      TEXT NOT NULL,
            turma     TEXT NOT NULL DEFAULT '',
            turno     TEXT NOT NULL DEFAULT '',
            curso     TEXT NOT NULL DEFAULT '',
            ja_votou  INTEGER NOT NULL DEFAULT 0,
            data_voto TEXT
        );
        CREATE TABLE IF NOT EXISTS chapas(
            id     INTEGER PRIMARY KEY AUTOINCREMENT,
            numero INTEGER UNIQUE NOT NULL,
            nome   TEXT NOT NULL
        );
        -- Sem matrícula, sem horário, ID aleatório e sem rowid (ordem física aleatória)
        CREATE TABLE IF NOT EXISTS votos(
            id       TEXT PRIMARY KEY,
            tipo     TEXT NOT NULL,      -- 'chapa' | 'branco' | 'nulo'
            chapa_id INTEGER
        ) WITHOUT ROWID;
        CREATE TABLE IF NOT EXISTS eventos(
            id      INTEGER PRIMARY KEY AUTOINCREMENT,
            quando  TEXT NOT NULL,
            tipo    TEXT NOT NULL,
            detalhe TEXT
        );
        """
    )
    # migração: bancos criados em versões anteriores não tinham turno/curso
    existentes = {r["name"] for r in conn.execute("PRAGMA table_info(eleitores)")}
    for col in ("turno", "curso"):
        if col not in existentes:
            conn.execute(f"ALTER TABLE eleitores ADD COLUMN {col} TEXT NOT NULL DEFAULT ''")
    conn.execute("INSERT OR IGNORE INTO config VALUES('status','preparacao')")
    conn.close()


CURSOS = {   # sigla usada na matrícula/turma -> nome do curso
    "TIIMI": "Técnico Integrado em Informática para Internet",
    "TMEMI": "Técnico Integrado em Mecatrônica",
    "EJAQEL": "Qualificação Profissional em Eletricista Instalador Predial de Baixa Tensão",
    "TPMAI": "Técnico em Automação Industrial (concomitante)",
    "TPMI": "Técnico em Informática (concomitante)",
}
ORDEM_TURNOS = ["Matutino", "Vespertino", "Noturno"]
SIGLA_EXIBIDA = {"EJAQEL": "ProEJA"}   # nome pelo qual a escola chama o curso


def deduzir_curso(turma, matricula):
    """Sigla do curso a partir da turma (20262.TIIMI.3) ou da matrícula (20252TIIMI0017)."""
    m = re.fullmatch(r"\d{5}\.([A-Za-z]+)\..+", turma or "") or re.fullmatch(r"\d{5}([A-Za-z]+)\d{4}", matricula or "")
    return m.group(1).upper() if m else ""


def rot_turma(t):
    return re.sub(r"^\d{5}\.", "", t or "") or "Sem turma"


def rot_curso(sigla):
    if not sigla:
        return "Curso não identificado"
    return f"{SIGLA_EXIBIDA.get(sigla, sigla)} – {CURSOS[sigla]}" if sigla in CURSOS else sigla


def rot_turno(t):
    return t or "Não informado"


def cfg(conn, chave, padrao=None):
    r = conn.execute("SELECT valor FROM config WHERE chave=?", (chave,)).fetchone()
    return r["valor"] if r else padrao


def set_cfg(conn, chave, valor):
    conn.execute("INSERT OR REPLACE INTO config VALUES(?,?)", (chave, valor))


def evento(conn, tipo, detalhe=""):
    conn.execute(
        "INSERT INTO eventos(quando,tipo,detalhe) VALUES(?,?,?)",
        (agora_br().strftime("%d/%m/%Y %H:%M:%S"), tipo, detalhe),
    )


# ---------------------------------------------------------------- senhas ----
def hash_senha(s):
    salt = secrets.token_hex(8)
    h = hashlib.pbkdf2_hmac("sha256", s.encode(), salt.encode(), 200_000).hex()
    return f"{salt}${h}"


def confere_hash(s, armazenado):
    try:
        salt, h = armazenado.split("$")
    except (ValueError, AttributeError):
        return False
    h2 = hashlib.pbkdf2_hmac("sha256", s.encode(), salt.encode(), 200_000).hex()
    return hmac.compare_digest(h, h2)


def senhas_configuradas():
    conn = db()
    try:
        return bool(cfg(conn, "admin_hash")) and bool(cfg(conn, "mesario_hash"))
    finally:
        conn.close()


def resetar_senhas():
    """Uso: python app.py --resetar-senhas (exige acesso ao computador)."""
    conn = db()
    conn.execute("DELETE FROM config WHERE chave IN ('admin_hash','mesario_hash')")
    evento(conn, "senhas_resetadas", "")
    conn.close()
    SESSOES.clear()


def senha_ok(papel, senha):
    conn = db()
    try:
        if papel == "admin":
            return confere_hash(senha, cfg(conn, "admin_hash"))
        # senha do admin também vale como mesário
        return confere_hash(senha, cfg(conn, "mesario_hash")) or confere_hash(
            senha, cfg(conn, "admin_hash")
        )
    finally:
        conn.close()


# ------------------------------------------------------------------ util ----
def esc(s):
    return html.escape(str(s), quote=True)


def norm(s):
    s = unicodedata.normalize("NFKD", s).encode("ascii", "ignore").decode()
    return s.lower().strip()


CSS = """
*{box-sizing:border-box}
body{font-family:system-ui,Segoe UI,Arial,sans-serif;margin:0;background:#f1f3f6;color:#1d2433}
main{max-width:980px;margin:0 auto;padding:24px}
h1{margin:.2em 0 .4em}h2{margin-top:1.6em}
.topo{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:8px}
.topo a{color:#475066}
.card{background:#fff;border-radius:14px;padding:20px;box-shadow:0 1px 4px #0002;margin:14px 0}
.btn,button{display:inline-block;background:#1f5eff;color:#fff;border:0;border-radius:10px;padding:12px 20px;
  font-size:1rem;cursor:pointer;text-decoration:none}
.btn.sec,button.sec{background:#e3e7ef;color:#1d2433}
.btn.verde,button.verde{background:#17a34a}
.btn.verm,button.verm{background:#d93025}
input[type=text],input[type=password],input[type=number],textarea{width:100%;padding:12px;font-size:1.1rem;
  border:1px solid #b9c0cf;border-radius:10px}
textarea{min-height:120px;font-family:monospace;font-size:.9rem}
label{display:block;margin:10px 0 4px;font-weight:600}
table{border-collapse:collapse;width:100%}
th,td{padding:8px 10px;border-bottom:1px solid #e1e5ee;text-align:left}
.ok{background:#e6f7ec;border-left:5px solid #17a34a;padding:12px;border-radius:8px;margin:12px 0}
.erro{background:#fdecea;border-left:5px solid #d93025;padding:12px;border-radius:8px;margin:12px 0}
.aviso{background:#fff7e0;border-left:5px solid #e0a100;padding:12px;border-radius:8px;margin:12px 0}
.grande{font-size:1.6rem;font-weight:700}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:16px}
.opcao{background:#fff;border:3px solid #cfd6e4;border-radius:16px;padding:26px 14px;font-size:1.3rem;
  color:#1d2433;text-align:center}
.opcao .num{display:block;font-size:3rem;font-weight:800;color:#1f5eff}
.opcao:hover{border-color:#1f5eff}
.opcao.neutra .num{color:#6b7385}
#confirma{display:none;position:fixed;inset:0;background:#000a;align-items:center;justify-content:center}
#confirma .caixa{background:#fff;border-radius:18px;padding:32px;max-width:520px;text-align:center}
.barra{background:#dfe4ef;border-radius:99px;height:14px;overflow:hidden}
.barra>div{background:#1f5eff;height:100%}
.pill{display:inline-block;border-radius:99px;padding:4px 12px;font-weight:700;font-size:.85rem}
.pill.prep{background:#fff3c4}.pill.aberta{background:#c9f2d6}.pill.enc{background:#e3e7ef}
.urna{display:grid;grid-template-columns:1fr 360px;gap:20px;align-items:start}
.tela{background:#eef1f5;border:4px solid #2b3342;border-radius:12px;min-height:470px;padding:22px;display:flex;flex-direction:column;gap:14px}
.tela .cab{font-size:.9rem;letter-spacing:.08em;color:#475066;font-weight:700}
.tela .titulo{font-size:1.4rem;font-weight:700}
.caixas{display:flex;gap:10px}
.caixa{width:66px;height:84px;border:3px solid #2b3342;border-radius:8px;background:#fff;font-size:3rem;font-weight:700;
  display:flex;align-items:center;justify-content:center}
.caixa.vazia{border-color:#aab3c5}
.info{display:flex;gap:22px;align-items:center;flex-wrap:wrap;min-height:210px}
.icone{width:200px;height:200px;object-fit:contain;border:2px solid #2b3342;background:#fff;border-radius:10px}
.icone.sem{display:flex;align-items:center;justify-content:center;font-size:5rem;font-weight:800;color:#1f5eff}
.nome{font-size:2.2rem;font-weight:800;line-height:1.1}
.sub{font-size:1.1rem;color:#475066;margin-top:6px}
.vbig{font-size:2.6rem;font-weight:800}
.nulo-aviso{font-size:1.4rem;font-weight:800;color:#d93025}
.dica{font-size:1.3rem;color:#6b7385}
.rodape{margin-top:auto;border-top:2px solid #2b3342;padding-top:10px;font-size:.95rem;color:#2b3342;min-height:44px}
.teclado{background:#2b3342;border-radius:12px;padding:16px}
.teclas{display:grid;grid-template-columns:repeat(3,1fr);gap:10px}
.tecla{background:#111827;color:#fff;font-size:2rem;padding:18px 0;border-radius:8px}
.tecla:active{background:#374151}
.acoes{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin-top:14px}
.acoes button{padding:20px 4px;font-size:.95rem;font-weight:800;border-radius:8px;color:#111}
.t-branco{background:#fff}.t-corrige{background:#f5a623}.t-confirma{background:#22b24c;color:#fff!important}
@media(max-width:820px){.urna{grid-template-columns:1fr}}
@media print{.noprint{display:none}body{background:#fff}.card{box-shadow:none;border:1px solid #ccc}}
"""


def pagina(titulo, corpo, head=""):
    return (
        f'<!doctype html><html lang="pt-br"><head><meta charset="utf-8">'
        f'<meta name="viewport" content="width=device-width,initial-scale=1">'
        f"<title>{esc(titulo)}</title>{head}<style>{CSS}</style></head>"
        f"<body><main>{corpo}</main></body></html>"
    )


def topo(papel):
    links = ""
    if papel:
        links = '<a href="/logout">Sair</a>'
    return f'<div class="topo noprint"><a href="/">🗳️ Eleição do Grêmio</a>{links}</div>'


def pill(status):
    nomes = {"preparacao": ("prep", "Em preparação"), "aberta": ("aberta", "Votação aberta"),
             "encerrada": ("enc", "Votação encerrada")}
    c, t = nomes[status]
    return f'<span class="pill {c}">{t}</span>'


# ------------------------------------------------------------- importação ----
def importar_csv(texto):
    """Retorna (qtd_ok, lista_de_erros). Aceita ; , ou TAB, com ou sem cabeçalho."""
    texto = texto.lstrip("\ufeff")
    primeira = texto.split("\n", 1)[0]
    delim = max([";", ",", "\t"], key=lambda d: primeira.count(d))
    if primeira.count(delim) == 0:
        delim = ","
    linhas = [r for r in csv.reader(io.StringIO(texto), delimiter=delim) if any(c.strip() for c in r)]
    if not linhas:
        return 0, ["Arquivo vazio."]

    cab = [norm(c) for c in linhas[0]]

    def acha(*nomes):
        for i, c in enumerate(cab):
            if any(c.startswith(n) for n in nomes):
                return i
        return None

    i_mat, i_nome, i_turma = acha("matricula", "mat", "ra", "codigo"), acha("nome", "aluno"), acha("turma", "serie", "classe")
    i_turno, i_curso = acha("turno", "periodo"), acha("curso", "sigla")
    if i_mat is not None and i_nome is not None:
        dados, inicio = linhas[1:], 2
    else:  # sem cabeçalho: ordem matrícula, nome, turma, turno
        i_mat, i_nome, i_turma, i_turno, i_curso, dados, inicio = 0, 1, 2, 3, None, linhas, 1

    def campo(r, i):
        return r[i].strip() if i is not None and i < len(r) else ""

    ok, erros, sem_turma = 0, [], 0
    conn = db()
    with lock:
        conn.execute("BEGIN IMMEDIATE")
        for n, r in enumerate(dados, start=inicio):
            try:
                mat = r[i_mat].strip().upper()
                nome = " ".join(r[i_nome].split())
                turma, turno, curso = campo(r, i_turma), campo(r, i_turno), campo(r, i_curso).upper()
            except IndexError:
                erros.append(f"Linha {n}: colunas faltando.")
                continue
            if not mat or not nome:
                erros.append(f"Linha {n}: matrícula ou nome vazio.")
                continue
            curso = curso or deduzir_curso(turma, mat)
            sem_turma += 0 if turma else 1
            conn.execute(
                "INSERT INTO eleitores(matricula,nome,turma,turno,curso) VALUES(?,?,?,?,?) "
                "ON CONFLICT(matricula) DO UPDATE SET nome=excluded.nome, turma=excluded.turma, "
                "turno=excluded.turno, curso=excluded.curso",
                (mat, nome, turma, turno, curso),
            )
            ok += 1
        evento(conn, "importacao", f"{ok} eleitores importados, {len(erros)} erros")
        conn.execute("COMMIT")
    conn.close()
    if sem_turma:
        erros.append(f"Atenção: {sem_turma} aluno(s) sem turma informada (importados mesmo assim).")
    return ok, erros


# ------------------------------------------------------------------ voto ----
def registrar_voto(matricula, escolha):
    """Marca que o eleitor votou e grava o voto anônimo, na MESMA transação."""
    tipo, chapa_id = None, None
    if escolha in ("branco", "nulo"):
        tipo = escolha
    elif escolha.startswith("chapa:") and escolha[6:].isdigit():
        tipo, chapa_id = "chapa", int(escolha[6:])
    else:
        return False, "Opção inválida."

    conn = db()
    try:
        with lock:
            conn.execute("BEGIN IMMEDIATE")
            if cfg(conn, "status") != "aberta":
                conn.execute("ROLLBACK")
                return False, "A votação não está aberta."
            if tipo == "chapa" and not conn.execute("SELECT 1 FROM chapas WHERE id=?", (chapa_id,)).fetchone():
                conn.execute("ROLLBACK")
                return False, "Chapa inexistente."
            r = conn.execute(
                "UPDATE eleitores SET ja_votou=1, data_voto=? WHERE matricula=? AND ja_votou=0",
                (agora_br().date().isoformat(), matricula),
            )
            if r.rowcount != 1:
                conn.execute("ROLLBACK")
                evento(conn, "voto_duplicado_bloqueado", f"matrícula {matricula}")
                return False, "Este eleitor já votou ou não existe."
            conn.execute("INSERT INTO votos(id,tipo,chapa_id) VALUES(?,?,?)", (uuid.uuid4().hex, tipo, chapa_id))
            evento(conn, "voto_registrado", "")
            conn.execute("COMMIT")
        return True, ""
    except Exception as e:
        try:
            conn.execute("ROLLBACK")
        except Exception:
            pass
        return False, f"Erro ao gravar: {e}"
    finally:
        conn.close()


def apurar(conn):
    chapas = conn.execute(
        "SELECT c.numero, c.nome, COUNT(v.id) AS votos FROM chapas c "
        "LEFT JOIN votos v ON v.chapa_id=c.id AND v.tipo='chapa' "
        "GROUP BY c.id ORDER BY votos DESC, c.numero"
    ).fetchall()
    brancos = conn.execute("SELECT COUNT(*) FROM votos WHERE tipo='branco'").fetchone()[0]
    nulos = conn.execute("SELECT COUNT(*) FROM votos WHERE tipo='nulo'").fetchone()[0]
    total_votos = conn.execute("SELECT COUNT(*) FROM votos").fetchone()[0]
    eleitores = conn.execute("SELECT COUNT(*) FROM eleitores").fetchone()[0]
    votaram = conn.execute("SELECT COALESCE(SUM(ja_votou),0) FROM eleitores").fetchone()[0]
    def grupo(col, rot, ordem):
        d = {r["g"]: r for r in conn.execute(
            f"SELECT {col} AS g, COUNT(*) AS total, COALESCE(SUM(ja_votou),0) AS votaram FROM eleitores GROUP BY {col}")}
        return [dict(rot=rot(k), total=d[k]["total"], votaram=d[k]["votaram"]) for k in sorted(d, key=ordem)]

    turmas = grupo("turma", rot_turma, lambda k: (k == "", k))
    cursos = grupo("curso", rot_curso, lambda k: (k == "", list(CURSOS).index(k) if k in CURSOS else 99, k))
    turnos = grupo("turno", rot_turno, lambda k: (ORDEM_TURNOS.index(k) if k in ORDEM_TURNOS else 99, k))
    return dict(chapas=chapas, brancos=brancos, nulos=nulos, total_votos=total_votos,
                eleitores=eleitores, votaram=votaram, turmas=turmas, cursos=cursos, turnos=turnos,
                integro=(total_votos == votaram))


# ----------------------------------------------------------------- rotas ----
ROTAS = {}


def rota(metodo, caminho):
    def deco(fn):
        ROTAS[(metodo, caminho)] = fn
        return fn
    return deco


def exige(h, *papeis):
    if h.papel() in papeis:
        return True
    alvo = "admin" if papeis == ("admin",) else "mesario"
    h.redirect(f"/login?papel={alvo}")
    return False


@rota("GET", "/")
def home(h, q, f):
    h.send(pagina("Eleição do Grêmio",
        '<h1>🗳️ Eleição do Grêmio Estudantil</h1><div class="card">'
        '<p><a class="btn verde" href="/mesario">Mesário</a> '
        '<a class="btn sec" href="/admin">Administração</a></p></div>'))


def tela_configurar(h, erro=""):
    msg = f'<div class="erro">{esc(erro)}</div>' if erro else ""
    campo = lambda rot, nome: (f'<label>{rot}</label><input type="password" name="{nome}" required>')
    h.send(pagina("Configuração inicial",
        '<h1>Configuração inicial</h1><div class="card">' + msg +
        '<p>Defina as senhas (mínimo 4 caracteres). Elas devem ser diferentes.</p>'
        '<form method="post" action="/configurar">'
        + campo("Senha do ADMINISTRADOR", "admin") + campo("Repita a senha do administrador", "admin2")
        + campo("Senha dos MESÁRIOS", "mes") + campo("Repita a senha dos mesários", "mes2")
        + '<p><button>Salvar senhas</button></p></form></div>'))


@rota("GET", "/configurar")
def configurar_get(h, q, f):
    if senhas_configuradas():
        return h.redirect("/")
    tela_configurar(h)


@rota("POST", "/configurar")
def configurar_post(h, q, f):
    if senhas_configuradas():
        return h.redirect("/")
    a, a2, m, m2 = (f.get(k, "") for k in ("admin", "admin2", "mes", "mes2"))
    if len(a) < 4 or len(m) < 4:
        return tela_configurar(h, "Use pelo menos 4 caracteres em cada senha.")
    if a != a2 or m != m2:
        return tela_configurar(h, "A confirmação de uma das senhas não confere.")
    if a == m:
        return tela_configurar(h, "A senha do administrador e a dos mesários devem ser diferentes.")
    conn = db()
    set_cfg(conn, "admin_hash", hash_senha(a))
    set_cfg(conn, "mesario_hash", hash_senha(m))
    evento(conn, "senhas_definidas", "")
    conn.close()
    h.redirect("/login?papel=admin")


@rota("GET", "/login")
def login_get(h, q, f, erro=""):
    papel = q.get("papel", ["mesario"])[0]
    papel = papel if papel in ("admin", "mesario") else "mesario"
    msg = f'<div class="erro">{esc(erro)}</div>' if erro else ""
    nome = "Administração" if papel == "admin" else "Mesário"
    h.send(pagina("Entrar", f'{topo(None)}<h1>{nome}</h1><div class="card">{msg}'
        f'<form method="post" action="/login"><input type="hidden" name="papel" value="{papel}">'
        '<label>Senha</label><input type="password" name="senha" autofocus>'
        '<p><button>Entrar</button></p></form></div>'))


@rota("POST", "/login")
def login_post(h, q, f):
    papel = f.get("papel", "mesario")
    if senha_ok(papel, f.get("senha", "")):
        tok = secrets.token_urlsafe(24)
        SESSOES[tok] = papel
        h.redirect("/admin" if papel == "admin" else "/mesario",
                   [("Set-Cookie", f"sid={tok}; Path=/; HttpOnly; SameSite=Strict")])
    else:
        time.sleep(1)
        login_get(h, {"papel": [papel]}, {}, "Senha incorreta.")


@rota("GET", "/logout")
def logout(h, q, f):
    c = SimpleCookie(h.headers.get("Cookie", ""))
    if "sid" in c:
        SESSOES.pop(c["sid"].value, None)
    h.redirect("/")


# ---------------------------------------------------------------- mesário ----
def tela_mesario(h, msg="", tipo="erro", confirmar=None):
    conn = db()
    status = cfg(conn, "status")
    total = conn.execute("SELECT COUNT(*) FROM eleitores").fetchone()[0]
    votaram = conn.execute("SELECT COALESCE(SUM(ja_votou),0) FROM eleitores").fetchone()[0]
    conn.close()

    corpo = f"{topo(h.papel())}<h1>Mesa de votação {pill(status)}</h1>"
    corpo += f'<p>Votaram <b>{votaram}</b> de <b>{total}</b> eleitores.</p>'
    if msg:
        corpo += f'<div class="{tipo}">{msg}</div>'

    if status != "aberta":
        corpo += '<div class="aviso">A votação não está aberta. Peça ao administrador para abri-la.</div>'
    elif LIBERADO["matricula"]:
        corpo += ('<div class="aviso">Há uma urna liberada neste momento. '
                  '<a class="btn" href="/urna">Ir para a urna</a></div>')
    elif confirmar:
        corpo += (f'<div class="card"><p>Confira o documento do aluno:</p>'
                  f'<p class="grande">{esc(confirmar["nome"])}</p>'
                  f'<p>Turma: <b>{esc(rot_turma(confirmar["turma"]))}</b> &nbsp;·&nbsp; Turno: <b>{esc(rot_turno(confirmar["turno"]))}</b> &nbsp;·&nbsp; Matrícula: <b>{esc(confirmar["matricula"])}</b></p>'
                  f'<p>Curso: <b>{esc(rot_curso(confirmar["curso"]))}</b></p>'
                  f'<form method="post" action="/mesario/liberar">'
                  f'<input type="hidden" name="matricula" value="{esc(confirmar["matricula"])}">'
                  f'<button class="verde">✔ É o aluno — liberar urna</button> '
                  f'<a class="btn sec" href="/mesario">Cancelar</a></form></div>')
    else:
        corpo += ('<div class="card"><form method="post" action="/mesario/buscar">'
                  '<label>Matrícula do aluno</label>'
                  '<input type="text" name="matricula" autofocus autocomplete="off">'
                  '<p><button>Buscar</button></p></form></div>')
    h.send(pagina("Mesário", corpo))


@rota("GET", "/mesario")
def mesario(h, q, f):
    if exige(h, "mesario", "admin"):
        tela_mesario(h)


@rota("POST", "/mesario/buscar")
def mesario_buscar(h, q, f):
    if not exige(h, "mesario", "admin"):
        return
    mat = f.get("matricula", "").strip().upper()
    conn = db()
    try:
        if cfg(conn, "status") != "aberta":
            return tela_mesario(h, "A votação não está aberta.")
        r = conn.execute("SELECT * FROM eleitores WHERE upper(matricula)=?", (mat,)).fetchone()
        if not r:
            evento(conn, "matricula_nao_encontrada", mat)
            return tela_mesario(h, f"Matrícula <b>{esc(mat)}</b> não encontrada.")
        if r["ja_votou"]:
            evento(conn, "tentativa_voto_duplicado", mat)
            return tela_mesario(h, f"<b>{esc(r['nome'])}</b> JÁ VOTOU. Não é possível votar novamente.")
        tela_mesario(h, confirmar=dict(r))
    finally:
        conn.close()


@rota("POST", "/mesario/liberar")
def mesario_liberar(h, q, f):
    if not exige(h, "mesario", "admin"):
        return
    mat = f.get("matricula", "")
    conn = db()
    try:
        r = conn.execute("SELECT * FROM eleitores WHERE matricula=?", (mat,)).fetchone()
        if cfg(conn, "status") != "aberta" or not r or r["ja_votou"]:
            return tela_mesario(h, "Não foi possível liberar este eleitor.")
        with lock:
            if LIBERADO["matricula"] and LIBERADO["matricula"] != mat:
                return tela_mesario(h, "Já existe outra urna liberada.")
            LIBERADO["matricula"] = mat
        evento(conn, "urna_liberada", mat)
    finally:
        conn.close()
    h.redirect("/urna")


# ------------------------------------------------------------------ urna ----
ICONES_DIR = os.path.join(BASE, "icones")
ICONE_TIPOS = {".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
               ".webp": "image/webp", ".gif": "image/gif", ".svg": "image/svg+xml"}


def achar_icone(numero):
    """Procura icones/<numero>.<ext> (extensão em qualquer caixa). Retorna (caminho, tipo) ou (None, None)."""
    try:
        for nome in os.listdir(ICONES_DIR):
            raiz, ext = os.path.splitext(nome)
            if raiz == str(numero) and ext.lower() in ICONE_TIPOS:
                return os.path.join(ICONES_DIR, nome), ICONE_TIPOS[ext.lower()]
    except OSError:
        pass
    return None, None


@rota("GET", "/icone")
def icone(h, q, f):
    n = q.get("n", [""])[0]
    caminho, tipo = achar_icone(int(n)) if n.isdigit() else (None, None)
    if not caminho:
        return h.send(b"", 404)
    with open(caminho, "rb") as arq:
        h.send(arq.read(), ctype=tipo)


def json_seguro(x):
    return json.dumps(x).replace("</", "<\\/")


JS_URNA = """
<script>
const CHAPAS=__CHAPAS__;           // [{id,numero,nome,icone}]
const SOM_ARQUIVO=__SOM__;
const N=Math.max(1,...CHAPAS.map(c=>String(c.numero).length));   // nº de dígitos
let digitos='', modo='digitando', chapa=null, enviando=false;      // modo: digitando|chapa|nulo|branco
const $=id=>document.getElementById(id);
const H=t=>String(t).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
CHAPAS.forEach(c=>{if(c.icone){new Image().src='/icone?n='+c.numero;}});   // pré-carrega

function avaliar(){
  chapa=null;
  if(modo==='branco') return;
  if(digitos===''){modo='digitando';return;}
  const exata=CHAPAS.find(c=>String(c.numero)===digitos);
  if(exata){modo='chapa';chapa=exata;return;}
  modo=CHAPAS.some(c=>String(c.numero).startsWith(digitos))?'digitando':'nulo';
}
function podeDigitar(){
  if(modo==='branco'||modo==='nulo'||digitos.length>=N) return false;
  if(modo==='chapa') return CHAPAS.some(c=>String(c.numero).startsWith(digitos)&&String(c.numero)!==digitos);
  return true;
}
function digito(d){ if(enviando||!podeDigitar()) return; digitos+=d; avaliar(); desenhar(); }
function corrige(){ if(enviando) return; digitos=''; modo='digitando'; chapa=null; desenhar(); }
function branco(){ if(enviando) return; digitos=''; chapa=null; modo='branco'; desenhar(); }

function desenhar(){
  let cx=''; for(let i=0;i<N;i++){const d=digitos[i];cx+='<div class="caixa'+(d?'':' vazia')+'">'+(d||'')+'</div>';}
  $('caixas').style.display=(modo==='branco')?'none':'flex';
  $('caixas').innerHTML=cx;
  let info='', rod='';
  if(modo==='branco'){info='<div class="vbig">VOTO EM BRANCO</div>';}
  else if(modo==='nulo'){info='<div><div class="nulo-aviso">NÚMERO ERRADO</div><div class="vbig">VOTO NULO</div></div>';}
  else if(modo==='chapa'){
    info=(chapa.icone?'<img class="icone" src="/icone?n='+chapa.numero+'" alt="">':'<div class="icone sem">'+H(chapa.numero)+'</div>')
        +'<div><div class="nome">'+H(chapa.nome)+'</div><div class="sub">Chapa nº '+H(chapa.numero)+'</div></div>';
  } else {info='<div class="dica">Digite o número da chapa</div>';}
  if(modo!=='digitando') rod='Aperte <b>CONFIRMA</b> para confirmar este voto<br>Aperte <b>CORRIGE</b> para recomeçar';
  $('info').innerHTML=info; $('rodape').innerHTML=rod;
}

// Som de fim de votação. Edite as notas: [frequência Hz, início s, duração s]
const NOTAS=[[1400,0,0.09],[1400,0.13,0.06],[1400,0.24,0.06]];  // "pi-li-li"
function tocar(){
  if(SOM_ARQUIVO){const a=new Audio(SOM_ARQUIVO);a.play().catch(()=>{});return;}
  const AC=window.AudioContext||window.webkitAudioContext; if(!AC) return;
  const ctx=new AC(), t0=ctx.currentTime+0.05;
  NOTAS.forEach(([f,ini,dur])=>{
    const o=ctx.createOscillator(), g=ctx.createGain();
    o.type='square'; o.frequency.value=f; o.connect(g); g.connect(ctx.destination);
    g.gain.setValueAtTime(0.0001,t0+ini); g.gain.exponentialRampToValueAtTime(0.18,t0+ini+0.01);
    g.gain.setValueAtTime(0.18,t0+ini+dur-0.03); g.gain.exponentialRampToValueAtTime(0.0001,t0+ini+dur);
    o.start(t0+ini); o.stop(t0+ini+dur+0.02);
  });
}
async function confirma(){
  if(enviando) return;
  let escolha=null;
  if(modo==='chapa') escolha='chapa:'+chapa.id; else if(modo==='branco') escolha='branco'; else if(modo==='nulo') escolha='nulo';
  if(!escolha){ $('rodape').innerHTML='<b>Digite o número completo da chapa, ou aperte BRANCO.</b>'; return; }
  enviando=true;
  let r; try{
    const resp=await fetch('/votar',{method:'POST',headers:{'Accept':'application/json'},body:new URLSearchParams({escolha})});
    r=await resp.json();
  }catch(_){r={ok:false,msg:'Falha de comunicação com o servidor.'};}
  if(r.ok){
    tocar();
    document.body.innerHTML='<div style="text-align:center;margin-top:14vh;font-family:system-ui">'+
      '<h1 style="font-size:9rem;margin:0">FIM</h1><p style="font-size:1.8rem">Voto registrado. Obrigado!</p></div>';
    setTimeout(()=>{location.href='/mesario';},3000);
  }else{
    document.body.innerHTML='<main><div class="erro">'+H(r.msg)+'</div><a class="btn" href="/mesario">Voltar</a></main>';
  }
}
document.querySelectorAll('[data-d]').forEach(b=>b.addEventListener('click',()=>digito(b.dataset.d)));
$('b-branco').addEventListener('click',branco);
$('b-corrige').addEventListener('click',corrige);
$('b-confirma').addEventListener('click',confirma);
document.addEventListener('keydown',e=>{
  if(e.target.tagName==='INPUT') return;
  if(/^[0-9]$/.test(e.key)) digito(e.key);
  else if(e.key==='Backspace'||e.key==='Delete'||e.key==='Escape'){e.preventDefault();corrige();}
  else if(e.key==='Enter'){e.preventDefault();confirma();}
  else if(e.key==='b'||e.key==='B') branco();
});
desenhar();
</script>"""


@rota("GET", "/urna")
def urna(h, q, f):
    if not LIBERADO["matricula"]:
        return h.redirect("/mesario")
    conn = db()
    chapas = conn.execute("SELECT id,numero,nome FROM chapas ORDER BY numero").fetchall()
    conn.close()
    dados = [{"id": c["id"], "numero": c["numero"], "nome": c["nome"],
              "icone": achar_icone(c["numero"])[0] is not None} for c in chapas]
    teclas = "".join(f'<button type="button" class="tecla" data-d="{d}">{d}</button>' for d in "123456789")
    teclas += f'<span></span><button type="button" class="tecla" data-d="0">0</button><span></span>'
    corpo = (
        '<div class="urna"><div class="tela">'
        '<div class="cab">ELEIÇÃO DO GRÊMIO ESTUDANTIL</div>'
        '<div class="titulo">SEU VOTO PARA</div>'
        '<div id="caixas" class="caixas"></div><div id="info" class="info"></div><div id="rodape" class="rodape"></div>'
        '</div><div class="teclado"><div class="teclas">' + teclas + '</div>'
        '<div class="acoes"><button type="button" class="t-branco" id="b-branco">BRANCO</button>'
        '<button type="button" class="t-corrige" id="b-corrige">CORRIGE</button>'
        '<button type="button" class="t-confirma" id="b-confirma">CONFIRMA</button></div></div></div>'
        '<details class="noprint" style="margin-top:30px"><summary>Cancelar (somente mesário)</summary>'
        '<form method="post" action="/urna/cancelar"><label>Senha do mesário</label>'
        '<input type="password" name="senha"><p><button class="verm">Cancelar liberação</button></p></form></details>'
        + JS_URNA.replace("__CHAPAS__", json_seguro(dados)).replace("__SOM__", json_seguro(achar_som()))
    )
    h.send(pagina("Urna", corpo))


SOM_TIPOS = {".mp3": "audio/mpeg", ".wav": "audio/wav", ".ogg": "audio/ogg"}


def achar_som():
    """Se existir urna.mp3 / urna.wav / urna.ogg ao lado do app.py, ele é usado no lugar do beep sintético."""
    for ext in SOM_TIPOS:
        if os.path.exists(os.path.join(BASE, "urna" + ext)):
            return "/som"
    return None


@rota("GET", "/som")
def som(h, q, f):
    for ext, tipo in SOM_TIPOS.items():
        caminho = os.path.join(BASE, "urna" + ext)
        if os.path.exists(caminho):
            with open(caminho, "rb") as arq:
                return h.send(arq.read(), ctype=tipo)
    h.send(b"", 404)


@rota("POST", "/urna/cancelar")
def urna_cancelar(h, q, f):
    if senha_ok("mesario", f.get("senha", "")):
        conn = db()
        evento(conn, "liberacao_cancelada", LIBERADO["matricula"] or "")
        conn.close()
        LIBERADO["matricula"] = None
        return h.redirect("/mesario")
    time.sleep(1)
    h.redirect("/urna")


@rota("POST", "/votar")
def votar(h, q, f):
    quer_json = "application/json" in h.headers.get("Accept", "")
    mat = LIBERADO["matricula"]
    if not mat:
        if quer_json:
            return h.send(json.dumps({"ok": False, "msg": "Nenhuma urna liberada."}), ctype="application/json")
        return h.redirect("/mesario")
    ok, msg = registrar_voto(mat, f.get("escolha", ""))
    if ok or "já votou" in msg:
        LIBERADO["matricula"] = None
    if quer_json:
        return h.send(json.dumps({"ok": ok, "msg": msg}), ctype="application/json")
    if ok:
        h.send(pagina("Voto registrado",
            '<div style="text-align:center;margin-top:12vh"><h1 style="font-size:3rem">✅ Voto registrado!</h1>'
            '<p class="grande">Obrigado por participar.</p></div>',
            head='<meta http-equiv="refresh" content="4;url=/mesario">'))
    else:
        h.send(pagina("Erro", f'<div class="erro">{esc(msg)}</div><a class="btn" href="/mesario">Voltar</a>'))


# ----------------------------------------------------------------- admin ----
def card_part(titulo, rotulo, grupos):
    if not grupos:
        return ""
    c = (f'<div class="card"><h2 style="margin-top:0">{titulo}</h2><table><tr><th>{rotulo}</th><th>Aptos</th>'
         '<th>Votaram</th><th>Abstenções</th><th>Comparecimento</th></tr>')
    for g in grupos:
        cp = 100 * g["votaram"] / g["total"] if g["total"] else 0
        c += (f'<tr><td>{esc(g["rot"])}</td><td>{g["total"]}</td><td>{g["votaram"]}</td>'
              f'<td>{g["total"] - g["votaram"]}</td><td>{cp:.1f}%</td></tr>')
    return c + "</table></div>"


def tela_admin(h, msg="", tipo="ok"):
    conn = db()
    status = cfg(conn, "status")
    a = apurar(conn)
    chapas = conn.execute("SELECT id,numero,nome FROM chapas ORDER BY numero").fetchall()
    conn.close()

    c = topo("admin") + f"<h1>Administração {pill(status)}</h1>"
    if msg:
        c += f'<div class="{tipo}">{msg}</div>'

    # --- Participação
    pct = round(100 * a["votaram"] / a["eleitores"]) if a["eleitores"] else 0
    c += (f'<div class="card"><h2 style="margin-top:0">Participação</h2>'
          f'<p>{a["votaram"]} de {a["eleitores"]} eleitores ({pct}%)</p>'
          f'<div class="barra"><div style="width:{pct}%"></div></div></div>')

    # --- Chapas
    c += '<div class="card"><h2 style="margin-top:0">Chapas</h2>'
    if chapas:
        c += "<table><tr><th>Nº</th><th>Nome</th><th>Ícone</th><th></th></tr>"
        for ch in chapas:
            rem = ""
            if status == "preparacao":
                rem = (f'<form method="post" action="/admin/chapa/remover" style="margin:0">'
                       f'<input type="hidden" name="id" value="{ch["id"]}"><button class="sec">Remover</button></form>')
            if achar_icone(ch["numero"])[0]:
                ic = f'<img src="/icone?n={ch["numero"]}" alt="" style="height:44px">'
            else:
                ic = f'<span style="color:#d93025">sem ícone (salve como icones/{ch["numero"]}.png)</span>'
            c += f'<tr><td>{ch["numero"]}</td><td>{esc(ch["nome"])}</td><td>{ic}</td><td>{rem}</td></tr>'
        c += "</table>"
    else:
        c += "<p>Nenhuma chapa cadastrada.</p>"
    if status == "preparacao":
        c += ('<form method="post" action="/admin/chapa/adicionar"><div class="grid">'
              '<div><label>Número</label><input type="number" name="numero" min="1" required></div>'
              '<div><label>Nome da chapa</label><input type="text" name="nome" required></div></div>'
              '<p><button>Adicionar chapa</button></p></form>')
    c += "</div>"

    # --- Importação
    if status == "preparacao":
        c += ('<div class="card"><h2 style="margin-top:0">Importar eleitores (CSV)</h2>'
              '<p>Colunas: <b>matricula; nome; turma; turno</b> (com ou sem cabeçalho; o curso é identificado pela turma/matrícula). '
              'Reimportar atualiza os dados sem apagar quem já votou.</p>'
              '<form method="post" action="/admin/importar">'
              '<input type="file" id="arq" accept=".csv,.txt">'
              '<textarea name="csv" id="csv" placeholder="…ou cole o conteúdo aqui" required></textarea>'
              '<p><button>Importar</button></p></form></div>'
              '<script>document.getElementById("arq").addEventListener("change",async e=>{'
              'const buf=await e.target.files[0].arrayBuffer();let t;'
              'try{t=new TextDecoder("utf-8",{fatal:true}).decode(buf)}catch(_){t=new TextDecoder("windows-1252").decode(buf)}'
              'document.getElementById("csv").value=t;});</script>')

    # --- Controle
    c += '<div class="card"><h2 style="margin-top:0">Controle da votação</h2>'
    if status == "preparacao":
        c += ('<form method="post" action="/admin/status"><input type="hidden" name="acao" value="abrir">'
              '<button class="verde" onclick="return confirm(\'Abrir a votação? Depois disso não será mais possível '
              'alterar chapas ou eleitores.\')">▶ Abrir votação</button></form>')
    elif status == "aberta":
        c += ('<form method="post" action="/admin/status"><input type="hidden" name="acao" value="encerrar">'
              '<button class="verm" onclick="return confirm(\'Encerrar a votação? Isso não pode ser desfeito.\')">'
              '■ Encerrar votação e apurar</button></form>')
    else:
        c += ('<p><a class="btn verde" href="/admin/resultado">Ver resultado</a> <a class="btn" href="/admin/relatorio">📄 Relatório para PDF</a></p>'
              '<hr><h3>Nova eleição</h3>'
              '<p>Guarda uma cópia completa desta eleição na pasta <code>eleicoes_anteriores/</code> '
              'e zera o sistema para a próxima. As senhas são mantidas.</p>'
              '<form method="post" action="/admin/nova">'
              '<label><input type="checkbox" name="manter" value="1" style="width:auto"> '
              'Manter a lista de eleitores (todos voltam a "não votou")</label>'
              '<p><button class="verm" onclick="return confirm(\'Arquivar esta eleição e começar uma nova? '
              'Antes, confirme que você imprimiu ou salvou o resultado.\')">Arquivar e iniciar nova eleição</button></p></form>')
    c += ('<form method="post" action="/admin/backup" style="margin-top:12px"><button class="sec">💾 Fazer backup agora</button> '
          '<a class="btn sec" href="/admin/log">Ver registro de eventos</a></form></div>')

    # --- Participação por curso, turno e turma
    c += (card_part("Participação por curso", "Curso", a["cursos"]) + card_part("Participação por turno", "Turno", a["turnos"])
          + card_part("Participação por turma", "Turma", a["turmas"]))
    h.send(pagina("Administração", c))


@rota("GET", "/admin")
def admin(h, q, f):
    if exige(h, "admin"):
        tela_admin(h)


@rota("POST", "/admin/chapa/adicionar")
def chapa_add(h, q, f):
    if not exige(h, "admin"):
        return
    conn = db()
    try:
        if cfg(conn, "status") != "preparacao":
            return tela_admin(h, "Não é possível alterar chapas após abrir a votação.", "erro")
        nome = f.get("nome", "").strip()
        if not nome or not f.get("numero", "").isdigit():
            return tela_admin(h, "Informe número e nome.", "erro")
        try:
            conn.execute("INSERT INTO chapas(numero,nome) VALUES(?,?)", (int(f["numero"]), nome))
        except sqlite3.IntegrityError:
            return tela_admin(h, "Já existe uma chapa com esse número.", "erro")
    finally:
        conn.close()
    tela_admin(h, "Chapa adicionada.")


@rota("POST", "/admin/chapa/remover")
def chapa_del(h, q, f):
    if not exige(h, "admin"):
        return
    conn = db()
    try:
        if cfg(conn, "status") == "preparacao" and f.get("id", "").isdigit():
            conn.execute("DELETE FROM chapas WHERE id=?", (int(f["id"]),))
    finally:
        conn.close()
    tela_admin(h, "Chapa removida.")


@rota("POST", "/admin/importar")
def admin_importar(h, q, f):
    if not exige(h, "admin"):
        return
    conn = db()
    status = cfg(conn, "status")
    conn.close()
    if status != "preparacao":
        return tela_admin(h, "Importação só é permitida antes de abrir a votação.", "erro")
    ok, erros = importar_csv(f.get("csv", ""))
    msg = f"{ok} eleitores importados."
    tipo = "ok"
    if erros:
        tipo = "aviso"
        msg += "<br>" + "<br>".join(esc(e) for e in erros[:10])
        if len(erros) > 10:
            msg += f"<br>… e mais {len(erros) - 10} avisos."
    tela_admin(h, msg, tipo)


@rota("POST", "/admin/status")
def admin_status(h, q, f):
    if not exige(h, "admin"):
        return
    acao = f.get("acao")
    conn = db()
    try:
        status = cfg(conn, "status")
        if acao == "abrir" and status == "preparacao":
            n_e = conn.execute("SELECT COUNT(*) FROM eleitores").fetchone()[0]
            n_c = conn.execute("SELECT COUNT(*) FROM chapas").fetchone()[0]
            if n_e == 0 or n_c == 0:
                return tela_admin(h, "Cadastre ao menos uma chapa e importe os eleitores antes de abrir.", "erro")
            set_cfg(conn, "status", "aberta")
            evento(conn, "votacao_aberta", f"{n_e} eleitores, {n_c} chapas")
            msg = "Votação aberta."
        elif acao == "encerrar" and status == "aberta":
            set_cfg(conn, "status", "encerrada")
            LIBERADO["matricula"] = None
            r = apurar(conn)
            evento(conn, "votacao_encerrada",
                   f"{r['votaram']} votaram, {r['eleitores'] - r['votaram']} abstenções, {r['eleitores']} aptos")
            return h.redirect("/admin/resultado")
        else:
            msg = "Ação inválida para o estado atual."
    finally:
        conn.close()
    tela_admin(h, msg)


def linhas_oficiais(a):
    """Registro oficial: (numero, opcao, votos, % dos votos computados, % dos eleitores aptos)."""
    def pv(n):
        return 100 * n / a["total_votos"] if a["total_votos"] else 0.0

    def pa(n):
        return 100 * n / a["eleitores"] if a["eleitores"] else 0.0

    L = [(ch["numero"], ch["nome"], ch["votos"], pv(ch["votos"]), pa(ch["votos"])) for ch in a["chapas"]]
    L.append(("", "Votos em branco", a["brancos"], pv(a["brancos"]), pa(a["brancos"])))
    L.append(("", "Votos nulos", a["nulos"], pv(a["nulos"]), pa(a["nulos"])))
    return L


@rota("GET", "/admin/resultado")
def resultado(h, q, f):
    if not exige(h, "admin"):
        return
    conn = db()
    status = cfg(conn, "status")
    a = apurar(conn)
    conn.close()
    if status != "encerrada":
        return tela_admin(h, "O resultado só fica disponível depois de encerrar a votação.", "aviso")

    abst = a["eleitores"] - a["votaram"]
    pct_abst = 100 * abst / a["eleitores"] if a["eleitores"] else 0.0
    pct_comp = 100 - pct_abst if a["eleitores"] else 0.0

    c = topo("admin") + "<h1>Resultado da eleição</h1>"
    c += f'<p>Apurado em {agora_br().strftime("%d/%m/%Y %H:%M")} (horário de Brasília)</p>'
    if a["integro"]:
        c += (f'<div class="ok">Verificação de integridade: OK — {a["total_votos"]} votos na urna '
              f'= {a["votaram"]} eleitores marcados como votantes.</div>')
    else:
        c += (f'<div class="erro">ATENÇÃO: {a["total_votos"]} votos na urna ≠ {a["votaram"]} eleitores que votaram. '
              'Investigue antes de divulgar.</div>')

    c += ('<div class="card"><h2 style="margin-top:0">Registro oficial</h2><table>'
          '<tr><th>Nº</th><th>Opção</th><th>Votos</th><th>% dos votos</th><th>% dos eleitores aptos</th></tr>')
    for num, nome, v, pv, pa in linhas_oficiais(a):
        c += (f'<tr><td>{num}</td><td>{esc(nome)}</td><td><b>{v}</b></td>'
              f'<td>{pv:.2f}%</td><td>{pa:.2f}%</td></tr>')
    c += (f'<tr><th></th><th>Total de votos (comparecimento)</th><th>{a["total_votos"]}</th>'
          f'<th>100,00%</th><th>{pct_comp:.2f}%</th></tr>')
    c += (f'<tr><td></td><td><b>Abstenções</b> (aptos que não votaram)</td><td><b>{abst}</b></td>'
          f'<td>—</td><td>{pct_abst:.2f}%</td></tr>')
    c += (f'<tr><th></th><th>Total de eleitores aptos</th><th>{a["eleitores"]}</th><th></th><th>100,00%</th></tr>'
          '</table>'
          '<p style="color:#6b7385;font-size:.9rem">“% dos votos” considera todos os votos computados '
          '(chapas, brancos e nulos). “% dos eleitores aptos” considera todos os eleitores importados.</p></div>')

    if len(a["chapas"]) >= 2 and a["chapas"][0]["votos"] == a["chapas"][1]["votos"]:
        c += '<div class="aviso">Empate entre as chapas mais votadas — verifique o regulamento da eleição.</div>'

    c += (card_part("Participação por curso", "Curso", a["cursos"]) + card_part("Participação por turno", "Turno", a["turnos"])
          + card_part("Participação por turma", "Turma", a["turmas"]))
    c += '<p class="noprint"><a class="btn verde" href="/admin/relatorio">📄 Relatório para PDF</a> <button class="sec" onclick="print()">🖨 Imprimir esta página</button> '
    c += '<a class="btn sec" href="/admin/resultado.csv">Baixar CSV</a> <a class="btn sec" href="/admin">Voltar</a></p>'
    h.send(pagina("Resultado", c))


@rota("GET", "/admin/resultado.csv")
def resultado_csv(h, q, f):
    if not exige(h, "admin"):
        return
    conn = db()
    if cfg(conn, "status") != "encerrada":
        conn.close()
        return h.redirect("/admin")
    a = apurar(conn)
    conn.close()
    abst = a["eleitores"] - a["votaram"]

    def fmt(x):
        return f"{x:.2f}".replace(".", ",")

    buf = io.StringIO()
    w = csv.writer(buf, delimiter=";")
    w.writerow(["numero", "opcao", "votos", "pct_dos_votos", "pct_dos_eleitores_aptos"])
    for num, nome, v, pv, pa in linhas_oficiais(a):
        w.writerow([num, nome, v, fmt(pv), fmt(pa)])
    pct_abst = 100 * abst / a["eleitores"] if a["eleitores"] else 0.0
    w.writerow(["", "Total de votos", a["total_votos"], "100,00", fmt(100 - pct_abst if a["eleitores"] else 0)])
    w.writerow(["", "Abstencoes", abst, "", fmt(pct_abst)])
    w.writerow(["", "Total de eleitores aptos", a["eleitores"], "", "100,00"])
    w.writerow([])
    for titulo, chave in (("curso", "cursos"), ("turno", "turnos"), ("turma", "turmas")):
        w.writerow([titulo, "votaram", "abstencoes", "total", "comparecimento_pct"])
        for t in a[chave]:
            w.writerow([t["rot"], t["votaram"], t["total"] - t["votaram"], t["total"],
                        fmt(100 * t["votaram"] / t["total"] if t["total"] else 0)])
        w.writerow([])
    h.send(("\ufeff" + buf.getvalue()).encode("utf-8"), ctype="text/csv; charset=utf-8",
           headers=[("Content-Disposition", 'attachment; filename="resultado.csv"')])


REL_CSS = """
@page{size:A4;margin:14mm}
.rel,.rel *{-webkit-print-color-adjust:exact;print-color-adjust:exact}
.rel{max-width:800px;margin:0 auto;background:#fff;padding:28px 32px;border-radius:12px;box-shadow:0 1px 6px #0003;color:#1d2433}
.rel header{border-bottom:4px solid #1f5eff;padding-bottom:12px;margin-bottom:6px}
.rel .escola{color:#475066;font-weight:700;letter-spacing:.04em;text-transform:uppercase;font-size:.85rem}
.rel h1{font-size:1.8rem;margin:2px 0 6px}
.rel .meta{color:#6b7385;font-size:.82rem;line-height:1.5}
.rel section{margin:22px 0;page-break-inside:avoid;break-inside:avoid}
.rel section.longa{page-break-inside:auto;break-inside:auto}
.rel tr{page-break-inside:avoid}.rel thead{display:table-header-group}
.rel h2{font-size:1.05rem;margin:0 0 10px;padding:2px 0 2px 10px;border-left:6px solid #1f5eff;text-transform:uppercase;letter-spacing:.03em}
.rel table{border-collapse:collapse;width:100%;table-layout:fixed;font-size:.92rem}
.rel th{background:#eef1f5;text-align:left;padding:7px 9px;border-bottom:2px solid #cfd6e4;font-size:.8rem;text-transform:uppercase;color:#475066}
.rel td{padding:7px 9px;border-bottom:1px solid #e1e5ee;vertical-align:middle}
.rel td.n,.rel th.n{text-align:right;white-space:nowrap}
.rel table.cards{border-collapse:separate;border-spacing:0}
.rel table.cards td{border:0;padding:0 5px;width:25%;vertical-align:top}.rel table.cards td:first-child{padding-left:0}.rel table.cards td:last-child{padding-right:0}
.kpi{border-radius:10px;padding:12px 14px;color:#fff;height:96px;box-sizing:border-box;overflow:hidden}
.kpi span{display:block;font-size:.78rem;opacity:.95}
.kpi b{display:block;font-size:1.9rem;line-height:1.15}
.k-azul{background:#1f5eff}.k-verde{background:#17a34a}.k-ambar{background:#d98e04}.k-verm{background:#d93025}.k-cinza{background:#6b7385}
.destaque{border:2px solid #17a34a;background:#e6f7ec;border-radius:12px;padding:14px 18px}
.destaque.empate{border-color:#d98e04;background:#fff7e0}
.destaque small{display:block;text-transform:uppercase;letter-spacing:.06em;font-weight:700;color:#17803c}
.destaque.empate small{color:#9a6700}
.destaque .nome{font-size:1.6rem;font-weight:800;line-height:1.15}
.r-verde td{background:#e6f7ec;font-weight:700}.r-cinza td{background:#f1f3f6}.r-verm td{background:#fdecea}
.r-ambar td{background:#fff7e0}.r-total td{background:#eef1f5;font-weight:800;border-top:2px solid #cfd6e4}
.ic{object-fit:contain;border:1px solid #cfd6e4;border-radius:8px;background:#fff;vertical-align:middle;margin-right:8px}
.ic.sem{display:inline-block;text-align:center;font-weight:800;color:#1f5eff}
.bar{background:#e8ecf3;border-radius:6px;height:20px;overflow:hidden}
.bar i{display:block;height:100%}
.c-verde{background:#17a34a}.c-azul{background:#1f5eff}.c-ambar{background:#d98e04}.c-verm{background:#d93025}.c-cinza{background:#8a93a6}
.lbl{width:30%}
.chip{display:inline-block;border-radius:99px;padding:4px 12px;font-weight:700;font-size:.82rem;margin:0 6px 6px 0}
.chip.cv{background:#c9f2d6;color:#146c35}.chip.ca{background:#ffe9a8;color:#7a5200}.chip.cn{background:#e3e7ef;color:#475066}
.integ{border-radius:10px;padding:12px 16px;font-weight:600}
.integ.bom{background:#e6f7ec;border:2px solid #17a34a;color:#146c35}.integ.mau{background:#fdecea;border:2px solid #d93025;color:#a0231a}
.assin{margin-top:34px}.assin table td{border:0;padding:0 14px;width:33.33%;text-align:center;font-size:.85rem;color:#475066;vertical-align:top}.assin table td:first-child{padding-left:0}.assin table td:last-child{padding-right:0}
.assin .linha{border-top:1.5px solid #1d2433;margin-top:46px;padding-top:4px;line-height:1.4}.assin .linha b{color:#1d2433;font-size:.95rem}.assin .linha span{font-size:.78rem;color:#6b7385}
.rodape-rel{margin-top:26px;padding-top:8px;border-top:1px solid #cfd6e4;color:#8a93a6;font-size:.75rem;text-align:center}
.cols{columns:2}
.grid2{display:flex;gap:12px}.grid2>div{flex:1}
@media print{.rel{box-shadow:none;border-radius:0;padding:0;max-width:none}}
"""

REL_SECOES = [
    ("destaque", "Destaque: chapa mais votada"),
    ("resumo", "Resumo geral (cartões coloridos)"),
    ("tabela", "Registro oficial: votos e percentuais"),
    ("grafico", "Gráficos de barras"),
    ("icones", "Mostrar ícones das chapas"),
    ("cursos", "Participação por curso"),
    ("turnos", "Participação por turno"),
    ("turmas", "Participação por turma"),
    ("integridade", "Verificação de integridade"),
    ("ocorrencias", "Ocorrências durante a votação"),
    ("assinaturas", "Espaço para assinaturas (ata)"),
]
EVENTOS_REL = {
    "votacao_aberta": "Votação aberta",
    "votacao_encerrada": "Votação encerrada",
    "importacao": "Lista de eleitores importada",
    "tentativa_voto_duplicado": "Tentativa de voto duplicado (bloqueada)",
    "voto_duplicado_bloqueado": "Voto duplicado bloqueado",
    "matricula_nao_encontrada": "Matrícula não encontrada",
    "liberacao_cancelada": "Liberação de urna cancelada pelo mesário",
    "backup": "Backup realizado",
    "senhas_resetadas": "Senhas redefinidas",
}
EVENTOS_COM_DETALHE = {"votacao_aberta", "votacao_encerrada", "importacao"}   # os demais podem citar matrícula: omitidos


def pt(x, casas=2):
    return f"{x:.{casas}f}".replace(".", ",")


def _ic(num, tam=44):
    if achar_icone(num)[0]:
        return f'<img class="ic" src="/icone?n={num}" alt="" style="width:{tam}px;height:{tam}px">'
    return f'<span class="ic" style="display:inline-block;width:{tam}px;height:{tam}px;visibility:hidden"></span>'


def _barra(pct, cor):
    return f'<div class="bar"><i class="c-{cor}" style="width:{max(0.0, min(100.0, pct)):.1f}%"></i></div>'


def secao_part(titulo, rotulo, grupos, larg, longa=False, legenda=False):
    cols = "".join(f'<col style="width:{w}%">' for w in larg)
    t = (f'<section class="{"longa" if longa else ""}"><h2>{titulo}</h2><table><colgroup>{cols}</colgroup>'
         f'<thead><tr><th>{rotulo}</th><th class="n">Aptos</th><th class="n">Votaram</th><th class="n">Abstenções</th>'
         '<th>Comparecimento</th></tr></thead><tbody>')
    for x in grupos:
        cp = 100 * x["votaram"] / x["total"] if x["total"] else 0
        cor = "verde" if cp >= 75 else ("ambar" if cp >= 50 else "verm")
        t += (f'<tr><td><b>{esc(x["rot"])}</b></td><td class="n">{x["total"]}</td><td class="n">{x["votaram"]}</td>'
              f'<td class="n">{x["total"] - x["votaram"]}</td><td><table style="width:100%;table-layout:fixed"><tr>'
              f'<td style="border:0;padding:0">{_barra(cp, cor)}</td><td class="n" style="border:0;padding:0 0 0 8px;width:60px">{pt(cp, 1)}%</td>'
              '</tr></table></td></tr>')
    t += '</tbody></table>'
    if legenda:
        t += ('<p style="margin:6px 0 0;font-size:.78rem;color:#6b7385">'
              '<span class="chip cv">verde ≥ 75%</span><span class="chip ca">amarelo 50–74%</span>'
              '<span class="chip" style="background:#fdecea;color:#a0231a">vermelho &lt; 50%</span></p>')
    return t + '</section>'


@rota("GET", "/admin/relatorio")
def relatorio(h, q, f):
    if not exige(h, "admin"):
        return
    conn = db()
    if cfg(conn, "status") != "encerrada":
        conn.close()
        return tela_admin(h, "O relatório só fica disponível depois de encerrar a votação.", "aviso")
    if "aplicar" in q:
        sel = set(q.get("s", []))
        set_cfg(conn, "rel_escola", q.get("escola", [""])[0].strip()[:120])
        set_cfg(conn, "rel_titulo", q.get("titulo", [""])[0].strip()[:120])
        set_cfg(conn, "rel_rodape", q.get("rodape", [""])[0].strip()[:200])
        set_cfg(conn, "rel_pres_nome", q.get("pres_nome", [""])[0].strip()[:80])
        set_cfg(conn, "rel_pres_cargo", q.get("pres_cargo", [""])[0].strip()[:80])
    else:
        sel = {k for k, _ in REL_SECOES}
    escola = cfg(conn, "rel_escola", "")
    titulo = cfg(conn, "rel_titulo", "") or "Eleição do Grêmio Estudantil"
    rodape = cfg(conn, "rel_rodape", None)
    pres_nome = cfg(conn, "rel_pres_nome", "")
    pres_cargo = cfg(conn, "rel_pres_cargo", "") or "Presidente da Comissão Eleitoral"
    if rodape is None:   # nunca editado: texto padrão (texto vazio = sem rodapé)
        rodape = "Gerado automaticamente pela Urna do Grêmio · {data}"
    a = apurar(conn)
    por_num = sorted(a["chapas"], key=lambda c: c["numero"])
    padrao_ch = [str(c["numero"]) for c in por_num[:2]] + ["", ""]
    mes = []
    for i in (1, 2):
        if "aplicar" in q:
            set_cfg(conn, f"rel_mes{i}_nome", q.get(f"mes{i}", [""])[0].strip()[:80])
            set_cfg(conn, f"rel_mes{i}_chapa", q.get(f"ch{i}", [""])[0])
        ch = cfg(conn, f"rel_mes{i}_chapa", None)
        mes.append((cfg(conn, f"rel_mes{i}_nome", ""), padrao_ch[i - 1] if ch is None else ch))
    r_ab = conn.execute("SELECT quando FROM eventos WHERE tipo='votacao_aberta' ORDER BY id LIMIT 1").fetchone()
    r_en = conn.execute("SELECT quando FROM eventos WHERE tipo='votacao_encerrada' ORDER BY id DESC LIMIT 1").fetchone()
    marcas = ",".join("?" * len(EVENTOS_REL))
    ocorr = conn.execute(f"SELECT quando,tipo,detalhe FROM eventos WHERE tipo IN ({marcas}) ORDER BY id LIMIT 200",
                         tuple(EVENTOS_REL)).fetchall()
    n_dup = conn.execute("SELECT COUNT(*) FROM eventos WHERE tipo IN ('tentativa_voto_duplicado','voto_duplicado_bloqueado')").fetchone()[0]
    n_nao = conn.execute("SELECT COUNT(*) FROM eventos WHERE tipo='matricula_nao_encontrada'").fetchone()[0]
    n_can = conn.execute("SELECT COUNT(*) FROM eventos WHERE tipo='liberacao_cancelada'").fetchone()[0]
    conn.close()

    chapas = a["chapas"]
    ico = "icones" in sel and any(achar_icone(c["numero"])[0] for c in chapas)
    nomes_ch = {str(c["numero"]): c["nome"] for c in chapas}
    abst = a["eleitores"] - a["votaram"]
    pct_abst = 100 * abst / a["eleitores"] if a["eleitores"] else 0.0
    pct_comp = (100 - pct_abst) if a["eleitores"] else 0.0
    tv = a["total_votos"]
    agora = agora_br().strftime("%d/%m/%Y às %H:%M")

    R = []   # corpo do relatório
    meta = f"Relatório final · gerado em {agora} (horário de Brasília)"
    if r_ab:
        meta += f"<br>Votação aberta em {esc(r_ab['quando'])}"
    if r_en:
        meta += f" · encerrada em {esc(r_en['quando'])}"
    R.append(f'<header>{"<div class=escola>" + esc(escola) + "</div>" if escola else ""}'
             f'<h1>{esc(titulo)}</h1><div class="meta">{meta}</div></header>')

    # --- destaque
    if "destaque" in sel:
        if chapas and chapas[0]["votos"] > 0:
            top = [c for c in chapas if c["votos"] == chapas[0]["votos"]]
            if len(top) > 1:
                nomes = "; ".join(f'Chapa {c["numero"]} – {esc(c["nome"])}' for c in top)
                R.append(f'<section><div class="destaque empate"><small>Empate</small>'
                         f'<div class="nome">{nomes}</div>'
                         f'<div>{chapas[0]["votos"]} votos cada. Consulte o regulamento da eleição.</div></div></section>')
            else:
                c = top[0]
                R.append(f'<section><div class="destaque"><small>Chapa mais votada</small>'
                         f'<div class="nome">{_ic(c["numero"], 64) if ico else ""}Chapa {c["numero"]} – {esc(c["nome"])}</div>'
                         f'<div>{c["votos"]} votos · {pt(100 * c["votos"] / tv)}% dos votos · '
                         f'{pt(100 * c["votos"] / a["eleitores"])}% dos eleitores aptos</div></div></section>')
        else:
            R.append('<section><div class="destaque empate"><small>Sem votos em chapas</small>'
                     '<div>Nenhuma chapa recebeu votos.</div></div></section>')

    # --- resumo
    if "resumo" in sel:
        def kpi(rot, val, sub, cor):
            return f'<td><div class="kpi k-{cor}"><span>{rot}</span><b>{val}</b><span>{sub}</span></div></td>'
        R.append('<section><h2>Resumo geral</h2><table class="cards"><tr>'
                 + kpi("Eleitores aptos", a["eleitores"], "total de alunos na lista", "azul")
                 + kpi("Compareceram", a["votaram"], f"{pt(pct_comp)}% de comparecimento", "verde")
                 + kpi("Abstenções", abst, f"{pt(pct_abst)}% dos aptos", "ambar")
                 + kpi("Integridade", "OK" if a["integro"] else "FALHA",
                       "votos = votantes" if a["integro"] else "votos ≠ votantes", "verde" if a["integro"] else "verm")
                 + '</tr></table></section>')

    # --- tabela oficial
    if "tabela" in sel:
        linhas = linhas_oficiais(a)
        t = ('<section><h2>Registro oficial</h2><table><colgroup><col style="width:17%"><col style="width:39%"><col style="width:12%"><col style="width:16%"><col style="width:16%"></colgroup><tr><th>Nº</th><th>Opção</th><th class="n">Votos</th>'
             '<th class="n">% dos votos</th><th class="n">% dos aptos</th></tr>')
        n_top = chapas[0]["votos"] if chapas else 0
        for i, (num, nome, v, pv, pa) in enumerate(linhas):
            if i < len(chapas):
                cls = "r-verde" if (v == n_top and v > 0) else ""
                cel = f'{_ic(num) if ico else ""}<b>{num}</b>'
            else:
                cls = "r-cinza" if nome.startswith("Votos em branco") else "r-verm"
                cel = ""
            t += (f'<tr class="{cls}"><td>{cel}</td><td>{esc(nome)}</td><td class="n">{v}</td>'
                  f'<td class="n">{pt(pv)}%</td><td class="n">{pt(pa)}%</td></tr>')
        t += (f'<tr class="r-total"><td></td><td>Total de votos (comparecimento)</td><td class="n">{tv}</td>'
              f'<td class="n">100,00%</td><td class="n">{pt(pct_comp)}%</td></tr>'
              f'<tr class="r-ambar"><td></td><td>Abstenções (aptos que não votaram)</td><td class="n">{abst}</td>'
              f'<td class="n">—</td><td class="n">{pt(pct_abst)}%</td></tr>'
              f'<tr class="r-total"><td></td><td>Total de eleitores aptos</td><td class="n">{a["eleitores"]}</td>'
              f'<td class="n"></td><td class="n">100,00%</td></tr></table>'
              '<p style="color:#6b7385;font-size:.78rem;margin:6px 0 0">“% dos votos”: base = todos os votos computados '
              '(chapas, brancos e nulos). “% dos aptos”: base = todos os eleitores importados.</p></section>')
        R.append(t)

    # --- gráficos
    if "grafico" in sel:
        g = '<section><h2>Gráficos</h2><p style="margin:0 0 6px;font-weight:700">Votos computados</p><table><colgroup><col style="width:30%"><col style="width:46%"><col style="width:24%"></colgroup>'
        n_top = chapas[0]["votos"] if chapas else 0
        for c in chapas:
            cor = "verde" if (c["votos"] == n_top and n_top > 0) else "azul"
            pv = 100 * c["votos"] / tv if tv else 0
            g += (f'<tr><td class="lbl">{_ic(c["numero"], 28) if ico else ""}{c["numero"]} – {esc(c["nome"])}</td>'
                  f'<td style="width:46%">{_barra(pv, cor)}</td><td class="n">{c["votos"]} ({pt(pv, 1)}%)</td></tr>')
        for rot, v, cor in (("Em branco", a["brancos"], "cinza"), ("Nulos", a["nulos"], "verm")):
            pv = 100 * v / tv if tv else 0
            g += f'<tr><td class="lbl">{rot}</td><td style="width:46%">{_barra(pv, cor)}</td><td class="n">{v} ({pt(pv, 1)}%)</td></tr>'
        g += ('</table><p style="margin:14px 0 6px;font-weight:700">Comparecimento e abstenções</p><table><colgroup><col style="width:30%"><col style="width:46%"><col style="width:24%"></colgroup>'
              f'<tr><td class="lbl">Compareceram</td><td style="width:46%">{_barra(pct_comp, "verde")}</td><td class="n">{a["votaram"]} ({pt(pct_comp, 1)}%)</td></tr>'
              f'<tr><td class="lbl">Abstenções</td><td style="width:46%">{_barra(pct_abst, "ambar")}</td><td class="n">{abst} ({pt(pct_abst, 1)}%)</td></tr>'
              '</table></section>')
        R.append(g)

    # --- participação por curso / turno / turma
    PART = [("cursos", "Participação por curso", "Curso", (38, 12, 12, 14, 24), False),
            ("turnos", "Participação por turno", "Turno", (24, 14, 14, 16, 32), False),
            ("turmas", "Participação por turma", "Turma", (18, 13, 13, 15, 41), True)]
    ativos = [x for x in PART if x[0] in sel]
    for i, (k, tit, col, larg, longa) in enumerate(ativos):
        R.append(secao_part(tit, col, a[k], larg, longa, legenda=(i == len(ativos) - 1)))

    # --- integridade
    if "integridade" in sel:
        if a["integro"]:
            R.append(f'<section><h2>Verificação de integridade</h2><div class="integ bom">✔ Os {tv} votos na urna correspondem '
                     f'exatamente aos {a["votaram"]} eleitores marcados como votantes. O voto é secreto: nenhum voto '
                     f'está associado a matrícula ou nome.</div></section>')
        else:
            R.append(f'<section><h2>Verificação de integridade</h2><div class="integ mau">✖ ATENÇÃO: {tv} votos na urna, mas '
                     f'{a["votaram"]} eleitores marcados como votantes. Investigue antes de divulgar este resultado.</div></section>')

    # --- ocorrências
    if "ocorrencias" in sel:
        def chip(txt, n, aviso=True):
            return f'<span class="chip {"ca" if n else "cv"}">{txt}: {n}</span>'
        o = ('<section><h2>Ocorrências durante a votação</h2>'
             + chip("Tentativas de voto duplicado bloqueadas", n_dup) + chip("Matrículas não encontradas", n_nao)
             + chip("Liberações canceladas", n_can) + '<table><colgroup><col style="width:28%"><col style="width:72%"></colgroup><tr><th>Quando</th><th>Evento</th></tr>')
        for r in ocorr:
            det = f' — {esc(r["detalhe"])}' if (r["tipo"] in EVENTOS_COM_DETALHE and r["detalhe"]) else ""
            o += f'<tr><td>{esc(r["quando"])}</td><td>{esc(EVENTOS_REL[r["tipo"]])}{det}</td></tr>'
        o += '</table></section>'
        R.append(o)

    # --- assinaturas
    if "assinaturas" in sel:
        def cel(papel, sub_="", nome=""):
            return ('<td><div class="linha">' + (f'<b>{esc(nome)}</b><br>' if nome else "") + papel
                    + (f'<br><span>{sub_}</span>' if sub_ else "") + '</div></td>')
        cels = cel(esc(pres_cargo), nome=pres_nome)
        for nome, ch in mes:
            rot = f"Chapa {esc(ch)} – {esc(nomes_ch[ch])}" if ch in nomes_ch else ""
            cels += cel("Mesário(a)", rot, nome)
        R.append('<section class="assin"><h2>Assinaturas</h2><p style="margin:0">Local e data: ______________________________, ____ / ____ / ________</p>'
                 f'<table><tr>{cels}</tr></table></section>')

    if rodape:
        R.append(f'<div class="rodape-rel">{esc(rodape.replace("{data}", agora))}</div>')

    checks = "".join(
        f'<label style="font-weight:400;display:flex;gap:8px;align-items:center;margin:6px 0">'
        f'<input type="checkbox" name="s" value="{k}" style="width:auto"{" checked" if k in sel else ""}> {esc(t)}</label>'
        for k, t in REL_SECOES)
    def opcoes(sel_ch):
        o = '<option value="">— nenhuma —</option>'
        for c in por_num:
            o += f'<option value="{c["numero"]}"{" selected" if str(c["numero"]) == sel_ch else ""}>Chapa {c["numero"]} – {esc(c["nome"])}</option>'
        return o
    mes_campos = "".join(
        f'<div class="grid2" style="margin-bottom:8px"><div><input type="text" name="mes{i}" placeholder="Nome do mesário {i} (opcional)" value="{esc(mes[i - 1][0])}"></div>'
        f'<div><select name="ch{i}" style="width:100%;padding:12px;font-size:1rem;border:1px solid #b9c0cf;border-radius:10px">{opcoes(mes[i - 1][1])}</select></div></div>'
        for i in (1, 2))
    painel = (
        topo("admin") + '<div class="card noprint"><h2 style="margin-top:0">Relatório final</h2>'
        '<form method="get" action="/admin/relatorio"><input type="hidden" name="aplicar" value="1">'
        f'<div class="grid2"><div><label>Nome da escola (opcional)</label><input type="text" name="escola" value="{esc(escola)}"></div>'
        f'<div><label>Título do relatório</label><input type="text" name="titulo" value="{esc(titulo)}"></div></div>'
        f'<label>Texto do rodapé</label><input type="text" name="rodape" value="{esc(rodape)}">'
        '<p style="color:#6b7385;font-size:.85rem;margin:4px 0 0">Use <b>{data}</b> para inserir a data e hora (horário de Brasília). Deixe em branco para não mostrar rodapé.</p>'
        '<label>Assinatura da Comissão Eleitoral</label>'
        f'<div class="grid2" style="margin-bottom:8px"><div><input type="text" name="pres_nome" placeholder="Nome (opcional)" value="{esc(pres_nome)}"></div>'
        f'<div><input type="text" name="pres_cargo" placeholder="Cargo" value="{esc(pres_cargo)}"></div></div>'
        f'<label>Mesários que assinam (um indicado por chapa)</label>{mes_campos}'
        f'<label>O que incluir no relatório</label><div class="cols">{checks}</div>'
        '<p><button class="sec">Atualizar pré-visualização</button></p></form><hr>'
        '<p><button class="verde" onclick="print()">🖨 Imprimir / Salvar como PDF</button> '
        '<a class="btn sec" href="/admin/resultado">Voltar</a></p>'
        '<p style="color:#6b7385;font-size:.9rem;margin:0">Na janela de impressão, escolha <b>Salvar como PDF</b> como destino, '
        'papel <b>A4</b>. Se aparecerem URL e data nas margens da folha, desmarque <b>Cabeçalhos e rodapés</b>.</p></div>')
    nome_arq = "".join(ch if ch.isalnum() else "_" for ch in titulo)[:50] + f"_{agora_br().date().isoformat()}"
    h.send(pagina(nome_arq, painel + '<article class="rel">' + "".join(R) + '</article>', head=f"<style>{REL_CSS}</style>"))


ARQUIVO_DIR = os.path.join(BASE, "eleicoes_anteriores")


@rota("POST", "/admin/nova")
def nova_eleicao(h, q, f):
    if not exige(h, "admin"):
        return
    conn = db()
    try:
        if cfg(conn, "status") != "encerrada":
            return tela_admin(h, "Só é possível iniciar uma nova eleição depois de encerrar a atual.", "erro")
        os.makedirs(ARQUIVO_DIR, exist_ok=True)
        destino = os.path.join(ARQUIVO_DIR, f"eleicao_{agora_br():%Y%m%d_%H%M%S}.db")
        dst = sqlite3.connect(destino)
        conn.backup(dst)
        n_votos = dst.execute("SELECT COUNT(*) FROM votos").fetchone()[0]
        dst.close()
        if n_votos != conn.execute("SELECT COUNT(*) FROM votos").fetchone()[0]:
            return tela_admin(h, "Falha ao arquivar a cópia. Nada foi apagado.", "erro")
        manter = f.get("manter") == "1"
        with lock:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("DELETE FROM votos")
            conn.execute("DELETE FROM chapas")
            conn.execute("DELETE FROM eventos")
            conn.execute("DELETE FROM sqlite_sequence WHERE name IN ('chapas','eventos')")
            if manter:
                conn.execute("UPDATE eleitores SET ja_votou=0, data_voto=NULL")
            else:
                conn.execute("DELETE FROM eleitores")
            set_cfg(conn, "status", "preparacao")
            evento(conn, "nova_eleicao", f"anterior arquivada em {os.path.basename(destino)}")
            conn.execute("COMMIT")
        LIBERADO["matricula"] = None
    finally:
        conn.close()
    tela_admin(h, f"Eleição anterior arquivada em <code>{esc(destino)}</code>. Sistema pronto para a nova eleição.")


@rota("POST", "/admin/backup")
def backup(h, q, f):
    if not exige(h, "admin"):
        return
    os.makedirs(BACKUP_DIR, exist_ok=True)
    destino = os.path.join(BACKUP_DIR, f"eleicao_{agora_br():%Y%m%d_%H%M%S}.db")
    src, dst = db(), sqlite3.connect(destino)
    src.backup(dst)
    dst.close()
    evento(src, "backup", os.path.basename(destino))
    src.close()
    tela_admin(h, f"Backup salvo em: <code>{esc(destino)}</code>")


@rota("GET", "/admin/log")
def log(h, q, f):
    if not exige(h, "admin"):
        return
    conn = db()
    rows = conn.execute("SELECT * FROM eventos ORDER BY id DESC LIMIT 300").fetchall()
    conn.close()
    c = topo("admin") + '<h1>Registro de eventos</h1><div class="card"><table><tr><th>Quando</th><th>Evento</th><th>Detalhe</th></tr>'
    for r in rows:
        c += f'<tr><td>{esc(r["quando"])}</td><td>{esc(r["tipo"])}</td><td>{esc(r["detalhe"])}</td></tr>'
    c += '</table></div><a class="btn sec" href="/admin">Voltar</a>'
    h.send(pagina("Log", c))


# ------------------------------------------------------------- servidor ----
class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def papel(self):
        c = SimpleCookie(self.headers.get("Cookie", ""))
        return SESSOES.get(c["sid"].value) if "sid" in c else None

    def send(self, body, status=200, ctype="text/html; charset=utf-8", headers=None):
        data = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        for k, v in headers or []:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def redirect(self, destino, headers=None):
        self.send_response(303)
        self.send_header("Location", destino)
        self.send_header("Content-Length", "0")
        for k, v in headers or []:
            self.send_header(k, v)
        self.end_headers()

    def do_GET(self):
        self.despachar("GET")

    def do_POST(self):
        self.despachar("POST")

    def despachar(self, metodo):
        try:
            u = urlparse(self.path)
            q = parse_qs(u.query)
            form = {}
            if metodo == "POST":
                n = int(self.headers.get("Content-Length", 0))
                bruto = self.rfile.read(n).decode("utf-8", errors="replace")
                form = {k: v[0] for k, v in parse_qs(bruto, keep_blank_values=True).items()}
            if u.path != "/configurar" and not senhas_configuradas():
                return self.redirect("/configurar")
            fn = ROTAS.get((metodo, u.path))
            if not fn:
                return self.send(pagina("404", '<p>Página não encontrada. <a href="/">Início</a></p>'), 404)
            fn(self, q, form)
        except Exception as e:  # noqa
            import traceback
            traceback.print_exc()
            self.send(pagina("Erro", f"<div class='erro'>Erro interno: {esc(e)}</div>"), 500)


def main():
    init_db()
    if "--resetar-senhas" in sys.argv:
        resetar_senhas()
        print("Senhas apagadas. Abra a urna e defina novas senhas no navegador.")
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)  # só aceita acesso deste computador
    url = f"http://localhost:{PORT}"
    print(f"\nUrna rodando em {url}  (Ctrl+C para parar)")
    try:
        webbrowser.open(url)
    except Exception:
        pass
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nEncerrado.")


if __name__ == "__main__":
    main()
