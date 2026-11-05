# Urna do Grêmio — guia rápido

## Requisitos
Python 3.8+ (python.org). Não precisa de internet nem de instalar pacotes.

## Iniciar
- Windows: dê dois cliques em `iniciar.bat`
- Linux/Mac: `python3 app.py`

Na **primeira vez** o navegador abre uma tela para definir duas senhas: **administrador** e **mesários** (diferentes entre si).
Esqueceu a senha? Feche a urna e rode `python app.py --resetar-senhas` (não apaga os votos).
O navegador abre em http://localhost:8000 (use F11 para tela cheia).

## Antes da eleição (Administração)
1. Cadastre as chapas (número e nome) e coloque o ícone de cada uma na pasta `icones/`, com o número da chapa no nome do arquivo (`1.png`, `12.jpg`, `25.svg`…). A lista de chapas na Administração mostra quais já têm ícone.
2. Importe o CSV de eleitores (`matricula;nome;turma;turno`, veja `exemplo_eleitores.csv`). O curso é identificado automaticamente pela turma/matrícula (TIIMI, TMEMI, EJAQEL = ProEJA, TPMAI, TPMI). Ao importar, o sistema avisa quantos alunos estão sem turma.
3. Faça um teste com um banco de teste e depois APAGUE o arquivo `eleicao.db`
   para começar a eleição real do zero.
4. Clique em **Abrir votação**. Depois disso chapas e eleitores ficam bloqueados.

## No dia (Mesários)
1. Entrar como Mesário (senha dos mesários).
2. Digitar a matrícula → conferir nome/turma/documento → **Liberar urna**.
3. O aluno digita o número da chapa (teclado na tela ou do computador). Aparecem o nome e o ícone; ele aperta CONFIRMA (verde), CORRIGE (laranja) ou BRANCO. Número inexistente = voto nulo. A tela volta sozinha para o mesário.
   Atalhos do teclado: números, Enter = confirma, Backspace = corrige, B = branco.
- Aluno já votou ou matrícula inexistente: o sistema bloqueia e registra no log.
- Se liberou o aluno errado: "Cancelar (somente mesário)" no fim da tela da urna.

## Encerramento (Administração)
**Encerrar votação e apurar** → registro oficial com votos, % dos votos e % dos eleitores aptos por opção (chapas, brancos, nulos), abstenções, comparecimento por turma e verificação de integridade
(votos na urna = eleitores que votaram), impressão e CSV. Encerrar não pode ser desfeito.

## Relatório final em PDF
Com a votação encerrada: **Ver resultado → Relatório para PDF**.
- Informe o nome da escola e o título (ficam salvos para a próxima vez).
- Edite o **texto do rodapé** (use `{data}` para inserir data e hora; em branco = sem rodapé).
- Todas as datas e horas do sistema (relatório, registro de eventos, backups) usam o **horário de Brasília**, mesmo que o relógio do computador esteja em outro fuso.
- Marque as seções que quer incluir: destaque da chapa mais votada, resumo em cartões, registro oficial
  (votos e percentuais), gráficos de barras, ícones das chapas, participação por turma, verificação de
  integridade, ocorrências durante a votação e assinaturas (Presidente da Comissão Eleitoral e os 2 mesários).
- Em "Assinatura da Comissão Eleitoral", escreva o nome (opcional) e o cargo de quem vai assinar (padrão: Presidente da Comissão Eleitoral; pode ser outro cargo).
- Em "Mesários que assinam", informe o nome (opcional) e a chapa que indicou cada mesário. O padrão é uma chapa para cada mesário, na ordem dos números.
- Clique em **Atualizar pré-visualização** e depois em **Imprimir / Salvar como PDF**
  (destino: Salvar como PDF, papel A4; se aparecerem URL/data nas margens, desmarque "Cabeçalhos e rodapés").
- A participação (aptos, votaram, abstenções, comparecimento) é mostrada por **curso**, por **turno** e por **turma**, na Administração, no resultado, no CSV e no relatório. O voto continua secreto: o sistema nunca guarda em qual chapa cada curso, turno ou turma votou.
- Cores: verde = chapa mais votada / bom comparecimento, amarelo = abstenções / atenção, vermelho = nulos / baixo comparecimento, cinza = brancos.
- O relatório não mostra matrículas nem nomes de alunos.

## Terminar e começar uma nova eleição
Com a votação encerrada, na Administração use **Arquivar e iniciar nova eleição**:
- Salva uma cópia completa em `eleicoes_anteriores/` (guarde junto com a ata).
- Zera chapas, votos e registro de eventos. As senhas são mantidas.
- Opção de manter a lista de eleitores (todos voltam a "não votou") ou apagá-la para importar uma nova.
Para consultar uma eleição antiga, abra o arquivo `.db` com o DB Browser for SQLite,
ou copie-o para `eleicao.db` (com o app fechado) para ver o resultado na tela.

## Som de fim de votação
Ao confirmar, a tela mostra "FIM" e toca um "pi-li-li" (três bipes curtos) gerado pelo navegador, sem arquivo.
Para usar o som original da urna, coloque um arquivo `urna.mp3`, `urna.wav` ou `urna.ogg` na mesma pasta do `app.py`.
Para ajustar o beep sintético, edite a linha `NOTAS` no `app.py`. Verifique o volume do computador antes da votação.

## Segurança e sigilo
- Tabela `votos`: sem matrícula, sem horário, ID aleatório. Impossível ligar voto a aluno.
- Marcar "já votou" e gravar o voto acontecem na mesma transação.
- Servidor aceita acesso só do próprio computador.
- Use "Fazer backup agora" de tempos em tempos (pasta `backups/`) e copie para um pendrive.
- Guarde `eleicao.db` e o relatório impresso/assinado junto com a ata.
- Evite deixar a urna em janela comum: use tela cheia para o aluno não navegar para outras páginas.
