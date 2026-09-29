# Arquitetura

O IDAP Monitor possui quatro blocos principais:

1. **Coleta CAP**: consulta o índice de `idapcap.mdr.gov.br`, seleciona os XML pelo período e UF e armazena os dados necessários.
2. **Avaliação automática**: verifica vigência e conteúdo textual da mensagem principal.
3. **Revisão humana**: preserva a avaliação automática original e grava o resultado validado, que passa a ter precedência na interface.
4. **Aprendizado supervisionado**: reúne divergências entre máquina e revisor, permite aprovar novas expressões e reprocessa os alertas em cache sem apagar as validações humanas.

## Persistência

Por padrão a aplicação usa SQLite. Localmente, o banco fica junto ao projeto. Em hospedagem, use `IDAP_DATA_DIR` apontando para armazenamento persistente.

O banco não deve ser versionado no GitHub.

## Escalabilidade

SQLite é adequado para teste e uso com uma única instância. Se a aplicação passar a ter vários processos ou instâncias simultâneas, a próxima evolução recomendada é migrar a persistência para PostgreSQL.
