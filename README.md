# IDAP Monitor

Aplicação para monitoramento da conformidade de alertas publicados pela IDAP, com foco em **vigência** e **conteúdo textual**, revisão humana e aprendizado supervisionado.

## Funcionalidades

- consulta alertas reais no repositório CAP;
- filtros por período, UF, nível, vigência, texto, revisão humana e resultado;
- exibição do ID operacional do alerta no padrão `100008/2022`;
- uso de `senderName` como nome da instituição;
- avaliação automática de vigência e texto;
- revisão humana com justificativa;
- precedência permanente da avaliação validada pelo humano;
- histórico de versões do avaliador;
- área de Aprendizado para analisar divergências e aprovar novas expressões.

## Rodar localmente

Requer Python 3.10 ou superior.

```bash
python3 app.py
```

Abra `http://127.0.0.1:8765/`.

O banco `idap_monitor.db` será criado automaticamente e **não deve ser enviado ao GitHub**.

## Proteção por senha

A autenticação é opcional localmente. Para ativá-la:

```bash
export IDAP_BASIC_USER="seu_usuario"
export IDAP_BASIC_PASSWORD="uma_senha_forte"
python3 app.py
```

Em hospedagem pública, use essas variáveis obrigatoriamente.

## Publicar no GitHub

Crie um repositório vazio e, dentro desta pasta, execute:

```bash
git init
git add .
git commit -m "Versão inicial do IDAP Monitor"
git branch -M main
git remote add origin URL_DO_SEU_REPOSITORIO
git push -u origin main
```

O `.gitignore` já exclui banco, arquivos temporários e variáveis de ambiente.

## Deploy no Render

O arquivo `render.yaml` deixa o projeto preparado para um Blueprint do Render. Ele configura:

- serviço web Python;
- endpoint de saúde `/healthz`;
- armazenamento persistente em `/var/data` para o SQLite;
- variáveis para usuário e senha;
- deploy automático a partir do GitHub.

No Render, informe valores para `IDAP_BASIC_USER` e `IDAP_BASIC_PASSWORD` quando solicitado.

### Importante sobre SQLite

Para esta fase, SQLite com disco persistente é suficiente para uma única instância. Se o projeto passar a receber muitos usuários simultâneos ou precisar escalar horizontalmente, a persistência deve migrar para PostgreSQL.

## Estrutura

```text
idap-monitor/
├── app.py
├── index.html
├── render.yaml
├── requirements.txt
├── .gitignore
├── .env.example
├── data/
├── docs/
│   ├── ARQUITETURA.md
│   ├── REGRAS_AVALIACAO.md
│   └── mapa_avaliacao_headline.png
├── tests/
│   └── test_parser.py
└── .github/workflows/
    └── validate.yml
```

## Segurança e dados

Não envie `idap_monitor.db`, senhas ou arquivos `.env` para o GitHub. O banco contém as revisões e o histórico operacional da aplicação.

Antes de disponibilizar a aplicação para uso institucional amplo, vale definir autenticação institucional, perfis de usuário, política de backup e migração para um banco centralizado.
