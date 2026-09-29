# IDAP Monitor V5.1

Esta versão separa a coleta CAP da aplicação web.

## Arquitetura

`idapcap.mdr.gov.br` → GitHub Actions → Cloudflare D1 → Cloudflare Worker → navegador

A sincronização automática é executada pelo GitHub Actions a cada 15 minutos. A interface consulta apenas o D1, portanto não depende do acesso direto do Worker ao repositório CAP.

## Cloudflare

O `wrangler.jsonc` já aponta para:

- Worker: `idap-monitor`
- D1 binding: `DB`
- Banco: `idap-monitor-db`
- Database ID: `410a7557-5a1d-442a-a0ac-7e9743622231`

## Secrets necessários no GitHub

Em `Settings → Secrets and variables → Actions`, crie:

- `CLOUDFLARE_ACCOUNT_ID`
- `CLOUDFLARE_API_TOKEN`

O token deve ser um Custom API Token do Cloudflare limitado à sua conta e com permissão `Account → D1 → Edit`.

O Database ID já está configurado no workflow e não precisa ser criado como secret.

## Primeira sincronização

Depois de adicionar os secrets:

1. GitHub → Actions
2. Abra `Sincronizar CAP com D1`
3. `Run workflow`
4. Informe `7` dias para o primeiro teste
5. Aguarde a conclusão
6. Volte ao IDAP Monitor e consulte o período

A rotina agendada posterior verifica os últimos 3 dias a cada 15 minutos e só baixa XML novos ou processados por uma versão antiga do parser.

## Sincronização histórica

Para carregar um período mais antigo, execute manualmente o workflow e aumente `lookback_days`, até 90 dias.

## Deploy do Worker

O deploy existente no Cloudflare continua usando o GitHub. Depois do `git push`, o Cloudflare fará um novo deploy automaticamente.
