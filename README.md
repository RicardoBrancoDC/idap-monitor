# IDAP Monitor V5 - Cloudflare Workers + D1

Esta versão foi preparada para a conta Cloudflare Free.

## Banco D1 já configurado

- Nome: `idap-monitor-db`
- Binding no Worker: `DB`
- Database ID: `410a7557-5a1d-442a-a0ac-7e9743622231`

O banco já foi criado no Dashboard e as cinco tabelas foram criadas.

## Arquitetura

GitHub -> Cloudflare Workers Builds -> Worker + Static Assets -> D1

A interface continua sendo servida pelo próprio Worker. As rotas `/api/*` usam o banco D1.

Para reduzir o uso de CPU do plano Free, o índice grande de `idapcap.mdr.gov.br` é apenas repassado pelo Worker e filtrado no navegador. Os XML selecionados são enviados para processamento em pequenos lotes de 5 arquivos.

## Publicação pelo GitHub

Substitua o conteúdo do repositório `RicardoBrancoDC/idap-monitor` pelos arquivos desta pasta e faça:

```bash
git add -A
git commit -m "Migra IDAP Monitor para Cloudflare Workers e D1"
git push
```

Depois, no Cloudflare:

1. Workers & Pages
2. Create application
3. Import a repository
4. Selecione `RicardoBrancoDC/idap-monitor`
5. Production branch: `main`
6. Build command: deixe em branco
7. Deploy command: `npx wrangler deploy`
8. Save and Deploy

O arquivo `wrangler.jsonc` já contém o binding do D1, então não é necessário cadastrar manualmente o Database ID.

## Desenvolvimento local

Requer Node.js.

```bash
npm install
npm run dev
```

Por padrão, o Wrangler usa um banco D1 local durante desenvolvimento. Para testar diretamente contra o D1 remoto, use as opções remotas do Wrangler com cuidado.

## Persistência

As revisões humanas, alertas processados, termos aprovados e histórico ficam no D1. Um novo deploy do Worker não apaga esses dados.
