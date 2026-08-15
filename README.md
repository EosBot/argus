# ARGUS 2.0

Plataforma local de apoio a investigações OSINT/Tor orientada a casos. O ARGUS coordena agentes de coleta e análise, preserva fontes e evidências e separa pesquisa passiva de ações ativas autorizadas.

## Aviso operacional

Use somente dentro da lei, das políticas da sua instituição e do escopo formal da investigação. A aba **Exploitation** não concede autorização: ela apenas registra a confirmação do operador. Não carregue, redistribua nem exponha material ilícito; siga o protocolo institucional para conteúdo sensível.

## Instalação recomendada

```bash
./install.sh
```

O instalador cria `.env` com segredos aleatórios, valida o acesso ao Docker e sobe a stack com build local. Ele não imprime os valores. A senha administrativa inicial está em `ARGUS_ADMIN_PASSWORD`; altere-a no primeiro acesso. Use `./install.sh --secrets-only` quando quiser apenas preparar o Compose. Docker Compose é o único deployment suportado; o instalador não altera serviços ou pacotes do host.

Após adicionar o usuário ao grupo Docker, encerre a sessão e entre novamente. Então valide:

```bash
docker compose config -q
docker compose up -d
docker compose ps
```

A interface fica em `http://127.0.0.1:3000` e a API em `http://127.0.0.1:8000`. As portas do Compose são vinculadas ao loopback por padrão.

## Fluxo de investigação

- Crie uma investigação pela barra lateral. Por padrão, **Criar e investigar** inicia imediatamente o DAG autônomo; desmarque a opção apenas para preparar o caso sem coleta.
- Use **Collection** para adicionar uma nova coleta a um caso existente. O modo autônomo planeja, distribui e correlaciona o trabalho.
- Acompanhe fontes no Terminal e o estado no Inspector/Agent Status.
- Abra links `.onion` pelo **Safe Browser**. A captura textual sanitizada recebe hash e vínculo com o caso.
- Use **Exploitation** apenas para ativos autorizados, selecionando o caso e confirmando o escopo.
- Revise os achados e gere o formato de relatório exigido pela instituição.

O botão `?` abre um guia de cinco passos. Configurações → Como Funciona contém a referência permanente.

Na aba Tools, apenas itens marcados como disponíveis são executáveis. O catálogo contém somente ferramentas com executor concreto e distingue agentes, executores locais, binários opcionais, APIs públicas e conectores autenticados. Dependências ausentes e conexões não configuradas ficam explicitamente indisponíveis. Os executores determinísticos operam sobre dados fornecidos, sem shell e sem acesso à rede.

## Verificação local

```bash
.venv/bin/pytest -q tests
cd frontend
npm ci
npm run build -- --webpack
```

O código Python reutilizado pelo fork foi consolidado em `argus_engine/`; não existe runtime, UI, plugin ou repositório Robin aninhado. O plano interno de implementação não faz parte do artefato público.

## Segurança e evidência

- JWT e RBAC protegem REST e WebSockets.
- Investigações, coletas e ações são filtradas por proprietário; administradores mantêm supervisão institucional.
- Segredos de providers/conectores são criptografados no backend e mascarados na resposta.
- Produção falha ao iniciar com segredos publicados de desenvolvimento.
- Capturas do navegador registram operador, horário, URL, hash do conteúdo, hash anterior e hash encadeado.
- Collection, Exploitation e execução de tools geram eventos de auditoria.

Consulte [docs/operator-guide.md](docs/operator-guide.md) antes de usar o sistema em um caso real.
