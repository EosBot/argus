# Guia operacional do investigador

## Antes de abrir um caso

- Confirme autoridade legal, finalidade, período, fontes permitidas e ativos autorizados.
- Registre o identificador institucional do caso no título/descrição, sem inserir segredos no título.
- Verifique `docker compose ps` e `GET /api/monitoring/health`.
- Confirme Tor/OPSEC em Configurações antes de acessar uma fonte `.onion`.
- Defina retenção e destino dos relatórios conforme a política da instituição.
- Mantenha **Iniciar pipeline autônomo** marcado para que os subagentes planejem pesquisa, coleta, análise e relatório após a criação. Se o caso for criado mas a orquestração falhar, a interface distingue os dois estados; consulte Agent Status antes de repetir para evitar casos duplicados.

## Coleta passiva

Use Collection com o modo autônomo ativo para objetivos amplos. A consulta deve descrever a informação procurada e os critérios relevantes; o operador não precisa escolher engines ou inserir IDs técnicos. Resultados de busca são pistas, não fatos confirmados. Valide fonte, data, consistência e confiabilidade antes de promover um achado.

### Conectores de inteligência

Configurações → Connections aceita chaves para Shodan, Censys, VirusTotal, AbuseIPDB, AlienVault OTX, ThreatFox e URLhaus. A execução usa hosts oficiais fixos e ignora endpoints personalizados, limita cada resposta a 1 MB, não segue redirects, redige campos de segredo e exige vínculo com um caso. Consultas podem consumir créditos ou cotas da instituição; confirme o plano do provedor antes de automatizar volume.

- [Shodan REST API](https://developer.shodan.io/api)
- [Censys Platform API v3](https://docs.censys.com/reference/get-started)
- [VirusTotal API v3](https://docs.virustotal.com/reference/overview)
- [AbuseIPDB API](https://www.abuseipdb.com/api.html)
- [AlienVault OTX API](https://otx.alienvault.com/api)
- [ThreatFox API](https://threatfox.abuse.ch/api/)
- [URLhaus API](https://urlhaus.abuse.ch/api/)

Censys nesta versão executa lookup de IP público; não anuncia busca CenQL genérica. AbuseIPDB também aceita somente IP público. Entradas privadas, loopback, reservadas ou malformadas são recusadas antes de qualquer conexão externa.

O lookup Wayback não exige chave: consulta somente a API de disponibilidade do Internet Archive pelo proxy Tor configurado, aceita URL pública sem credenciais, limita a resposta a 1 MB e devolve apenas disponibilidade, timestamp, status e URL de snapshot validada no domínio `web.archive.org`.

## Safe Browser

O navegador aceita apenas endereços Tor v3. JavaScript, downloads, service workers, WebSocket e subrecursos externos são bloqueados. O backend sanitiza o HTML e preserva uma captura textual; ele não é uma VM genérica e não deve ser usado para abrir arquivos. Nunca copie uma URL `.onion` para o navegador convencional.

## Ações ativas

Exploitation exige uma investigação selecionada, permissão `pentest:execute` e confirmação explícita. A confirmação é auditada, mas não substitui mandado, contrato, ordem ou autorização institucional. Defina alvo e limites de taxa com precisão; interrompa se o alvo resolvido sair do escopo.

## Cadeia de custódia

Para cada artefato, preserve:

- caso e operador;
- URL/origem e horário UTC;
- método/ferramenta e identificador da tarefa;
- conteúdo original quando permitido;
- hash SHA-256 e vínculo com o hash anterior;
- transformações e exports realizados.

Não edite manualmente evidências persistidas. Gere uma nova derivação e mantenha referência ao original. Exports auxiliam interoperabilidade; valide o formato exigido pelo destinatário.

## Resposta a falhas

- **Backend offline:** consulte `docker compose logs backend` e o health check; não repita ações ativas às cegas.
- **Tor indisponível:** interrompa navegação `.onion`; não faça fallback direto para clearnet.
- **Provider LLM indisponível:** selecione outro provider ou Ollama; a origem de pesquisa deve continuar distinguível do texto gerado.
- **Ferramenta desabilitada:** leia o estado em Configurações → Tools. O catálogo só lista integrações com executor; binários ausentes e conexões não configuradas permanecem indisponíveis e não devem ser contornados.
- **Resultado parcial:** preserve o erro e o ID da tarefa; reinicie somente após verificar se a ação é idempotente.
- **Suspeita de comprometimento:** pare os serviços, preserve logs/volumes, revogue chaves e siga o procedimento institucional de incidente.

## Encerramento do caso

- Revise falsos positivos e marque limitações.
- Confirme hashes e fontes no relatório.
- Exporte apenas o necessário ao destinatário autorizado.
- Aplique a política de retenção; não apague evidência fora do procedimento formal.

## Backup e restauração

- Execute `./scripts/backup.sh` em janela operacional: PostgreSQL, Redis e Neo4j são pausados durante o snapshot consistente.
- O destino padrão é `./backups/<data-UTC>`; use `ARGUS_BACKUP_DIR` para armazenamento dedicado com acesso restrito.
- Cada conjunto contém `SHA256SUMS`; copie o diretório completo para mídia institucional protegida.
- Teste a restauração periodicamente em um ambiente isolado com `./scripts/restore.sh CAMINHO --confirm`.
- O restore substitui integralmente os três volumes e só aceita conjuntos dentro de `ARGUS_BACKUP_DIR`. Faça um backup novo antes de restaurar produção.
- O snapshot é point-in-time (RPO igual ao início da janela cold). No ensaio local de 2026-08-14, o backup levou cerca de 18 s e o restore mais retorno ao readiness cerca de 20 s; meça novamente no hardware e no volume de dados institucionais antes de definir o RTO oficial.
- Os arquivos e o manifesto são gravados com modo `0600` e propriedade do operador que iniciou o procedimento; valide isso após copiar para outra mídia.
- Registre versão do ARGUS, ferramentas indisponíveis e falhas ocorridas.

## Atualização de imagens

- O Compose e todos os Dockerfiles fixam imagens externas por digest SHA-256. Uma tag legível continua presente, mas não controla silenciosamente o conteúdo executado.
- Não substitua um digest apenas porque uma tag `latest`, `7`, `17` ou `slim` mudou. Revise notas de versão e vulnerabilidades, consulte o novo digest no registry e faça a alteração em revisão versionada.
- Valide a atualização com `docker compose config -q`, `docker build --check` para cada Dockerfile, build completo, health checks e a suíte E2E antes da promoção.
- A troca de digest pode recriar containers, mas não deve remover volumes nomeados. Faça backup antes de atualizar PostgreSQL, Redis ou Neo4j e nunca use `docker compose down -v` em produção.
