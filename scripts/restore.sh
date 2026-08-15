#!/usr/bin/env bash
set -Eeuo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BACKUP_ROOT="${ARGUS_BACKUP_DIR:-${PROJECT_DIR}/backups}"
SOURCE="${1:-}"
CONFIRM="${2:-}"
VOLUMES=(postgres_data redis_data neo4j_data)
STOPPED=0

usage() {
  echo "Uso: $0 DIRETORIO_DO_BACKUP --confirm" >&2
  echo "A restauração substitui integralmente PostgreSQL, Redis e Neo4j." >&2
}
resume_services() {
  if [[ "${STOPPED}" == "1" ]]; then
    docker compose --project-directory "${PROJECT_DIR}" start postgres redis neo4j >/dev/null
  fi
}
trap resume_services EXIT

[[ -n "${SOURCE}" && "${CONFIRM}" == "--confirm" ]] || { usage; exit 2; }
SOURCE="$(realpath -e "${SOURCE}")"
ROOT_REAL="$(realpath -e "${BACKUP_ROOT}")"
[[ "${SOURCE}" == "${ROOT_REAL}/"* ]] || { echo "ERRO: backup deve estar dentro de ${ROOT_REAL}." >&2; exit 2; }
[[ -f "${SOURCE}/SHA256SUMS" ]] || { echo "ERRO: manifesto SHA256SUMS ausente." >&2; exit 2; }
for volume in "${VOLUMES[@]}"; do
  [[ -f "${SOURCE}/${volume}.tar.gz" ]] || { echo "ERRO: ${volume}.tar.gz ausente." >&2; exit 2; }
done
(cd "${SOURCE}" && sha256sum -c SHA256SUMS)

command -v docker >/dev/null || { echo "ERRO: Docker não encontrado." >&2; exit 1; }
docker info >/dev/null 2>&1 || { echo "ERRO: daemon Docker inacessível para o usuário atual." >&2; exit 1; }

echo "Parando bancos e restaurando snapshot verificado..."
docker compose --project-directory "${PROJECT_DIR}" stop postgres redis neo4j >/dev/null
STOPPED=1

for volume in "${VOLUMES[@]}"; do
  full_name="argus_${volume}"
  docker volume inspect "${full_name}" >/dev/null
  docker run --rm \
    -v "${full_name}:/target" \
    -v "${SOURCE}:/backup:ro" \
    busybox:1.36.1 sh -ceu \
    'find /target -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +; tar -C /target -xzf "/backup/$1.tar.gz"' sh "${volume}"
done

echo "Restore concluído. Serviços de dados serão reiniciados."
