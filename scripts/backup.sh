#!/usr/bin/env bash
set -Eeuo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BACKUP_ROOT="${ARGUS_BACKUP_DIR:-${PROJECT_DIR}/backups}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
DESTINATION="${BACKUP_ROOT}/${STAMP}"
VOLUMES=(postgres_data redis_data neo4j_data)
STOPPED=0

resume_services() {
  if [[ "${STOPPED}" == "1" ]]; then
    docker compose --project-directory "${PROJECT_DIR}" start postgres redis neo4j >/dev/null
  fi
}
trap resume_services EXIT

command -v docker >/dev/null || { echo "ERRO: Docker não encontrado." >&2; exit 1; }
docker info >/dev/null 2>&1 || { echo "ERRO: daemon Docker inacessível para o usuário atual." >&2; exit 1; }
mkdir -p "${DESTINATION}"
chmod 700 "${BACKUP_ROOT}" "${DESTINATION}"

echo "Parando bancos para snapshot consistente..."
docker compose --project-directory "${PROJECT_DIR}" stop postgres redis neo4j >/dev/null
STOPPED=1

for volume in "${VOLUMES[@]}"; do
  full_name="argus_${volume}"
  docker volume inspect "${full_name}" >/dev/null
  docker run --rm --read-only \
    -e ARGUS_BACKUP_UID="$(id -u)" \
    -e ARGUS_BACKUP_GID="$(id -g)" \
    -v "${full_name}:/source:ro" \
    -v "${DESTINATION}:/backup" \
    busybox:1.36.1 sh -ceu \
    'tar -C /source -czf "/backup/$1.tar.gz" .; chown "$ARGUS_BACKUP_UID:$ARGUS_BACKUP_GID" "/backup/$1.tar.gz"; chmod 600 "/backup/$1.tar.gz"' \
    sh "${volume}"
done

(
  cd "${DESTINATION}"
  sha256sum ./*.tar.gz > SHA256SUMS
)
chmod 600 "${DESTINATION}"/*
ln -sfn "${STAMP}" "${BACKUP_ROOT}/latest"

echo "Backup concluído e verificado em: ${DESTINATION}"
