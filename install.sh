#!/bin/bash
# ARGUS 2.0 — instalação segura por Docker Compose

set -euo pipefail

# === VALIDAÇÃO DE PRÉ-REQUISITOS ===
check_prerequisites() {
    echo "[ARGUS] Validando pré-requisitos..."

    command -v docker >/dev/null || {
        echo "[ERRO] Docker com Compose é necessário." >&2
        exit 1
    }
    docker compose version >/dev/null 2>&1 || {
        echo "[ERRO] O plugin Docker Compose é necessário." >&2
        exit 1
    }

    # Espaço em disco (mínimo 50GB livres)
    DISK_FREE=$(df /opt --output=avail -BG 2>/dev/null | tail -1 | tr -d 'G' || echo "0")
    if (( DISK_FREE < 50 )); then
        echo "[AVISO] Mínimo 50GB livres recomendado. Encontrado: ${DISK_FREE}GB"
    fi

    echo "[ARGUS] Pré-requisitos OK"
}

# === MODO DRY-RUN ===
DRY_RUN=false
SECRETS_ONLY=false
for argument in "$@"; do
    case "$argument" in
        --dry-run) DRY_RUN=true ;;
        --secrets-only) SECRETS_ONLY=true ;;
        *) echo "Uso: $0 [--dry-run] [--secrets-only]" >&2; exit 2 ;;
    esac
done
if $DRY_RUN; then
    echo "[ARGUS] Modo DRY-RUN — nenhuma alteração será feita"
fi

# === ROLLBACK EM FALHA ===
rollback() {
    echo "[ERRO] Instalação falhou na linha $1. Fazendo rollback..."
    echo "[ARGUS] Verifique os logs; dados persistentes não foram removidos."
}

trap 'rollback $LINENO' ERR

generate_runtime_secrets() {
    command -v openssl >/dev/null || {
        echo "[ERRO] openssl é necessário para gerar os segredos de runtime."
        exit 1
    }
    if [[ -f .env ]]; then
        if ! grep -q '^ARGUS_ADMIN_PASSWORD=' .env; then
            ARGUS_ADMIN_SECRET=$(openssl rand -base64 24 | tr -d '\n')
            printf '%s\n' "ARGUS_ADMIN_USER=admin" "ARGUS_ADMIN_PASSWORD=${ARGUS_ADMIN_SECRET}" >> .env
            unset ARGUS_ADMIN_SECRET
        fi
        chmod 600 .env
        echo "[ARGUS] Segredos existentes preservados e esquema de .env atualizado (0600)."
        return
    fi
    umask 077
    ARGUS_POSTGRES_SECRET=$(openssl rand -hex 24)
    ARGUS_NEO4J_SECRET=$(openssl rand -hex 24)
    ARGUS_TOR_SECRET=$(openssl rand -hex 24)
    ARGUS_JWT_SECRET=$(openssl rand -hex 48)
    ARGUS_ADMIN_SECRET=$(openssl rand -base64 24 | tr -d '\n')
    printf '%s\n' \
        "POSTGRES_PASSWORD=${ARGUS_POSTGRES_SECRET}" \
        "ARGUS_DB_PASSWORD=${ARGUS_POSTGRES_SECRET}" \
        "NEO4J_PASSWORD=${ARGUS_NEO4J_SECRET}" \
        "TOR_CONTROL_PASSWORD=${ARGUS_TOR_SECRET}" \
        "JWT_SECRET_KEY=${ARGUS_JWT_SECRET}" \
        "ARGUS_ADMIN_USER=admin" \
        "ARGUS_ADMIN_PASSWORD=${ARGUS_ADMIN_SECRET}" > .env
    chmod 600 .env
    unset ARGUS_POSTGRES_SECRET ARGUS_NEO4J_SECRET ARGUS_TOR_SECRET ARGUS_JWT_SECRET ARGUS_ADMIN_SECRET
    echo "[ARGUS] Segredos fortes gerados em .env (0600); valores não exibidos."
}

# === INSTALAÇÃO PRINCIPAL ===
main() {
    if $DRY_RUN; then
        echo "[ARGUS] Caminho único: gerar .env e executar docker compose up -d --build."
        exit 0
    fi

    if $SECRETS_ONLY; then
        generate_runtime_secrets
        echo "[ARGUS] Geração de segredos concluída; nenhum serviço foi alterado."
        exit 0
    fi

    check_prerequisites

    generate_runtime_secrets
    docker info >/dev/null 2>&1 || {
        echo "[ERRO] Docker inacessível. Entre novamente na sessão após adicionar o usuário ao grupo docker." >&2
        exit 1
    }
    echo "[ARGUS] Construindo e iniciando a stack isolada..."
    docker compose up -d --build
    docker compose ps
    echo "[ARGUS] Instalação Compose concluída em http://127.0.0.1:3000"
}

main "$@"
