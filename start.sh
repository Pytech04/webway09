#!/usr/bin/env bash
set -euo pipefail

# Production entry point. WEBWAY_API_TOKEN is required for public deployments.
exec gunicorn server:app \
  --bind "0.0.0.0:${PORT:-5000}" \
  --worker-class gthread \
  --threads 4 \
  --timeout 120 \
  --access-logfile - \
  --error-logfile -
