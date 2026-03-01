# Another S3 Manager

Лёгкий веб-UI для управления файлами в S3 и S3-совместимых хранилищах.

## Стек

- **Backend**: Python 3.13+, FastAPI, Boto3, JWT auth
- **Frontend**: Vanilla HTML/JS/CSS (миграция на React + Mantine в процессе)
- **Деплой**: Docker, Docker Compose, Kubernetes (Helm)
- **Package manager**: uv

## Структура

```
another-s3-manager/
├── src/
│   └── another_s3_manager/
│       ├── __init__.py
│       ├── main.py          # FastAPI app, API endpoints
│       ├── auth.py           # JWT auth, CSRF, ban logic
│       ├── config.py         # Config management (config.json)
│       ├── constants.py      # App constants, paths
│       ├── s3_client.py      # S3 client, role management
│       ├── users.py          # User management (users.json)
│       ├── utils.py          # Validation, sanitization
│       └── static/           # Frontend assets (HTML/JS/CSS)
├── tests/                    # pytest tests
├── frontend/                 # React + Mantine scaffold (WIP)
├── demo/                     # MinIO demo configs
├── data/                     # Runtime data (not tracked)
├── pyproject.toml
├── Dockerfile
├── docker-compose.yml
└── uv.lock
```

## Команды разработки

```bash
# Установка зависимостей
uv sync

# Линтер и форматирование
uv run ruff check .
uv run ruff format .

# Тесты
uv run pytest --cov

# Запуск локально
JWT_SECRET_KEY=dev-secret uv run python -m another_s3_manager.main

# Docker
docker compose up --build
```

## Версионирование

Версия берётся из git tag через `APP_VERSION` env var. В локальной разработке — `dev`.

## Особенности

- Поддержка нескольких AWS аккаунтов (assume_role, profiles, direct credentials)
- S3-совместимые сервисы (MinIO, R2, Wasabi)
- JWT аутентификация с CSRF защитой
- Автоматическое обновление истекших credentials
- Гранулярный доступ per-role, per-bucket
