# Стенд DVWA + nginx (Linux-сервер, Docker)

Прокси **nginx** принимает трафик на `http://<сервер>:8080` и пересылает его в **DVWA**. Журнал в формате **combined** пишется в **`docker-stand/logs/nginx/access.log` на хосте** — тот же путь можно передать агенту: `--log /path/to/docker-stand/logs/nginx/access.log`.

Сервис **`logs-init`** при `docker compose up` один раз создаёт каталог `./logs/nginx` на хосте (через bind mount), затем завершается; nginx стартует после успешного `logs-init`.

## Требования

- Docker Engine и Docker Compose v2 (поддержка `depends_on: condition: service_completed_successfully`)

## Запуск

```bash
cd docker-stand
docker compose up -d
```

Первый запуск DVWA: в браузере откройте `http://<хост>:8080/setup.php`, нажмите **Create / Reset Database**, затем войдите (часто `admin` / `password` для образа `vulnerables/web-dvwa` — уточните в документации образа при смене).

## Путь к логу для агента (на том же Linux-хосте)

```bash
/path/to/rust-ai-agent/target/release/rust-ai-agent \
  --log /path/to/docker-stand/logs/nginx/access.log \
  --dry-run
```

Рекомендуется начинать с **`--dry-run`**, чтобы не вызывать `iptables`, пока проверяете политику.

## Агент в отдельном контейнере (опционально)

Если бинарник агента упакован в свой образ, смонтируйте тот же каталог только для чтения:

```yaml
volumes:
  - ./logs/nginx:/logs:ro
```

и укажите `--log /logs/access.log`.

## Генерация трафика

- Вручную: работа в браузере по разделам DVWA.  
- Скрипты с инструментами: каталог `attack-scripts/` (нужны `sqlmap` / `hydra` и cookie сессии — см. комментарии в скриптах).

### Нагрузка (k6, каталог `load-tests/`)

Один раз: `setup.php` → создать БД. В скриптах логин `admin` / `password`.

| Файл | Смысл |
|------|--------|
| `dvwa_auth.js` | вход в DVWA |
| `paths.js` | списки URL: легитимные, гостевые, с payload (можно дополнять) |
| `k6-mixed.js` | обычные запросы + с payload в URL |
| `k6-benign.js` | только обычные |

На Linux, если [k6](https://k6.io/) установлен:

```bash
cd load-tests
k6 run k6-mixed.js
# или: k6 run k6-benign.js
```

Без k6 на хосте — из каталога `docker-stand`:

```bash
docker compose --profile load run --rm k6-mixed
```

Переменные при необходимости: `BASE_URL`, `BAD_RATIO`, `K6_VUS`, `K6_DURATION`, `DVWA_USER`, `DVWA_PASSWORD`, `SKIP_LOGIN=1`.

Фон benign + утилита атаки в одной оболочке:

```bash
cd load-tests
k6 run k6-benign.js &
K6=$!
../attack-scripts/run_sqlmap.sh
kill $K6
```

## Остановка

```bash
docker compose down
```

Данные БД DVWA хранятся в контейнере; при удалении контейнера настройки сбрасываются.
