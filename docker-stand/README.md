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

## Остановка

```bash
docker compose down
```

Данные БД DVWA хранятся в контейнере; при удалении контейнера настройки сбрасываются.
