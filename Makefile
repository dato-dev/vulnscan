.PHONY: help venv lock up down logs test test-integration test-e2e lint fmt typecheck samples smoke \
        corpus corpus-check rules-check findings-doc buildx-setup images push release \
        config config-check check-stack

# Локальный venv используется, если он есть: системный python может быть старее 3.12.
PY := $(if $(wildcard .venv/bin/python),.venv/bin/python,python3)
export PYTHONPATH := packages:services/gateway:services/worker:services/bot:services/writer:services/notifier

help:
	@grep -E '^[a-z-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-12s %s\n", $$1, $$2}'

# --- сборка образов под целевую архитектуру ---
# Прод — x86_64, разработка может идти на arm64, поэтому платформа задаётся явно.
REGISTRY   ?=
NAMESPACE  ?=
PROJECT    ?= vulnscantg
TAG        ?= $(shell git rev-parse --short HEAD 2>/dev/null || date +%Y%m%d-%H%M)
PLATFORMS  ?= linux/amd64
SERVICES   ?= gateway worker bot cvdmirror writer notifier

# Пример подключения лежит вне `services/`: это не часть сервиса, а показ того,
# как к нему подключаются, и у него свой compose. Правило сборки общее, поэтому
# путь до Dockerfile выбирается здесь, а не дублируется отдельной целью.
dockerfile = $(if $(filter demo-site,$*),examples/feedback-site/Dockerfile,services/$*/Dockerfile)
BUILDER    ?= vulnscan

# Docker Hub не поддерживает вложенные пространства имён, поэтому сервис
# попадает в имя образа через дефис: dato1/vulnscantg-gateway.
image_name = $(if $(REGISTRY),$(REGISTRY)/)$(if $(NAMESPACE),$(NAMESPACE)/)$(PROJECT)-$*

buildx-setup:  ## Создать builder и включить эмуляцию чужих архитектур
	docker run --privileged --rm tonistiigi/binfmt --install all
	docker buildx create --name $(BUILDER) --use --bootstrap 2>/dev/null || \
		docker buildx use $(BUILDER)
	docker buildx inspect --bootstrap | head -20

images: $(addprefix image-,$(SERVICES))  ## Собрать образы под PLATFORMS (без push)

image-%:
	docker buildx build --platform $(PLATFORMS) \
		-f $(dockerfile) \
		-t $(image_name):$(TAG) -t $(image_name):latest \
		--cache-to type=inline --cache-from $(image_name):latest \
		.

push: guard-NAMESPACE $(addprefix push-,$(SERVICES))  ## Собрать и запушить

push-%:
	docker buildx build --platform $(PLATFORMS) \
		-f $(dockerfile) \
		-t $(image_name):$(TAG) -t $(image_name):latest \
		--cache-to type=inline --cache-from $(image_name):latest \
		--push .

release: guard-NAMESPACE  ## Показать, что будет запушено
	@echo "registry:   $(if $(REGISTRY),$(REGISTRY),docker.io)"
	@echo "namespace:  $(NAMESPACE)"
	@echo "tag:        $(TAG)"
	@echo "платформы:  $(PLATFORMS)"
	@for s in $(SERVICES); do \
		echo "  $(if $(REGISTRY),$(REGISTRY)/)$(NAMESPACE)/$(PROJECT)-$$s:$(TAG)"; \
	done

guard-%:
	@test -n "$($*)" || { echo "не задано $*: make push NAMESPACE=ваш-аккаунт"; exit 1; }

venv:  ## Создать локальное окружение для тестов и линта (нужен uv)
	# Ровно то, что записано в uv.lock, без запасного варианта. Прежний
	# `|| uv pip install <список руками>` тихо ставил урезанный набор, когда
	# основная установка падала, — и локальный прогон оказывался не тем, что
	# в образе. Так yara-python не стоял ни у кого: правила не компилировал
	# никто, а тесты были зелёными.
	uv sync --frozen --all-groups

up:  ## Поднять стек (первый старт долгий: clamd тянет базы)
	docker compose up --build -d

down:  ## Остановить и удалить тома
	docker compose down -v

logs:  ## Логи gateway и воркеров
	docker compose logs -f gateway worker

test-integration:  ## Интеграционные тесты: нужны настоящие Redis и PostgreSQL
	docker compose -f tests/integration/docker-compose.yml up -d --wait
	$(PY) -m pytest tests/integration -v -p no:cacheprovider; \
		status=$$?; \
		docker compose -f tests/integration/docker-compose.yml down -v; \
		exit $$status

test:  ## Прогнать тесты
	$(PY) -m pytest -q

lint:  ## Линт
	$(PY) -m ruff check .

fmt:  ## Форматирование
	$(PY) -m ruff format .
	$(PY) -m ruff check --fix .

typecheck:  ## Проверка типов
	$(PY) -m mypy packages services

check-stack:  ## Проверить конфигурацию мониторинга (нужен Docker)
	@# M10.5: до выката, а не по логам упавшего контейнера. Коллектор уже
	@# падал на `duplicate dimension name`, и узнали мы это с сервера.
	@# Монтируем туда же, куда в проде: `rule_files` в конфигурации задан
	@# абсолютным путём и по-другому не разрешится.
	docker run --rm -v $(PWD)/deploy/lgtp/prometheus:/etc/prometheus:ro \
		prom/prometheus:v3.13.0 promtool check config /etc/prometheus/prometheus.yml
	docker run --rm -v $(PWD)/deploy/lgtp/prometheus/rules:/r:ro \
		prom/prometheus:v3.13.0 promtool check rules /r/vulnscantg.yml
	docker run --rm -v $(PWD)/deploy/lgtp/otel-collector:/c:ro \
		otel/opentelemetry-collector-contrib:0.157.0 validate --config=/c/config.yaml
	docker run --rm -v $(PWD)/deploy/lgtp/alertmanager:/a:ro \
		prom/alertmanager:v0.30.1 amtool check-config /a/alertmanager.yml

findings-doc:  ## Пересобрать справочник признаков
	$(PY) docs/generate_findings.py

corpus:  ## Скачать корпус реальных PDF (см. corpus/README.md)
	$(PY) corpus/fetch.py --budget-mb $(or $(BUDGET_MB),150)

corpus-check:  ## Регрессия на ложные срабатывания по корпусу
	$(PY) corpus/check.py $(if $(API),--api $(API),)

test-e2e:  ## Сквозной прогон доставки: поднимает стек и гоняет по нему файлы
	# Первый запуск долгий: clamd тянет антивирусные базы. Том переживает
	# прогоны, дальше быстро.
	$(PY) tests/e2e/configure_sink.py
	docker compose -f tests/e2e/docker-compose.yml up -d --build --wait
	$(PY) samples/make_samples.py
	$(PY) -m pytest tests/e2e -v -p no:cacheprovider; \
		status=$$?; \
		docker compose -f tests/e2e/docker-compose.yml logs --tail 100 > .e2e-logs.txt 2>&1 || true; \
		docker compose -f tests/e2e/docker-compose.yml down; \
		exit $$status

lock:  ## Пересчитать uv.lock после правки зависимостей в pyproject.toml
	uv lock

rules-check:  ## Шлюз YARA-правил: компиляция и прогон по корпусу (нужен yara-python)
	$(PY) rules/check.py $(if $(COMPILE_ONLY),--compile-only,)

config:  ## Настроить keys.json, weights.json, policies.json (диалог в консоли)
	$(PY) deploy/configure.py $(if $(CONFIG_DIR),--config-dir $(CONFIG_DIR),) $(CMD)

config-check:  ## Проверить конфигурацию загрузчиками сервиса, ничего не меняя
	$(PY) deploy/configure.py $(if $(CONFIG_DIR),--config-dir $(CONFIG_DIR),) check

samples:  ## Сгенерировать тестовые файлы
	$(PY) samples/make_samples.py

smoke: samples  ## Отправить сэмплы в поднятый gateway
	@for f in samples/generated/*; do \
		echo "--- $$f"; \
		curl -s -X POST http://localhost:8080/v1/scan \
			-F "file=@$$f" \
			-F 'meta={"profile":"standard","wait_ms":3000}' \
			| $(PY) -m json.tool | head -30; \
	done
