.PHONY: help venv up down logs test test-integration lint fmt typecheck samples smoke \
        corpus corpus-check findings-doc buildx-setup images push release

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
		-f services/$*/Dockerfile \
		-t $(image_name):$(TAG) -t $(image_name):latest \
		--cache-to type=inline --cache-from $(image_name):latest \
		.

push: guard-NAMESPACE $(addprefix push-,$(SERVICES))  ## Собрать и запушить

push-%:
	docker buildx build --platform $(PLATFORMS) \
		-f services/$*/Dockerfile \
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
	uv venv --python 3.12 .venv
	uv pip install --python .venv/bin/python -e ".[dev]" || \
		uv pip install --python .venv/bin/python \
			pydantic pydantic-settings pikepdf pillow redis httpx fastapi \
			python-multipart pytest pytest-asyncio ruff mypy

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

findings-doc:  ## Пересобрать справочник признаков
	$(PY) docs/generate_findings.py

corpus:  ## Скачать корпус реальных PDF (см. corpus/README.md)
	$(PY) corpus/fetch.py --budget-mb $(or $(BUDGET_MB),150)

corpus-check:  ## Регрессия на ложные срабатывания по корпусу
	$(PY) corpus/check.py $(if $(API),--api $(API),)

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
