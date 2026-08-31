# Демонстрационный сайт с формой обратной связи.
#
# Не часть сервиса: показывает, как подключается чужая команда.
FROM python:3.12-slim

WORKDIR /app

RUN pip install --no-cache-dir \
    "fastapi>=0.115" "uvicorn[standard]>=0.32" "python-multipart>=0.0.12" "httpx>=0.28"

COPY packages/vulnscan_client /app/vulnscan_client
COPY examples/feedback-site/feedback_site.py /app/feedback_site.py

RUN adduser --disabled-password --uid 10001 site && chown -R site:site /app
USER site

ENV PYTHONPATH=/app PYTHONUNBUFFERED=1
EXPOSE 8000
CMD ["uvicorn", "feedback_site:app", "--host", "0.0.0.0", "--port", "8000"]
