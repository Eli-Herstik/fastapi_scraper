FROM mcr.microsoft.com/playwright/python:v1.47.0-jammy

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY api/ ./api/
COPY scraper/ ./scraper/
COPY alembic/ ./alembic/
COPY alembic.ini config_loader.py config.json ./

RUN chgrp -R 0 /app && chmod -R g=u /app

EXPOSE 8000
USER 1001

CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
