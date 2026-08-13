FROM python:3.13-slim

WORKDIR /app
COPY pyproject.toml README.md ./
COPY airlock ./airlock
RUN pip install --no-cache-dir '.[postgres,prometheus]' && pip install --no-cache-dir uvicorn

COPY examples/deployment/service.py ./service.py

EXPOSE 8000
CMD ["python", "service.py"]
