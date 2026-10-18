# Shared pattern for every SENTINEL-TRAP service (build context = repo root).
FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 DATA_DIR=/data
WORKDIR /srv
ARG REQUIREMENTS=requirements.txt
COPY requirements.txt requirements-dev.txt /srv/
RUN pip install --no-cache-dir -r /srv/${REQUIREMENTS}
COPY shared/ /srv/shared/
COPY gateway/ /srv/gateway/
RUN useradd --uid 1000 --create-home st && mkdir -p /data && chown st /data
USER st
EXPOSE 8080
HEALTHCHECK --interval=5s --timeout=3s --start-period=5s --retries=10   CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=2).status == 200 else 1)"
CMD ["python", "-m", "uvicorn", "gateway.main:app", "--host", "0.0.0.0", "--port", "8080", "--no-server-header", "--proxy-headers", "--forwarded-allow-ips", "*"]
