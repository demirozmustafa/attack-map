FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    DATA_DIR=/data EVE_ROOT=/eve HTTP_HOST=0.0.0.0 HTTP_PORT=8080 SYSLOG_PORT=5514

RUN pip install --no-cache-dir maxminddb==2.6.2 \
 && useradd --system --uid 10001 --home /app app \
 && mkdir -p /data /eve && chown app:app /data

WORKDIR /app
COPY server.py ./
COPY static ./static

USER app
EXPOSE 8080/tcp 5514/udp
VOLUME ["/data"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz',timeout=4).status==200 else 1)"

CMD ["python", "server.py"]
