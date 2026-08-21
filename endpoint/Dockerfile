FROM python:3.13-alpine

RUN apk add --no-cache openssl
WORKDIR /app
COPY server.py /app/server.py
COPY probe.py /app/probe.py

ENV PYTHONUNBUFFERED=1 \
    ENDPOINT_IP=192.168.7.20 \
    MAX_ARTIFACT_BYTES=1048576

HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
  CMD python -c "import json,urllib.request; assert json.load(urllib.request.urlopen('http://127.0.0.1/healthz', timeout=2))['status']=='ok'"

ENTRYPOINT ["python", "/app/server.py"]
