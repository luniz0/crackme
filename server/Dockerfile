# path: RankGateInsane/server/Dockerfile
#
# Local-only educational challenge server. Runs FastAPI/uvicorn on 31337.
FROM python:3.12-slim

# libsodium runtime for PyNaCl wheels is bundled; no system packages needed.
WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

# Bind inside the container; docker-compose maps this to 127.0.0.1 on the host
# so the service is never exposed beyond localhost.
EXPOSE 31337
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "31337"]
