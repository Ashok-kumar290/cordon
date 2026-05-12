# Hugging Face Space — Cordon Cloud dashboard + ingest backend.
#
# Layout in the Space's git repo (populated by cloud_server/space/deploy.sh):
#
#   README.md           — HF Space frontmatter (sdk: docker, app_port: 7860)
#   Dockerfile          — this file
#   app.py              — cloud_server/app.py copied at deploy time
#   storage.py          — cloud_server/storage.py copied at deploy time
#   templates/          — dashboard.html, landing.html
#   static/             — dashboard.js, policies.js
#
# The Space's $HOME is writable for user 1000, so the sqlite db lives at
# /home/app/data/cordon_cloud.db. Note that this filesystem is ephemeral:
# on every container rebuild the db is reset and the startup seed runs.
#
# For persistence across rebuilds set the ``CORDON_CLOUD_DB`` Space
# secret to a ``postgresql://...`` URL (Neon free tier is the
# documented path). The image ships with psycopg pre-installed so no
# Dockerfile changes are needed when flipping the backend.

FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    HOME=/home/app \
    CORDON_CLOUD_DB=/home/app/data/cordon_cloud.db

RUN useradd -m -u 1000 app
WORKDIR /home/app

RUN pip install \
        "fastapi>=0.110,<1.0" \
        "uvicorn[standard]>=0.27,<1.0" \
        "pydantic>=2.5,<3.0" \
        "psycopg[binary,pool]>=3.2,<4.0" \
        "cordon-ai==0.2.2"

# Lay the Python module out as ``cloud_server`` so the imports in
# ``app.py`` (``from cloud_server.storage import EventStore``) resolve
# without any sys.path tweaks.
COPY --chown=app:app __init__.py /home/app/cloud_server/__init__.py
COPY --chown=app:app app.py      /home/app/cloud_server/app.py
COPY --chown=app:app storage.py  /home/app/cloud_server/storage.py
COPY --chown=app:app templates/  /home/app/cloud_server/templates/
COPY --chown=app:app static/     /home/app/cloud_server/static/

RUN mkdir -p /home/app/data && chown -R app:app /home/app/data

USER app
EXPOSE 7860

# ``--proxy-headers`` + ``--forwarded-allow-ips=*`` so any future rate
# limiter sees the real client IP behind the HF Space reverse proxy.
CMD ["uvicorn", "cloud_server.app:app", \
     "--host", "0.0.0.0", \
     "--port", "7860", \
     "--proxy-headers", \
     "--forwarded-allow-ips", "*"]
