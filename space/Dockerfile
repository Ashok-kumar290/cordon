# Hugging Face Space — Cordon playground backend.
#
# HF Spaces expects the Dockerfile at the repo root and the app to
# listen on the port declared in README frontmatter (``app_port: 7860``).
#
# We install the published ``cordon-ai`` wheel rather than building
# from source, so every verdict served here is byte-identical to what
# users get from ``pip install``.

FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    HOME=/home/app

# Spaces require a non-root user with a writable HOME.
RUN useradd -m -u 1000 app
WORKDIR /home/app

RUN pip install \
        "cordon-ai>=0.2,<0.3" \
        "fastapi>=0.110,<1.0" \
        "uvicorn[standard]>=0.27,<1.0" \
        "pydantic>=2.5,<3.0"

# The Space ships the FastAPI app plus the landing-page templates
# and static assets, so a single URL serves BOTH the marketing page
# and the live playground API. This avoids the GitHub Pages
# custom-domain interaction that happens when the repo owner's user
# site already has a CNAME and a SPA 404 fallback that swallows
# project-page paths.
COPY --chown=app:app app.py             /home/app/app.py
COPY --chown=app:app templates/         /home/app/templates/
COPY --chown=app:app static/            /home/app/static/

USER app
EXPOSE 7860

# ``--proxy-headers`` so the rate limiter sees the real client IP
# behind the HF Space reverse proxy. ``--forwarded-allow-ips=*`` is
# safe here because we only use those headers for rate-limit bucketing.
CMD ["uvicorn", "app:app", \
     "--host", "0.0.0.0", \
     "--port", "7860", \
     "--proxy-headers", \
     "--forwarded-allow-ips", "*"]
