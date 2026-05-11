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

# The Space ships the FastAPI app module; templates and static
# assets are intentionally NOT included because the static landing
# page lives on GitHub Pages and calls this backend cross-origin.
# When TEMPLATES_DIR is empty, the canonical app.py at ``/`` falls
# back to a JSON manifest — see ``web/app.py::index``.
COPY --chown=app:app app.py /home/app/app.py

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
