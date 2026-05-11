# Cordon landing page + live playground.
#
# Build: docker build -t cordon-web -f web/Dockerfile .
# Run:   docker run -p 8080:8080 cordon-web
#
# This image installs the published `cordon-ai` wheel rather than
# copying the source tree, so the deployed playground always runs the
# same code your users get from `pip install`.

FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Install runtime deps. cordon-ai is the PyPI distribution name; the
# import path is `cordon`. Pin majors so a surprise breaking release
# can't take the playground down silently.
RUN pip install \
        "cordon-ai>=0.2,<0.3" \
        "fastapi>=0.110,<1.0" \
        "uvicorn[standard]>=0.27,<1.0" \
        "pydantic>=2.5,<3.0"

COPY web/ /app/web/

EXPOSE 8080

# `--proxy-headers` so the rate limiter sees the real client IP behind
# Fly's proxy. `--forwarded-allow-ips=*` is fine here because we only
# trust the headers for rate-limit bucketing, never for auth.
CMD ["uvicorn", "web.app:app", \
     "--host", "0.0.0.0", \
     "--port", "8080", \
     "--proxy-headers", \
     "--forwarded-allow-ips", "*"]
