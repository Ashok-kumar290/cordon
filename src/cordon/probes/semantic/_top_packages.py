"""Reference set of legitimate top-N package names used by typosquat detection.

Ported from ActionLens semantic_guard (Apart Research AI Control Hackathon 2026).
Keep this list curated and stable: adding a popular package here prevents false
positives; adding a typo candidate here would hide a real attack.
"""

TOP_PYPI_PACKAGES: frozenset[str] = frozenset({
    "requests", "flask", "django", "numpy", "pandas", "scipy", "matplotlib",
    "pillow", "sqlalchemy", "celery", "redis", "boto3", "botocore",
    "urllib3", "certifi", "charset-normalizer", "idna", "packaging",
    "setuptools", "wheel", "pip", "six", "python-dateutil", "pyyaml",
    "jinja2", "markupsafe", "click", "werkzeug", "itsdangerous",
    "cryptography", "pyopenssl", "cffi", "pycparser", "attrs", "pytest",
    "coverage", "tox", "virtualenv", "pipenv", "black", "flake8", "mypy",
    "pylint", "isort", "autopep8", "bandit", "safety", "twine",
    "sphinx", "docutils", "pygments", "pydantic", "fastapi", "uvicorn",
    "gunicorn", "httpx", "aiohttp", "tornado", "starlette", "sanic",
    "scrapy", "beautifulsoup4", "lxml", "selenium", "playwright",
    "tensorflow", "torch", "keras", "scikit-learn", "xgboost", "lightgbm",
    "transformers", "tokenizers", "datasets", "accelerate", "diffusers",
    "opencv-python", "tqdm", "rich", "typer", "colorama", "tabulate",
    "psutil", "paramiko", "fabric", "ansible", "docker", "kubernetes",
    "grpcio", "protobuf", "msgpack", "orjson", "ujson", "simplejson",
    "arrow", "pendulum", "pytz", "babel", "chardet", "cchardet",
    "httptools", "websockets", "h11", "h2", "anyio", "trio",
    "greenlet", "gevent", "eventlet",
    "psycopg2", "pymysql", "pymongo", "motor", "elasticsearch",
    "alembic", "marshmallow", "wtforms", "pyjwt", "passlib",
    "bcrypt", "argon2-cffi", "python-dotenv",
    "toml", "tomli", "typing-extensions",
    "importlib-metadata", "zipp", "filelock", "watchdog",
    "schedule", "apscheduler", "rq", "dramatiq", "huey",
    "stripe", "twilio", "sendgrid", "slack-sdk",
    "sentry-sdk", "newrelic", "datadog", "prometheus-client",
    "opentelemetry-api", "jaeger-client", "structlog", "loguru",
    "httpie", "pycurl",
})

STANDARD_PACKAGE_SOURCES: frozenset[str] = frozenset({
    "pypi.org",
    "pypi.python.org",
    "files.pythonhosted.org",
    "npmjs.org",
    "registry.npmjs.org",
    "maven.org",
    "repo1.maven.org",
    "rubygems.org",
    "crates.io",
})
