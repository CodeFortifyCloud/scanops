# Dockerfile for ScanOps
FROM python:3.12-slim

# Prevents Python from writing pyc files to disc and buffering stdout/stderr
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Install system packages required for building python packages and runtime deps
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       build-essential \
       gcc \
       nmap \
       libpq-dev \
       default-mysql-client \
       postgresql-client \
       libjpeg-dev \
       zlib1g-dev \
       libpng-dev \
       libfreetype6-dev \
       liblcms2-dev \
       libwebp-dev \
       libxml2-dev \
       libxslt1-dev \
       libffi-dev \
       libcairo2 \
       libpango-1.0-0 \
       libgdk-pixbuf-xlib-2.0-0 \
       shared-mime-info \
       fonts-dejavu-core \
       fonts-liberation \
       curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user and app directory
RUN useradd -m -d /home/app -s /bin/bash app
WORKDIR /app

# Copy and install Python dependencies first (leverages Docker layer caching)
COPY requirements.txt /app/
RUN pip install --upgrade pip wheel \
    && pip install --no-cache-dir "setuptools<81" \
    && pip install --no-cache-dir -r requirements.txt

# Copy project
COPY . /app/

# Create required runtime directories and set ownership
RUN mkdir -p /app/static_root/static /app/media_root/media /app/app_logs /app/state \
    && chown -R app:app /app/static_root /app/media_root /app/app_logs /app/state /app

# Copy entrypoint and make it executable
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# Expose the port the app will run on
EXPOSE 8008

# Run as non-root user
USER app

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["sh", "-c", "gunicorn core.wsgi:application --bind 0.0.0.0:8008 --workers ${GUNICORN_WORKERS:-3} --access-logfile - --error-logfile -"]
