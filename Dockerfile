FROM python:3.12-slim

# System dependencies (for eventlet and requests SSL)
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc \
        libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies first (layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY radar/          radar/
COPY radar_api.py    .
COPY wsgi.py         .
COPY geo_data.json   .
COPY i18n.js         .
COPY radar.js        .
COPY radar.css       .
COPY index.html      .

# Ensure persistence directory exists (mounted as volume in production)
RUN mkdir -p radar/persistence plugins

# Expose default port
EXPOSE 8000

# Production server: gunicorn + gevent WebSocket worker
# -w 1 is required for Flask-SocketIO (gevent handles concurrency via greenlets)
CMD ["gunicorn", \
     "-k", "geventwebsocket.gunicorn.workers.GeventWebSocketWorker", \
     "-w", "1", \
     "--bind", "0.0.0.0:8000", \
     "--timeout", "120", \
     "--graceful-timeout", "30", \
     "--log-level", "info", \
     "--access-logfile", "-", \
     "--error-logfile", "-", \
     "wsgi:app"]
