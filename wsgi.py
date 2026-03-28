# wsgi.py -- Gunicorn/gevent production entry point.
#
# gevent.monkey.patch_all() MUST be called before any other imports.
# This replaces blocking stdlib calls (socket, threading, etc.) with
# non-blocking greenlet equivalents so Flask-SocketIO can handle
# WebSocket upgrades inside a single gunicorn gevent worker.
#
# Usage:
#   gunicorn -k geventwebsocket.gunicorn.workers.GeventWebSocketWorker \
#            -w 1 --bind 0.0.0.0:8000 wsgi:app
from gevent import monkey
monkey.patch_all()  # noqa: E402 — must be first

from radar import app, socketio  # noqa: E402,F401 -- triggers full initialization

__all__ = ["app"]
