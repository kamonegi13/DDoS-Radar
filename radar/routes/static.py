"""Static file serving — index.html + whitelisted extensions only."""
from __future__ import annotations
import os
from flask import send_from_directory
from radar.routes import bp, _PROJECT_ROOT

_STATIC_ALLOWED_EXT = {".html", ".js", ".css", ".json", ".png", ".jpg", ".jpeg",
                       ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".eot", ".map"}


@bp.route("/", methods=["GET"])
def index():
    return send_from_directory(_PROJECT_ROOT, "index.html")


@bp.route("/<path:filename>", methods=["GET"])
def static_files(filename):
    if filename.startswith("api/"):
        return ("Not Found", 404)
    # Block path traversal and hidden/sensitive files
    normalized = filename.replace("\\", "/")
    if ".." in normalized or normalized.startswith("."):
        return ("Forbidden", 403)
    # Block persistence directory
    if normalized.startswith("persistence/") or normalized.startswith("persistence\\"):
        return ("Forbidden", 403)
    # Check file extension against whitelist
    ext = os.path.splitext(filename)[1].lower()
    if ext not in _STATIC_ALLOWED_EXT:
        return ("Forbidden", 403)
    return send_from_directory(_PROJECT_ROOT, filename)
