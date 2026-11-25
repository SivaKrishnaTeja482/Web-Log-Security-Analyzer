"""Flask entry point for the Web Log Security Analyzer."""

from __future__ import annotations

import os

from flask import Flask, jsonify, render_template, request
from werkzeug.exceptions import RequestEntityTooLarge

from analyzer import AnalysisError, MAX_INPUT_BYTES, SAMPLE_LOG, analyse_log


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__)
    app.config.update(
        JSON_SORT_KEYS=False,
        MAX_CONTENT_LENGTH=MAX_INPUT_BYTES + 10_000,
    )
    if test_config:
        app.config.update(test_config)

    @app.after_request
    def add_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; style-src 'self'; script-src 'self'; "
            "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'"
        )
        return response

    @app.get("/")
    def index():
        return render_template("index.html")

    @app.get("/health")
    def health():
        return jsonify(
            status="ok",
            service="web-log-security-analyzer",
            version=os.getenv("APP_VERSION", "development"),
        )

    @app.get("/api/version")
    def version():
        return jsonify(version=os.getenv("APP_VERSION", "development"))

    @app.get("/api/sample")
    def sample():
        return jsonify(
            log_text=SAMPLE_LOG,
            description="Synthetic documentation-range IP addresses in combined-log format",
        )

    @app.post("/api/analyse")
    def analyse():
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify(error="Request body must be a JSON object"), 400
        try:
            result = analyse_log(payload.get("log_text"))
        except AnalysisError as exc:
            return jsonify(error=str(exc)), exc.status_code
        return jsonify(result)

    @app.errorhandler(RequestEntityTooLarge)
    def request_too_large(_error):
        return jsonify(error="Request body exceeds the allowed analysis size"), 413

    @app.errorhandler(404)
    def not_found(_error):
        if request.path.startswith("/api/"):
            return jsonify(error="API endpoint not found"), 404
        return render_template("index.html"), 404

    return app


app = create_app()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8080")))
