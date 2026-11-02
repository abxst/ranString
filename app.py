import os
from pathlib import Path

from flask import Flask, jsonify, request

from algorithms import catalog, generate

# Absolute path so it also resolves inside a Nuitka standalone build.
BASE = Path(__file__).resolve().parent
app = Flask(__name__, static_folder=str(BASE / "static"), static_url_path="/static")


@app.get("/")
def index():
    return app.send_static_file("index.html")


@app.get("/api/algorithms")
def algorithms():
    return jsonify(catalog())


@app.post("/api/generate")
def api_generate():
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return jsonify(error="Body phải là JSON object"), 400
    try:
        result = generate(
            body.get("algorithm"),
            body.get("length"),
            body.get("rounds"),
            body.get("digest_size"),
            body.get("text"),
        )
    except ValueError as exc:
        return jsonify(error=str(exc)), 400
    return jsonify(result)


if __name__ == "__main__":
    from waitress import serve

    # HOST=0.0.0.0 inside Docker so the published port works; localhost otherwise.
    serve(
        app,
        host=os.environ.get("HOST", "127.0.0.1"),
        port=int(os.environ.get("PORT", "5000")),
        threads=4,
        max_request_body_size=256 * 1024,
    )
