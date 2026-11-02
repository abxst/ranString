from flask import Flask, jsonify, request

from algorithms import catalog, generate

app = Flask(__name__, static_folder="static", static_url_path="/static")


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
    import os
    # 0.0.0.0 inside Docker so the published port works; localhost otherwise.
    app.run(host=os.environ.get("HOST", "127.0.0.1"), port=5000)
