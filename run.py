"""
Development entry point.

For production, run behind a real WSGI server (gunicorn/uwsgi) behind a
TLS-terminating reverse proxy, e.g.:

    gunicorn -w 4 -b 127.0.0.1:8000 "run:app"

Do NOT use the Flask/Werkzeug development server (app.run) in production.
"""
from app import create_app

app = create_app()

if __name__ == "__main__":
    # host="127.0.0.1" for local-only dev; debug is controlled by
    # SECUREVAULT_DEBUG and must be False in any real deployment.
    app.run(host="127.0.0.1", port=5000, debug=app.config["DEBUG"])
