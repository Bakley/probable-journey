"""
app/__init__.py  —  Application Factory
One job: wire every part together and return a Flask app.
"""
from flask import Flask
from app.database import close_db, init_db
from app.authentication.view import api_response


def create_app() -> Flask:
    app = Flask(__name__)
    app.teardown_appcontext(close_db)
    with app.app_context():
        init_db()

    from app.authentication.controllers.routes.auth_bp     import auth_bps

    # register endpoints
    app.register_blueprint(auth_bps)

    return app
