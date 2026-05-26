from flask import Flask
from .config import Config
from .database import close_db, init_db


def create_app():
    app = Flask(__name__, instance_relative_config=False)
    app.config.from_object(Config)

    with app.app_context():
        init_db()

    app.teardown_appcontext(close_db)

    from .routes import main_blueprint
    app.register_blueprint(main_blueprint)

    return app
