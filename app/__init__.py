from pathlib import Path

from flask import Flask
from .config import Config
from .database import close_db, init_db


def create_app():
    base_dir = Path(__file__).resolve().parent.parent
    app = Flask(
        __name__,
        instance_relative_config=False,
        template_folder=str(base_dir / 'templates'),
        static_folder=str(base_dir / 'static'),
    )
    app.config.from_object(Config)

    with app.app_context():
        init_db()

    app.teardown_appcontext(close_db)

    from .routes import main_blueprint
    app.register_blueprint(main_blueprint)

    return app
