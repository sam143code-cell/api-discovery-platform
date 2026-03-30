from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_cors import CORS
from .config import Config

db = SQLAlchemy()
migrate = Migrate()


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)
    migrate.init_app(app, db)
    CORS(app)

    from .models import (
        Engagement, ApiEndpoint, DiscoverySource, OWASPFinding,
        OWASPConformance, SecretFinding, OutboundApi, OutboundDependency,
        PackageDependency, CVEFinding, ScanPhaseLog, ShadowRogueRegister
    )

    from .routes import bp
    app.register_blueprint(bp)

    return app
