from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from config import Config

# Initialize extensions (without app)
db = SQLAlchemy()
login_manager = LoginManager()
login_manager.login_view = 'auth.login'

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Initialize extensions with app
    db.init_app(app)
    login_manager.init_app(app)

    with app.app_context():
        # Create tables if they don't exist
        db.create_all()

        # Register blueprints
        from app.routes import main_bp, auth_bp
        app.register_blueprint(auth_bp)
        app.register_blueprint(main_bp)

    # Temporary home route for testing
    @app.route('/')
    def home():
        return "CNPS User Audit App is running!"

    return app

@login_manager.user_loader
def load_user(user_id):
    from app.models import User
    return User.query.get(int(user_id))