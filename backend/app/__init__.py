from flask import Flask, send_from_directory
from decouple import config
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from datetime import timedelta

# Initialize extensions
db = SQLAlchemy()
migrate = Migrate()
jwt = JWTManager()

def create_app():
    app = Flask(__name__, static_folder='static')

    # Config
    app.config['SECRET_KEY'] = config('SECRET_KEY')
    app.config['SQLALCHEMY_DATABASE_URI'] = config('DATABASE_URL')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['JWT_SECRET_KEY'] = config('JWT_SECRET_KEY')
    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=30)

    # Initialize extensions with app
    db.init_app(app)
    migrate.init_app(app, db)
    jwt.init_app(app)
    CORS(app)

    # Import models here to avoid circular imports
    from .models import HR, AuditLog

    # Register blueprints
    from .routes import routes
    app.register_blueprint(routes)

    # Serve sponsor approval page
    @app.route('/sponsor_approve')
    def serve_sponsor_approve():
        return send_from_directory('static', 'sponsor_approve.html')

    # Serve dashboard page
    @app.route('/dashboard')
    def serve_dashboard():
        return send_from_directory('static', 'dashboard.html')

    with app.app_context():
        db.create_all()
        # Create initial HR user if no HR users exist (just for testing)
        if not db.session.query(HR).first():
            initial_user = HR(
                username='admin',
                email='medmajdisoufargi1@gmail.com',
                sponsor_email='none@example.com',  # No sponsor needed for initial user
                is_active=True  # Active by default
            )
            initial_user.set_password('123')  # Strong initial password
            db.session.add(initial_user)
            audit = AuditLog(
                type='initial_setup',
                user_id=None,
                success=True,
                reason='Created initial HR user: admin',
                ip_address='127.0.0.1'
            )
            db.session.add(audit)
            db.session.commit()
            print("Created initial HR user: username=admin, email=admin@example.com, password=Admin123!")

    return app