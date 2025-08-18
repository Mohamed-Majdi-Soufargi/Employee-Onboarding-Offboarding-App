from flask import Flask
from decouple import config
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_cors import CORS
from flask_jwt_extended import JWTManager

app = Flask(__name__)
app.config['SECRET_KEY'] = config('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = config('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = config('JWT_SECRET_KEY')

db = SQLAlchemy(app)
migrate = Migrate(app, db)
CORS(app)  # Allow frontend origins, configure later for production
jwt = JWTManager(app)

# Import models and routes from the same package
try:
    from .models import *  # Assuming models.py will be in backend/app/
    from .routes import *  # Assuming routes.py will be in backend/app/
except ImportError:
    pass  # Avoid errors if files don't exist yet

if __name__ == '__main__':
    app.run(debug=True)