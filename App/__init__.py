from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_session import Session


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///usm.sqlite"
app.config["SECRET_KEY"] = "3a1d619724b96dd2abf51ccc"
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"]='filesystem'


db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
Session(app)
#================================================================================================================
from App import routes
from App.models import Admin

with app.app_context():
    db.create_all()
    print("Tables created")
    
    if not Admin.query.first():
            # Hash the password before storing it
        hashed_password = bcrypt.generate_password_hash('Nduduzo123')
            
            # Create the admin with the hashed password
        admin = Admin(username='Nduduzo Sibiya', password=hashed_password)
            
            # Add the admin to the database and commit
        db.session.add(admin)
        db.session.commit()
        print("Admin created!")