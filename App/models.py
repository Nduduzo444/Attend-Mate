from App import db, bcrypt
from datetime import datetime
#___________________________Database Tables_____________________

# USER CLASS
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    fname = db.Column(db.String(255), nullable=False)
    lname = db.Column(db.String(255), nullable=False)  # Added lname column
    email = db.Column(db.String(255), nullable=False)
    username = db.Column(db.String(255), nullable=False)
    password = db.Column(db.String(255), nullable=False)
    status = db.Column(db.Integer, default=0, nullable=False)
    isAuthority = db.Column(db.Integer, default=0, nullable=False)
    managed_grade = db.Column(db.Integer, nullable=True)
    
     
    
    # Relationship to children
    children = db.relationship('Child', backref='parent', lazy=True)
    
    def __repr__(self):
        return f'User("{self.id}", "{self.fname}", "{self.lname}", "{self.email}", "{self.username}", "{self.status}")'
    
# Admin CLASS
class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), nullable=False)
    password = db.Column(db.String(255), nullable=False)
    
    def __repr__(self):
        return f'Admin("{self.id}", "{self.username}")'
    
# Child CLASS
class Child(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(100), nullable=False)
    grade = db.Column(db.Integer, nullable=False)
    gender = db.Column(db.String(10), nullable=False)
    dob = db.Column(db.Date, nullable=False)
    time_in = db.Column(db.DateTime, nullable=True)  # Nullable initially, updated when marked
    time_out = db.Column(db.DateTime, nullable=True)

    # Foreign key linking to the User (Parent)
    parent_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    def __repr__(self):
        return f'<Child {self.full_name}>'

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    parent_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message = db.Column(db.String(255), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.now)
    is_read = db.Column(db.Boolean, default=False)  # New field to track read status

    parent = db.relationship('User', backref='notifications', lazy=True)

    def __repr__(self):
        return f'<Notification {self.message}>'

# Alert CLASS (Updated)
class Alert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    child_id = db.Column(db.Integer, db.ForeignKey('child.id'), nullable=False)
    status = db.Column(db.String(50), nullable=False)  # Status can be 'arrived', 'departed', 'absent'
    timestamp = db.Column(db.DateTime, default=datetime.now)

    # Foreign key linking to the User (Authority receiving the alert)
    authority_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    # Establish relationship with Child and User models
    child = db.relationship('Child', backref='alerts', lazy=True)
    authority = db.relationship('User', backref='alerts', lazy=True)

    def __repr__(self):
        return f'<Alert for {self.child.full_name} - Status: {self.status}>'
