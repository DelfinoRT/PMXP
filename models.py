from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

db = SQLAlchemy()

# Define User model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    first_name = db.Column(db.String(100), nullable=False)  # Added based on your requirement
    last_name = db.Column(db.String(100), nullable=False)   # Added based on your requirement
    member_id = db.Column(db.String(50), unique=True, nullable=False)  # Added based on your requirement
    password_hash = db.Column(db.String(60), nullable=False)
    is_password_changed = db.Column(db.Boolean, default=False)
    def set_password(self, password):
      self.password_hash = generate_password_hash(password)
    def check_password(self, password):
      return check_password_hash(self.password_hash, password)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)