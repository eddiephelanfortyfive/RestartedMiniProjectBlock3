from . import db
from flask_login import UserMixin
from sqlalchemy import func

class Note (db.Model):
    id = db.Column(db.Integer, primary_key=True)
    data = db.Column(db.String(10000))
    date = db.Column(db.DateTime(timezone = True), default=func.now())
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    # if you want to get the columns from another table you use .whatever (user.email, user.password)
    class User(db.Model, UserMixin):
        id = db.Column(db.Integer, primary_key=True)
        username = db.Column(db.String(50), unique=True, nullable=False)
        email = db.Column(db.String(150), unique=True, nullable=False)
        password = db.Column(db.String(150), nullable=False)
        first_name = db.Column(db.String(150), nullable=False)
        last_name = db.Column(db.String(150), nullable=False)
        user_type = db.Column(db.String(50), nullable=False)
        notes = db.relationship('Note', backref='')
