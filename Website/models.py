from flask_login import UserMixin
from sqlalchemy import func


from .utils import db

class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    data = db.Column(db.String(10000))
    date = db.Column(db.DateTime(timezone=True), default=func.now())
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    # if you want to get the columns from another table you use .whatever (user.email, user.password)


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    first_name = db.Column(db.String(150), nullable=False)
    last_name = db.Column(db.String(150))
    user_type = db.Column(db.String(50))
    notes = db.relationship('Note', backref='')
    contact_number = db.Column(db.String(15), unique=True)
    is_coordinator = db.Column(db.Boolean, default=False)


class Clubs(db.Model):
    club_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    club_name = db.Column(db.String(255), nullable=False, unique=True)
    club_description = db.Column(db.Text, nullable=False)
    coordinator_id = db.Column(db.Integer)
    club_approval = db.Column(db.Boolean)

class Members(db.Model):
    club_id = db.Column(db.Integer, db.ForeignKey('clubs.club_id'), primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), primary_key=True)
    user_approval = db.Column(db.Boolean)
    # is_coordinator = db.Column(db.Boolean)




class Events(db.Model):
    event_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    club_id = db.Column(db.Integer, db.ForeignKey('clubs.club_id'))
    event_title = db.Column(db.Text, nullable=False)
    event_description = db.Column(db.Text, nullable=False)
    event_venue = db.Column(db.Text, nullable=False)
    event_date_time = db.Column(db.TIMESTAMP, nullable=False)