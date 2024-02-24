from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from os import path
from flask import current_app


db = SQLAlchemy()
DB_NAME = "ClubHub.db"



def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'EdAndPa'
    # database is stored
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DB_NAME}'

    # connects database to flask app
    db.init_app(app)


    from .views import views
    from .auth import auth


    app.register_blueprint(views,url_prefix='/')
    app.register_blueprint(auth,url_prefix='/')

    from .models import User, Note
    create_database(app)

    return app

def create_database(app):
    with app.app_context():
        if not path.exists('Website/' + DB_NAME):
            # next line allows you to delete database and start fresh
            # db.drop_all()
            db.create_all()
            # prints out database created successfully
            print('Database created successfully!')
