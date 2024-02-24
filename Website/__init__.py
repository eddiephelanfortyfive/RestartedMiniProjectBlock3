from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from os import path
from flask import current_app
from flask_login import LoginManager


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

    login_manager = LoginManager()
    login_manager.login_view = 'auth.login'
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(id):
        """ telling flask how we load a user.Similar to 'filter by'
         except by default it looks for the primary key (in this case id) """
        return User.query.get(int(id))

    return app

def create_database(app):
    with app.app_context():
        if not path.exists('Website/' + DB_NAME):
            # next line allows you to delete database and start fresh
            # db.drop_all()
            db.create_all()
            # prints out database created successfully
            print('Database created successfully!')
