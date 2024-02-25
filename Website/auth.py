from flask import Blueprint, request, render_template, flash, redirect, url_for
from . import db
from .models import User
from .models import Clubs
from werkzeug.security import generate_password_hash, check_password_hash
auth = Blueprint('auth', __name__)
from flask_login import login_user, login_required, logout_user, current_user
from flask import session

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        # next line filters users by specific email and returns the first result
        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                flash('Logged in successfully!', category='success')
                login_user(user, remember=True)
                return redirect(url_for('views.home'))
            else:
                flash('Incorrect password, try again.', category='error')
        else:
            flash('Email does not exist.', category='error')

    return render_template("login.html", user=current_user)


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))


@auth.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        email = request.form.get('email')
        first_name = request.form.get('firstName')
        last_name = request.form.get('lastName')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')

        users_count = User.query.count()
        if users_count == 0:
            user_type = 'admin'
        else:
            user_type = 'pending'

        user = User.query.filter_by(email=email).first()
        if user:
            flash('User already exists.', category='error')

        elif len(email) < 4:
            flash('Email must be greater than 4 characters.', category='error')

        elif len(first_name) < 2:
            flash('First name must be greater than 1 characters.', category='error')

        elif len(last_name) < 2:
            flash('Last name must be greater than 1 characters.', category='error')

        elif password1 != password2:
            flash('Passwords don\'t match.', category='error')

        elif len(password1) < 7:
            flash('Password must be at least 7 characters', category='error')

        else:
            new_user = User(email=email, first_name=first_name,last_name=last_name, password=generate_password_hash(
                password1, method='pbkdf2:sha256'), user_type=user_type)
            db.session.add(new_user)
            db.session.commit()

            # logs in user after they create their account , might want to change to pending
            # login_user(user, remember=True)
            flash('Account created', category='success')
            # return redirect(url_for('views.home'))

            #add to database
    return render_template("sign_up.html", user=current_user)

# @auth.route('/profile', methods=['GET', 'POST'])
# def edit_profile():
#     return
@auth.route('/clubs')
def clubs():
    clubs = Clubs.query.all()
    return render_template("clubs.html", clubs=clubs, user=current_user)


from flask import request, redirect, url_for


from flask import redirect, url_for

@auth.route('/create_club', methods=['POST'])
def create_club():
    if request.method == 'POST':
        # Get form data
        club_name = request.form['name']
        club_description = request.form['description']
        coordinator_id = current_user.id  # Get current user's ID

        # Check if a club with the same name already exists
        existing_club = Clubs.query.filter_by(club_name=club_name).first()
        if existing_club:
            flash('A club with the same name already exists.', 'error')
            return redirect(url_for('auth.clubs'))

        # Save the club to the database
        new_club = Clubs(club_name=club_name, club_description=club_description, coordinator_id=coordinator_id)
        db.session.add(new_club)
        db.session.commit()

        # Redirect back to the clubs page after creating the club
        flash('Club created successfully.', 'success')
        return redirect(url_for('auth.clubs'))  # Corrected URL

    # Handle other HTTP methods if necessary
    return redirect(url_for('auth.clubs'))  # Corrected URL


