from flask import request, flash, redirect, url_for, render_template, Blueprint
from flask_login import login_user, current_user, login_required, logout_user
from werkzeug.datastructures import auth
from werkzeug.security import check_password_hash, generate_password_hash

from .models import User

from .utils import db

auth = Blueprint('auth', __name__)


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
                return render_template("home.html", user=current_user)
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
            flash('Email already exists.', category='error')

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


@auth.route('/user-approval')
@login_required
def user_approval():
    # Ensure the current user is authorized to access this route (admin or coordinator)
    if current_user.user_type not in ['admin', 'coordinator']:
        flash('You are not authorized to access this page.', category='error')
        return redirect(url_for('auth.login'))

    # Query the database to fetch pending users
    pending_users = User.query.filter_by(user_type='pending').all()

    # Render the user_approval.html template, passing the pending_users variable to it
    return render_template("user_approval.html", user=current_user, pending_users=pending_users)




@auth.route('/approve-user/<int:user_id>', methods=['POST'])
@login_required
def approve_user(user_id):
    pending_users = User.query.filter_by(user_type='pending').all()
    print(pending_users)
    user = User.query.get(user_id)
    action = request.form.get('action')  # Retrieve action from form data

    if action == 'approve':
        user.user_type = 'student'
        db.session.commit()
        flash('User approved successfully!', category='success')
    elif action == 'approve_coordinator':
        user.user_type = 'coordinator'
        db.session.commit()
        flash('User approved as Coordinator successfully', category='success')
    elif action == 'deny':
        db.session.delete(user)
        db.session.commit()
        flash('User denied and removed successfully!', category='success')
    else:
        flash('Invalid action!', category='error')

    return render_template("user_approval.html", user=current_user, pending_users=pending_users)


