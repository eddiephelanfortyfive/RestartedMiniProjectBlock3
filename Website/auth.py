from flask import request, flash, redirect, url_for, render_template, Blueprint

from .models import User
from .utils import db
from .models import Clubs
from .models import Events
from .models import Members
from werkzeug.security import generate_password_hash, check_password_hash
auth = Blueprint('auth', __name__)
from flask_login import login_user, login_required, logout_user, current_user
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
            return redirect(url_for('views.home'))

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
    user = User.query.get(user_id)
    action = request.form.get('action')  # Retrieve action from form data

    if action == 'approve':
        user.user_type = 'student'
        flash('User approved successfully!', category='success')
    elif action == 'approve_coordinator':
        user.user_type = 'coordinator'
        flash('User approved as Coordinator successfully', category='success')
    elif action == 'deny':
        db.session.delete(user)
        flash('User denied and removed successfully!', category='success')
    else:
        flash('Invalid action!', category='error')

    db.session.commit()
    pending_users = User.query.filter_by(user_type='pending').all()

    return render_template("user_approval.html", user=current_user, pending_users=pending_users)


@auth.route('/clubs')
def clubs():
    approved_clubs = Clubs.query.filter_by(club_approval=True).all()
    return render_template("clubs.html", clubs=approved_clubs, user=current_user)



@auth.route('/create_club', methods=['POST'])
def create_club():
    if request.method == 'POST':
        # Get form data
        club_name = request.form['name']
        club_description = request.form['description']
        coordinator_id = current_user.id

        current_user.is_coordinator = True

        existing_club = Clubs.query.filter_by(club_name=club_name).first()
        if existing_club:
            flash('A club with the same name already exists.', 'error')
            return redirect(url_for('auth.clubs'))

        new_club = Clubs(club_name=club_name, club_description=club_description, coordinator_id=coordinator_id)
        db.session.add(new_club)
        db.session.commit()
        flash('Club created successfully. It is now pending approval.', 'success')
        new_Member = Members(club_id=new_club.club_id , user_id=current_user.id, user_approval=True, is_coordinator=True)
        db.session.add(new_Member)
        db.session.commit()
        return redirect(url_for('auth.clubs'))

    return redirect(url_for('auth.clubs'))

from flask_login import current_user

@auth.route('/club-approval')
@login_required
def club_approval():
    # Ensure the current user is authorized to access this page (admin or coordinator)
    if current_user.user_type not in ['admin', 'coordinator']:
        flash('You are not authorized to access this page.', category='error')
        return redirect(url_for('auth.login'))

    # Query the database to fetch pending clubs
    pending_clubs = Clubs.query.filter_by(club_approval=None).all()

    # Render the club_approval.html template, passing the pending_clubs and current_user variables to it
    return render_template("club_approval.html", pending_clubs=pending_clubs, user=current_user)


@auth.route('/approve-club/<int:club_id>', methods=['POST'])
@login_required
def approve_club(club_id):
    club = Clubs.query.get(club_id)
    action = request.form.get('action')  # Retrieve action from form data

    if action == 'approve':
        club.club_approval = True
        flash('Club approved successfully!', category='success')
    elif action == 'deny':
        db.session.delete(club)
        flash('Club denied and removed successfully!', category='success')
    else:
        flash('Invalid action!', category='error')

    db.session.commit()

    # Query pending clubs again after the approval or denial
    pending_clubs = Clubs.query.filter_by(club_approval=None).all()

    # Render the club_approval.html template, passing the pending_clubs and current_user variables to it
    return render_template("club_approval.html", pending_clubs=pending_clubs, user=current_user)


@auth.route('/events')
def events():
    user_coordinated_clubs = Clubs.query.filter_by(coordinator_id=current_user.id).all()
    events = Events.query.all()
    return render_template("events.html", events=events, user_coordinated_clubs=user_coordinated_clubs,
                           user=current_user)



@auth.route('/register_event/<int:event_id>', methods=['POST'])
@login_required
def register_event(event_id):
    event = Events.query.get_or_404(event_id)
    user_club = Members.query.filter_by(user_id=current_user.id).first().club_id

    # Automatically approve registration requests from members of the same club
    if event.club_id == user_club:
        flash('Registration approved automatically.', 'success')
    else:
        flash('Registration request sent. Waiting for coordinator approval.', 'info')
    return redirect(url_for('auth.events'))


@auth.route('/approve_registration/<int:event_id>/<int:user_id>', methods=['POST'])
@login_required
def approve_registration(event_id, user_id):
    # Check if the current user is a coordinator
    if current_user.user_type != 'coordinator':
        flash('You are not authorized to approve registrations.', 'error')
        return redirect(url_for('auth.events'))

    # Perform the approval action for the given event and user
    # You'll need to update your database accordingly to track registration approvals
    flash('Registration approved.', 'success')
    return redirect(url_for('auth.events'))


from datetime import datetime
@auth.route('/create_event', methods=['GET', 'POST'])
@login_required
def create_event():
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        venue = request.form['venue']
        datetime_str = request.form['datetime']
        club_id = request.form['club']  # Extract club ID from form data

        # Convert the datetime string to a Python datetime object
        event_datetime = datetime.fromisoformat(datetime_str)

        new_event = Events(event_title=title, event_description=description, event_venue=venue,
                           event_date_time=event_datetime, club_id=club_id)  # Include club ID in the new event
        db.session.add(new_event)
        db.session.commit()

        flash('Event created successfully.', 'success')
        return redirect(url_for('auth.events'))

    return render_template("create_event.html", user=current_user)

@auth.route('/delete_event/<int:event_id>', methods=['POST'])
@login_required
def delete_event(event_id):
    event = Events.query.get_or_404(event_id)
    club = Clubs.query.get_or_404(event.club_id)

    if current_user.id == club.coordinator_id or current_user.is_admin_coordinator:
        db.session.delete(event)
        db.session.commit()
        flash('Event deleted successfully.', 'success')
    else:
        flash('You do not have permission to delete this event.', 'error')

    return redirect(url_for('auth.events'))