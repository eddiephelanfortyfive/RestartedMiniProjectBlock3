from flask import request, flash, redirect, url_for, render_template, Blueprint, abort

from .models import User
from .utils import db
from .models import Clubs
from .models import Events
from .models import Members
from .models import Event_registration
from werkzeug.security import generate_password_hash, check_password_hash
auth = Blueprint('auth', __name__)
from flask_login import login_user, login_required, logout_user, current_user

@auth.route('/homepage')
@login_required
def homepage():
    current_clubs_ids = [club.club_id for club in Members.query.filter_by(user_id=current_user.id, user_approval=True).all()]
    current_clubs = []
    for club_id in current_clubs_ids:
        current_clubs.extend(Clubs.query.filter_by(club_id=club_id).all())
    return render_template("homepage.html", user=current_user, clubs=current_clubs)

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                flash('Logged in successfully!', category='success')
                login_user(user, remember=True)
                return render_template("profile.html", user=current_user)
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

            flash('Account created, now you can login!', category='success')
            return redirect(url_for('auth.login'))

    return render_template("sign_up.html", user=current_user)

@auth.route('/user-approval')
@login_required
def user_approval():
    if current_user.user_type not in ['admin', 'coordinator']:
        flash('You are not authorized to access this page.', category='error')
        return redirect(url_for('auth.login'))
    pending_users = User.query.filter_by(user_type='pending').all()
    return render_template("user_approval.html", user=current_user, pending_users=pending_users)


@auth.route('/approve-user/<int:user_id>', methods=['POST'])
@login_required
def approve_user(user_id):
    user = User.query.get(user_id)
    action = request.form.get('action')

    if action == 'approve':
        user.user_type = 'student'
        flash('User approved successfully!', category='success')
    elif action == 'approve_coordinator':
        user.user_type = 'coordinator'
        # user.is_coordinator = True
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
    approved_club_ids = [member.club_id for member in
                         Members.query.filter_by(user_id=current_user.id, user_approval=True).all()]

    remaining_clubs = Clubs.query.filter(~Clubs.club_id.in_(approved_club_ids)).all()


    return render_template("clubs.html", clubs=remaining_clubs, user=current_user, Members=Members)


@auth.route('/create_club', methods=['POST'])
def create_club():
    if request.method == 'POST':
        club_name = request.form['name']
        club_description = request.form['description']
        coordinator_id = current_user.id

        current_user.is_coordinator = True

        existing_club = Clubs.query.filter_by(club_name=club_name).first()
        if existing_club:
            flash('A club with the same name already exists.', 'error')
            return redirect(url_for('auth.clubs'))

        approval_timestamp = datetime.now()

        new_club = Clubs(club_name=club_name, club_description=club_description, coordinator_id=coordinator_id )
        db.session.add(new_club)
        db.session.commit()
        flash('Club created successfully. It is now pending approval.', 'success')
        new_Member = Members(club_id=new_club.club_id , user_id=current_user.id, user_approval=True, approval_date_time=approval_timestamp)
        db.session.add(new_Member)
        db.session.commit()
        return redirect(url_for('auth.clubs'))

    return redirect(url_for('auth.clubs'))

from flask_login import current_user

@auth.route('/club-approval')
@login_required
def club_approval():
    if current_user.user_type not in ['admin', 'coordinator']:
        flash('You are not authorized to access this page.', category='error')
        return redirect(url_for('auth.login'))

    pending_clubs = Clubs.query.filter_by(club_approval=None).all()

    return render_template("club_approval.html", pending_clubs=pending_clubs, user=current_user)


@auth.route('/approve-club/<int:club_id>', methods=['POST'])
@login_required
def approve_club(club_id):
    club = Clubs.query.get(club_id)
    action = request.form.get('action')

    if action == 'approve':
        club.club_approval = True
        flash('Club approved successfully!', category='success')
    elif action == 'deny':
        db.session.delete(club)
        flash('Club denied and removed successfully!', category='success')
    else:
        flash('Invalid action!', category='error')

    db.session.commit()

    pending_clubs = Clubs.query.filter_by(club_approval=None).all()

    return render_template("club_approval.html", pending_clubs=pending_clubs, user=current_user)


@auth.route('/events')
def events():
    user_coordinated_clubs = Clubs.query.filter_by(coordinator_id=current_user.id).all()
    events = Events.query.all()

    return render_template("events.html", events=events, user_coordinated_clubs=user_coordinated_clubs,
                           user=current_user, Event_registration=Event_registration)


@auth.route('/register_event/<int:event_id>', methods=['POST'])
@login_required
def register_event(event_id):
    event = Events.query.get_or_404(event_id)
    user_club = Members.query.filter_by(user_id=current_user.id, club_id=event.club_id).first()
    event_registration = Event_registration.query.filter_by(event_id=event_id).first()

    if user_club is not None:
        flash('Registration approved automatically.', 'success')
        event_registration.user_event_approval = True
        student = Event_registration(event_id=event.event_id, user_id=current_user.id, user_event_approval=True)
        db.session.add(student)
    else:
        flash('Registration request sent. Waiting for coordinator approval.', 'info')
        pending_student = Event_registration(event_id = event.event_id, user_id = current_user.id, user_event_approval = None)
        db.session.add(pending_student)
        db.session.commit()
    return redirect(url_for('auth.events'))

@auth.route('/approve-event-students/<int:user_id>', methods=['POST'])
@login_required
def approve_event_students(user_id):
    event_registration = Event_registration.query.filter_by(user_id=user_id).first()

    if event_registration:
        action = request.form.get('action')

        if action == 'approve':
            event_registration.user_event_approval = True
            flash('Student accepted to event successfully!', category='success')
        elif action == 'deny':
            event_registration.user_event_approval = False
            flash('Student denied to event successfully', category='success')
        else:
            flash('Invalid action!', category='error')

        db.session.commit()
    else:
        flash('Event registration not found', category='error')


    pending_event_students = Event_registration.query.filter_by(user_event_approval=None).all()

    return render_template("event_approval.html",User=User, pending_event_students=pending_event_students, user=current_user)

@auth.route('/event-approval')
@login_required
def event_approval():
    if current_user.user_type not in ['admin', 'coordinator']:
        flash('You are not authorized to access this page.', category='error')
        return redirect(url_for('auth.login'))

    pending_event_students = Event_registration.query.filter_by(user_event_approval=None).all()

    return render_template("event_approval.html",User=User,  pending_event_students = pending_event_students, user=current_user,)



@auth.route('/approve_registration/<int:event_id>/<int:user_id>', methods=['POST'])
@login_required
def approve_registration(event_id, user_id):
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
        club_id = request.form['club']

        event_datetime = datetime.fromisoformat(datetime_str)

        new_event = Events(event_title=title, event_description=description, event_venue=venue,
                           event_date_time=event_datetime, club_id=club_id)
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
@auth.route('/apply-membership/<int:club_id>', methods=['POST'])
@login_required
def apply_membership(club_id):
    existing_membership = Members.query.filter_by(club_id=club_id, user_id=current_user.id).first()
    if existing_membership:
        flash('You have already applied to this club.', 'error')
        return redirect(url_for('auth.clubs'))

    user_clubs_count = Members.query.filter_by(user_id=current_user.id).count()
    if user_clubs_count >= 3:
        flash('You can only be a member of maximum 3 clubs.', 'error')
        return redirect(url_for('auth.clubs'))

    new_membership = Members(club_id=club_id, user_id=current_user.id,approval_date_time = datetime.now())
    db.session.add(new_membership)
    db.session.commit()

    flash('Membership application submitted. Wait for coordinator approval.', 'success')
    return redirect(url_for('auth.clubs'))


@auth.route('/members_approval')
@login_required
def members_approval():
    if current_user.user_type != 'coordinator':
        abort(403)

    club = Clubs.query.filter_by(coordinator_id=current_user.id).first()
    if not club:
        return render_template('no_applications.html')

    coordinator_club = Members.query.filter_by(user_id=current_user.id, user_approval=True).first()
    if coordinator_club is None:
        club_applications = []
    else:
        club_applications = Members.query.filter_by(club_id=coordinator_club.club_id, user_approval=None).all()

    return render_template('members_approval.html', club=club, applications=club_applications, user=current_user,
                           Users=User)


@auth.route('/approve-club/<int:member_id>/<int:club_id>', methods=['POST'])
@login_required
def approve_member(member_id, club_id):
    member = Members.query.filter_by(user_id=member_id, club_id=club_id).first()

    if member is not None:
        action = request.form.get('action')

        if action == 'approve':
            member.user_approval = True
            flash('Member approved successfully!', category='success')
        elif action == 'deny':
            db.session.delete(member)
            flash('Member denied and removed successfully!', category='success')
        else:
            flash('Invalid action!', category='error')

        db.session.commit()
    else:
        flash('Member not found!', category='error')

    return redirect(url_for('auth.members_approval'))

@auth.route('/members_list')
@login_required
def members_list():
    # Assuming current_user is an instance of User model
    club_id = Clubs.query.filter_by(coordinator_id=current_user.id).first().club_id
    all_members = Members.query.filter_by(club_id=club_id).all()
    return render_template('members_list.html', all_members=all_members, user=current_user,User=User)

@auth.route('/users_list')
@login_required
def Users_list():
    users = User.query.filter_by().all()
    return render_template('users_list.html',users=users,User=User, user=current_user)


