
import json
from flask import Blueprint, render_template, request, flash, jsonify, redirect, url_for
from flask_login import login_required, current_user

from .utils import db

views = Blueprint('views', __name__)

@views.route('/', methods=['GET', 'POST'])
@login_required
def home():
    return render_template("home.html", user=current_user)



@views.route('/profile')
@login_required
def profile():
    return render_template("profile.html", user=current_user)

@views.route('/add-contact-number', methods=['POST'])
def add_contact_number():
    if request.method == 'POST':
        contact_number = request.form.get('contactNumber')

        # Validate and update contact number in the database
        if contact_number:
            current_user.contact_number = contact_number
            db.session.commit()
            flash('Contact number added successfully!', category='success')
        else:
            flash('Invalid contact number.', category='error')

    return redirect(url_for('views.profile'))
