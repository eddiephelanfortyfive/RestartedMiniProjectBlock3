
import json
from flask import Blueprint, render_template, request, flash, jsonify, redirect, url_for
from flask_login import login_required, current_user

from .utils import db

from Website.models import Note

views = Blueprint('views', __name__)

@views.route('/', methods=['GET', 'POST'])
@login_required
def home():
    if request.method == 'POST':
        note = request.form.get('note')

        if len(note) < 1:
            flash('Note is too short.', category='error')
        else:
            new_note = Note(data=note, user_id=current_user.id)
            db.session.add(new_note)
            db.session.commit()
            flash('Note added.', category='success')
    return render_template("home.html", user=current_user)


@views.route('/delete-note', methods=['POST'])
def delete_note():
    # takes in data from a post request, loads it as a json object

    note = json.loads(request.data) # this function expects a JSON from the INDEX.js file
    noteId = note['noteId']
    # check if note exists, then check the user who owns the note is the one wants to delete
    note = Note.query.get(noteId)
    if note:
        if note.user_id == current_user.id:
            db.session.delete(note)
            db.session.commit()

    return jsonify({})

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
