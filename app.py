import os
from datetime import datetime

from dotenv import load_dotenv

from flask import (Flask, render_template, redirect, url_for, request,
                   flash, abort, jsonify)
from flask_login import (LoginManager, UserMixin, login_user, logout_user,
                         login_required, current_user)
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, PasswordField, TextAreaField, BooleanField
from wtforms.validators import DataRequired, Email, Length, EqualTo
from sqlalchemy import or_
from werkzeug.security import generate_password_hash, check_password_hash


load_dotenv()

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-secret-change-me")
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["WTF_CSRF_ENABLED"] = True

db = SQLAlchemy(app)
csrf = CSRFProtect(app)

login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message_category = "info"


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    notes = db.relationship("Note", backref="author", lazy="dynamic",
                            cascade="all, delete-orphan")

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Note(db.Model):
    __tablename__ = "notes"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    body = db.Column(db.Text, nullable=False, default="")
    is_public = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow,
                           onupdate=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"),
                        nullable=False, index=True)

    def to_dict(self):
        return {
            "id": self.id,
            "title": self.title,
            "body": self.body,
            "is_public": self.is_public,
            "updated_at": self.updated_at.isoformat(),
        }


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


class RegisterForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(3, 80)])
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired(), Length(6, 128)])
    confirm = PasswordField("Confirm Password",
                            validators=[DataRequired(), EqualTo("password")])


class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])


class NoteForm(FlaskForm):
    title = StringField("Title", validators=[DataRequired(), Length(1, 200)])
    body = TextAreaField("Body", validators=[Length(0, 10000)])
    is_public = BooleanField("Make public (readable via link)")


@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("notes"))
    form = RegisterForm()
    if form.validate_on_submit():
        existing = User.query.filter(
            or_(User.username == form.username.data,
                User.email == form.email.data)
        ).first()
        if existing:
            flash("Username or email already taken.", "error")
            return render_template("register.html", form=form)
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        login_user(user)
        flash("Account created.", "success")
        return redirect(url_for("notes"))
    return render_template("register.html", form=form)


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("notes"))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            return redirect(request.args.get("next") or url_for("notes"))
        flash("Invalid credentials.", "error")
    return render_template("login.html", form=form)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


@app.route("/")
@login_required
def notes():
    q = request.args.get("q", "").strip()
    query = current_user.notes
    if q:
        query = query.filter(or_(Note.title.ilike(f"%{q}%"),
                                 Note.body.ilike(f"%{q}%")))
    user_notes = query.order_by(Note.updated_at.desc()).all()
    return render_template("notes.html", notes=user_notes, q=q)


@app.route("/notes/new", methods=["GET", "POST"])
@login_required
def new_note():
    form = NoteForm()
    if form.validate_on_submit():
        note = Note(title=form.title.data, body=form.body.data,
                    is_public=form.is_public.data, user_id=current_user.id)
        db.session.add(note)
        db.session.commit()
        flash("Note created.", "success")
        return redirect(url_for("notes"))
    return render_template("edit_note.html", form=form, note=None)


@app.route("/notes/<int:note_id>/edit", methods=["GET", "POST"])
@login_required
def edit_note(note_id):
    note = db.session.get(Note, note_id)
    if note is None:
        abort(404)
    if note.user_id != current_user.id:
        abort(403)
    form = NoteForm(obj=note)
    if form.validate_on_submit():
        note.title = form.title.data
        note.body = form.body.data
        note.is_public = form.is_public.data
        db.session.commit()
        flash("Note updated.", "success")
        return redirect(url_for("notes"))
    return render_template("edit_note.html", form=form, note=note)


@app.route("/notes/<int:note_id>/delete", methods=["POST"])
@login_required
def delete_note(note_id):
    note = db.session.get(Note, note_id)
    if note is None:
        abort(404)
    if note.user_id != current_user.id:
        abort(403)
    db.session.delete(note)
    db.session.commit()
    flash("Note deleted.", "success")
    return redirect(url_for("notes"))


@app.route("/notes/<int:note_id>")
def view_note(note_id):
    note = db.session.get(Note, note_id)
    if note is None:
        abort(404)
    if not note.is_public and (not current_user.is_authenticated
                               or note.user_id != current_user.id):
        abort(403)
    return render_template("view_note.html", note=note)


@app.route("/api/notes")
@login_required
def api_notes():
    return jsonify([n.to_dict() for n in
                    current_user.notes.order_by(Note.updated_at.desc()).all()])


@app.cli.command("init-db")
def init_db():
    db.create_all()
    print("Database initialized.")


@app.errorhandler(403)
def forbidden(_e):
    return render_template("base.html",
                           error="403 — You don't have access to this page."), 403


@app.errorhandler(404)
def not_found(_e):
    return render_template("base.html",
                           error="404 — Page not found."), 404


if __name__ == "__main__":
    app.run(debug=True)