import os
import threading
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

from flask import Flask, render_template, request, redirect, url_for, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    logout_user,
    login_required,
    current_user,
)
from flask_mail import Mail, Message
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from wtforms import StringField, PasswordField, TextAreaField, DateTimeLocalField
from wtforms.validators import DataRequired, Email, Length, ValidationError

app = Flask(__name__)

# ======================
# CONFIG
# ======================
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "ivory-hall-secret-2026")
database_url = os.environ.get("DATABASE_URL", "sqlite:///event_hall.db")
if database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)
app.config["SQLALCHEMY_DATABASE_URI"] = database_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_pre_ping": True,
    "pool_timeout": 10,
    "pool_recycle": 300,
    "connect_args": {
        "connect_timeout": 10,
        "options": "-c statement_timeout=15000",
    },
}

# ======================
# EMAIL SETTINGS (GMAIL)
# ======================
app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USE_SSL"] = False
app.config["MAIL_USERNAME"] = os.environ.get("MAIL_USERNAME", "IVORYHALL38@gmail.com")
app.config["MAIL_PASSWORD"] = os.environ.get("MAIL_PASSWORD", "poak svlg mldh ihgw")
app.config["MAIL_DEFAULT_SENDER"] = os.environ.get("MAIL_USERNAME", "IVORYHALL38@gmail.com")
app.config["MAIL_TIMEOUT"] = 10

mail = Mail(app)
db = SQLAlchemy(app)
csrf = CSRFProtect(app)

login_manager = LoginManager(app)
login_manager.login_view = "login"

_db_ready = False


@app.before_request
def _init_db():
    global _db_ready
    if not _db_ready:
        try:
            db.create_all()
            _db_ready = True  # only mark ready on success; retries are safe with fast timeouts
        except Exception as e:
            app.logger.error("DB init error: %s", e)


# ======================
# FORMS (Flask-WTF — includes CSRF + validation)
# ======================

class RegisterForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(min=3, max=80)])
    email = StringField("Email", validators=[DataRequired(), Email(), Length(max=120)])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=6)])


class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(max=80)])
    password = PasswordField("Password", validators=[DataRequired()])


class BookingForm(FlaskForm):
    title = StringField("Title", validators=[DataRequired(), Length(max=120)])
    hall_name = StringField("Hall", validators=[DataRequired(), Length(max=120)])
    start_time = StringField("Start Time", validators=[DataRequired()])
    end_time = StringField("End Time", validators=[DataRequired()])
    description = TextAreaField("Description", validators=[Length(max=1000)])

    def validate_start_time(self, field):
        try:
            parse_dt(field.data)
        except ValueError:
            raise ValidationError("Invalid start time format.")

    def validate_end_time(self, field):
        try:
            parse_dt(field.data)
        except ValueError:
            raise ValidationError("Invalid end time format.")


class GuestBookingForm(FlaskForm):
    guest_name = StringField("Your Name", validators=[DataRequired(), Length(max=120)])
    guest_email = StringField("Email", validators=[DataRequired(), Email(), Length(max=120)])
    guest_phone = StringField("Phone", validators=[Length(max=50)])
    title = StringField("Event Title", validators=[DataRequired(), Length(max=120)])
    hall_name = StringField("Hall", validators=[DataRequired(), Length(max=120)])
    start_time = StringField("Start Time", validators=[DataRequired()])
    end_time = StringField("End Time", validators=[DataRequired()])
    description = TextAreaField("Description", validators=[Length(max=1000)])


class GuestCancelForm(FlaskForm):
    booking_id = StringField("Booking ID", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(), Email()])


class AdminCancelForm(FlaskForm):
    reason = TextAreaField("Cancellation Reason", validators=[Length(max=500)])


class AdminMessageForm(FlaskForm):
    subject = StringField("Subject", validators=[DataRequired(), Length(max=200)])
    body = TextAreaField("Message", validators=[DataRequired(), Length(max=2000)])


class ChangePasswordForm(FlaskForm):
    current_password = PasswordField("Current Password", validators=[DataRequired()])
    new_password = PasswordField("New Password", validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField("Confirm New Password", validators=[DataRequired()])

    def validate_confirm_password(self, field):
        if field.data != self.new_password.data:
            raise ValidationError("Passwords do not match.")


class SearchForm(FlaskForm):
    q = StringField("Search", validators=[Length(max=100)])
    status = StringField("Status", validators=[Length(max=20)])
    hall = StringField("Hall", validators=[Length(max=120)])


# ======================
# MODELS
# ======================

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    appointments = db.relationship("Appointment", backref="owner", lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Appointment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), nullable=False)
    hall_name = db.Column(db.String(120), nullable=False)
    start_time = db.Column(db.DateTime, nullable=False)
    end_time = db.Column(db.DateTime, nullable=False)
    description = db.Column(db.Text)
    status = db.Column(db.String(20), default="pending")
    cancel_reason = db.Column(db.Text)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    guest_name = db.Column(db.String(120))
    guest_email = db.Column(db.String(120))
    guest_phone = db.Column(db.String(50))


# ======================
# HELPERS
# ======================

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


def parse_dt(v):
    return datetime.strptime(v, "%Y-%m-%dT%H:%M")


def send_email(to_email, subject, body):
    if not to_email:
        return

    def _send():
        try:
            with app.app_context():
                msg = Message(subject=subject, recipients=[to_email], body=body)
                mail.send(msg)
        except Exception as e:
            print("EMAIL ERROR:", e)

    threading.Thread(target=_send, daemon=True).start()


def overlaps(a_start, a_end, b_start, b_end):
    return a_start < b_end and b_start < a_end


def hall_conflict(hall_name, start_time, end_time, exclude_id=None):
    q = Appointment.query.filter(
        Appointment.hall_name == hall_name,
        Appointment.status.in_(["pending", "approved"]),
    )
    if exclude_id is not None:
        q = q.filter(Appointment.id != exclude_id)
    for b in q.all():
        if overlaps(start_time, end_time, b.start_time, b.end_time):
            return True
    return False


# ======================
# ROUTES
# ======================

@app.route("/")
def index():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    return redirect(url_for("guest_book"))


@app.route("/init-db")
def init_db():
    db.create_all()
    return "Database initialised."


# ---------- REGISTER ----------
@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        username = form.username.data.strip()
        email = form.email.data.strip().lower()
        password = form.password.data

        if User.query.filter((User.username == username) | (User.email == email)).first():
            flash("Username or email already exists.")
            return redirect(url_for("register"))

        user = User(username=username, email=email)
        user.set_password(password)

        if User.query.count() == 0:
            user.is_admin = True

        db.session.add(user)
        db.session.commit()

        flash("Account created. Please login.")
        return redirect(url_for("login"))

    return render_template("register.html", form=form)


# ---------- LOGIN ----------
@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data.strip()
        password = form.password.data

        user = User.query.filter_by(username=username).first()
        if not user or not user.check_password(password):
            flash("Invalid login.")
            return redirect(url_for("login"))

        login_user(user)
        return redirect(url_for("dashboard"))

    return render_template("login.html", form=form)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


# ---------- DASHBOARD ----------
@app.route("/dashboard")
@login_required
def dashboard():
    bookings = (
        Appointment.query
        .filter_by(user_id=current_user.id)
        .order_by(Appointment.start_time.asc())
        .all()
    )
    return render_template("dashboard.html", appointments=bookings)


# ---------- USER BOOK ----------
@app.route("/book", methods=["GET", "POST"])
@login_required
def book():
    form = BookingForm()
    if form.validate_on_submit():
        start_time = parse_dt(form.start_time.data)
        end_time = parse_dt(form.end_time.data)

        if start_time >= end_time:
            flash("Start time must be before end time.")
            return redirect(url_for("book"))

        if hall_conflict(form.hall_name.data.strip(), start_time, end_time):
            flash("Sorry, this hall is already booked in that time slot.")
            return redirect(url_for("book"))

        appt = Appointment(
            title=form.title.data.strip(),
            hall_name=form.hall_name.data.strip(),
            start_time=start_time,
            end_time=end_time,
            description=form.description.data,
            user_id=current_user.id,
            status="pending",
        )
        db.session.add(appt)
        db.session.commit()

        admins = User.query.filter_by(is_admin=True).all()
        admin_url = url_for("admin_panel", _external=True)
        for admin in admins:
            send_email(
                admin.email,
                f"IVORY HALL – New booking #{appt.id} from {current_user.username}",
                f"New booking request received.\n\nBooking ID: {appt.id}\nFrom: {current_user.username} ({current_user.email})\nTitle: {appt.title}\nHall: {appt.hall_name}\nStart: {appt.start_time.strftime('%d %b %Y, %H:%M')}\nEnd: {appt.end_time.strftime('%d %b %Y, %H:%M')}\n\nReview it here:\n{admin_url}\n\nIVORY HALL"
            )

        flash("Booking created (pending approval).")
        return redirect(url_for("dashboard"))

    return render_template("booking_form.html", form=form, mode="create", appt=None)


# ---------- GUEST BOOK ----------
@app.route("/guest-book", methods=["GET", "POST"])
def guest_book():
    form = GuestBookingForm()
    if form.validate_on_submit():
        start_time = parse_dt(form.start_time.data)
        end_time = parse_dt(form.end_time.data)

        if start_time >= end_time:
            flash("Start time must be before end time.")
            return redirect(url_for("guest_book"))

        if hall_conflict(form.hall_name.data.strip(), start_time, end_time):
            flash("Sorry, this hall is already booked in that time slot.")
            return redirect(url_for("guest_book"))

        appt = Appointment(
            title=form.title.data.strip(),
            hall_name=form.hall_name.data.strip(),
            start_time=start_time,
            end_time=end_time,
            description=form.description.data,
            guest_name=form.guest_name.data.strip(),
            guest_email=form.guest_email.data.strip().lower(),
            guest_phone=form.guest_phone.data.strip(),
            status="pending",
        )
        db.session.add(appt)
        db.session.commit()

        cancel_url = url_for("guest_cancel", _external=True)

        # Email guest confirmation
        send_email(
            appt.guest_email,
            "IVORY HALL – Booking request received",
            f"Hello {appt.guest_name},\n\nYour booking request has been received.\n\nBooking ID: {appt.id}\nTitle: {appt.title}\nHall: {appt.hall_name}\nStart: {appt.start_time.strftime('%d %b %Y, %H:%M')}\nEnd: {appt.end_time.strftime('%d %b %Y, %H:%M')}\n\nStatus: PENDING\n\nTo cancel:\n{cancel_url}\n\nThank you,\nIVORY HALL"
        )

        # Email all admins
        admins = User.query.filter_by(is_admin=True).all()
        admin_url = url_for("admin_panel", _external=True)
        for admin in admins:
            send_email(
                admin.email,
                f"IVORY HALL – New guest booking #{appt.id} from {appt.guest_name}",
                f"New guest booking received.\n\nBooking ID: {appt.id}\nGuest: {appt.guest_name} ({appt.guest_email})\nPhone: {appt.guest_phone or 'N/A'}\nTitle: {appt.title}\nHall: {appt.hall_name}\nStart: {appt.start_time.strftime('%d %b %Y, %H:%M')}\nEnd: {appt.end_time.strftime('%d %b %Y, %H:%M')}\n\nReview it here:\n{admin_url}\n\nIVORY HALL"
            )

        return render_template("guest_success.html", appt=appt)

    return render_template("guest_booking_form.html", form=form)


# ---------- GUEST CANCEL ----------
@app.route("/guest-cancel", methods=["GET", "POST"])
def guest_cancel():
    form = GuestCancelForm()
    if form.validate_on_submit():
        booking_id = form.booking_id.data.strip()
        email = form.email.data.strip().lower()

        if not booking_id.isdigit():
            flash("Invalid booking ID.")
            return redirect(url_for("guest_cancel"))

        appt = db.session.get(Appointment, int(booking_id))
        if not appt or not appt.guest_email:
            flash("Booking not found.")
            return redirect(url_for("guest_cancel"))

        if appt.guest_email.lower() != email:
            flash("Email does not match this booking.")
            return redirect(url_for("guest_cancel"))

        appt.status = "cancelled"
        appt.cancel_reason = "Cancelled by guest"
        db.session.commit()

        send_email(
            appt.guest_email,
            "IVORY HALL – Booking cancelled",
            f"Hello {appt.guest_name},\n\nYour booking (ID: {appt.id}) has been cancelled.\n\nThank you,\nIVORY HALL"
        )

        flash("Your booking has been cancelled.")
        return redirect(url_for("guest_book"))

    return render_template("guest_cancel.html", form=form)


# ---------- ADMIN PANEL ----------
@app.route("/admin")
@login_required
def admin_panel():
    if not current_user.is_admin:
        flash("Admin only.")
        return redirect(url_for("dashboard"))

    pending = Appointment.query.filter_by(status="pending").order_by(Appointment.start_time.asc()).all()
    approved = Appointment.query.filter_by(status="approved").order_by(Appointment.start_time.asc()).all()
    rejected = Appointment.query.filter_by(status="rejected").order_by(Appointment.start_time.asc()).all()
    cancelled = Appointment.query.filter_by(status="cancelled").order_by(Appointment.start_time.asc()).all()
    cancel_form = AdminCancelForm()

    return render_template("admin.html", pending=pending, approved=approved, rejected=rejected, cancelled=cancelled, cancel_form=cancel_form)


# ---------- APPROVE ----------
@app.route("/approve/<int:booking_id>", methods=["POST"])
@login_required
def approve_booking(booking_id):
    if not current_user.is_admin:
        abort(403)

    appt = db.session.get(Appointment, booking_id)
    if appt is None:
        abort(404)

    if hall_conflict(appt.hall_name, appt.start_time, appt.end_time, exclude_id=appt.id):
        flash("Cannot approve: conflict with another booking.")
        return redirect(url_for("admin_panel"))

    appt.status = "approved"
    db.session.commit()

    if appt.guest_email:
        send_email(
            appt.guest_email,
            "IVORY HALL – Booking approved",
            f"Hello {appt.guest_name},\n\nYour booking is APPROVED.\n\nBooking ID: {appt.id}\nTitle: {appt.title}\nHall: {appt.hall_name}\nStart: {appt.start_time.strftime('%d %b %Y, %H:%M')}\nEnd: {appt.end_time.strftime('%d %b %Y, %H:%M')}\n\nIVORY HALL"
        )

    flash("Booking approved.")
    return redirect(url_for("admin_panel"))


# ---------- REJECT ----------
@app.route("/reject/<int:booking_id>", methods=["POST"])
@login_required
def reject_booking(booking_id):
    if not current_user.is_admin:
        abort(403)

    appt = db.session.get(Appointment, booking_id)
    if appt is None:
        abort(404)

    appt.status = "rejected"
    appt.cancel_reason = "Rejected by admin"
    db.session.commit()

    if appt.guest_email:
        send_email(
            appt.guest_email,
            "IVORY HALL – Booking rejected",
            f"Hello {appt.guest_name},\n\nYour booking request was REJECTED.\n\nBooking ID: {appt.id}\n\nIVORY HALL"
        )

    flash("Booking rejected.")
    return redirect(url_for("admin_panel"))


# ---------- CANCEL ----------
@app.route("/cancel/<int:booking_id>", methods=["POST"])
@login_required
def cancel_booking(booking_id):
    if not current_user.is_admin:
        abort(403)

    appt = db.session.get(Appointment, booking_id)
    if appt is None:
        abort(404)

    form = AdminCancelForm()
    reason = form.reason.data.strip() if form.reason.data else "No reason provided"

    appt.status = "cancelled"
    appt.cancel_reason = reason
    db.session.commit()

    if appt.guest_email:
        send_email(
            appt.guest_email,
            "IVORY HALL – Booking cancelled",
            f"Hello {appt.guest_name},\n\nYour booking has been CANCELLED by the admin.\n\nBooking ID: {appt.id}\nTitle: {appt.title}\nHall: {appt.hall_name}\nReason: {reason}\n\nThank you,\nIVORY HALL"
        )

    flash("Booking cancelled.")
    return redirect(url_for("admin_panel"))


# ---------- ADMIN STATS ----------
@app.route("/admin/stats")
@login_required
def admin_stats():
    if not current_user.is_admin:
        abort(403)

    total = Appointment.query.count()
    pending_count = Appointment.query.filter_by(status="pending").count()
    approved_count = Appointment.query.filter_by(status="approved").count()
    rejected_count = Appointment.query.filter_by(status="rejected").count()
    cancelled_count = Appointment.query.filter_by(status="cancelled").count()

    from sqlalchemy import func
    hall_stats = db.session.query(
        Appointment.hall_name,
        func.count(Appointment.id).label("count")
    ).group_by(Appointment.hall_name).all()

    recent = Appointment.query.order_by(Appointment.id.desc()).limit(5).all()

    return render_template("admin_stats.html", total=total, pending_count=pending_count, approved_count=approved_count, rejected_count=rejected_count, cancelled_count=cancelled_count, hall_stats=hall_stats, recent=recent)


# ---------- INVOICE ----------
@app.route("/invoice/<int:booking_id>")
@login_required
def invoice(booking_id):
    if not current_user.is_admin:
        abort(403)
    appt = db.session.get(Appointment, booking_id)
    if appt is None:
        abort(404)
    return render_template("invoice.html", appt=appt)


# ---------- ADMIN SEND MESSAGE ----------
@app.route("/message/<int:booking_id>", methods=["GET", "POST"])
@login_required
def send_message(booking_id):
    if not current_user.is_admin:
        abort(403)

    appt = db.session.get(Appointment, booking_id)
    if appt is None:
        abort(404)

    form = AdminMessageForm()
    if form.validate_on_submit():
        to_email = appt.guest_email or (appt.owner.email if appt.owner else None)
        if not to_email:
            flash("No email address found for this booking.")
            return redirect(url_for("admin_panel"))

        send_email(to_email, form.subject.data, form.body.data)
        flash(f"Message sent to {to_email}.")
        return redirect(url_for("admin_panel"))

    return render_template("admin_message.html", form=form, appt=appt)


# ---------- CHANGE PASSWORD ----------
@app.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if not current_user.check_password(form.current_password.data):
            flash("Current password is incorrect.")
            return redirect(url_for("change_password"))
        current_user.set_password(form.new_password.data)
        db.session.commit()
        flash("Password changed successfully.")
        return redirect(url_for("dashboard"))
    return render_template("change_password.html", form=form)


# ---------- ADMIN USER MANAGEMENT ----------
@app.route("/admin/users")
@login_required
def admin_users():
    if not current_user.is_admin:
        abort(403)
    users = User.query.order_by(User.id.asc()).all()
    return render_template("admin_users.html", users=users)


@app.route("/admin/users/promote/<int:user_id>", methods=["POST"])
@login_required
def promote_user(user_id):
    if not current_user.is_admin:
        abort(403)
    user = db.session.get(User, user_id)
    if user is None:
        abort(404)
    if user.id == current_user.id:
        flash("You cannot change your own admin status.")
        return redirect(url_for("admin_users"))
    user.is_admin = not user.is_admin
    db.session.commit()
    flash(f"{'Promoted' if user.is_admin else 'Demoted'} {user.username}.")
    return redirect(url_for("admin_users"))


@app.route("/admin/users/delete/<int:user_id>", methods=["POST"])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        abort(403)
    user = db.session.get(User, user_id)
    if user is None:
        abort(404)
    if user.id == current_user.id:
        flash("You cannot delete yourself.")
        return redirect(url_for("admin_users"))
    Appointment.query.filter_by(user_id=user.id).update({"user_id": None})
    db.session.delete(user)
    db.session.commit()
    flash(f"User {user.username} deleted.")
    return redirect(url_for("admin_users"))


# ---------- ADMIN SEARCH ----------
@app.route("/admin/search")
@login_required
def admin_search():
    if not current_user.is_admin:
        abort(403)

    q = request.args.get("q", "").strip()
    status_filter = request.args.get("status", "").strip()
    hall_filter = request.args.get("hall", "").strip()

    query = Appointment.query

    if q:
        like = f"%{q}%"
        query = query.filter(
            db.or_(
                Appointment.title.ilike(like),
                Appointment.guest_name.ilike(like),
                Appointment.guest_email.ilike(like),
                Appointment.hall_name.ilike(like),
            )
        )
    if status_filter:
        query = query.filter(Appointment.status == status_filter)
    if hall_filter:
        query = query.filter(Appointment.hall_name == hall_filter)

    results = query.order_by(Appointment.start_time.desc()).all()
    halls = sorted(set(b.hall_name for b in Appointment.query.all() if b.hall_name))
    cancel_form = AdminCancelForm()

    return render_template("admin_search.html", results=results, q=q, status_filter=status_filter, hall_filter=hall_filter, halls=halls, cancel_form=cancel_form)


# ---------- REMINDER EMAILS ----------
@app.route("/admin/send-reminders", methods=["POST"])
@login_required
def send_reminders():
    if not current_user.is_admin:
        abort(403)

    from datetime import timedelta
    tomorrow = datetime.today().date() + timedelta(days=1)

    bookings = Appointment.query.filter(
        Appointment.status == "approved",
        db.func.date(Appointment.start_time) == tomorrow,
    ).all()

    sent = 0
    for b in bookings:
        to_email = b.guest_email or (b.owner.email if b.owner else None)
        name = b.guest_name or (b.owner.username if b.owner else "Guest")
        if to_email:
            send_email(
                to_email,
                "IVORY HALL – Reminder: Your event is tomorrow",
                f"Hello {name},\n\nThis is a reminder that your event is TOMORROW.\n\nBooking ID: {b.id}\nTitle: {b.title}\nHall: {b.hall_name}\nStart: {b.start_time.strftime('%d %b %Y, %H:%M')}\nEnd: {b.end_time.strftime('%d %b %Y, %H:%M')}\n\nWe look forward to hosting you!\n\nIVORY HALL"
            )
            sent += 1

    flash(f"Reminder emails sent to {sent} booking(s) for tomorrow.")
    return redirect(url_for("admin_panel"))


# ---------- CALENDAR ----------
@app.route("/calendar")
@login_required
def calendar_view():
    from datetime import timedelta

    start_param = request.args.get("start")
    hall_filter = request.args.get("hall", "")

    if start_param:
        try:
            week_start = datetime.strptime(start_param, "%Y-%m-%d").date()
        except ValueError:
            week_start = datetime.today().date()
    else:
        today = datetime.today().date()
        week_start = today - timedelta(days=today.weekday())

    days = [week_start + timedelta(days=i) for i in range(7)]
    prev_week = (week_start - timedelta(days=7)).isoformat()
    next_week = (week_start + timedelta(days=7)).isoformat()

    q = Appointment.query.filter(Appointment.status.in_(["pending", "approved"]))
    if hall_filter:
        q = q.filter(Appointment.hall_name == hall_filter)

    all_bookings = q.order_by(Appointment.start_time.asc()).all()

    bookings_by_day = {d.isoformat(): [] for d in days}
    for b in all_bookings:
        day_key = b.start_time.date().isoformat()
        if day_key in bookings_by_day:
            bookings_by_day[day_key].append(b)

    halls = sorted(set(b.hall_name for b in Appointment.query.all() if b.hall_name))

    return render_template("calendar.html", days=days, bookings_by_day=bookings_by_day, week_start=week_start, prev_week=prev_week, next_week=next_week, hall=hall_filter, halls=halls)


if __name__ == "__main__":
    app.run(debug=True)