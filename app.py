import os
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
# Load from environment variables — never hardcode secrets.
# Set these in a .env file (use python-dotenv) or your deployment environment.
app.config["SECRET_KEY"] = "ivory-hall-secret-2026"
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///event_hall.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# ======================
# EMAIL SETTINGS (GMAIL)
# ======================
app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USE_SSL"] = False
app.config["MAIL_USERNAME"] = "IVORYHALL38@gmail.com"
app.config["MAIL_PASSWORD"] = "poak svlg mldh ihgw"
app.config["MAIL_DEFAULT_SENDER"] = "IVORYHALL38@gmail.com"

mail = Mail(app)
db = SQLAlchemy(app)
csrf = CSRFProtect(app)

login_manager = LoginManager(app)
login_manager.login_view = "login"


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
    start_time = StringField("Start Time", validators=[DataRequired()])  # datetime-local string
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
    # status: pending / approved / cancelled / rejected
    # "rejected" = admin denied a pending request
    # "cancelled" = admin or guest cancelled an existing/pending booking
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
    # input type="datetime-local" => 2026-02-23T12:30
    return datetime.strptime(v, "%Y-%m-%dT%H:%M")


def send_email(to_email, subject, body):
    if not to_email:
        return
    try:
        msg = Message(subject=subject, recipients=[to_email], body=body)
        mail.send(msg)
    except Exception as e:
        print("EMAIL ERROR:", e)


def overlaps(a_start, a_end, b_start, b_end):
    return a_start < b_end and b_start < a_end


def hall_conflict(hall_name, start_time, end_time, exclude_id=None):
    """Check for overlapping bookings (pending + approved only)."""
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
@login_required
def init_db():
    """Admin-only route to initialise the database."""
    if not current_user.is_admin:
        abort(403)
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

        send_email(
            appt.guest_email,
            "IVORY HALL – Booking request received",
            f"Hello {appt.guest_name},\n\n"
            f"Your booking request has been received.\n\n"
            f"Booking ID: {appt.id}\n"
            f"Title: {appt.title}\n"
            f"Hall: {appt.hall_name}\n"
            f"Start: {appt.start_time}\n"
            f"End: {appt.end_time}\n\n"
            "Status: PENDING\n\n"
            f"To cancel (if you change your mind):\n{cancel_url}\n\n"
            "Thank you,\nIVORY HALL"
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

        # Use "cancelled" to distinguish from admin "rejected"
        appt.status = "cancelled"
        appt.cancel_reason = "Cancelled by guest"
        db.session.commit()

        send_email(
            appt.guest_email,
            "IVORY HALL – Booking cancelled",
            f"Hello {appt.guest_name},\n\n"
            f"Your booking (ID: {appt.id}) has been cancelled.\n\n"
            "Thank you,\nIVORY HALL"
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

    return render_template(
        "admin.html",
        pending=pending,
        approved=approved,
        rejected=rejected,
        cancelled=cancelled,
        cancel_form=cancel_form,
    )


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
            "IVORY HALL – Booking approved ✅",
            f"Hello {appt.guest_name},\n\n"
            f"Your booking is APPROVED ✅\n\n"
            f"Booking ID: {appt.id}\n"
            f"Title: {appt.title}\n"
            f"Hall: {appt.hall_name}\n"
            f"Start: {appt.start_time}\n"
            f"End: {appt.end_time}\n\n"
            "IVORY HALL"
        )

    flash("Booking approved.")
    return redirect(url_for("admin_panel"))


# ---------- REJECT (admin denies a pending request) ----------
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
            "IVORY HALL – Booking rejected ❌",
            f"Hello {appt.guest_name},\n\n"
            f"Your booking request was REJECTED ❌\n\n"
            f"Booking ID: {appt.id}\n\n"
            "IVORY HALL"
        )

    flash("Booking rejected.")
    return redirect(url_for("admin_panel"))


# ---------- CANCEL (admin cancels an approved booking with a reason) ----------
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
            f"Hello {appt.guest_name},\n\n"
            f"Your booking has been CANCELLED by the admin.\n\n"
            f"Booking ID: {appt.id}\n"
            f"Title: {appt.title}\n"
            f"Hall: {appt.hall_name}\n"
            f"Start: {appt.start_time}\n"
            f"End: {appt.end_time}\n\n"
            f"Reason: {reason}\n\n"
            "Thank you,\nIVORY HALL"
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

    # Bookings per hall
    from sqlalchemy import func
    hall_stats = db.session.query(
        Appointment.hall_name,
        func.count(Appointment.id).label("count")
    ).group_by(Appointment.hall_name).all()

    # Recent 5 bookings
    recent = Appointment.query.order_by(Appointment.id.desc()).limit(5).all()

    return render_template(
        "admin_stats.html",
        total=total,
        pending_count=pending_count,
        approved_count=approved_count,
        rejected_count=rejected_count,
        cancelled_count=cancelled_count,
        hall_stats=hall_stats,
        recent=recent,
    )


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
    # Detach their bookings
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

    return render_template(
        "admin_search.html",
        results=results,
        q=q,
        status_filter=status_filter,
        hall_filter=hall_filter,
        halls=halls,
        cancel_form=cancel_form,
    )


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
                "IVORY HALL – Reminder: Your event is tomorrow 🗓️",
                f"Hello {name},\n\n"
                f"This is a friendly reminder that your event is TOMORROW.\n\n"
                f"Booking ID: {b.id}\n"
                f"Title: {b.title}\n"
                f"Hall: {b.hall_name}\n"
                f"Start: {b.start_time.strftime('%d %b %Y, %H:%M')}\n"
                f"End: {b.end_time.strftime('%d %b %Y, %H:%M')}\n\n"
                "We look forward to hosting you!\n\n"
                "IVORY HALL"
            )
            sent += 1

    flash(f"Reminder emails sent to {sent} booking(s) for tomorrow.")
    return redirect(url_for("admin_panel"))


# ---------- CALENDAR ----------
@app.route("/calendar")
@login_required
def calendar_view():
    from datetime import timedelta

    # Get week start from query param, default to this Monday
    start_param = request.args.get("start")
    hall_filter = request.args.get("hall", "")

    if start_param:
        try:
            week_start = datetime.strptime(start_param, "%Y-%m-%d").date()
        except ValueError:
            week_start = datetime.today().date()
    else:
        today = datetime.today().date()
        week_start = today - timedelta(days=today.weekday())  # Monday

    # 7 days of the week
    days = [week_start + timedelta(days=i) for i in range(7)]
    prev_week = (week_start - timedelta(days=7)).isoformat()
    next_week = (week_start + timedelta(days=7)).isoformat()

    # Get all bookings (filter by hall if selected)
    q = Appointment.query.filter(
        Appointment.status.in_(["pending", "approved"])
    )
    if hall_filter:
        q = q.filter(Appointment.hall_name == hall_filter)

    all_bookings = q.order_by(Appointment.start_time.asc()).all()

    # Group bookings by day (key = date isoformat)
    bookings_by_day = {d.isoformat(): [] for d in days}
    for b in all_bookings:
        day_key = b.start_time.date().isoformat()
        if day_key in bookings_by_day:
            bookings_by_day[day_key].append(b)

    # Get unique hall names for filter dropdown
    halls = sorted(set(
        b.hall_name for b in Appointment.query.all() if b.hall_name
    ))

    return render_template(
        "calendar.html",
        days=days,
        bookings_by_day=bookings_by_day,
        week_start=week_start,
        prev_week=prev_week,
        next_week=next_week,
        hall=hall_filter,
        halls=halls,
    )


if __name__ == "__main__":
    app.run(debug=True)
