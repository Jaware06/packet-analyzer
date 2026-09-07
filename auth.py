from flask import (
    Blueprint,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    session
)

from flask_login import (
    login_user,
    logout_user,
    login_required
)

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)

from models import db, User

import random
import re
import os
import time
import secrets
import resend

from datetime import datetime, timedelta

from dotenv import load_dotenv


# ============================================================
# LOAD ENVIRONMENT VARIABLES
# ============================================================

load_dotenv()

resend.api_key = os.getenv("RESEND_API_KEY")


# ============================================================
# BLUEPRINT
# ============================================================

auth_bp = Blueprint(
    'auth',
    __name__
)


# ============================================================
# GENERATE OTP
# ============================================================

def generate_otp():

    return str(
        random.randint(
            100000,
            999999
        )
    )


# ============================================================
# VALIDATE EMAIL
# ============================================================

def valid_email(email):

    pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'

    return re.match(
        pattern,
        email
    ) is not None


# ============================================================
# SEND EMAIL USING RESEND
# ============================================================

def send_email(
    receiver_email,
    subject,
    html
):

    if not resend.api_key:

        raise Exception(
            "RESEND_API_KEY is not configured."
        )

    params = {
        "from": "onboarding@resend.dev",
        "to": [receiver_email],
        "subject": subject,
        "html": html
    }

    return resend.Emails.send(params)


# ============================================================
# SEND OTP EMAIL
# ============================================================

def send_otp_email(
    receiver_email,
    otp
):

    html = f"""
    <html>

    <body style="
        font-family: Arial, sans-serif;
        background:#f4f7fb;
        padding:30px;
    ">

        <div style="
            max-width:500px;
            margin:auto;
            background:white;
            padding:30px;
            border-radius:12px;
        ">

            <h2>🛡️ Packet Analyzer</h2>

            <p>Hello,</p>

            <p>
                Your email verification code is:
            </p>

            <div style="
                font-size:32px;
                font-weight:bold;
                letter-spacing:8px;
                padding:15px;
                text-align:center;
                background:#f1f3f5;
                border-radius:8px;
            ">
                {otp}
            </div>

            <p>
                This OTP is valid for
                <strong>5 minutes</strong>.
            </p>

            <p>
                If you did not request this verification,
                please ignore this email.
            </p>

            <p>
                Regards,<br>
                <strong>Packet Analyzer Team</strong>
            </p>

        </div>

    </body>
    </html>
    """

    return send_email(
        receiver_email,
        "Packet Analyzer - Email Verification",
        html
    )


# ============================================================
# SEND PASSWORD RESET EMAIL
# ============================================================

def send_reset_email(
    receiver_email,
    reset_link
):

    html = f"""
    <html>

    <body style="
        font-family: Arial, sans-serif;
        background:#f4f7fb;
        padding:30px;
    ">

        <div style="
            max-width:500px;
            margin:auto;
            background:white;
            padding:30px;
            border-radius:12px;
        ">

            <h2>🛡️ Packet Analyzer</h2>

            <h3>Password Reset Request</h3>

            <p>Hello,</p>

            <p>
                We received a request to reset your
                Packet Analyzer password.
            </p>

            <p>
                Click the button below to create
                a new password.
            </p>

            <div style="
                text-align:center;
                margin:30px 0;
            ">

                <a href="{reset_link}"
                   style="
                   background:#2563eb;
                   color:white;
                   padding:14px 25px;
                   text-decoration:none;
                   border-radius:8px;
                   display:inline-block;
                   font-weight:bold;
                   ">

                    Reset Password

                </a>

            </div>

            <p>
                This link is valid for
                <strong>30 minutes</strong>.
            </p>

            <p>
                If you did not request a password reset,
                you can safely ignore this email.
            </p>

            <p>
                Regards,<br>
                <strong>Packet Analyzer Team</strong>
            </p>

        </div>

    </body>
    </html>
    """

    return send_email(
        receiver_email,
        "Packet Analyzer - Password Reset",
        html
    )


# ============================================================
# REGISTER
# ============================================================

@auth_bp.route(
    '/register',
    methods=['GET', 'POST']
)
def register():

    if request.method == 'POST':

        username = request.form.get(
            'username',
            ''
        ).strip()

        email = request.form.get(
            'email',
            ''
        ).strip().lower()

        password = request.form.get(
            'password',
            ''
        )

        # Check fields

        if not username or not email or not password:

            flash(
                "All fields are required.",
                "danger"
            )

            return redirect(
                url_for('auth.register')
            )

        # Validate email

        if not valid_email(email):

            flash(
                "Please enter a valid email address.",
                "danger"
            )

            return redirect(
                url_for('auth.register')
            )

        # Check username

        existing_user = User.query.filter_by(
            username=username
        ).first()

        if existing_user:

            flash(
                "Username already exists.",
                "danger"
            )

            return redirect(
                url_for('auth.register')
            )

        # Check email

        existing_email = User.query.filter_by(
            email=email
        ).first()

        if existing_email:

            flash(
                "Email already registered.",
                "danger"
            )

            return redirect(
                url_for('auth.register')
            )

        # Generate OTP

        otp = generate_otp()

        # Store temporary registration data

        session['registration_username'] = username

        session['registration_email'] = email

        session['registration_password'] = (
            generate_password_hash(password)
        )

        session['verification_otp'] = otp

        session['otp_created_at'] = time.time()

        # Send email

        try:

            send_otp_email(
                email,
                otp
            )

            flash(
                "Verification code sent to your email.",
                "success"
            )

            return redirect(
                url_for('auth.verify_email')
            )

        except Exception as e:

            print(
                "EMAIL ERROR:",
                e
            )

            session.clear()

            flash(
                "Unable to send verification email.",
                "danger"
            )

            return redirect(
                url_for('auth.register')
            )

    return render_template(
        'register.html'
    )


# ============================================================
# VERIFY EMAIL
# ============================================================

@auth_bp.route(
    '/verify-email',
    methods=['GET', 'POST']
)
def verify_email():

    email = session.get(
        'registration_email'
    )

    if not email:

        flash(
            "No verification request found. Please register again.",
            "warning"
        )

        return redirect(
            url_for('auth.register')
        )

    if request.method == 'POST':

        entered_otp = request.form.get(
            'otp',
            ''
        ).strip()

        stored_otp = session.get(
            'verification_otp'
        )

        otp_created_at = session.get(
            'otp_created_at'
        )

        # Check OTP exists

        if not stored_otp:

            flash(
                "OTP expired. Please register again.",
                "danger"
            )

            return redirect(
                url_for('auth.register')
            )

        # Check timestamp

        if not otp_created_at:

            flash(
                "OTP expired. Please register again.",
                "danger"
            )

            return redirect(
                url_for('auth.register')
            )

        # 5 minute expiry

        if time.time() - otp_created_at > 300:

            session.pop(
                'verification_otp',
                None
            )

            session.pop(
                'otp_created_at',
                None
            )

            flash(
                "OTP has expired. Please register again.",
                "danger"
            )

            return redirect(
                url_for('auth.register')
            )

        # Check OTP

        if entered_otp != stored_otp:

            flash(
                "Invalid verification code.",
                "danger"
            )

            return redirect(
                url_for('auth.verify_email')
            )

        # Get registration data

        username = session.get(
            'registration_username'
        )

        email = session.get(
            'registration_email'
        )

        password_hash = session.get(
            'registration_password'
        )

        # Safety check

        if not username or not email or not password_hash:

            flash(
                "Registration session expired. Please register again.",
                "danger"
            )

            return redirect(
                url_for('auth.register')
            )

        # Create user

        user = User(
            username=username,
            email=email,
            password_hash=password_hash,
            email_verified=True
        )

        try:

            db.session.add(user)

            db.session.commit()

        except Exception as e:

            db.session.rollback()

            print(
                "DATABASE ERROR:",
                e
            )

            flash(
                "Unable to create account. Please try again.",
                "danger"
            )

            return redirect(
                url_for('auth.register')
            )

        # Clear registration session

        session.pop(
            'registration_username',
            None
        )

        session.pop(
            'registration_email',
            None
        )

        session.pop(
            'registration_password',
            None
        )

        session.pop(
            'verification_otp',
            None
        )

        session.pop(
            'otp_created_at',
            None
        )

        flash(
            "Email verified successfully! Please sign in.",
            "success"
        )

        return redirect(
            url_for('auth.login')
        )

    return render_template(
        'verify_email.html',
        email=email
    )


# ============================================================
# LOGIN
# ============================================================

@auth_bp.route(
    '/login',
    methods=['GET', 'POST']
)
def login():

    if request.method == 'POST':

        username = request.form.get(
            'username',
            ''
        ).strip()

        password = request.form.get(
            'password',
            ''
        )

        if not username or not password:

            flash(
                "Please enter username and password.",
                "danger"
            )

            return redirect(
                url_for('auth.login')
            )

        user = User.query.filter_by(
            username=username
        ).first()

        if not user:

            flash(
                "Invalid username or password.",
                "danger"
            )

            return redirect(
                url_for('auth.login')
            )

        if not user.email_verified:

            flash(
                "Please verify your email before logging in.",
                "warning"
            )

            return redirect(
                url_for('auth.verify_email')
            )

        if check_password_hash(
            user.password_hash,
            password
        ):

            login_user(user)

            print(
                "LOGIN SUCCESS:",
                user.username
            )

            return redirect(
                url_for('dashboard_view')
            )

        flash(
            "Invalid username or password.",
            "danger"
        )

        return redirect(
            url_for('auth.login')
        )

    return render_template(
        'login.html'
    )


# ============================================================
# FORGOT PASSWORD
# ============================================================

@auth_bp.route(
    '/forgot-password',
    methods=['GET', 'POST']
)
def forgot_password():

    if request.method == 'POST':

        email = request.form.get(
            'email',
            ''
        ).strip().lower()

        if not email:

            flash(
                "Please enter your email address.",
                "danger"
            )

            return redirect(
                url_for('auth.forgot_password')
            )

        if not valid_email(email):

            flash(
                "Please enter a valid email address.",
                "danger"
            )

            return redirect(
                url_for('auth.forgot_password')
            )

        user = User.query.filter_by(
            email=email
        ).first()

        # Don't reveal whether account exists

        if not user:

            flash(
                "If this email is registered, a password reset link has been sent.",
                "info"
            )

            return redirect(
                url_for('auth.login')
            )

        # Generate secure token

        token = secrets.token_urlsafe(32)

        user.reset_token = token

        user.reset_token_expiry = (
            datetime.utcnow()
            + timedelta(minutes=30)
        )

        db.session.commit()

        # Create reset URL

        reset_link = url_for(
            'auth.reset_password',
            token=token,
            _external=True
        )

        try:

            send_reset_email(
                email,
                reset_link
            )

            flash(
                "Password reset link sent to your email.",
                "success"
            )

        except Exception as e:

            print(
                "RESET EMAIL ERROR:",
                e
            )

            user.reset_token = None

            user.reset_token_expiry = None

            db.session.commit()

            flash(
                "Unable to send reset email. Please try again.",
                "danger"
            )

        return redirect(
            url_for('auth.login')
        )

    return render_template(
        'forgot_password.html'
    )


# ============================================================
# RESET PASSWORD
# ============================================================

@auth_bp.route(
    '/reset-password/<token>',
    methods=['GET', 'POST']
)
def reset_password(token):

    user = User.query.filter_by(
        reset_token=token
    ).first()

    if not user:

        flash(
            "Invalid or expired password reset link.",
            "danger"
        )

        return redirect(
            url_for('auth.login')
        )

    # Check expiry

    if (
        not user.reset_token_expiry
        or
        datetime.utcnow()
        > user.reset_token_expiry
    ):

        user.reset_token = None

        user.reset_token_expiry = None

        db.session.commit()

        flash(
            "Password reset link has expired. Please request a new one.",
            "danger"
        )

        return redirect(
            url_for('auth.forgot_password')
        )

    if request.method == 'POST':

        password = request.form.get(
            'password',
            ''
        )

        confirm_password = request.form.get(
            'confirm_password',
            ''
        )

        if not password or not confirm_password:

            flash(
                "Please fill in both password fields.",
                "danger"
            )

            return redirect(
                url_for(
                    'auth.reset_password',
                    token=token
                )
            )

        if len(password) < 6:

            flash(
                "Password must contain at least 6 characters.",
                "danger"
            )

            return redirect(
                url_for(
                    'auth.reset_password',
                    token=token
                )
            )

        if password != confirm_password:

            flash(
                "Passwords do not match.",
                "danger"
            )

            return redirect(
                url_for(
                    'auth.reset_password',
                    token=token
                )
            )

        # Update password

        user.password_hash = (
            generate_password_hash(password)
        )

        # Invalidate token

        user.reset_token = None

        user.reset_token_expiry = None

        db.session.commit()

        flash(
            "Password reset successfully! Please sign in.",
            "success"
        )

        return redirect(
            url_for('auth.login')
        )

    return render_template(
        'reset_password.html'
    )


# ============================================================
# LOGOUT
# ============================================================

@auth_bp.route('/logout')
@login_required
def logout():

    logout_user()

    return redirect(
        url_for('auth.login')
    )