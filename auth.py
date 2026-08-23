from flask import Blueprint, request, jsonify, render_template, redirect, url_for, flash
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, logout_user, login_required, current_user
from models import db, User

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard_view'))
        
    if request.method == 'POST':
        # Accept JSON or Form Data
        if request.is_json:
            data = request.get_json()
            username = data.get('username')
            password = data.get('password')
        else:
            username = request.form.get('username')
            password = request.form.get('password')

        if not username or not password:
            if request.is_json:
                return jsonify({'error': 'Username and password are required'}), 400
            flash('Username and password are required', 'error')
            return render_template('register.html')

        # Check password complexity/length
        if len(password) < 6:
            if request.is_json:
                return jsonify({'error': 'Password must be at least 6 characters long'}), 400
            flash('Password must be at least 6 characters long', 'error')
            return render_template('register.html')

        # Check if username exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            if request.is_json:
                return jsonify({'error': 'Username already exists'}), 400
            flash('Username already exists', 'error')
            return render_template('register.html')

        # Create user
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, password_hash=hashed_password)
        
        db.session.add(new_user)
        db.session.commit()

        if request.is_json:
            return jsonify({'message': 'Registration successful'}), 201
            
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('auth.login'))

    return render_template('register.html')

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard_view'))

    if request.method == 'POST':
        if request.is_json:
            data = request.get_json()
            username = data.get('username')
            password = data.get('password')
        else:
            username = request.form.get('username')
            password = request.form.get('password')

        if not username or not password:
            if request.is_json:
                return jsonify({'error': 'Username and password are required'}), 400
            flash('Username and password are required', 'error')
            return render_template('login.html')

        user = User.query.filter_by(username=username).first()
        if not user or not check_password_hash(user.password_hash, password):
            if request.is_json:
                return jsonify({'error': 'Invalid username or password'}), 401
            flash('Invalid username or password', 'error')
            return render_template('login.html')

        # Log in the user
        login_user(user, remember=True)

        if request.is_json:
            return jsonify({'message': 'Login successful', 'username': user.username}), 200
            
        return redirect(url_for('dashboard_view'))

    return render_template('login.html')

@auth_bp.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    if request.is_json or request.headers.get('Accept') == 'application/json':
        return jsonify({'message': 'Logged out successfully'}), 200
    return redirect(url_for('auth.login'))

@auth_bp.route('/session', methods=['GET'])
def get_session():
    if current_user.is_authenticated:
        return jsonify({
            'authenticated': True,
            'username': current_user.username
        }), 200
    return jsonify({
        'authenticated': False
    }), 200
