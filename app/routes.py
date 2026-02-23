from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from flask_login import login_user, logout_user, login_required, current_user
from app import db
from app.models import User, Role, AuditLog
from app.auth import ADAuthenticator
from app.twofa import TOTPManager
from app.audit import log_action

auth_bp = Blueprint('auth', __name__)
main_bp = Blueprint('main', __name__)

ad_auth = ADAuthenticator()

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """Login with Active Directory credentials"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        success, ad_user = ad_auth.authenticate(username, password)
        
        if success:
            log_action(username, 'ad_login', 'success')
            user = User.query.filter_by(username=username).first()
            
            if not user:
                user_info = ad_auth.get_user_info(username)
                default_role = Role.query.filter_by(name='Standard User').first()
                if not default_role:
                    default_role = Role(name='Standard User', description='Regular User')
                    db.session.add(default_role)
                    db.session.commit()
                
                user = User(
                    username=username,
                    email=user_info['email'] if user_info else f"{username}@domain.local",
                    role=default_role
                )
                db.session.add(user)
                db.session.commit()
            
            if user.is_2fa_enabled:
                session['pre_2fa_user'] = username
                return redirect(url_for('auth.verify_2fa'))
            else:
                login_user(user)
                log_action(username, 'login', 'success')
                return redirect(url_for('main.dashboard'))
        else:
            log_action(username, 'ad_login', 'failure', 'Invalid credentials')
            flash('Invalid username or password', 'danger')
    
    return render_template('login.html')

@auth_bp.route('/verify-2fa', methods=['GET', 'POST'])
def verify_2fa():
    """Verify 2FA TOTP code"""
    if 'pre_2fa_user' not in session:
        return redirect(url_for('auth.login'))
    
    username = session['pre_2fa_user']
    user = User.query.filter_by(username=username).first()
    
    if request.method == 'POST':
        token = request.form.get('token')
        
        if user.totp_secret and TOTPManager.verify_token(user.totp_secret, token):
            log_action(username, '2fa_verify', 'success')
            login_user(user)
            session.pop('pre_2fa_user')
            log_action(username, 'login', 'success')
            return redirect(url_for('main.dashboard'))
        else:
            log_action(username, '2fa_verify', 'failure', 'Invalid TOTP code')
            flash('Invalid 2FA code', 'danger')
    
    return render_template('verify_2fa.html', username=username)

@auth_bp.route('/logout')
@login_required
def logout():
    """Logout user"""
    log_action(current_user.username, 'logout', 'success')
    logout_user()
    return redirect(url_for('auth.login'))

@main_bp.route('/dashboard')
@login_required
def dashboard():
    """Main dashboard"""
    return render_template('dashboard.html', user=current_user)

@main_bp.route('/audit-logs')
@login_required
def audit_logs():
    """View audit logs"""
    if current_user.role.name not in ['Admin', 'Auditor']:
        flash('Access denied', 'danger')
        return redirect(url_for('main.dashboard'))
    
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).paginate(page=1, per_page=50)
    return render_template('audit_logs.html', logs=logs)