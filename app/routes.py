from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify
from flask_login import login_user, logout_user, login_required, current_user
from app import db
from app.models import User, Role, AuditLog
from app.auth import ADAuthenticator
from app.twofa import TOTPManager
from app.audit import log_action
import qrcode
from io import BytesIO
import base64
from datetime import datetime

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')
main_bp = Blueprint('main', __name__)

ad_auth = ADAuthenticator()

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """Login with Active Directory credentials"""
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        if not username or not password:
            flash('Username and password are required', 'danger')
            return render_template('login.html')
        
        # Authenticate against Active Directory
        success, ad_user = ad_auth.authenticate(username, password)
        
        if success:
            log_action(username, 'ad_login', 'success', 'Active Directory authentication successful')
            
            # Get user info from AD (INCLUDES ROLE FROM GROUP MEMBERSHIP)
            user_info = ad_auth.get_user_info(username)
            print(f"[DEBUG] User info retrieved: {user_info}")
            
            # Get or create user in database
            user = User.query.filter_by(username=username).first()
            
            if not user:
                # NEW USER - Create with role from AD
                if user_info:
                    role_name = user_info.get('role', 'Standard User')
                else:
                    role_name = 'Standard User'
                
                print(f"[DEBUG] Creating NEW user: {username} with role: {role_name}")
                
                role = Role.query.filter_by(name=role_name).first()
                if not role:
                    role = Role.query.filter_by(name='Standard User').first()
                
                user = User(
                    username=username,
                    email=user_info['email'] if user_info else f"{username}@cnpslocal.local",
                    role=role,
                    is_2fa_enabled=False
                )
                db.session.add(user)
                db.session.commit()
                log_action(username, 'user_created', 'success', f'New user created with role: {role.name}')
                print(f"[DEBUG] ✓ User created in database with role: {role.name}")
            else:
                # EXISTING USER - Update role from AD if changed
                if user_info:
                    new_role_name = user_info.get('role', 'Standard User')
                    new_role = Role.query.filter_by(name=new_role_name).first()
                    
                    if new_role and user.role.name != new_role.name:
                        print(f"[DEBUG] Updating {username} role from {user.role.name} to {new_role.name}")
                        user.role = new_role
                        db.session.commit()
                        log_action(username, 'role_updated', 'success', f'Role updated to {new_role.name}')
            
            # Update last login
            user.last_login = datetime.utcnow()
            db.session.commit()
            
            # Check if 2FA is enabled
            if user.is_2fa_enabled:
                session['pre_2fa_user'] = username
                session['pre_2fa_user_id'] = user.id
                return redirect(url_for('auth.verify_2fa'))
            else:
                session['setup_2fa_user'] = username
                session['setup_2fa_user_id'] = user.id
                return redirect(url_for('auth.setup_2fa'))
        else:
            log_action(username, 'ad_login', 'failure', 'Invalid credentials')
            flash('Invalid username or password', 'danger')
    
    return render_template('login.html')

@auth_bp.route('/setup-2fa', methods=['GET', 'POST'])
def setup_2fa():
    """Setup 2FA for first-time users"""
    if 'setup_2fa_user' not in session:
        return redirect(url_for('auth.login'))
    
    username = session['setup_2fa_user']
    user = User.query.filter_by(username=username).first()
    
    if not user:
        flash('User not found', 'danger')
        return redirect(url_for('auth.login'))
    
    if request.method == 'POST':
        token = request.form.get('token', '').strip()
        
        if not token:
            flash('Please enter the verification code', 'danger')
            return render_template('setup_2fa.html', username=username, qr_code=session.get('qr_code'), secret=session.get('setup_2fa_secret'))
        
        if not user.totp_secret:
            flash('Please generate 2FA secret first', 'danger')
            return redirect(url_for('auth.setup_2fa'))
        
        # Verify the TOTP token
        if TOTPManager.verify_token(user.totp_secret, token):
            # Token is valid - enable 2FA
            user.is_2fa_enabled = True
            db.session.commit()
            log_action(username, '2fa_setup', 'success', '2FA enabled successfully')
            
            # Clear session and login user
            session.pop('setup_2fa_user', None)
            session.pop('setup_2fa_user_id', None)
            session.pop('qr_code', None)
            session.pop('setup_2fa_secret', None)
            
            login_user(user)
            log_action(username, 'login', 'success', 'User logged in successfully')
            flash('2FA setup completed! You are now logged in.', 'success')
            return redirect(url_for('main.dashboard'))
        else:
            # Invalid token
            log_action(username, '2fa_setup', 'failure', 'Invalid TOTP verification code')
            flash('Invalid code. Please try again.', 'danger')
    
    # Generate TOTP secret if not already generated
    if not user.totp_secret:
        user.totp_secret = TOTPManager.generate_secret()
        db.session.commit()
    
    # Generate QR code
    provisioning_uri = TOTPManager.get_totp_uri(username, user.totp_secret)
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(provisioning_uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    
    # Convert to base64
    buffered = BytesIO()
    img.save(buffered, format="PNG")
    img_str = base64.b64encode(buffered.getvalue()).decode()
    
    return render_template('setup_2fa.html', username=username, qr_code=img_str, secret=user.totp_secret)

@auth_bp.route('/verify-2fa', methods=['GET', 'POST'])
def verify_2fa():
    """Verify 2FA TOTP code during login"""
    if 'pre_2fa_user' not in session:
        return redirect(url_for('auth.login'))
    
    username = session['pre_2fa_user']
    user = User.query.filter_by(username=username).first()
    
    if not user:
        flash('User not found', 'danger')
        return redirect(url_for('auth.login'))
    
    if request.method == 'POST':
        token = request.form.get('token', '').strip()
        
        if not token:
            flash('Please enter the code', 'danger')
            return render_template('verify_2fa.html', username=username)
        
        # Verify the TOTP token
        if user.totp_secret and TOTPManager.verify_token(user.totp_secret, token):
            log_action(username, '2fa_verify', 'success', '2FA verification successful')
            
            # Clear session
            session.pop('pre_2fa_user', None)
            session.pop('pre_2fa_user_id', None)
            
            # Login user
            login_user(user)
            user.last_login = datetime.utcnow()
            db.session.commit()
            
            log_action(username, 'login', 'success', 'User logged in successfully')
            flash('Login successful!', 'success')
            return redirect(url_for('main.dashboard'))
        else:
            log_action(username, '2fa_verify', 'failure', 'Invalid TOTP code')
            flash('Invalid 2FA code. Please try again.', 'danger')
    
    return render_template('verify_2fa.html', username=username)

@auth_bp.route('/logout')
@login_required
def logout():
    """Logout user"""
    log_action(current_user.username, 'logout', 'success', 'User logged out')
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('auth.login'))

# ==================== MAIN ROUTES ====================

@main_bp.route('/')
def index():
    """Redirect to dashboard if logged in, else to login"""
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    return redirect(url_for('auth.login'))

@main_bp.route('/dashboard')
@login_required
def dashboard():
    """Main dashboard"""
    log_action(current_user.username, 'dashboard_access', 'success', 'Accessed dashboard')
    return render_template('dashboard.html', user=current_user)

@main_bp.route('/audit-logs')
@login_required
def audit_logs():
    """View audit logs - Only Admins and Auditors"""
    if current_user.role.name not in ['Admin', 'Auditor']:
        log_action(current_user.username, 'audit_logs_access', 'failure', 'Unauthorized access attempt')
        flash('Access denied. You do not have permission to view audit logs.', 'danger')
        return redirect(url_for('main.dashboard'))
    
    page = request.args.get('page', 1, type=int)
    username_filter = request.args.get('username', '').strip()
    action_filter = request.args.get('action', '').strip()
    
    query = AuditLog.query
    
    if username_filter:
        query = query.filter(AuditLog.username.ilike(f'%{username_filter}%'))
    
    if action_filter:
        query = query.filter(AuditLog.action.ilike(f'%{action_filter}%'))
    
    logs = query.order_by(AuditLog.timestamp.desc()).paginate(page=page, per_page=50)
    log_action(current_user.username, 'audit_logs_view', 'success', f'Viewed audit logs (page {page})')
    
    return render_template('audit_logs.html', logs=logs, username_filter=username_filter, action_filter=action_filter)

@main_bp.route('/users')
@login_required
def users():
    """View all users - Only Admins"""
    if current_user.role.name != 'Admin':
        log_action(current_user.username, 'users_list_access', 'failure', 'Unauthorized access attempt')
        flash('Access denied.', 'danger')
        return redirect(url_for('main.dashboard'))
    
    page = request.args.get('page', 1, type=int)
    users_list = User.query.paginate(page=page, per_page=50)
    log_action(current_user.username, 'users_list_view', 'success', f'Viewed users list (page {page})')
    
    return render_template('users.html', users=users_list)

@main_bp.route('/profile')
@login_required
def profile():
    """User profile page"""
    return render_template('profile.html', user=current_user)

@main_bp.route('/profile/reset-2fa', methods=['POST'])
@login_required
def reset_2fa():
    """Reset 2FA - Allow users to reset their own 2FA"""
    current_user.is_2fa_enabled = False
    current_user.totp_secret = None
    db.session.commit()
    log_action(current_user.username, '2fa_reset', 'success', 'User reset their 2FA')
    flash('2FA has been reset. Please set it up again on your next login.', 'success')
    return redirect(url_for('main.profile'))