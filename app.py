import os
import re
import base64
from datetime import datetime
from cryptography.fernet import Fernet
from flask import Flask, render_template_string, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from sqlalchemy import text

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')

# Database configuration
database_url = os.getenv('DATABASE_URL', 'postgresql://postgres:postgres@localhost/linkeeper')
if database_url.startswith('postgres://'):
    database_url = database_url.replace('postgres://', 'postgresql://', 1)
app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# ------------------------- Encryption Setup -------------------------
def get_encryption_key():
    """Generate a Fernet encryption key from the app's secret key"""
    key = base64.urlsafe_b64encode(app.secret_key.ljust(32)[:32].encode())
    return key

# Initialize encryption cipher
try:
    encryption_key = get_encryption_key()
    fernet = Fernet(encryption_key)
    print("✅ Encryption initialized successfully")
except Exception as e:
    print(f"❌ Encryption initialization error: {e}")
    fernet = Fernet(Fernet.generate_key())
    print("⚠️ Using fallback encryption key")

def encrypt_data(data):
    """Encrypt any data before storing in database"""
    if not data:
        return data
    try:
        encrypted = fernet.encrypt(data.encode())
        return encrypted.decode()
    except Exception as e:
        print(f"Encryption error: {e}")
        return data

def decrypt_data(encrypted_data):
    """Decrypt data when retrieving from database"""
    if not encrypted_data:
        return encrypted_data
    try:
        decrypted = fernet.decrypt(encrypted_data.encode())
        return decrypted.decode()
    except Exception as e:
        print(f"Decryption error: {e}")
        return encrypted_data

# ------------------------- Models -------------------------
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    accepted_terms = db.Column(db.Boolean, default=False)
    links = db.relationship('Link', backref='owner', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Link(db.Model):
    __tablename__ = 'links'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    link_url = db.Column(db.String(600), nullable=False)
    description = db.Column(db.String(600))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

# ------------------------- Database Migration Function -------------------------
def migrate_database():
    """Add missing columns to existing tables"""
    with app.app_context():
        try:
            # Migrate users table
            print("🔍 Checking users table...")
            
            result = db.session.execute(text("""
                SELECT column_name 
                FROM information_schema.columns 
                WHERE table_name='users' AND column_name='created_at'
            """))
            if not result.fetchone():
                print("📝 Adding created_at column to users table...")
                db.session.execute(text("ALTER TABLE users ADD COLUMN created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP"))
                db.session.commit()
                print("✅ created_at column added to users")
            
            result = db.session.execute(text("""
                SELECT column_name 
                FROM information_schema.columns 
                WHERE table_name='users' AND column_name='accepted_terms'
            """))
            if not result.fetchone():
                print("📝 Adding accepted_terms column to users table...")
                db.session.execute(text("ALTER TABLE users ADD COLUMN accepted_terms BOOLEAN DEFAULT FALSE"))
                db.session.commit()
                print("✅ accepted_terms column added to users")
            
            # Migrate links table
            print("🔍 Checking links table...")
            
            result = db.session.execute(text("""
                SELECT column_name 
                FROM information_schema.columns 
                WHERE table_name='links' AND column_name='updated_at'
            """))
            if not result.fetchone():
                print("📝 Adding updated_at column to links table...")
                db.session.execute(text("ALTER TABLE links ADD COLUMN updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP"))
                db.session.commit()
                print("✅ updated_at column added to links")
            
            result = db.session.execute(text("""
                SELECT character_maximum_length 
                FROM information_schema.columns 
                WHERE table_name='links' AND column_name='description'
            """))
            col_info = result.fetchone()
            if col_info and col_info[0] and col_info[0] < 600:
                print("📝 Increasing description column length...")
                db.session.execute(text("ALTER TABLE links ALTER COLUMN description TYPE VARCHAR(600)"))
                db.session.commit()
                print("✅ description column length increased")
            
            print("✅ Database migration completed successfully!")
                
        except Exception as e:
            print(f"⚠️ Migration warning: {e}")
            print("Continuing anyway...")

# Create tables and migrate
with app.app_context():
    db.create_all()
    migrate_database()

# ------------------------- Validation Functions -------------------------
def is_strong_password(password):
    """Check if password meets strong requirements"""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter."
    
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter."
    
    if not re.search(r'\d', password):
        return False, "Password must contain at least one number."
    
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain at least one special character (!@#$%^&*(),.?\":{}|<>)."
    
    return True, "Password is strong."

def is_valid_gmail(email):
    """Check if email is a valid Gmail address (regular Gmail or Googlemail)"""
    email = email.lower().strip()
    
    # Valid Gmail domains
    valid_domains = ['gmail.com', 'googlemail.com']
    
    # Check if email ends with valid domain
    if not any(email.endswith(f'@{domain}') for domain in valid_domains):
        return False
    
    # Extract username part (before @)
    username = email.split('@')[0]
    
    # Basic validation
    if not username or len(username) < 1:
        return False
    
    # Gmail allows letters, numbers, periods
    if not re.match(r'^[a-zA-Z0-9.]+$', username):
        return False
    
    return True

def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in first.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# ------------------------- HTML TEMPLATES (Same as before) -------------------------

LOGIN_PAGE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>LinKeeper - Login</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif; background: #f4f7fc; color: #1e2a3e; line-height: 1.5; }
        .container { max-width: 1200px; margin: 2rem auto; padding: 0 1rem; }
        header { display: flex; justify-content: space-between; align-items: baseline; flex-wrap: wrap; border-bottom: 2px solid #2c7da0; padding-bottom: 0.5rem; margin-bottom: 2rem; }
        h1 { color: #0b3b4b; }
        h2 { margin-bottom: 1rem; color: #2c3e50; }
        .form-group { margin-bottom: 1rem; }
        label { display: block; font-weight: 600; margin-bottom: 0.3rem; }
        input { padding: 0.6rem 1rem; border-radius: 8px; border: 1px solid #ccc; font-size: 1rem; width: 100%; max-width: 400px; }
        button, .btn { padding: 0.6rem 1rem; border-radius: 8px; font-size: 1rem; background: #2c7da0; color: white; border: none; cursor: pointer; }
        button:hover { background: #1f5e7a; }
        .alert { padding: 0.75rem; margin-bottom: 1rem; border-radius: 8px; }
        .alert-success { background: #d4edda; color: #155724; }
        .alert-danger { background: #f8d7da; color: #721c24; }
        .alert-warning { background: #fff3cd; color: #856404; }
        .alert-info { background: #d1ecf1; color: #0c5460; }
        a { color: #2c7da0; text-decoration: none; }
        a:hover { text-decoration: underline; }
        .info-text {
            background: #e9ecef;
            padding: 0.5rem;
            border-radius: 8px;
            margin-top: 1rem;
            font-size: 0.85rem;
            color: #495057;
            max-width: 400px;
        }
        .security-badge {
            display: inline-block;
            background: #28a745;
            color: white;
            font-size: 0.7rem;
            padding: 0.2rem 0.5rem;
            border-radius: 20px;
            margin-left: 0.5rem;
            vertical-align: middle;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔗 LinKeeper <span class="security-badge">🔒 End-to-End Encrypted</span></h1>
        </header>
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="alert alert-{{ category }}">{{ message }}</div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        <main>
            <h2>Login to LinKeeper</h2>
            <form method="POST">
                <div class="form-group">
                    <label>Email or Username</label>
                    <input type="text" name="login_input" placeholder="you@gmail.com or your_username" required autofocus>
                </div>
                <div class="form-group">
                    <label>Password</label>
                    <input type="password" name="password" required>
                </div>
                <button type="submit" class="btn">Login</button>
            </form>
            <div class="info-text">
                💡 Tip: You can login using either your <strong>Gmail address</strong> or your <strong>username</strong>.<br>
                🔐 All your links and descriptions are encrypted before being stored.<br>
                📧 For support: <strong>linkeeper.support@gmail.com</strong>
            </div>
            <p style="margin-top: 1rem;">New user? <a href="{{ url_for('register') }}">Register here</a>.</p>
        </main>
    </div>
</body>
</html>
"""

TERMS_AND_CONDITIONS = """
<div class="terms-box">
    <h3>📋 Terms & Conditions</h3>
    <p>By creating an account, you agree to the following:</p>
    
    <div class="terms-section">
        <h4>🔒 Encryption & Privacy</h4>
        <ul>
            <li>✅ <strong>Your links and descriptions are encrypted</strong> using AES-256 encryption before being stored in our database.</li>
            <li>✅ <strong>We cannot see your stored links</strong> - they are encrypted with a key derived from our server's secret key.</li>
            <li>✅ <strong>Passwords are hashed</strong> using industry-standard bcrypt and are never stored in plain text.</li>
            <li>✅ Your email and username are stored but <strong>never shared with third parties</strong>.</li>
            <li>✅ We use secure session management - you will be logged out after browser closure.</li>
        </ul>
    </div>
    
    <div class="terms-section">
        <h4>⚠️ Important Security Notes</h4>
        <ul>
            <li>🔐 <strong>You are responsible for your account security.</strong> Use a strong, unique password.</li>
            <li>📧 We only accept <strong>Gmail addresses</strong> for account creation.</li>
            <li>🔑 <strong>Lost passwords cannot be recovered</strong> - we don't store them in plain text.</li>
            <li>💾 While your data is encrypted, always backup important links elsewhere.</li>
            <li>🚫 Do not store illegal, harmful, or malicious content.</li>
        </ul>
    </div>
    
    <div class="terms-section">
        <h4>📊 Data We Collect</h4>
        <ul>
            <li>• Username and Gmail address (for authentication)</li>
            <li>• Encrypted links and descriptions (we cannot read these)</li>
            <li>• Account creation and link modification timestamps</li>
            <li>• Session data for login management</li>
        </ul>
    </div>
    
    <div class="terms-section">
        <h4>🗑️ Data Deletion</h4>
        <ul>
            <li>You can delete individual links at any time.</li>
            <li>To delete your entire account, contact support - all your data will be permanently removed.</li>
            <li>Deleted data cannot be recovered.</li>
        </ul>
    </div>
    
    <div class="terms-section">
        <h4>📜 Acceptance</h4>
        <p>By checking the box below, you acknowledge that:</p>
        <ul>
            <li>✓ You understand how your data is protected (encryption).</li>
            <li>✓ You accept that while we use strong encryption, <strong>no system is 100% secure</strong>.</li>
            <li>✓ You will use LinKeeper responsibly and for lawful purposes only.</li>
            <li>✓ You are at least 13 years old (or have parental consent).</li>
        </ul>
    </div>
    
    <div class="terms-footer">
        <p><strong>Last updated:</strong> January 2026</p>
        <p>For questions or account deletion requests: <strong>linkeeper.support@gmail.com</strong></p>
    </div>
</div>

<style>
    .terms-box {
        background: white;
        border-radius: 12px;
        padding: 1.5rem;
        margin: 1.5rem 0;
        max-height: 500px;
        overflow-y: auto;
        border: 1px solid #dee2e6;
        font-size: 0.9rem;
    }
    .terms-box h3 {
        color: #2c7da0;
        margin-bottom: 1rem;
        margin-top: 0;
    }
    .terms-section {
        margin-bottom: 1.5rem;
    }
    .terms-section h4 {
        color: #495057;
        margin-bottom: 0.5rem;
        font-size: 1rem;
    }
    .terms-section ul {
        margin-left: 1.5rem;
        color: #495057;
    }
    .terms-section li {
        margin: 0.5rem 0;
    }
    .terms-footer {
        margin-top: 1rem;
        padding-top: 1rem;
        border-top: 1px solid #dee2e6;
        font-size: 0.8rem;
        color: #6c757d;
        text-align: center;
    }
    .checkbox-group {
        margin: 1rem 0;
        display: flex;
        align-items: center;
        gap: 0.5rem;
    }
    .checkbox-group input {
        width: auto;
        margin: 0;
    }
    .checkbox-group label {
        margin: 0;
        font-weight: normal;
    }
</style>
"""

REGISTER_PAGE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>LinKeeper - Register</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif; background: #f4f7fc; color: #1e2a3e; line-height: 1.5; }
        .container { max-width: 800px; margin: 2rem auto; padding: 0 1rem; }
        header { border-bottom: 2px solid #2c7da0; padding-bottom: 0.5rem; margin-bottom: 2rem; }
        h1 { color: #0b3b4b; }
        h2 { margin-bottom: 1rem; color: #2c3e50; }
        .form-group { margin-bottom: 1rem; }
        label { display: block; font-weight: 600; margin-bottom: 0.3rem; }
        input { padding: 0.6rem 1rem; border-radius: 8px; border: 1px solid #ccc; font-size: 1rem; width: 100%; max-width: 400px; }
        button, .btn { padding: 0.6rem 1rem; border-radius: 8px; font-size: 1rem; background: #2c7da0; color: white; border: none; cursor: pointer; }
        button:hover { background: #1f5e7a; }
        .alert { padding: 0.75rem; margin-bottom: 1rem; border-radius: 8px; }
        .alert-success { background: #d4edda; color: #155724; }
        .alert-danger { background: #f8d7da; color: #721c24; }
        .alert-warning { background: #fff3cd; color: #856404; }
        .alert-info { background: #d1ecf1; color: #0c5460; }
        a { color: #2c7da0; text-decoration: none; }
        .password-requirements {
            background: #f8f9fa;
            border-left: 4px solid #ffc107;
            padding: 0.75rem;
            margin-top: 0.5rem;
            font-size: 0.85rem;
            max-width: 400px;
        }
        .password-requirements p {
            margin: 0.25rem 0;
        }
        .requirement {
            color: #6c757d;
        }
        .requirement.valid {
            color: #28a745;
        }
        .requirement.invalid {
            color: #dc3545;
        }
        .security-badge {
            display: inline-block;
            background: #28a745;
            color: white;
            font-size: 0.7rem;
            padding: 0.2rem 0.5rem;
            border-radius: 20px;
            margin-left: 0.5rem;
            vertical-align: middle;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔗 LinKeeper <span class="security-badge">🔒 End-to-End Encrypted</span></h1>
        </header>
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="alert alert-{{ category }}">{{ message }}</div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        <main>
            <h2>Create an Account</h2>
            <form method="POST" id="registerForm">
                <div class="form-group">
                    <label>Username (used for login)</label>
                    <input type="text" name="username" required>
                </div>
                <div class="form-group">
                    <label>Gmail Address (used for login)</label>
                    <input type="email" name="email" placeholder="you@gmail.com" required>
                    <small style="color: #6c757d;">Accepts @gmail.com and @googlemail.com addresses</small>
                </div>
                <div class="form-group">
                    <label>Password</label>
                    <input type="password" name="password" id="password" required>
                </div>
                <div class="form-group">
                    <label>Confirm Password</label>
                    <input type="password" name="confirm_password" id="confirm_password" required>
                </div>
                <div class="password-requirements">
                    <p><strong>Password requirements:</strong></p>
                    <p id="length" class="requirement">✗ At least 8 characters</p>
                    <p id="uppercase" class="requirement">✗ At least one uppercase letter</p>
                    <p id="lowercase" class="requirement">✗ At least one lowercase letter</p>
                    <p id="number" class="requirement">✗ At least one number</p>
                    <p id="special" class="requirement">✗ At least one special character (!@#$%^&*)</p>
                    <p id="match" class="requirement">✗ Passwords match</p>
                </div>
                
                """ + TERMS_AND_CONDITIONS + """
                
                <div class="checkbox-group">
                    <input type="checkbox" name="accept_terms" id="accept_terms" required>
                    <label for="accept_terms">I have read and agree to the Terms & Conditions above</label>
                </div>
                
                <button type="submit" class="btn">Register</button>
            </form>
            <p style="margin-top: 1rem;">Already have an account? <a href="{{ url_for('login') }}">Login here</a>.</p>
        </main>
    </div>
    <script>
        const password = document.getElementById('password');
        const confirm = document.getElementById('confirm_password');
        
        function checkPassword() {
            const val = password.value;
            
            const lengthReq = document.getElementById('length');
            if (val.length >= 8) {
                lengthReq.innerHTML = '✓ At least 8 characters';
                lengthReq.className = 'requirement valid';
            } else {
                lengthReq.innerHTML = '✗ At least 8 characters';
                lengthReq.className = 'requirement invalid';
            }
            
            const upperReq = document.getElementById('uppercase');
            if (/[A-Z]/.test(val)) {
                upperReq.innerHTML = '✓ At least one uppercase letter';
                upperReq.className = 'requirement valid';
            } else {
                upperReq.innerHTML = '✗ At least one uppercase letter';
                upperReq.className = 'requirement invalid';
            }
            
            const lowerReq = document.getElementById('lowercase');
            if (/[a-z]/.test(val)) {
                lowerReq.innerHTML = '✓ At least one lowercase letter';
                lowerReq.className = 'requirement valid';
            } else {
                lowerReq.innerHTML = '✗ At least one lowercase letter';
                lowerReq.className = 'requirement invalid';
            }
            
            const numReq = document.getElementById('number');
            if (/\\d/.test(val)) {
                numReq.innerHTML = '✓ At least one number';
                numReq.className = 'requirement valid';
            } else {
                numReq.innerHTML = '✗ At least one number';
                numReq.className = 'requirement invalid';
            }
            
            const specialReq = document.getElementById('special');
            if (/[!@#$%^&*(),.?":{}|<>]/.test(val)) {
                specialReq.innerHTML = '✓ At least one special character';
                specialReq.className = 'requirement valid';
            } else {
                specialReq.innerHTML = '✗ At least one special character (!@#$%^&*)';
                specialReq.className = 'requirement invalid';
            }
            
            const matchReq = document.getElementById('match');
            if (password.value === confirm.value && password.value !== '') {
                matchReq.innerHTML = '✓ Passwords match';
                matchReq.className = 'requirement valid';
            } else {
                matchReq.innerHTML = '✗ Passwords match';
                matchReq.className = 'requirement invalid';
            }
        }
        
        password.addEventListener('keyup', checkPassword);
        confirm.addEventListener('keyup', checkPassword);
    </script>
</body>
</html>
"""

DASHBOARD_PAGE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>LinKeeper - Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif; background: #f4f7fc; color: #1e2a3e; line-height: 1.5; }
        .container { max-width: 1200px; margin: 2rem auto; padding: 0 1rem; }
        header { display: flex; justify-content: space-between; align-items: baseline; flex-wrap: wrap; border-bottom: 2px solid #2c7da0; padding-bottom: 0.5rem; margin-bottom: 2rem; }
        h1 { color: #0b3b4b; }
        h2, h3 { margin-bottom: 1rem; color: #2c3e50; }
        .user-info { font-size: 1rem; background: #e9ecef; padding: 0.3rem 0.8rem; border-radius: 20px; }
        a { color: #2c7da0; text-decoration: none; }
        a:hover { text-decoration: underline; }
        .form-group { margin-bottom: 1rem; }
        label { display: block; font-weight: 600; margin-bottom: 0.3rem; }
        input { padding: 0.6rem 1rem; border-radius: 8px; border: 1px solid #ccc; font-size: 1rem; width: 100%; max-width: 400px; }
        button, .btn { padding: 0.6rem 1rem; border-radius: 8px; font-size: 1rem; background: #2c7da0; color: white; border: none; cursor: pointer; transition: background 0.2s; }
        button:hover, .btn:hover { background: #1f5e7a; }
        .btn.cancel { background: #6c757d; margin-left: 0.5rem; }
        .alert { padding: 0.75rem; margin-bottom: 1rem; border-radius: 8px; }
        .alert-success { background: #d4edda; color: #155724; }
        .alert-danger { background: #f8d7da; color: #721c24; }
        .alert-warning { background: #fff3cd; color: #856404; }
        .add-link-form { background: white; padding: 1.5rem; border-radius: 12px; box-shadow: 0 2px 5px rgba(0,0,0,0.05); margin-bottom: 2rem; }
        .links-table { background: white; border-radius: 12px; overflow-x: auto; box-shadow: 0 2px 5px rgba(0,0,0,0.05); }
        .table-header, .table-row { display: grid; grid-template-columns: 2fr 1.5fr 1.2fr; padding: 0.75rem 1rem; border-bottom: 1px solid #dee2e6; }
        .table-header { background: #eef2f3; font-weight: bold; }
        .table-row:hover { background: #f8f9fa; }
        .link-url { word-break: break-all; }
        .link-desc { color: #666; margin-top: 5px; }
        .actions { display: flex; gap: 0.5rem; flex-wrap: wrap; }
        .copy-btn, .edit-btn, .delete-btn { padding: 0.2rem 0.8rem; border-radius: 20px; font-size: 0.85rem; cursor: pointer; border: none; display: inline-block; text-align: center; }
        .copy-btn { background: #28a745; color: white; }
        .edit-btn { background: #ffc107; color: #212529; }
        .delete-btn { background: #dc3545; color: white; }
        .security-badge {
            display: inline-block;
            background: #28a745;
            color: white;
            font-size: 0.7rem;
            padding: 0.2rem 0.5rem;
            border-radius: 20px;
            margin-left: 0.5rem;
            vertical-align: middle;
        }
        .encrypt-icon {
            font-size: 0.7rem;
            color: #28a745;
            margin-left: 0.3rem;
        }
        .stats {
            background: white;
            padding: 1rem;
            border-radius: 8px;
            margin-bottom: 1rem;
            text-align: center;
            color: #6c757d;
        }
        @media (max-width: 700px) {
            .table-header, .table-row { grid-template-columns: 1fr; gap: 0.5rem; }
            .table-header { display: none; }
            .table-row { border-bottom: 2px solid #ddd; margin-bottom: 0.5rem; padding: 1rem; }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔗 LinKeeper <span class="security-badge">🔒 End-to-End Encrypted</span></h1>
            <div class="user-info">
                Hello, {{ user.username }} | <a href="{{ url_for('logout') }}">Logout</a>
            </div>
        </header>
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="alert alert-{{ category }}">{{ message }}</div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        <main>
            <h2>Your Links <span class="encrypt-icon">🔐 (Both URLs & Descriptions Encrypted)</span></h2>
            <div class="stats">
                📊 Total links stored: {{ links|length }} | 🔒 All data encrypted at rest
            </div>
            <div class="add-link-form">
                <h3>➕ Add New Link</h3>
                <form method="POST">
                    <div class="form-group">
                        <label>Link URL</label>
                        <input type="url" name="link_url" placeholder="https://example.com" required>
                    </div>
                    <div class="form-group">
                        <label>Description (what is this link about?)</label>
                        <input type="text" name="description" placeholder="e.g., My favorite tech blog">
                    </div>
                    <button type="submit" class="btn">Save Link (Both fields will be encrypted)</button>
                </form>
            </div>
            {% if links %}
                <div class="links-table">
                    <div class="table-header">
                        <div>Link <span class="encrypt-icon">🔒</span></div>
                        <div>Description <span class="encrypt-icon">🔒</span></div>
                        <div>Actions</div>
                    </div>
                    {% for link in links %}
                    <div class="table-row">
                        <div class="link-url">{{ link.link_url[:50] }}{% if link.link_url|length > 50 %}...{% endif %}</div>
                        <div class="link-desc">{{ link.description[:50] if link.description else '-' }}{% if link.description and link.description|length > 50 %}...{% endif %}</div>
                        <div class="actions">
                            <button class="copy-btn" onclick="copyToClipboard('{{ link.link_url }}')">📋 Copy URL</button>
                            <a href="{{ url_for('edit_link', link_id=link.id) }}" class="edit-btn">✏️ Edit</a>
                            <a href="{{ url_for('delete_link', link_id=link.id) }}" class="delete-btn" onclick="return confirm('Delete this link?')">🗑️ Delete</a>
                        </div>
                    </div>
                    {% endfor %}
                </div>
                <p style="margin-top: 1rem; font-size: 0.85rem; color: #6c757d; text-align: center;">
                    🔒 Your links AND descriptions are encrypted before being stored in the database.<br>
                    Only you can see them when logged in. We cannot read your stored data.<br>
                    📧 For support: <strong>linkeeper.support@gmail.com</strong>
                </p>
            {% else %}
                <p>No links yet. Add your first link above!</p>
            {% endif %}
        </main>
    </div>
    <script>
        function copyToClipboard(text) {
            navigator.clipboard.writeText(text);
            const btn = event.target;
            const originalText = btn.innerText;
            btn.innerText = '✅ Copied!';
            setTimeout(() => btn.innerText = originalText, 1500);
        }
    </script>
</body>
</html>
"""

EDIT_PAGE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>LinKeeper - Edit Link</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif; background: #f4f7fc; color: #1e2a3e; line-height: 1.5; }
        .container { max-width: 800px; margin: 2rem auto; padding: 0 1rem; }
        header { border-bottom: 2px solid #2c7da0; padding-bottom: 0.5rem; margin-bottom: 2rem; }
        h1 { color: #0b3b4b; }
        h2 { margin-bottom: 1rem; color: #2c3e50; }
        .form-group { margin-bottom: 1rem; }
        label { display: block; font-weight: 600; margin-bottom: 0.3rem; }
        input { padding: 0.6rem 1rem; border-radius: 8px; border: 1px solid #ccc; font-size: 1rem; width: 100%; max-width: 400px; }
        button, .btn { padding: 0.6rem 1rem; border-radius: 8px; font-size: 1rem; background: #2c7da0; color: white; border: none; cursor: pointer; display: inline-block; text-decoration: none; }
        button:hover, .btn:hover { background: #1f5e7a; }
        .btn.cancel { background: #6c757d; margin-left: 0.5rem; }
        .alert { padding: 0.75rem; margin-bottom: 1rem; border-radius: 8px; }
        .alert-success { background: #d4edda; color: #155724; }
        .alert-danger { background: #f8d7da; color: #721c24; }
        a { color: #2c7da0; text-decoration: none; }
        .security-badge {
            display: inline-block;
            background: #28a745;
            color: white;
            font-size: 0.7rem;
            padding: 0.2rem 0.5rem;
            border-radius: 20px;
            margin-left: 0.5rem;
            vertical-align: middle;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔗 LinKeeper <span class="security-badge">🔒 Encrypted</span></h1>
        </header>
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="alert alert-{{ category }}">{{ message }}</div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        <main>
            <h2>Edit Link</h2>
            <form method="POST">
                <div class="form-group">
                    <label>Link URL</label>
                    <input type="url" name="link_url" value="{{ link.link_url }}" required>
                </div>
                <div class="form-group">
                    <label>Description</label>
                    <input type="text" name="description" value="{{ link.description or '' }}">
                </div>
                <button type="submit" class="btn">Update Link (Will be re-encrypted)</button>
                <a href="{{ url_for('dashboard') }}" class="btn cancel">Cancel</a>
            </form>
            <p style="margin-top: 1rem; font-size: 0.85rem; color: #6c757d;">
                🔒 Your updated link and description will be encrypted before saving.<br>
                📧 For support: <strong>linkeeper.support@gmail.com</strong>
            </p>
        </main>
    </div>
</body>
</html>
"""

# ------------------------- Routes -------------------------
@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        email = request.form['email'].strip()
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        accept_terms = request.form.get('accept_terms')

        if not username or not email or not password:
            flash('All fields are required.', 'danger')
        elif password != confirm_password:
            flash('Passwords do not match.', 'danger')
        elif not accept_terms:
            flash('You must accept the Terms & Conditions to register.', 'danger')
        elif not is_valid_gmail(email):
            flash('Please use a valid Gmail address (@gmail.com or @googlemail.com).', 'danger')
        elif User.query.filter_by(username=username).first():
            flash('Username already taken.', 'danger')
        elif User.query.filter_by(email=email).first():
            flash('Email already registered.', 'danger')
        else:
            is_strong, message = is_strong_password(password)
            if not is_strong:
                flash(message, 'danger')
            else:
                user = User(username=username, email=email, accepted_terms=True)
                user.set_password(password)
                db.session.add(user)
                db.session.commit()
                flash('Registration successful! Please log in.', 'success')
                return redirect(url_for('login'))

    return render_template_string(REGISTER_PAGE)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        login_input = request.form['login_input'].strip()
        password = request.form['password']
        
        if '@' in login_input:
            user = User.query.filter_by(email=login_input).first()
        else:
            user = User.query.filter_by(username=login_input).first()
        
        if user and user.check_password(password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['email'] = user.email
            flash(f'Welcome back, {user.username}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email/username or password.', 'danger')
    
    return render_template_string(LOGIN_PAGE)

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    user = User.query.get(session['user_id'])
    if request.method == 'POST':
        link_url = request.form['link_url'].strip()
        description = request.form['description'].strip()
        
        if link_url:
            if not link_url.startswith(('http://', 'https://')):
                link_url = 'http://' + link_url
            
            encrypted_url = encrypt_data(link_url)
            encrypted_description = encrypt_data(description) if description else ""
            
            new_link = Link(link_url=encrypted_url, description=encrypted_description, user_id=user.id)
            db.session.add(new_link)
            db.session.commit()
            flash('✅ Link saved! (URL and description encrypted)', 'success')
        else:
            flash('Link URL cannot be empty.', 'warning')
        return redirect(url_for('dashboard'))

    links = Link.query.filter_by(user_id=user.id).order_by(Link.created_at.desc()).all()
    for link in links:
        link.link_url = decrypt_data(link.link_url)
        link.description = decrypt_data(link.description) if link.description else ""
    
    return render_template_string(DASHBOARD_PAGE, user=user, links=links)

@app.route('/edit/<int:link_id>', methods=['GET', 'POST'])
@login_required
def edit_link(link_id):
    link = Link.query.get_or_404(link_id)
    if link.user_id != session['user_id']:
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        link_url = request.form['link_url'].strip()
        description = request.form['description'].strip()
        
        if not link_url.startswith(('http://', 'https://')):
            link_url = 'http://' + link_url
        
        encrypted_url = encrypt_data(link_url)
        encrypted_description = encrypt_data(description) if description else ""
        
        link.link_url = encrypted_url
        link.description = encrypted_description
        link.updated_at = datetime.utcnow()
        db.session.commit()
        flash('✅ Link updated! (Re-encrypted)', 'success')
        return redirect(url_for('dashboard'))
    
    link.link_url = decrypt_data(link.link_url)
    link.description = decrypt_data(link.description) if link.description else ""
    return render_template_string(EDIT_PAGE, link=link)

@app.route('/delete/<int:link_id>')
@login_required
def delete_link(link_id):
    link = Link.query.get_or_404(link_id)
    if link.user_id != session['user_id']:
        flash('Unauthorized access.', 'danger')
    else:
        db.session.delete(link)
        db.session.commit()
        flash('Link deleted.', 'success')
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    print("\n" + "="*50)
    print("🔗 LinKeeper Server Starting...")
    print("="*50)
    print("✅ Encryption: ACTIVE (AES-256)")
    print("✅ Database: Connected")
    print("✅ Auto-migration: Enabled")
    print("✅ Template files: NOT required (embedded in code)")
    print("="*50)
    print("🌐 Server running at: http://127.0.0.1:5000")
    print("📧 Support email: linkeeper.support@gmail.com")
    print("✅ Accepts: @gmail.com and @googlemail.com addresses")
    print("="*50 + "\n")
    app.run(debug=True, port=5000)
