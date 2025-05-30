from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from flask_login import LoginManager, login_user, login_required, logout_user, UserMixin, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from random import randint
from urllib.parse import quote
from dotenv import load_dotenv
import os



app = Flask(__name__)

# Configuration
load_dotenv() 
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///lost_found.db'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')  # Use App Password if using Gmail

# Extensions
db = SQLAlchemy(app)
mail = Mail(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    role = db.Column(db.String(50), nullable=False, default='user')
    otp = db.Column(db.String(6))  
    otp_expiration = db.Column(db.DateTime)  
    items = db.relationship('Item', back_populates='user', lazy=True)
    profile = db.relationship('Profile', back_populates='user', uselist=False, lazy=True)
    full_name = db.Column(db.String(100), nullable=False)

class Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    name = db.Column(db.String(100))
    category = db.Column(db.String(50))   
    date = db.Column(db.String(50))
    description = db.Column(db.Text)
    location = db.Column(db.String(100))
    image = db.Column(db.String(100))
    status = db.Column(db.String(20)) 

    user = db.relationship('User', back_populates='items')

class Profile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    full_name = db.Column(db.String(100))
    phone = db.Column(db.String(20))

    user = db.relationship('User', back_populates='profile', lazy=True)
   



# Login manager setup
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# Routes
@app.route('/')
def index():
    return render_template('index.html')

 

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        full_name = request.form.get('name')
        phone = request.form.get('phone')

        # Check if the fields are filled out
        if not email or not password or not full_name or not phone:
            flash('Please fill out all fields.', 'danger')
            return redirect(url_for('register'))

        # Check if the email already exists
        if User.query.filter_by(email=email).first():
            flash('Email already registered.', 'danger')
            return redirect(url_for('register'))

        
        new_user = User(email=email, password=password, full_name=full_name)


        db.session.add(new_user)    # session me add karo
        db.session.commit()         # changes save karo database me

        flash('Registration successful! Please sign in.', 'success')
        return redirect(url_for('login'))   # sign-in page pe bhejo

    return render_template('register.html')


# OTP Email sender function
def send_otp_email(email, otp):
    msg = Message('OTP Verification - Lost and Found', sender=app.config['MAIL_USERNAME'], recipients=[email])
    msg.body = f'Your OTP is: {otp}. It expires in 5 minutes.'
    mail.send(msg)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('profile'))  # Redirect to dashboard after login

        flash('Invalid credentials.', 'danger')

    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    items = Item.query.filter_by(user_id=current_user.id).all()
    return render_template('dashboard.html', items=items)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

# Verify OTP route


# Forgot Password route
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        if user:
            otp = str(randint(100000, 999999))
            user.otp = otp
            user.otp_expiration = datetime.utcnow() + timedelta(minutes=5)
            db.session.commit()
            send_otp_email(user.email, otp)
            flash('OTP sent to your email.', 'info')
            return redirect(url_for('reset_password_verify', email=email))
        else:
            flash('Email not found.', 'danger')
    return render_template('forgot_password.html')

@app.route('/reset_password_verify/<email>', methods=['GET', 'POST'])
def reset_password_verify(email):
    user = User.query.filter_by(email=email).first()

    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        entered_otp = request.form.get('otp')

        if user.otp == entered_otp and datetime.utcnow() <= user.otp_expiration:
            user.otp = None  # Clear OTP after verification
            user.otp_expiration = None
            db.session.commit()

            flash('OTP verified successfully. You can now reset your password.', 'success')
            return redirect(url_for('reset_password', email=email))
        else:
            flash('Invalid or expired OTP.', 'danger')

    return render_template('reset_password_verify.html', email=email)

@app.route('/reset_password/<email>', methods=['GET', 'POST'])
def reset_password(email):
    user = User.query.filter_by(email=email).first()

    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('reset_password.html', email=email)

        user.password = generate_password_hash(password)
        db.session.commit()

        flash('Password has been reset successfully.', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password.html', email=email)

@app.route('/report_lost', methods=['GET', 'POST'])
@login_required
def report_lost():
    if request.method == 'POST':
        item = Item(
            user_id=current_user.id,
            name=request.form.get('name'),
            category=request.form.get('category'),
            date=request.form.get('date'),
            description=request.form.get('description'),
            location=request.form.get('location'),
            image=request.form.get('image', ''),  # Placeholder
            status='lost'
        )
        db.session.add(item)
        db.session.commit()

        # ✅ Send email notification to all users
        notify_all_users_about_lost_item(item)

        flash('Lost item reported successfully')
        return redirect(url_for('profile'))
    return render_template('report_lost.html')


@app.route('/report_found', methods=['GET', 'POST'])
@login_required
def report_found():
    if request.method == 'POST':
        item = Item(
            user_id=current_user.id,
            name=request.form.get('name'),
            category=request.form.get('category'),
            date=request.form.get('date'),
            description=request.form.get('description'),
            location=request.form.get('location'),
            image=request.form.get('image', ''),  # Placeholder for image
            status='found'
        )
        db.session.add(item)
        db.session.commit()
        flash('Found item reported successfully.')
        return redirect(url_for('dashboard'))
    return render_template('report_found.html')

@app.route('/lost_items')
def lost_items():
    items = Item.query.filter_by(status='lost').all()
    return render_template('lost_items.html', items=items)

@app.route('/found_items')
def found_items():
    items = Item.query.filter(Item.status.in_(['found', 'resolved'])).all()
    return render_template('found_items.html', items=items)

@app.route('/admin')
@login_required
def admin_portal():
    if not current_user.is_admin:
        flash('Access denied.')
        return redirect(url_for('dashboard'))
    all_items = Item.query.all()
    return render_template('admin.html', items=all_items)

@app.route('/admin/delete/<int:item_id>', methods=['POST'])
@login_required
def delete_item(item_id):
    if not current_user.is_admin:
        flash("Access denied. Admins only!", "danger")
        return redirect(url_for('dashboard'))

    item = Item.query.get_or_404(item_id)
    db.session.delete(item)
    db.session.commit()
    flash('Item deleted.', 'danger')
    
    return redirect(url_for('admin_portal'))

@app.route('/admin/resolve/<int:item_id>', methods=['POST'])
@login_required
def mark_resolved(item_id):
    if not current_user.is_admin:
        flash('Access denied.')
        return redirect(url_for('dashboard'))

    item = Item.query.get_or_404(item_id)
    item.status = 'resolved'
    db.session.commit()

    user = User.query.get(item.user_id)

    if user:
        try:
            send_notification_email(user.email, item)
            flash('Item marked as resolved. Notification email sent to the user.')
        except Exception as e:
            flash(f'Item marked as resolved but failed to send email: {str(e)}')
    else:
        flash('Item marked as resolved, but user not found.')

    return redirect(url_for('admin_portal'))
# Email sender function
def send_notification_email(user_email, item):
    msg = Message(
        'Your Lost Item Has Been Found!',
        sender=app.config['MAIL_USERNAME'],
        recipients=[user_email]
    )
    msg.body = f"""
Hello,

We're happy to inform you that your lost item '{item.name}' has been found and marked as resolved.

Details:
- Item: {item.name}
- Category: {item.category}
- Description: {item.description}
- Location: {item.location}

Thank you for using our Lost and Found system.

Best regards,
Lost & Found Team
    """
    mail.send(msg)
def notify_all_users_about_lost_item(item):
    all_users = User.query.all()
    for user in all_users:
      
            msg = Message(
                subject="New Lost Item Reported",
                sender=app.config['MAIL_USERNAME'],
                recipients=[user.email])
            msg.body = f"""
Hello,

A new lost item has been reported:

- Item: {item.name}
- Description: {item.description}
- Location: {item.location}
- Date: {item.date}

If you have any information, please help by reporting it via the system.

Regards,  
Lost & Found Team
            """
            try:
                mail.send(msg)
            except Exception as e:
                print(f"❌ Failed to send email to {user.email}: {e}")



def create_admin():
    admin_email = 'founditem64@gmail.com'  # Updated admin email
    admin_password = 'admin123'                
    admin_full_name = 'Admin User'             # Add full name for the admin

    existing_admin = User.query.filter_by(email=admin_email).first()
    if not existing_admin:
        hashed_password = generate_password_hash(admin_password)
        admin_user = User(
            email=admin_email,
            password=hashed_password,
            is_admin=True,
            full_name=admin_full_name,  # Add full name field
            role='user'  # Make sure role is set
        )
        db.session.add(admin_user)
        db.session.commit()
        print("✅ Admin user created.")
    else:
        if not existing_admin.is_admin:
            existing_admin.is_admin = True
        existing_admin.password = generate_password_hash(admin_password)  # Optional reset
        existing_admin.full_name = admin_full_name  # Ensure full name is updated
        db.session.commit()
        print("✅ Admin user updated.")

@app.route('/verify_otp/<email>', methods=['GET', 'POST'])
def verify_otp(email):
    email = quote(email)
    user = User.query.filter_by(email=email).first()

    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('register'))

    if request.method == 'POST':
        entered_otp = request.form.get('otp')

        if user.otp == entered_otp and datetime.utcnow() <= user.otp_expiration:
            user.otp = None  # Clear OTP after verification
            user.otp_expiration = None
            db.session.commit()

            login_user(user)
            flash('OTP verified successfully. You are now logged in.', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid or expired OTP.', 'danger')

    return render_template('verify_otp.html', email=email)

@app.route('/profile')
@login_required
def profile():
    # Fetch user profile from the database
    user = current_user
    profile = user.profile  # Fetch the profile associated with the current user
    
    # If the user doesn't have a profile, create one with default values
    if not profile:
        profile = Profile(user_id=current_user.id, phone='')
        db.session.add(profile)
        db.session.commit()
    
    # Fetch items reported by the user
    user_items = Item.query.filter_by(user_id=current_user.id).all()

    return render_template('profile.html', profile=profile, items=user_items)

 



# Run the app
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
