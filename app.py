import os
from flask import Flask, render_template, redirect, url_for, flash, session, request
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
# Ensure all validators are here, especially Regexp if you added it earlier
from wtforms.validators import DataRequired, Email, EqualTo, ValidationError, Length, Regexp
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer # <<< ADD THIS IMPORT

# --- App Configuration ---
app = Flask(__name__)

# IMPORTANT: Use a strong, consistent SECRET_KEY. For production, use environment variables.
# This key MUST MATCH the one you will use in your Streamlit app.
# Example: FLASK_APP_SECRET_KEY = os.environ.get('FLASK_APP_SECRET_KEY')
# if not FLASK_APP_SECRET_KEY:
#     FLASK_APP_SECRET_KEY = 'a_very_strong_random_secret_key_32_bytes_or_more' # Fallback for dev
#     print("WARNING: Using fallback SECRET_KEY. Set FLASK_APP_SECRET_KEY environment variable for production.")
# app.config['SECRET_KEY'] = FLASK_APP_SECRET_KEY
# For simplicity in this step-by-step, we'll keep your existing one, but be mindful for later.
app.config['SECRET_KEY'] = 'a_very_secret_key_for_development_CHANGE_ME_LATER' # <<< ENSURE THIS IS NOTED FOR STREAMLIT

basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'users.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Define your Streamlit app's URL (adjust port if necessary)
STREAMLIT_APP_URL = "https://hpfn-nlp-phase5-app-hyoek7fmq2eqmczpuzcpaf.streamlit.app"

# Initialize Extensions
db = SQLAlchemy(app)

# --- Database Model (User class - should be unchanged) ---
class User(db.Model):
    # ... (your existing User model code) ...
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username}>'


# --- Forms (RegistrationForm, LoginForm - should be unchanged) ---
class RegistrationForm(FlaskForm):
    # ... (your existing RegistrationForm code) ...
    username = StringField('Username',
                           validators=[
                               DataRequired(message="Username is required."),
                               Length(min=3, max=25, message="Username must be between 3 and 25 characters."),
                               Regexp('^[A-Za-z][A-Za-z0-9_.-]*$', 0,
                                      'Username must start with a letter and '
                                      'contain only letters, numbers, underscores (_), periods (.), or hyphens (-). '
                                      'No spaces allowed.')
                           ])
    email = StringField('Email',
                        validators=[DataRequired(), Email(message="Invalid email address.")])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField(
        'Confirm Password', validators=[DataRequired(), EqualTo('password', message='Passwords must match.')]
    )
    submit = SubmitField('Register')

    def validate_username(self, username_field):
        user = User.query.filter_by(username=username_field.data).first()
        if user:
            raise ValidationError('Username already taken. Please choose a different one.')

    def validate_email(self, email_field):
        user = User.query.filter_by(email=email_field.data).first()
        if user:
            raise ValidationError('Email address already registered. Please choose a different one.')

class LoginForm(FlaskForm):
    # ... (your existing LoginForm code) ...
    email = StringField('Email', validators=[DataRequired(), Email(message="Invalid email address.")])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


# --- Routes ---
@app.route('/')
def index():
    # If user is already logged in (has Flask session), maybe redirect them to Streamlit directly?
    # Or let them see the Flask home page, which then has links to login (which redirects to Streamlit)
    # For now, keeping it simple:
    return render_template('index.html', title='Home')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session: # Check Flask session
        # If already logged into Flask, consider redirecting them to Streamlit with a token
        # For simplicity, we can just flash a message and redirect to Flask login,
        # which will then handle the Streamlit redirect.
        flash('You are already logged in. Redirecting to NLP Tool login.', 'info')
        return redirect(url_for('login')) # Login route will handle Streamlit token generation

    form = RegistrationForm()
    if form.validate_on_submit():
        # ... (your existing registration logic for creating user) ...
        username = form.username.data
        email = form.email.data
        password = form.password.data
        new_user = User(username=username, email=email)
        new_user.set_password(password)
        try:
            db.session.add(new_user)
            db.session.commit()
            flash(f'Account created for {username}! You can now log in.', 'success')
            return redirect(url_for('login')) # Good, redirects to login to get token
        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred during registration: {str(e)}', 'danger')
            app.logger.error(f"Error during registration for user {username}: {e}", exc_info=True)
    return render_template('register.html', title='Register', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session: # Check Flask session
        # If already logged into Flask, generate a new token and redirect to Streamlit
        s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
        token_data = {'user_id': session['user_id'], 'username': session.get('username', 'User')}
        streamlit_token = s.dumps(token_data)
        # flash(f'Already logged in. Redirecting to the NLP tool...', 'info') # Optional
        return redirect(f"{STREAMLIT_APP_URL}/?token={streamlit_token}")

    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            # Set Flask session
            session['user_id'] = user.id
            session['username'] = user.username
            
            # Generate a timed token for Streamlit
            s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
            token_data = {'user_id': user.id, 'username': user.username}
            streamlit_token = s.dumps(token_data)
            
            flash(f'Welcome back, {user.username}! Redirecting to the NLP tool.', 'success')
            
            # Redirect to Streamlit app with the token
            return redirect(f"{STREAMLIT_APP_URL}/?token={streamlit_token}")
        else:
            flash('Login unsuccessful. Please check your email and password.', 'danger')
    return render_template('login.html', title='Login', form=form)

@app.route('/dashboard') # This Flask dashboard route is now primarily a launcher to Streamlit
def dashboard():
    if 'user_id' not in session: # Check Flask session
        flash('Please log in to access the NLP tool.', 'warning')
        # If they tried to access Flask dashboard directly, 'next' might not be set for Streamlit.
        # So, we send them to login, which will then generate a Streamlit token.
        return redirect(url_for('login')) # Redirect to login to get a Streamlit token

    # User is logged into Flask, generate token and redirect to Streamlit
    s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    token_data = {'user_id': session['user_id'], 'username': session.get('username', 'User')}
    streamlit_token = s.dumps(token_data)
    # flash('Redirecting to the NLP tool...', 'info') # Optional
    return redirect(f"{STREAMLIT_APP_URL}/?token={streamlit_token}")

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    flash('You have been successfully logged out.', 'success')
    return redirect(url_for('index')) # Or url_for('login')

# --- Utility: Create Database Tables (should be unchanged) ---
def create_tables_command():
    # ... (your existing create_tables_command function) ...
    with app.app_context():
        print("Attempting to create database tables...")
        db.create_all()
        print("Database tables creation process completed.")

# --- Main Execution (should be unchanged) ---
if __name__ == '__main__':
    # ... (your existing main execution block) ...
    db_file = os.path.join(basedir, 'users.db')
    if not os.path.exists(db_file):
        print(f"Database file '{db_file}' not found. Creating tables...")
        create_tables_command()
        print(f"Database file '{db_file}' should now exist.")
    else:
        print(f"Database file '{db_file}' already exists.")
    app.run(debug=True)