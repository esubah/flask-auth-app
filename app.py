import os
from flask import Flask, render_template, redirect, url_for, flash, session, request
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo, ValidationError
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms.validators import DataRequired, Email, EqualTo, ValidationError, Length, Regexp # Add Regexp

# --- App Configuration ---
app = Flask(__name__)

# Secret Key: Essential for session management and WTForms CSRF protection
# In production, use a strong, randomly generated key stored securely (e.g., environment variable)
# For now, we'll use a simple development key.
app.config['SECRET_KEY'] = 'a_very_secret_key_for_development_CHANGE_ME_LATER'

# Database Configuration (SQLite for simplicity)
# In production, use PostgreSQL, MySQL, etc.
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'users.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False # Disable modification tracking to save resources

# Initialize Extensions
db = SQLAlchemy(app)

# --- Database Model ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False) # Store hashed password

    def set_password(self, password):
        """Hashes the password and stores it."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Checks if the provided password matches the stored hash."""
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        """String representation of the User object, useful for debugging."""
        return f'<User {self.username}>'

# --- Forms (using Flask-WTF) ---

class RegistrationForm(FlaskForm):
    username = StringField('Username',
                           validators=[
                               DataRequired(message="Username is required."),
                               Length(min=3, max=25, message="Username must be between 3 and 25 characters."),
                               Regexp('^[A-Za-z][A-Za-z0-9_.-]*$', 0, # Corrected Regexp
                                      'Username must start with a letter and '
                                      'contain only letters, numbers, underscores (_), periods (.), or hyphens (-). '
                                      'No spaces allowed.')
                           ])
    email = StringField('Email',
                        validators=[DataRequired(), Email(message="Invalid email address.")])
    password = PasswordField('Password',
                             validators=[DataRequired(),
                                         # You could add a Length validator for password strength
                                        ])
    confirm_password = PasswordField(
        'Confirm Password',
        validators=[DataRequired(),
                    EqualTo('password', message='Passwords must match.')]
    )
    submit = SubmitField('Register')

    # Custom validator to ensure username isn't already taken
    def validate_username(self, username_field): # The parameter name must match the field name
        user = User.query.filter_by(username=username_field.data).first()
        if user:
            raise ValidationError('Username already taken. Please choose a different one.')

    # Custom validator to ensure email isn't already registered
    def validate_email(self, email_field): # The parameter name must match the field name
        user = User.query.filter_by(email=email_field.data).first()
        if user:
            raise ValidationError('Email address already registered. Please choose a different one.')

class LoginForm(FlaskForm):
    email = StringField('Email',
                        validators=[DataRequired(), Email(message="Invalid email address.")])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

# --- Routes ---

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Handles user registration."""
    # Prevent logged-in users from accessing the register page (we'll add session check later)
    # if 'user_id' in session:
    #     flash('You are already logged in and cannot register again.', 'info')
    #     return redirect(url_for('dashboard')) # Or 'index'

    form = RegistrationForm() # Create an instance of our registration form

    if form.validate_on_submit():
        # This block executes if the form was submitted (POST request) AND passed all validations
        # (both built-in WTForms validators and our custom validate_username/validate_email)

        # Get data from the validated form
        username = form.username.data
        email = form.email.data
        password = form.password.data # Plain text password from the form

        # Create a new User instance
        new_user = User(username=username, email=email)
        new_user.set_password(password) # Hash the password using our model's method

        try:
            # Add the new user to the database session
            db.session.add(new_user)
            # Commit the session to save the user to the database
            db.session.commit()

            flash(f'Account created for {username}! You can now log in.', 'success')
            return redirect(url_for('login')) # Redirect to login page after successful registration
                                              # We'll create the 'login' route next.
        except Exception as e:
            db.session.rollback() # Rollback the session in case of an error during commit
            flash(f'An error occurred during registration: {str(e)}', 'danger')
            # It's good to log the actual exception for server-side debugging
            app.logger.error(f"Error during registration for user {username}: {e}", exc_info=True)


    # If it's a GET request (user just navigated to /register)
    # OR if form validation failed (form.validate_on_submit() was false)
    # re-render the registration page.
    # If validation failed, form.errors will be populated and displayed by the template.
    return render_template('register.html', title='Register', form=form)


@app.route('/')
def index():
    """Home page."""
    return render_template('index.html', title='Home') # Pass a title variable

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handles user login."""
    # Prevent logged-in users from accessing the login page again
    if 'user_id' in session: # We'll implement session management soon
        flash('You are already logged in.', 'info')
        return redirect(url_for('dashboard')) # We'll create dashboard route later

    form = LoginForm() # Create an instance of our login form

    if form.validate_on_submit():
        # Form was submitted and basic validation (e.g., fields not empty, email format) passed
        email = form.email.data
        password = form.password.data

        # Find the user by email in the database
        user = User.query.filter_by(email=email).first()

        # Check if user exists and the password is correct
        if user and user.check_password(password):
            # Login successful!
            # Store user's ID in the session to mark them as logged in
            session['user_id'] = user.id
            session['username'] = user.username # Optional: store username for easy display

            flash(f'Welcome back, {user.username}! You have been successfully logged in.', 'success')

            # Redirect to a 'next' page if it was provided (e.g., user tried to access a protected page)
            # Otherwise, redirect to a default page (e.g., dashboard)
            next_page = request.args.get('next')
            if next_page:
                # Basic security check: ensure next_page is a relative path within our app
                # A more robust check would involve urlparse and checking netloc
                if next_page.startswith('/'):
                    return redirect(next_page)
                else:
                    # if next_page is not relative, or potentially malicious, redirect to dashboard
                    return redirect(url_for('dashboard'))
            else:
                return redirect(url_for('dashboard')) # We'll create 'dashboard' route later
        else:
            # Login failed (user not found or password incorrect)
            flash('Login unsuccessful. Please check your email and password.', 'danger')

    # If GET request or form validation failed on the initial WTForms checks (not our custom logic here)
    return render_template('login.html', title='Login', form=form)
@app.route('/dashboard')
def dashboard():
    """A protected page only accessible to logged-in users."""
    # Check if the user is logged in (i.e., if user_id is in session)
    if 'user_id' not in session:
        flash('Please log in to access this page.', 'warning')
        # Store the current URL (dashboard) in 'next' so user is redirected back here after login
        return redirect(url_for('login', next=request.url))

    # If user_id is in session, the user is logged in.
    # We can fetch the user from DB if we need more user details not in session,
    # but for now, session['username'] and session['user_id'] are enough.
    # user = User.query.get(session['user_id']) # Example if you needed full user object
    return render_template('dashboard.html', title='Dashboard')
@app.route('/logout')
def logout():
    """Logs the user out by clearing the session."""
    # Remove user_id and username from the session
    session.pop('user_id', None) # .pop() is safe; it won't error if key is not present
    session.pop('username', None)
    flash('You have been successfully logged out.', 'success')
    return redirect(url_for('index')) # Redirect to the home page after logout
# --- Utility: Create Database Tables (Run once or when models change) ---
# (The rest of your file like create_tables() and if __name__ == '__main__' block follows here)
# ...

# --- Main Execution ---
if __name__ == '__main__':
    # Check if the database file exists. If not, create tables.
    # This is a simple way to initialize the DB for this example.
    db_file = os.path.join(basedir, 'users.db')
    if not os.path.exists(db_file):
        print(f"Database file '{db_file}' not found. Creating tables...")
        create_tables()
        print(f"Database file '{db_file}' should now exist.")
    else:
        print(f"Database file '{db_file}' already exists.")

    app.run(debug=True) # Enable debug mode for development
                        # **IMPORTANT:** Disable debug mode in production!