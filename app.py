from flask import Flask, render_template, url_for, redirect, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

app.config['SECRET_KEY'] = '3fa064c076d41c202e0e5628ee8c69dbaa1c78d51244f2af'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
db = SQLAlchemy(app)
migrate = Migrate(app, db)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Define User model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    first_name = db.Column(db.String(100), nullable=False)  # Added based on your requirement
    last_name = db.Column(db.String(100), nullable=False)   # Added based on your requirement
    member_id = db.Column(db.String(50), unique=True, nullable=False)  # Added based on your requirement
    password_hash = db.Column(db.String(60), nullable=False)
    is_password_changed = db.Column(db.Boolean, default=False)
    def set_password(self, password):
      self.password_hash = generate_password_hash(password)
    def check_password(self, password):
      return check_password_hash(self.password_hash, password)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class ChangePasswordForm(FlaskForm):
    password = PasswordField('New Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm New Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Change Password')
    
class CreateUserForm(FlaskForm):
    username = StringField('Nombre de usuario (Esto no se puede cambiar en un futuro, ten cuidado)', validators=[DataRequired(), Length(min=3, max=20)])
    first_name = StringField('Nombre(s)', validators=[DataRequired(), Length(max=100)])  # New
    last_name = StringField('Apellido(s)', validators=[DataRequired(), Length(max=100)])  # New
    member_id = StringField('# Miembro', validators=[DataRequired(), Length(max=50)])  # New
    initial_password = PasswordField('Contraseña Inicial', validators=[DataRequired(), Length(min=6)])
    submit = SubmitField('Crear usuario')
    
    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Username already in use, please choose a different one.')
    def validate_member_id(self, member_id):
        user = User.query.filter_by(member_id=member_id.data).first()
        if user:
            raise ValidationError('Member ID already in use, please choose a different one.')
    
class UserDetailsForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=20)])
    first_name = StringField('First Name', validators=[DataRequired(), Length(max=100)])
    last_name = StringField('Last Name', validators=[DataRequired(), Length(max=100)])
    member_id = StringField('Member ID', validators=[DataRequired(), Length(max=50)])
    submit = SubmitField('Update Details')

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    return redirect(url_for('login'))

@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('home'))
        else:
            flash('Login Unsuccessful. Please check username and password', 'danger')
    return render_template('login.html', title='Login', form=form)

@app.route("/change_password", methods=['GET', 'POST'])
@login_required
def change_password():
    if not current_user.username.startswith("ADM-"):
        flash("Password reset is not allowed.", "danger")
        return redirect(url_for('home'))
    form = ChangePasswordForm()
    if form.validate_on_submit():
        current_user.set_password(form.password.data)
        current_user.is_password_changed = True
        db.session.commit()
        flash('Your password has been updated!', 'success')
        return redirect(url_for('home'))
    return render_template('change_password.html', title='Change Password', form=form)

@app.route("/admin/create_user", methods=['GET', 'POST'])
@login_required
def admin_create_user():
    if not current_user.username.startswith("ADM-"):
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('home'))

    form = CreateUserForm()
    if form.validate_on_submit():
        username_exists = User.query.filter_by(username=form.username.data).first()
        member_id_exists = User.query.filter_by(member_id=form.member_id.data).first()
        
        # Check if either username or member ID already exists in the database.
        if username_exists:
            flash("Username already in use, please choose a different one.", "warning")
        elif member_id_exists:
            flash("Member ID already in use, please choose a different one.", "warning")
        else:
            hashed_password = generate_password_hash(form.initial_password.data)
            user = User(username=form.username.data, first_name=form.first_name.data, last_name=form.last_name.data, 
                        member_id=form.member_id.data, password_hash=hashed_password, is_password_changed=False)
            db.session.add(user)
            db.session.commit()
            flash('User created successfully.', 'success')
            return redirect(url_for('home'))
    
    # Render the form again (with feedback messages, if any) if validation failed, 
    # or if the username/member ID already exists.
    return render_template('admin_create_user.html', title='Create User', form=form)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/manage_users', methods=['GET', 'POST'])
@login_required
def manage_users():
    if not current_user.username.startswith("ADM-"):
        flash("Unauthorized.", "danger")
        return redirect(url_for('home'))
    search_query = request.form.get('search', '')
    if search_query:
        users = User.query.filter(User.username.contains(search_query)).all()
    else:
        users = User.query.all()
    return render_template('manage_users.html', users=users)

@app.route('/user/<int:user_id>/change_password', methods=['GET', 'POST'])
@login_required
def change_user_password(user_id):
    if not current_user.username.startswith("ADM-"):
        flash("Unauthorized. Admins only.", "danger")
        return redirect(url_for('home'))

    user = User.query.get_or_404(user_id)
    form = ChangePasswordForm()
    if form.validate_on_submit():
        user.set_password(form.password.data)
        db.session.commit()
        flash(f"{user.username}'s password has been updated successfully!", 'success')
        return redirect(url_for('manage_users'))
    return render_template('change_password.html', title='Change User Password', form=form, user=user)

@app.route('/user/<int:user_id>/details', methods=['GET', 'POST'])
@login_required
def manage_user_details(user_id):
    if not current_user.username.startswith("ADM-"):
        flash("Unauthorized. Admins only.", "danger")
        return redirect(url_for('home'))
    
    user = User.query.get_or_404(user_id)
    form = UserDetailsForm(obj=user)  
    if form.validate_on_submit():
        form.populate_obj(user)
        db.session.commit()
        flash(f"{user.username}'s details updated.", 'success')
        return redirect(url_for('manage_users'))
    return render_template('user_details.html', title='User Details', form=form)

@app.route('/home')
@login_required
def home():
    # Admin users see the manage users button
    return render_template('home.html', title='Home')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
