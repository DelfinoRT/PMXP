from flask import Flask, render_template, url_for, redirect, flash, request, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, EmailField, TelField
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError, Email
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
    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)
    member_id = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), nullable=True)
    phone = db.Column(db.String(20), nullable=True)
    city = db.Column(db.String(100), nullable=True)
    state = db.Column(db.String(100), nullable=True)
    aviary = db.Column(db.String(100), nullable=True)
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
    return db.session.get(User, int(user_id))

class LoginForm(FlaskForm):
    username = StringField('Usuario', validators=[DataRequired(), Length(min=2, max=20)])
    password = PasswordField('Contraseña', validators=[DataRequired()])
    submit = SubmitField('Acceder')

class ChangePasswordForm(FlaskForm):
    password = PasswordField('Nueva Contraseña', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirmar Nueva Contraseña', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Cambiar Contraseña')
    
class CreateUserForm(FlaskForm):
    username = StringField('Nombre de usuario (Esto no se puede cambiar en un futuro, ten cuidado)', validators=[DataRequired(), Length(min=3, max=20)])
    first_name = StringField('Nombre(s)', validators=[DataRequired(), Length(max=100)])  # New
    last_name = StringField('Apellido(s)', validators=[DataRequired(), Length(max=100)])  # New
    member_id = StringField('# Miembro', validators=[DataRequired(), Length(max=50)])  # New
    initial_password = PasswordField('Contraseña Inicial', validators=[DataRequired(), Length(min=6)])
    email = EmailField('Email', validators=[DataRequired(), Email()])
    phone = TelField('Teléfono')
    city = StringField('Ciudad', validators=[DataRequired(), Length(max=100)]) 
    state = StringField('Estado', validators=[DataRequired(), Length(max=100)])
    aviary = StringField('Aviario', validators=[DataRequired(), Length(max=100)])
    submit = SubmitField('Crear usuario')
    
    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Nombre de usuario ya en uso, por favor elige uno diferente.')
    def validate_member_id(self, member_id):
        user = User.query.filter_by(member_id=member_id.data).first()
        if user:
            raise ValidationError('Número de miembro ya en uso, por favor revisa y define uno diferente.')
    
class UserDetailsForm(FlaskForm):
    username = StringField('Usuario', validators=[DataRequired(), Length(min=3, max=20)])
    first_name = StringField('Nombre(s)', validators=[DataRequired(), Length(max=100)])
    last_name = StringField('Apellido(s)', validators=[DataRequired(), Length(max=100)])
    member_id = StringField('# Miembro', validators=[DataRequired(), Length(max=50)])
    email = EmailField('Email', validators=[DataRequired(), Email()])
    phone = TelField('Teléfono')
    city = StringField('Ciudad')
    state = StringField('Estado')
    aviary = StringField('Aviario')
    submit = SubmitField('Actualizar datos')

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    return redirect(url_for('login'))

@app.route('/profile')
@login_required
def profile():
    return render_template('user_profile.html', user=current_user)

@app.route('/user-management')
@login_required
def user_management():
    # Ensure only admins can access this page
    if not current_user.username.startswith("ADM-"):
        flash("Unauthorized. Admins only.", "danger")
        return redirect(url_for('home'))
    # Fetch users ordered by member_id in ascending order
    users = User.query.all()  # Fetch all users first
    # Assuming 'member_id' can be a mix of letters and numbers but ends with numbers
    def extract_numeric_id(member_id):
        # This extracts trailing digits from the member_id, returns 0 if none found
        numeric_part = ''.join(filter(str.isdigit, member_id))
        return int(numeric_part) if numeric_part else 0
    # Sort users in Python based on the numeric part of their member_id
    sorted_users = sorted(users, key=lambda user: extract_numeric_id(user.member_id))
    return render_template('user_management.html', users=sorted_users)

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
            flash('Error de inicio de sesión: Comprueba tu usuario y contraseña e inténtalo de nuevo.', 'danger')
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
        flash('No tienes permisos para acceder a esta página.', 'danger')
        return redirect(url_for('home'))

    form = CreateUserForm()
    if form.validate_on_submit():
        username_exists = User.query.filter_by(username=form.username.data).first()
        member_id_exists = User.query.filter_by(member_id=form.member_id.data).first()
        
        # Check if either username or member ID already exists in the database.
        if username_exists:
            flash("Nombre de usuario ya en uso, por favor elige uno diferente", "warning")
        elif member_id_exists:
            flash("Número de miembro ya en uso, por favor revisa y define uno diferente.", "warning")
        else:
            hashed_password = generate_password_hash(form.initial_password.data)
            user = User(username=form.username.data, email=form.email.data, phone=form.phone.data, city=form.city.data, state=form.state.data, aviary=form.aviary.data,
                first_name=form.first_name.data, last_name=form.last_name.data, member_id=form.member_id.data, 
                password_hash=hashed_password, is_password_changed=False)
            db.session.add(user)
            db.session.commit()
            flash(f"Usuario {user.first_name} {user.last_name} creado exitosamente.", 'success')
            return redirect(url_for('manage_users'))
    
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
        flash(f"La contraseña para {user.first_name} {user.last_name} fue cambiada exitosamente!", 'success')
        return redirect(url_for('manage_users'))
    return render_template('change_password.html', title='Change User Password', form=form, user=user)

@app.route('/user/<int:user_id>/details', methods=['GET', 'POST'])
@login_required
def manage_user_details(user_id):
    if not current_user.username.startswith("ADM-"):
        flash("Unauthorized. Admins only.", "danger")
        return redirect(url_for('home'))
    
    user = User.query.get_or_404(user_id)

    form = UserDetailsForm(obj=user)  # Pre-populates the form with the user's current details

    if form.validate_on_submit():
        form.populate_obj(user)  # This will update the user object with form data

        # Specifically account for fields that shouldn't just be blindly updated perhaps due to security or business rules; i.e., username or password
        user.email = form.email.data
        user.phone = form.phone.data
        user.city = form.city.data
        user.state = form.state.data
        user.aviary = form.aviary.data

        db.session.commit()  # Save changes to the database
        flash(f"Los datos de {user.first_name} {user.last_name} fueron actualizados exitosamente.", 'success')
        return redirect(url_for('manage_users'))

    # Flash form errors in case there are form/validation errors
    for error in form.errors.values():
        flash("; ".join(error), 'danger')

    # In case this is a GET request or there's form validation error
    return render_template('user_details.html', title='User Details', form=form, user_id=user_id)

@app.route('/home')
@login_required
def home():
    # Admin users see the manage users button
    return render_template('home.html', title='Home')

def create_database(app):
    with app.app_context():
        db.create_all()
if __name__ == '__main__':
    create_database(app)
#    app.run(debug=True)