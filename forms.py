# Import necessary classes from flask_wtf and wtforms for creating form elements
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
# Import validators to check for data presence, ensure length requirements, and check equality of fields
from wtforms.validators import DataRequired, EqualTo, Length

# Admin user creation form
# This class inherits from FlaskForm to utilize its functionalities for web form creation
class CreateUserForm(FlaskForm):
    # Username field that must be filled out and is restricted to a length between 3 and 20 characters
    username = StringField('Usuario', validators=[DataRequired(), 
                                                   Length(min=3, max=20)])
    # Initial password field that also must be filled out with at least 6 characters
    initial_password = PasswordField('Contraseña inicial', validators=[DataRequired(), 
                                                                      Length(min=6)])
    # A submit button for the form
    submit = SubmitField('Crear Usuario')
    
# Define LoginForm class which inherits from FlaskForm for user login functionality
class LoginForm(FlaskForm):
    # Define a StringField for username input, with a validator to ensure it is not empty
    # This is for user input during login where they must enter a username
    username = StringField('Usuario', validators=[DataRequired()])
    # Define a PasswordField for the password input, also checked to not be empty
    # This ensures the user provides a password for login
    password = PasswordField('Contraseña', validators=[DataRequired()])
    # Define a SubmitField button for form submission, allowing the user to submit the login form
    submit = SubmitField('Acceder')

# Define ChangePasswordForm class for changing passwords; it also inherits from FlaskForm
class ChangePasswordForm(FlaskForm):
    # Define a PasswordField for the new password, with a validator to ensure it is not empty
    # This field collects the new password the user wishes to change to
    password = PasswordField('Nueva Contraseña', validators=[DataRequired(), 
                                                         Length(min=6)]) # Added Length validator for a minimum password length
    # Define another PasswordField to confirm the new password. It has two validators:
    # Must not be empty and must equal the first password field to avoid mistype issues
    confirm_password = PasswordField('Confirma Nueva Contraseña',
                                     validators=[DataRequired(), EqualTo('password')])
    # Define a SubmitField button for form submission, which the user presses to confirm the password change
    submit = SubmitField('Cambiar Contraseña')