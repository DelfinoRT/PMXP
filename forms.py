# Import necessary classes from flask_wtf and wtforms for creating form elements
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
# Import validators to check for data presence and equality
from wtforms.validators import DataRequired, EqualTo

# Admin user creation form
class CreateUserForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=20)])
    initial_password = PasswordField('Initial Password', validators=[DataRequired(), Length(min=6)])
    submit = SubmitField('Create User')
    
# Define LoginForm class which inherits from FlaskForm for user login functionality
class LoginForm(FlaskForm):
    # Define a StringField for username input, with a validator to ensure it is not empty
    username = StringField('Username', validators=[DataRequired()])
    # Define a PasswordField for the password input, also checked to not be empty
    password = PasswordField('Password', validators=[DataRequired()])
    # Define a SubmitField button for form submission
    submit = SubmitField('Login')

# Define ChangePasswordForm class for changing passwords, also inherits from FlaskForm
class ChangePasswordForm(FlaskForm):
    # Define a PasswordField for the new password, with a validator to ensure it is not empty
    password = PasswordField('New Password', validators=[DataRequired()])
    # Define another PasswordField to confirm the new password. It has two validators: not empty and must equal the first password field
    confirm_password = PasswordField('Confirm New Password',
                                     validators=[DataRequired(), EqualTo('password')])
    # Define a SubmitField button for form submission
    submit = SubmitField('Change Password')