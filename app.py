import os
from flask import Flask, flash, render_template, request, url_for, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
from wtforms import SelectField
from werkzeug.utils import secure_filename
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, Email, ValidationError
from wtforms.fields import DateField, TimeField
import uuid
from datetime import datetime


app = Flask(__name__)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'thisisasecretkey'


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(50), nullable=True)
    phone_number = db.Column(db.String(15), nullable=True)
    appointments = db.relationship('Appointment', backref='user', lazy=True)


class RegisterForm(FlaskForm):
    username = StringField(validators=[
        InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[
        InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})
    email = StringField(validators=[
        InputRequired(), Email(), Length(max=50)], render_kw={"placeholder": "Email"})
    number = StringField(validators=[
        InputRequired(), Length(min=10, max=15)], render_kw={"placeholder": "Phone Number"})

    submit = SubmitField('Register')

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()
        if existing_user_username:
            raise ValidationError(
                'That username already exists. Please choose a different one.')


class Appointment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.DateTime, nullable=False)
    time = db.Column(db.Time, nullable=True)  # Define 'time' as a Time field
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __init__(self, date, user, time=None):
        self.date = date
        self.user = user
        self.time = time



class AppointmentForm(FlaskForm):
    date = DateField('Appointment Date', validators=[InputRequired()])
    time = TimeField('Appointment Time', validators=[InputRequired()])
    submit = SubmitField('Book Appointment')     




class LoginForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Login')


@app.route('/')
def home():
    return render_template('home.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('dashboard'))
    return render_template('login.html', form=form)


@app.route('/patient_dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
     form = AppointmentForm()

     if form.validate_on_submit():
        # Add the provided code block here
        appointment_date = form.date.data
        appointment_time = form.time.data
        print(f"Date: {appointment_date}, Time: {appointment_time}")

        appointment_datetime = datetime.combine(appointment_date, appointment_time)
        print(f"Combined DateTime: {appointment_datetime}")

        new_appointment = Appointment(date=appointment_datetime, user=current_user)
        print(f"New Appointment: {new_appointment}")

        db.session.add(new_appointment)
        db.session.commit()

        flash('Appointment booked successfully!', 'success')
        return redirect(url_for('patient_dashboard'))

     return render_template('patient_dashboard.html', form=form)



@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password, email=form.email.data, phone_number=form.number.data)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html', form=form)


    return render_template('register.html', form=form)
ALLOWED_EXTENSIONS = {'png'}  # Define the allowed file extensions (e.g., PNG)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/upload_image', methods=['POST'])
def upload_image():
    # Handle image upload and processing here
    # Make sure to validate the uploaded image and save it to the specified folder

    # Get the folder name or path from the form input
    folder = request.form['folder']

    # Ensure that 'folder' is a valid and secure path
    # Here you should add appropriate validation and security checks

    # Example: Saving the uploaded image to the specified folder
    uploaded_image = request.files['image']
    if uploaded_image and allowed_file(uploaded_image.filename):
        filename = secure_filename(uploaded_image.filename)
        file_path = os.path.join(folder, filename)
        uploaded_image.save(file_path)
        flash('Image uploaded successfully', 'success')
    else:
        flash('Invalid file format. Please upload a PNG image.', 'error')

    # Pass the path to the uploaded image to the template
    return render_template('user_dashboard.html', uploaded_image=file_path)








@app.route('/book_appointment', methods=['POST'])
def book_appointment():
    # Handle form submission here
    appointment_date = request.form.get('appointment_date')
    appointment_time = request.form.get('appointment_time')

    # Perform actions with appointment_date and appointment_time

    # Redirect to the 'my_appointments' page after booking
    return redirect(url_for('my_appointments'))

@app.route('/my_appointments',methods=['GET', 'POST'])
@login_required
def my_appointments():
  print("Current User ID:", current_user.id)
  user_appointments = Appointment.query.filter_by(user_id=current_user.id).all()
  print("User Appointments:", user_appointments)
  



  return render_template('my_appointments.html', appointments=user_appointments)

if __name__ == "__main__":
    app.run(debug=True)