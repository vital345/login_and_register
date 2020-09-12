from flask import Flask, render_template, request, url_for, redirect, flash
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from flask_login import LoginManager, UserMixin, current_user, login_user, logout_user

#initialising ----------------------------------------------------------------------------------------------------------------

app = Flask(__name__)
app.config['SECRET_KEY'] = '1de7bcf3be852a5f67c3e9fff5c309f5'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manger = LoginManager(app)


#-------------------------------------------------------------------------------------------------------------------------------------
@login_manger.user_loader    #setting up a extension that check if user is authenticated etc etc
def load_user(user_id):
    return User.query.get(int(user_id))


#creating the data base model ------------------------------------------------------------------------------------------------
class User(db.Model, UserMixin) :
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(30), unique=True, nullable=False)
    password = db.Column(db.String(60),nullable=False)

    def __repr__(self):
        return f''' User: (  name : {self.username}
                    email : {self.email}
                    password : {self.password} )'''

db.create_all() #to be run only once otherwise it overwrites the current database

#creating forms for login and registration forms -------------------------------------------------------------------------------

class RegistrationForm(FlaskForm):
    username = StringField('Username', 
                            validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', 
                        validators=[DataRequired(), Email()])
    password = PasswordField('password', validators=[DataRequired()])
    confirm_password = PasswordField('confirm password', 
                        validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign up')

    def validate_username(self, username):
        # if True: 
        #     raise ValidationError('validation message') this is a blueprint
        user = User.query.filter_by(username=username.data).first()  #its coming from form # checking if the user exists in the database
        if user:
            raise ValidationError('that user name is taken try another one......')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()  #its(email.data) coming from form # checking if the email exists in the database
        if user:
            raise ValidationError('that email name is taken try another one.......')

class LoginForm(FlaskForm):
    email = StringField('Email', 
                        validators=[DataRequired(), Email()])
    password = PasswordField('password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')


# creating routes in the url-------------------------------------------------------------------------------------------------------

@app.route('/')
def hello_world():
    return render_template('index.html', current_user=current_user.is_authenticated)


@app.route('/register', methods=["POST","GET"])
def registration_route():
    if current_user.is_authenticated:
        return redirect(url_for('hello_world'))
    registration_form = RegistrationForm()
    if registration_form.validate_on_submit():
        # email = User.query.filter_by(email=registration_form.email.data).first()
        # if email :
        #     raise ValidationError('This Email is taken try another ...........')
        # username = User.query.filter_by(username=registration_form.username.data).first()
        # if username :
        #     raise ValidationError('This username is taken try another ...........')
        hashed_password = bcrypt.generate_password_hash(registration_form.password.data).decode('utf-8')
        user = User(username=registration_form.username.data, 
                    email=registration_form.email.data,
                    password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash(f'account created for { registration_form.username.data }!!!\nYou can login now!!!', category='success')
        return redirect(url_for('login_route'))
    return render_template('register.html', title='register', registration_form=registration_form)

@app.route('/login',methods=["POST","GET"])
def login_route():
    if current_user.is_authenticated:
        return redirect(url_for('hello_world'))
    login_form = LoginForm()
    if login_form.validate_on_submit():
        user = User.query.filter_by(email=login_form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, login_form.password.data) :
            login_user(user, remember=login_form.remember.data)
            return redirect(url_for('hello_world'))
        else :
            flash('login unsuccessfull please check username and password', 'danger')
    return render_template('login.html', title='login', login_form=login_form)

@app.route('/logout')
def logout_route():
    logout_user()
    return redirect(url_for('hello_world'))



if __name__ == "__main__":
    app.run(debug=True)