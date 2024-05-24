from flask import Flask, render_template, redirect, request, session, flash, make_response, jsonify, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_qrcode import QRcode
from sqlalchemy.exc import IntegrityError, OperationalError
from werkzeug.security import generate_password_hash, check_password_hash
from pyotp import totp
from datetime import datetime
from os import path
import re

app = Flask(__name__)
settings = {
    "SECRET_KEY": 'G524T4D35DG46G5TT7',
    "SQLALCHEMY_DATABASE_URI": 'sqlite:///database.db',
    "SQLALCHEMY_TRACK_MODIFICATIONS": False,
}
app.config.update(settings)
app.debug = True
db = SQLAlchemy(app)
QRcode(app)


class Users(db.Model):
    """Creates db tables Users"""
    userId = db.Column(db.Text, primary_key=True)
    password = db.Column(db.Text, nullable=False)
    email = db.Column(db.Text, nullable=False)
    status = db.Column(db.Text, nullable=False)


@app.before_first_request
def before_request():
    """Tracks number of wrong password entries"""
    session['password_error_count'] = 0
    session['name'] = ''
    session['prev_name'] = ''


@app.route('/')
def index():
    """Returns the home page"""
    return render_template('index.html')


@app.route('/signup')
def signup():
    """Returns the signup page"""
    return render_template('signup.html')


@app.route('/signupVerify', methods=['POST'])
def signup_verify():
    """Called by web app to verify if sign up details are correct"""
    userid = request.get_json()['userid']
    password = request.get_json()['password']
    cpassword = request.get_json()['cpassword']
    email = request.get_json()['email']

    response = {}

    if not re.search(r"^EM\d{4}$", userid):
        response["id_error"] = "User ID is not valid"
    elif Users.query.filter_by(userId=userid).first():
        response["id_error"] = "User ID is already registered"
    else:
        pass

    if re.search(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[_@$!%*?&#-])[A-Za-z\d_@$!%*?#&-]{8,}$", password):
        pass
    else:
        response["password_error"] = "Password not valid. It should have 8 characters or more, at least 1 capital and non-capital letter, at least 1 number and at least 1 special character"

    if password != cpassword:
        response["cpassword_error"] = "Confirmation password does not match the first"

    if not re.search(r"^[a-zA-Z0-9]+@[a-z]+[.](com|net|org)$", email):
        response["email_error"] = "Email is not valid"
    elif Users.query.filter_by(email=email).first():
        response["email_error"] = "Email is already registered"

    if response:
        response["result"] = 0
    else:
        user = Users(
            userId=userid,
            password=generate_password_hash(password, method='sha256'),
            email=email,
            status="OPEN"
        )
        db.session.add(user)
        db.session.commit()
        response["result"] = 1
        write_log(f"User {userid} created successfully.")
    return make_response(jsonify(response))


@app.route('/captureMFA', methods=['POST'])
def capture_mfa():
    """Returns the MFA QRCode page"""
    userid = request.form.get('userid')
    totpauth = totp.TOTP(app.secret_key).provisioning_uri(name=userid, issuer_name="ERP Authenticator")
    write_log(f"MFA code for user {userid} generated successfully.")
    return render_template('generateMFA.html', auth=totpauth)


@app.route('/login')
def login():
    """Returns the login page"""
    return render_template('login.html')


@app.route('/loginVerify', methods=['POST'])
def login_verify():
    """Called by web application to verify if login details are correct"""
    Id = request.get_json()['userid']
    password = request.get_json()['password']

    user = Users.query.filter_by(userId=Id).first()

    session['name'] = Id
    if user and not session['prev_name']:
        session['prev_name'] = Id

    if session['name'] != session['prev_name']:
        session['password_error_count'] = 0

    if session['name'] == session['prev_name'] and session['password_error_count'] == 3:
        user.status = "LOCKED"
        db.session.commit()
        write_log(f"Account for user {user.userId} was Locked due to entry of wrong password 3 times.")

    if not user:
        response = {'result': 0, 'message': 'Credentials not found. Try Again!'}
    else:
        if user.status == "LOCKED":
            response = {'result': 0, 'message': 'Account Locked. Contact administrator!'}
        elif check_password_hash(user.password, password):
            if session['name'] == 'EM0001':
                session['role'] = 'admin'
            else:
                session['role'] = 'user'
            response = {'result': 1}
        else:
            session['password_error_count'] += 1
            response = {'result': 0, 'message': 'Credentials not found. Try Again!'}
    return make_response(jsonify(response))


@app.route('/verifyMFA', methods=['POST'])
def verify_mfa():
    """Returns the page where you enter MFA Code"""
    return render_template('verifyMFA.html')


@app.route('/confirmLogin', methods=['POST'])
def confirm_login():
    """Called by web application to verify if MFA Code is correct"""
    mfacode = request.form['mfacode']
    totpauth = totp.TOTP(app.secret_key)
    if totpauth.verify(mfacode):
        write_log(f"User {session['name']} logged into the system.")
        flash('You have successfully logged in.', 'success')
        if session['role'] == 'admin':
            return redirect(url_for('user_mgt'), code=307)
        else:
            return redirect('/')
    else:
        flash('Incorrect MFA Code entered. Try Again!', 'error')
        return redirect('/login')


@app.route('/usermgt', methods=['POST'])
def user_mgt():
    return render_template("manageAccs.html")


@app.route('/query', methods=['POST'])
def query():
    userid = request.get_json()['userid']

    acc = Users.query.filter_by(userId=userid).first()

    if acc:
        response = {
            'result': 1,
            'userid': acc.userId,
            'email': acc.email,
            'status': acc.status
        }
    else:
        response = {
            'result': 0
        }
    return make_response(jsonify(response))


@app.route('/toggle', methods=['POST'])
def toggle():
    userid = request.get_json()['userid']

    acc = Users.query.filter_by(userId=userid).first()
    if acc:
        if acc.status == 'OPEN':
            acc.status = 'LOCKED'
            db.session.commit()
            write_log(f"Account for user {userid} was locked by Admin.")
            return make_response(jsonify({'result': 0, 'status': acc.status}))
        else:
            acc.status = 'OPEN'
            db.session.commit()
            write_log(f"Account for user {userid} was opened by Admin.")
            return make_response(jsonify({'result': 1, 'status': acc.status}))
    else:
        return make_response(jsonify({'result': 2}))


@app.route('/delete', methods=['POST'])
def delete():
    userid = request.get_json()['userid']
    print(userid)
    acc = Users.query.filter_by(userId=userid).first()
    if acc:
        db.session.delete(acc)
        db.session.commit()
        write_log(f"Account for user {userid} was deleted by Admin.")
        return make_response(jsonify({'result': 1}))
    else:
        return make_response(jsonify({'result': 0}))


def write_log(info):
    """Writes user activity to audit trail log"""
    log = path.join(path.dirname(__file__), 'instance\\logs', datetime.now().strftime("%Y-%m-%d") + '.log')
    if path.isfile(log):
        with open(log, 'a') as file:
            file.write(datetime.now().strftime("%Y-%m-%d %H:%M:%S - "))
            file.write(info + "\n")
    else:
        with open(log, 'w'):
            pass
        write_log(info)


def create_database():
    """Creates database if it does not exist in environment"""
    if not path.exists("/instance/database.db"):
        try:
            db.create_all()
        except IntegrityError:
            pass
        except OperationalError:
            pass


if __name__ == '__main__':
    """Runs the web application"""
    with app.app_context():
        create_database()
        app.run()
