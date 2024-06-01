from flask import Flask, render_template, request, redirect, session, url_for, flash
import pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
import joblib
import sqlite3
import bcrypt
import re
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature



app = Flask(__name__, static_url_path='/static', static_folder='static')
app.secret_key = 'your_secret_key'
s = URLSafeTimedSerializer(app.secret_key)
from flask_mail import Mail, Message

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'deepikam2121@gmail.com'
app.config['MAIL_PASSWORD'] = 'deepika2002@'
app.config['MAIL_DEFAULT_SENDER'] = 'deepikam2121@gmail.com'

mail = Mail(app)

# Function to connect to the database
def get_db_connection():
    conn = sqlite3.connect('users.db')
    conn.row_factory = sqlite3.Row
    return conn

# Function to create the user table
def create_user_table():
    conn = get_db_connection()
    conn.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, email TEXT, password TEXT)')
    conn.commit()
    conn.close()

create_user_table()

# Load the trained model and preprocessing scaler
model = joblib.load("model.pkl")
scaler = joblib.load("scaler.pkl")

feature_order = ['Type', 'Air temperature [K]', 'Process temperature [K]', 'Rotational speed [rpm]', 'Torque [Nm]','Tool wear [min]']

@app.route("/main")
def main():
    return render_template("index.html")

@app.route("/")
def index():
    if 'username' not in session:
        return redirect("/login")  # Redirect to login page if not logged in
    return render_template("index.html")

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Retrieve user data from the database
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()

        if user:
            # Check if password matches the hashed password in the database
            if bcrypt.checkpw(password.encode('utf-8'), user['password']):
                session['username'] = user['username']
                return redirect('/')
            else:
                error = 'Incorrect password'  # Set error message for incorrect password
        else:
            error = 'User not found'

    return render_template('login.html', error=error)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        # Hash the password
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        # Insert user data into the database
        conn = get_db_connection()
        conn.execute('INSERT INTO users (username, email, password) VALUES (?, ?, ?)', (username, email, hashed_password))
        conn.commit()
        conn.close()

        return redirect("/login")

    return render_template('signup.html')

@app.route('/protected')
def protected():
    return "This is a protected page. You must be logged in to access it."

@app.route("/predict", methods=["POST"])
def predict():
    if request.method == "POST":
        # Get input data from the form
        air_temperature = float(request.form["air_temperature"])
        process_temperature = float(request.form["process_temperature"])
        rotational_speed = float(request.form["rotational_speed"])
        torque = float(request.form["torque"])
        tool_wear = float(request.form["tool_wear"])
        machine_type = request.form["machine_type"]

        # Preprocess the input data
        input_data = pd.DataFrame({
            "Air temperature [K]": [air_temperature],
            "Process temperature [K]": [process_temperature],
            "Rotational speed [rpm]": [rotational_speed],
            "Torque [Nm]": [torque],
            "Tool wear [min]": [tool_wear],  # Add default value for missing feature
            "Type": [machine_type] 
        })

        input_data = input_data[feature_order]

        input_data_scaled = scaler.transform(input_data)

        # Make prediction
        prediction = model.predict(input_data_scaled)
        failure_reason = None
        if tool_wear>200:
            failure_reason = "Tool wear Failure"
        elif tool_wear*torque > 11000:
            failure_reason = "Overstrain Failure"
        elif prediction==1:
            failure_reason = "Power Failure"
        
        return render_template("result.html", prediction=prediction, failure_reason=failure_reason)
    
@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if request.method == 'POST':
        username_email = request.form['username_email']
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ? OR email = ?', (username_email, username_email)).fetchone()

        

        if not user:
            flash('User not found.', 'error')
            return redirect(url_for('change_password'))

        if not bcrypt.checkpw(current_password.encode('utf-8'), user['password']):
            flash('Incorrect current password.', 'error')
            return redirect(url_for('change_password'))

        if new_password != confirm_password:
            flash('New password and confirm password do not match.', 'error')
            return redirect(url_for('change_password'))

        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
        conn.execute('UPDATE users SET password = ? WHERE id = ?', (hashed_password, user['id']))
        conn.commit()
        conn.close()

        flash('Your password has been updated.', 'success')
        return redirect(url_for('login'))

    return render_template('change_password.html')

@app.route('/logout')
def logout():
    session.pop('username', None)  # Remove the 'username' key from the session
    return redirect(url_for('login'))  # Redirect to the login page after logout


@app.route('/reset_password_request', methods=['GET', 'POST'])
def reset_password_request():
    if request.method == 'POST':
        email = request.form['email']
        
        # Retrieve user data from the database
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        conn.close()

        if user:
            # Generate a password reset token
            token = s.dumps(email, salt='password-reset-salt')

            # Generate a password reset URL
            reset_url = url_for('reset_password', token=token, _external=True)

            # Send the email
            msg = Message('Password Reset Request', sender='your_email@gmail.com', recipients=[email])
            msg.body = f'Please use the following link to reset your password: {reset_url}'
            mail.send(msg)
            
            flash('A password reset link has been sent to your email.', 'info')
        else:
            flash('Email address not found.', 'danger')
        
        return redirect(url_for('login'))

    return render_template('reset_password_request.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = s.loads(token, salt='password-reset-salt', max_age=3600)  # Token valid for 1 hour
    except (SignatureExpired, BadSignature):
        flash('The password reset link is invalid or has expired.', 'danger')
        return redirect(url_for('reset_password_request'))

    if request.method == 'POST':
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        if new_password != confirm_password:
            flash('New password and confirm password do not match.', 'danger')
        else:
            # Hash the new password
            hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
            
            # Update the password in the database
            conn = get_db_connection()
            conn.execute('UPDATE users SET password = ? WHERE email = ?', (hashed_password, email))
            conn.commit()
            conn.close()

            flash('Your password has been updated.', 'success')
            return redirect(url_for('login'))

    return render_template('reset_password.html')



if __name__ == "__main__":
    app.run()
