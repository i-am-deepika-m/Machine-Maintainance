from flask import Flask, render_template, request, redirect, session, url_for
import pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
import joblib

app = Flask(__name__, static_url_path='/static', static_folder='static')

app.secret_key = 'your_secret_key' 
users = []

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
    if request.method == 'POST':
        # Process login form submission (replace this with your login logic)
        username = request.form['username']
        password = request.form['password']
        # Dummy authentication (replace with your actual authentication logic)
        for user in users:
            if user['username'] == username and user['password'] == password:
                # Redirect to a protected page upon successful login
                return redirect(url_for('main'))
        # Redirect to signup page if login fails
        return redirect(url_for('signup'))
    # Render the login page template for GET requests
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        # Process signup form submission and create new user account
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        # Dummy user creation (replace with your actual user creation logic)
        new_user = {'username': username, 'email': email, 'password': password}
        users.append(new_user)
        # Redirect to login page upon successful signup
        return redirect("/login")
    # Render the signup page template for GET requests
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

if __name__ == "__main__":
    app.run()
