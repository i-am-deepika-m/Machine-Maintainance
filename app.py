from flask import Flask, render_template, request
import pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
import joblib

app = Flask(__name__, static_url_path='/static', static_folder='static')

# Load the trained model and preprocessing scaler
model = joblib.load("model.pkl")
scaler = joblib.load("scaler.pkl")

feature_order = ['Type', 'Air temperature [K]', 'Process temperature [K]', 'Rotational speed [rpm]', 'Torque [Nm]','Tool wear [min]']

@app.route("/")
def index():
    return render_template("index.html")

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
