import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.linear_model import LogisticRegression
import joblib

# Load the dataset
data = pd.read_csv('Machine Maintainance.csv')

# Drop irrelevant columns
data.drop(columns=['UDI', 'Product ID'], inplace=True)

# Encode categorical variables
label_encoder = LabelEncoder()
data['Type'] = label_encoder.fit_transform(data['Type'])

# Split data into features and target
X = data.drop(columns=['Target', 'Failure Type'])
y = data[['Target', 'Failure Type']]

# Split data into training and test sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Initialize and fit the scaler
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

# Train the machine learning model
model = LogisticRegression()
model.fit(X_train_scaled, y_train['Target'])

# Serialize the model and scaler
joblib.dump(model, 'model.pkl')
joblib.dump(scaler, 'scaler.pkl')
