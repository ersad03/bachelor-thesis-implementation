import streamlit as st
import pandas as pd
import numpy as np
import joblib
from sklearn.ensemble import BaggingClassifier, RandomForestClassifier
import streamlit.components.v1 as components

# Set page configuration
#st.set_page_config(page_title="Network Intrusion Detection Using Random Forest")

# Load the pre-trained model and predictor names
@st.cache_resource
def load_model():
    model = joblib.load('best_model_resaved.pkl')
    predictor_names = joblib.load('predictor_names_resaved.pkl')
    return model, predictor_names

# Function to process the uploaded data
def process_data(uploaded_file, predictor_names):
    df = pd.read_csv(uploaded_file)
    # Check for and handle null and infinite values
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)
    X = df[predictor_names]
    return X, df

# Function to make predictions
def make_predictions(model, X):
    y_proba = model.predict_proba(X)
    anomaly_scores = y_proba[:, 1]
    average_anomaly_score = np.mean(anomaly_scores) * 100
    return average_anomaly_score

# Streamlit app layout
st.title("Random Forest classifier using the CICIDS2017 dataset")

# Information Box
st.info("""
The machine learning model used in this application is trained on the **Friday-WorkingHours-Afternoon-DDos.csv** dataset, 
which is part of the CICIDS2017 dataset. This dataset contains benign and the most up-to-date common attacks, 
resembling real-world network traffic. 

The Random Forest algorithm is employed to detect anomalies and potential attacks within the network traffic data. 

**Using Your Own PCAP File:**
If you have a PCAP file, you can convert it to CSV using the CICFlowMeter tool. This conversion will generate CSV files with labeled flows based on timestamps, IPs, ports, protocols, and attack types.

**Preprocessing Steps:**
During the execution, necessary preprocessing steps are performed to ensure data integrity and avoid errors.

**Data Preview:**
You can view the first five columns of the uploaded dataset to get an initial understanding of the data structure.
""")

# Tabs for the Streamlit app
tab1, tab2 = st.tabs(["Detection", "Notebook"])

# First Tab: Detection
with tab1:
    st.header('ML Detection')

    st.write("Upload a CSV file to make predictions using the pre-trained model.")

    uploaded_file = st.file_uploader("Choose a file...", type="csv")

    if uploaded_file is not None:
        model, predictor_names = load_model()
        X, df = process_data(uploaded_file, predictor_names)
        avg_anomaly_score = make_predictions(model, X)

        st.write("### Uploaded Data")
        st.write(df.head())

        st.write(f"### Average Anomaly Score: {avg_anomaly_score:.2f}%")
        
        threshold = 0.4 * 100
        if avg_anomaly_score > threshold:
            st.error(f"This file has a high anomaly score of {avg_anomaly_score:.2f}%. It is considered too anomalous.")
        else:
            st.success(f"This file has a low anomaly score of {avg_anomaly_score:.2f}%. It is not considered too anomalous.")
    else:
        st.write("Please upload a CSV file to proceed.")

# Second Tab: Google Colab Notebook
with tab2:
    st.header("Google Colab Notebook")

    # Path to your HTML file
    html_file_name = 'attempt7-final.html'

    # Read the HTML file
    with open(html_file_name, 'r', encoding='utf-8') as f:
        html_content = f.read()

    # Display the HTML file in Streamlit
    components.html(html_content, height=1000, scrolling=True)
