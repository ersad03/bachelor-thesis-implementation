import streamlit as st
import pandas as pd
import subprocess
import os
import io
import tempfile

# Streamlit title
st.title("PCAP File Analysis with CICFlowMeter")

# Streamlit file uploader for PCAP files
uploaded_file = st.file_uploader("Upload a PCAP file", type=["pcap"])

if uploaded_file is not None:
    # Read the uploaded file into a BytesIO object
    pcap_data = uploaded_file.read()
    pcap_file = io.BytesIO(pcap_data)
    
    # Create a temporary directory to store the temporary files
    with tempfile.TemporaryDirectory() as tempdir:
        # Write the uploaded file to a temporary file
        pcap_file_path = os.path.join(tempdir, uploaded_file.name)
        with open(pcap_file_path, "wb") as f:
            f.write(pcap_file.getbuffer())
        
        # Define the output CSV file path
        csv_file_name = os.path.splitext(uploaded_file.name)[0] + "_flows.csv"
        csv_file_path = os.path.join(tempdir, csv_file_name)
        
        # Run CICFlowMeter to process the PCAP file
        st.info("Running CICFlowMeter...")
        command = ["cicflowmeter", "-f", pcap_file_path, "-c", csv_file_path]
        result = subprocess.run(command, capture_output=True, text=True)
        
        if result.returncode == 0:
            st.success(f"Flow data generated: {csv_file_name}")

            # Read the generated CSV file into a DataFrame
            df = pd.read_csv(csv_file_path)
            st.dataframe(df.head())
            
            # Provide a download button for the generated CSV file
            with open(csv_file_path, "rb") as f:
                csv_data = f.read()
                st.download_button(
                    label="Download CSV",
                    data=csv_data,
                    file_name=csv_file_name,
                    mime="text/csv"
                )
        else:
            st.error(f"Error running CICFlowMeter: {result.stderr}")

