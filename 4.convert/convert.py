import streamlit as st
import pandas as pd
import subprocess
import os
import tempfile

# Streamlit title
st.title("Convert PCAP File with CICFlowMeter")

#shorter description
st.info("""
CICFlowMeter is a network traffic flow generator and analyzer that creates bidirectional flows and calculates over 35 statistical features. It supports customizations through code adjustments, including feature selection, adding new features, and controlling flow timeout. The tool outputs results in CSV format, making it well-suited for detailed network traffic analysis.
""")

# Streamlit file uploader for PCAP files
uploaded_file = st.file_uploader("Upload a PCAP file", type=["pcap"])

if uploaded_file is not None:
    # Read the uploaded file
    pcap_data = uploaded_file.read()
    
    # Create a temporary directory to store the temporary files
    with tempfile.TemporaryDirectory() as tempdir:
        # Write the uploaded file to a temporary file
        pcap_file_path = os.path.join(tempdir, uploaded_file.name)
        with open(pcap_file_path, "wb") as f:
            f.write(pcap_data)
        
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
            
            # List of desired features
            desired_features = [
                "totlen_bwd_pkts", "flow_pkts_s", "tot_bwd_pkts", "fwd_pkt_len_mean", "flow_duration",
                "cwe_flag_count", "fwd_iat_std", "tot_fwd_pkts", "bwd_iat_min", "psh_flag_cnt",
                "bwd_iat_std", "ack_flag_cnt", "totlen_fwd_pkts", "ece_flag_cnt", "bwd_seg_size_avg",
                "fwd_pkt_len_std", "fwd_iat_max", "down_up_ratio", "fwd_pkt_len_max", "urg_flag_cnt",
                "pkt_size_avg", "bwd_pkt_len_min", "fwd_iat_min", "bwd_pkt_len_mean", "bwd_pkt_len_std",
                "subflow_bwd_byts", "subflow_bwd_pkts", "fwd_seg_size_avg", "bwd_iat_max", "rst_flag_cnt",
                "fwd_iat_mean", "subflow_fwd_byts", "syn_flag_cnt", "bwd_iat_mean", "fwd_pkt_len_min"
            ]
            
            # Filter the DataFrame to include only the desired features
            df_filtered = df[desired_features]
            
            st.dataframe(df_filtered.head())
            
            # Provide a download button for the filtered CSV file
            filtered_csv_path = os.path.join(tempdir, "filtered_" + csv_file_name)
            df_filtered.to_csv(filtered_csv_path, index=False)
            
            with open(filtered_csv_path, "rb") as f:
                csv_data = f.read()
                st.download_button(
                    label="Download CSV",
                    data=csv_data,
                    file_name="filtered_" + csv_file_name,
                    mime="text/csv"
                )
        else:
            st.error(f"Error running CICFlowMeter: {result.stderr}")
