import streamlit as st
import os
import base64
from pathlib import Path

# Use Path for more robust path handling
SCRIPT_DIR = Path(__file__).parent.absolute()
REPO_DIR = SCRIPT_DIR.parent / "bachelor-thesis-implementation" / "rep"

# Information about each file (file name as key)
files_info = {
    "Friday-WorkingHours-Afternoon-DDos_aligned.csv": "The Friday-WorkingHours-Afternoon-DDos_aligned.csv file is part of the CICDDoS2019 dataset, which captures real-world-like network traffic, including various DDoS attacks. This file contains data from attacks such as PortMap, NetBIOS, LDAP, MSSQL, UDP, UDP-Lag, SYN, NTP, DNS, SNMP, SSDP, WebDDoS, and TFTP. The attacks were carried out over two days, with each attack recorded alongside normal network activity to help test and evaluate network intrusion detection systems.",
    "Bad-DDOS.csv": "The Bad-DDOS.csv file is part of the training dataset, featuring around 130,000 packets that include both benign and mostly DDoS traffic (unlabeled) for testing.",
    "filtered_DarkWave.csv": "filtered_DarkWave.csv is a CSV file converted from the DarkWave.pcap, containing data from 700,000 network packets captured during a Mirai botnet infection, specifically prepared to test the Random Forest machine learning model for anomaly detection.",
    "DarkWave.pcap": "DarkWave contains approximately 700,000 packets captured over 118 minutes during a network infection by the Mirai botnet malware.",
    "DarkWave.png": "This image shows the anomaly scores generated by Kitsune during the processing of the DarkWave.pcap file, which contains 700,000 packets. The RMSE values are displayed on a logarithmic scale, with higher scores and red colors indicating more significant anomalies.",
    "filtered_bigFlows.csv": "filtered_bigFlows.csv is a CSV file created from the bigFlows.pcap, containing nearly 800,000 packets recorded during an OS Scanning. It's intended for testing the Random Forest model in detecting anomalies.",
    "bigFlows.pcap": "bigFlows contains nearly 800,000 packets captured over 5 minutes during a network infection by the OS Scanning.",
    "bigFlows.png": "This graph displays the anomaly scores generated by Kitsune during the processing of the bigFlows.pcap file, which contains 800,000 packets. The RMSE values are shown on a logarithmic scale, with a high number of scores and red colors indicating significant anomalies caused by OS Scanning during a 5-minute period.",
    "filtered_home-400k.csv": "filtered_home-400k.csv is a CSV file created from home-400k.pcap, containing data from 400,000 packets of normal home network activity, making it useful for identifying and differentiating typical network behavior.",
    "home-400k.pcap": "home-400k contains 400,000 packets captured over 7 minutes during normal home network activity.",
    "home-400k.png": "This image shows the anomaly scores generated by Kitsune during the processing of the home-400k.pcap file, which contains 400,000 packets. The RMSE values are displayed on a logarithmic scale, with only one red dot indicating a minor anomaly that is not significant.",
}

def get_file_path(filename: str) -> Path:
    """Get the full path for a file and verify its existence."""
    file_path = REPO_DIR / filename
    if not file_path.exists():
        st.error(f"File not found: {filename}")
        return None
    return file_path

def create_download_button(file_path: Path, mime_type: str):
    """Create a download button for a file with proper error handling."""
    try:
        with open(file_path, "rb") as f:
            st.download_button(
                label=f"⬇️ Download {file_path.name}",
                data=f,
                file_name=file_path.name,
                mime=mime_type
            )
    except Exception as e:
        st.error(f"Error creating download button for {file_path.name}: {str(e)}")

def display_file_section(files_dict: dict, file_extension: str, mime_type: str):
    """Display a section of files with their descriptions and download buttons."""
    for filename, description in files_dict.items():
        if filename.endswith(file_extension):
            file_path = get_file_path(filename)
            if file_path:
                st.markdown(f"### {filename}")
                st.write(description)
                create_download_button(file_path, mime_type)

                # Special handling for PNG files
                if file_extension == '.png':
                    try:
                        with open(file_path, "rb") as img_file:
                            encoded_image = base64.b64encode(img_file.read()).decode()
                            st.markdown(
                                f"""
                                <div style="border: 1px solid #ccc; padding: 10px; margin-bottom: 20px;">
                                    <img src="data:image/png;base64,{encoded_image}"
                                         style="width:100%; border-radius: 10px;"
                                         alt="{filename}"/>
                                    <div style="text-align: center; margin-top: 10px;">{filename}</div>
                                </div>
                                """,
                                unsafe_allow_html=True
                            )
                    except Exception as e:
                        st.error(f"Error displaying image {filename}: {str(e)}")

                st.markdown("---")

def main():
    st.title("Malicious File Repository")
    st.info(
        """
        This page showcases my results in a repository containing malicious data samples in .pcap, .pcapng, .csv, and .png formats.
        These files are designed to help test and simulate using the Kitsune autoencoder-based framework and the Random Forest classifier.
        """
    )

    # Debug information
    #if st.checkbox("Show Debug Info"):
    #    st.write(f"Repository directory: {REPO_DIR}")
    #    st.write(f"Files in directory: {[f.name for f in REPO_DIR.glob('*') if f.is_file()]}")

    # Create tabs for different categories
    tab1, tab2, tab3 = st.tabs(["PCAP Files", "CSV Files", "Images"])

    with tab1:
        st.header("PCAP Files")
        display_file_section(files_info, '.pcap', "application/octet-stream")

    with tab2:
        st.header("CSV Files")
        display_file_section(files_info, '.csv', "text/csv")

    with tab3:
        st.header("Images")
        display_file_section(files_info, '.png', "image/png")

if __name__ == "__main__":
    main()
