# Bachelor Thesis Implementation: Anomaly Detection in Network Traffic

## Abstract

In today's connected society, maintaining computer networks secure against cyber threats and unauthorized access is one of the most serious issues. The goal of this research is to design and implement a web-based utility for traffic monitoring within network data based on machine learning. The study employs established machine learning models, including the Kitsune autoencoder-based framework and the Random Forest classifier, to detect anomalies in network traffic. The Random Forest model is trained on the CICIDS2017 dataset from the Canadian Institute for Cybersecurity, while Kitsune operates unsupervised, without the need for explicitly labeled data. The process involves data preprocessing, feature engineering, and the integration of these models into a web application for ease of use and visualization. Implementation uses Python and popular machine learning libraries. A web-based front end is created using the Streamlit framework, which takes network traffic files as an input from the user and finds any sort of anomaly in them. Initial outcomes demonstrate that the method can efficiently classify different anomalies in network traffic, implying application potential. Overall, this study shows that integrating machine learning models into user-friendly web-based applications can tremendously improve network security issues by allowing quick and efficient anomaly detection.

## Features

- **Remote Packet Capture:** Capture network packets remotely on a server via SSH using tcpdump.
- **Anomaly Detection with Kitsune:** Upload and analyze PCAP, PCAPNG, or TSV files for anomalies using the Kitsune algorithm.
- **Random Forest Classifier:** Analyze network traffic files (converted to CSV) for anomalies using a model trained on the CICIDS2017 dataset.
- **PCAP Conversion:** Convert PCAP files to analyzable formats using CICFlowMeter.
- **Traffic Visualization:** Convert PCAP files to KML for visualizing connections, with markers indicating source and destination IPs.
- **Malicious File Repository:** Access a repository containing malicious data samples in various formats (e.g., PCAP, CSV, PNG).

## Installation

Follow these steps to set up and run the project:

1. Clone the repository:

   ```bash
   git clone https://github.com/ersad03/bachelor-thesis-implementation.git
   ```

2. Navigate to the project directory:

   ```bash
   cd bachelor-thesis-implementation
   ```

3. Install the required dependencies:

   ```bash
   pip install -r requirements.txt
   ```

4. Run the application:

   ```bash
   streamlit run main.py
   ```

5. Access the application in your browser via the provided Streamlit link.

> **Note:** The converter page for converting PCAP files using CICFlowMeter may require debugging. Follow [this video](https://youtu.be/iM2fBy8FUnw) for guidance.

## Usage

1. Launch the web application by either following the installation steps above, or directly accessing the live application at [bachelor-thesis.streamlit.app](https://bachelor-thesis.streamlit.app).
2. Upload a network traffic file (e.g., PCAP) through the interface.
3. The application processes the file and detects anomalies using the integrated machine learning models.
4. View and analyze the results through the visualization interface.

## Contribution

This project is a solo effort created as part of my bachelor thesis research.&#x20;

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

For more information or to access the live application, visit: [bachelor-thesis.streamlit.app](https://bachelor-thesis.streamlit.app).

