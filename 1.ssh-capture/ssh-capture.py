import streamlit as st
import paramiko
import io

# Constants
PCAP_FILE_PATH = "/tmp/capture.pcap"
TCPDUMP_INSTALL_CMD = "apt-get install -y tcpdump"
CAPTURE_CMD_TEMPLATE = "tcpdump -i {interface} -c {count} -w {file_path}"

# Utility functions for validation
def validate_hostname(hostname):
    import re
    if re.match(r"^([a-zA-Z0-9_\-\.]+)$", hostname):
        return True
    else:
        st.error("Invalid hostname format.")
        return False

def validate_port(port):
    if 0 < port < 65536:
        return True
    else:
        st.error("Port number must be between 1 and 65535.")
        return False

# SSHManager class to encapsulate SSH logic
class SSHManager:
    def __init__(self, host, port, username, password=None):
        self.ssh = paramiko.SSHClient()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.host = host
        self.port = port
        self.username = username
        self.password = password

    def connect(self):
        try:
            self.ssh.connect(hostname=self.host, port=self.port, username=self.username, password=self.password)
            return True
        except paramiko.AuthenticationException:
            st.error("Authentication failed. Please check your password.")
        except paramiko.SSHException as ssh_exception:
            st.error(f"SSH connection error: {str(ssh_exception)}")
        except Exception as e:
            st.error(f"Connection failed: {str(e)}")
        return False

    def execute_command(self, command, use_sudo=False):
        if use_sudo and self.password:
            command = f'sudo -S {command}'
        try:
            stdin, stdout, stderr = self.ssh.exec_command(command, get_pty=True)
            if use_sudo and self.password:
                stdin.write(self.password + '\n')
                stdin.flush()
            stdout.channel.recv_exit_status()
            return stdout.read().decode(), stderr.read().decode()
        except Exception as e:
            st.error(f"Failed to execute command: {str(e)}")
            return None, str(e)

    def close(self):
        if self.ssh:
            self.ssh.close()
            return True
        return False

# Function to check if tcpdump is installed and install it if necessary
@st.cache_data
def check_tcpdump_installed(host, port, username, password):
    ssh_manager = SSHManager(host, port, username, password)
    if ssh_manager.connect():
        stdout, _ = ssh_manager.execute_command('which tcpdump')
        ssh_manager.close()
        return stdout.strip() != ""
    else:
        return False

def ensure_tcpdump_installed(ssh_manager_params):
    if not check_tcpdump_installed(
        ssh_manager_params['host'],
        ssh_manager_params['port'],
        ssh_manager_params['username'],
        ssh_manager_params['password']
    ):
        st.info("tcpdump not found. Installing...")
        ssh_manager = SSHManager(
            ssh_manager_params['host'],
            ssh_manager_params['port'],
            ssh_manager_params['username'],
            ssh_manager_params['password']
        )
        ssh_manager.connect()
        stdout, error = ssh_manager.execute_command(TCPDUMP_INSTALL_CMD, use_sudo=True)
        ssh_manager.close()
        if error:
            st.error("Failed to install tcpdump.")
        else:
            st.success("tcpdump installed successfully.")

# Reusable CSS function
def apply_custom_css():
    st.markdown(
        """
        <style>
        .captured-packets {
            font-family: "Courier New", Courier, monospace;
            font-size: 14px;
            color: #f8f9fa;
            background-color: #212529;
            border-radius: 5px;
            padding: 10px;
            max-height: 300px;
            overflow-y: auto;
            white-space: pre-wrap;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )

# Main Streamlit app
def main():
    st.title("Network Packet Capture via SSH")
    apply_custom_css()

    # Info box with the provided explanation
    st.info(
        "Remotely capture network packets on a server via SSH using tcpdump. You can configure the server connection, "
        "select a network interface, and specify the packet count. The captured packets can be downloaded as a .pcap file "
        "for analysis in Wireshark, or for further inspection using Kitsune's autoencoder-based NIDS or a Random Forest model trained on a DDoS dataset."
    )

    if 'state' not in st.session_state:
        st.session_state.state = {
            'connection_established': False,
            'interface': None,
            'packet_count': 10
        }

    state = st.session_state.state

    # SSH Connection Inputs
    host = st.text_input("Host", disabled=state['connection_established'])
    port = st.number_input("Port", value=22, disabled=state['connection_established'])
    username = st.text_input("Username", disabled=state['connection_established'])
    password = st.text_input("Password", type="password", disabled=state['connection_established'])

    if not state['connection_established']:
        if st.button("Connect"):
            if validate_hostname(host) and validate_port(port):
                ssh_manager = SSHManager(host, port, username, password=password)
                if ssh_manager.connect():
                    state['ssh_manager_params'] = {
                        'host': host,
                        'port': port,
                        'username': username,
                        'password': password
                    }
                    state['connection_established'] = True
                    ensure_tcpdump_installed(state['ssh_manager_params'])
                    st.rerun()
    else:
        if st.button("Disconnect"):
            state['ssh_manager_params'] = None
            state['connection_established'] = False
            st.rerun()

    if state['connection_established']:
        # Recreate the SSHManager instance when needed
        ssh_manager = SSHManager(
            state['ssh_manager_params']['host'],
            state['ssh_manager_params']['port'],
            state['ssh_manager_params']['username'],
            state['ssh_manager_params']['password']
        )
        ssh_manager.connect()

        # Network interface selection
        interfaces = get_network_interfaces(ssh_manager)
        if interfaces:
            state['interface'] = st.selectbox("Select Network Interface", interfaces)
            state['packet_count'] = st.number_input("Enter the number of packets to capture", min_value=1, value=state['packet_count'])

            if st.button("Start Capture"):
                start_capture(state, ssh_manager)
        
        ssh_manager.close()

def get_network_interfaces(ssh_manager):
    stdout, _ = ssh_manager.execute_command("ip -o link show | awk -F': ' '{print $2}'")
    interfaces = stdout.splitlines()
    return [iface for iface in interfaces if iface != 'lo']

def start_capture(state, ssh_manager):
    with st.spinner(f"Capturing {state['packet_count']} packets..."):
        capture_cmd = CAPTURE_CMD_TEMPLATE.format(interface=state['interface'], count=state['packet_count'], file_path=PCAP_FILE_PATH)
        ssh_manager.execute_command(f"rm -f {PCAP_FILE_PATH}", use_sudo=True)  # Clean old file
        ssh_manager.execute_command(capture_cmd, use_sudo=True)
        ssh_manager.execute_command(f"chmod 644 {PCAP_FILE_PATH}", use_sudo=True)
        st.success(f"Captured {state['packet_count']} packets on interface {state['interface']}")

        stdout, _ = ssh_manager.execute_command(f"tcpdump -r {PCAP_FILE_PATH}")
        stdout_lines = stdout.splitlines()
        filtered_output = "\n".join(line for line in stdout_lines if not line.startswith("reading from file"))
        st.markdown(f"<div class='captured-packets'>{filtered_output}</div>", unsafe_allow_html=True)

        sftp = ssh_manager.ssh.open_sftp()
        with sftp.open(PCAP_FILE_PATH, 'rb') as f:
            pcap_data = f.read()
        st.download_button("Download .pcap file", data=pcap_data, file_name="capture.pcap", mime="application/octet-stream")

if __name__ == "__main__":
    main()
