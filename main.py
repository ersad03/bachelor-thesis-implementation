import streamlit as st
from streamlit_option_menu import option_menu
import os
import sys


# Set the page configuration once at the start - This MUST be the first Streamlit command
st.set_page_config(page_title="Streamlit Navigation iForest", layout="centered")

# Define the folder paths for different sections using absolute paths
script_dir = os.path.dirname(os.path.abspath(__file__))
folder_paths = {
    "Ssh": os.path.join(script_dir, "1.ssh-capture"),  # Key is changed to "Ssh" but path remains the same
    "Kitsune": os.path.join(script_dir, "2.kitsune"),
    "rForest": os.path.join(script_dir, "3.rforest"),
    "Convert": os.path.join(script_dir, "4.convert"),
    "Map": os.path.join(script_dir, "5.visualize"),  # Key is "Map" with underlying "visualize.py"
    "Rep": os.path.join(script_dir, "6.files")
}

# Add the directories to the system path to ensure modules can be found
for path in folder_paths.values():
    if path not in sys.path:
        sys.path.append(path)

# Create a horizontal navigation menu with the new "Ssh" and "Map" options
selected = option_menu(
    menu_title=None,  # Leave menu title as None for horizontal menu
    options=["Ssh", "Kitsune", "rForest", "Convert", "Map", "Rep"],  # "Map" is displayed instead of "Visualize"
    icons=["terminal", "graph-up", "tree", "repeat", "compass", "folder"],  # Using "network-wired" icon for "Map"
    menu_icon="cast",  # Optional menu icon
    default_index=0,  # Optional default selected index
    orientation="horizontal",  # Set the menu to horizontal
    styles={
        "container": {
            "padding": "0px",
        },
        "icon": {
            "font-size": "20px",  # Ensure icons are a consistent size
            "vertical-align": "middle",  # Align icons vertically to middle
        },
        "nav-link": {
            "text-align": "center",  # Center-align text in the menu items
            "margin": "0px",
            "padding": "8px 12px",  # Adjust padding to balance spacing
            "vertical-align": "middle",  # Align text vertically to middle
        },
        "nav-link-selected": {
            # Only adjust the necessary properties, do not change colors
            "font-weight": "bold",  # Highlight the selected option with bold text
        }
    }
)

# Display content based on the selected menu
if selected == "Ssh":
    # Change the working directory to the folder containing ssh-capture.py, but display "Ssh"
    os.chdir(folder_paths["Ssh"])
    with open("ssh-capture.py") as file:
        exec(file.read(), globals())

elif selected == "Kitsune":
    # Change the working directory to the folder containing examplestreamlit.py
    os.chdir(folder_paths["Kitsune"])
    with open("streamlit.py") as file:
        exec(file.read(), globals())

elif selected == "rForest":
    # Change the working directory to the folder containing app.py
    os.chdir(folder_paths["rForest"])
    with open("app.py") as file:
        exec(file.read(), globals())

elif selected == "Convert":
    # Change the working directory to the folder containing convert.py
    os.chdir(folder_paths["Convert"])
    with open("convert.py") as file:
        exec(file.read(), globals())

elif selected == "Map":
    # Change the working directory to the folder containing visualize.py, but display "Map"
    os.chdir(folder_paths["Map"])
    with open("visualize.py") as file:
        exec(file.read(), globals())

elif selected == "Rep":
    # Change the working directory to the folder containing repository.py
    os.chdir(folder_paths["Rep"])
    with open("repository.py") as file:
        exec(file.read(), globals())
