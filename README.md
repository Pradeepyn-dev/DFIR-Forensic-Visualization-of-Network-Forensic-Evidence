DFIR: Forensic Visualization of Network Forensic Evidence 📊

Project Description 📝
The DFIR project focuses on creating an advanced digital forensics tool designed for cybercrime investigators. This tool enhances the visualization of network forensic evidence using interactive graphs and charts. The primary emphasis is on traffic analysis, timeline graphs, and overall network activity visualization to provide investigators with a comprehensive understanding of communication patterns and network behavior over time.

Features ✨
•	Advanced Visualization: Intuitive graphics and layouts to represent complex network data, aiding in the understanding of intricate communication patterns.
•	Traffic Analysis: Analyze and understand device interactions, with real-time analytics offering insights into network behavior.
•	Timeline Graphs: Chronologically display communication events, allowing for tracking and understanding the sequence and impact of cyber incidents.
•	Comprehensive Understanding: Use visual aids like graphs and charts to help uncover hidden connections and patterns within network data.

Implementation ⚙️
•	GUI Components: Implemented using PyQt5 widgets such as QMainWindow, QWidget, QTabWidget, QPushButton, QVBoxLayout, and QFileDialog.
•	Packet Analysis: Custom modules for packet analysis, integrated with matplotlib for data visualization.
•	Packet Details Window: The PacketWindow class displays detailed information about specific packets when selected from the main window.
•	Tabs for Visualization: Multiple tabs (Tab2 to Tab6) represent different visualizations related to packet analysis, each using a matplotlib figure embedded in a canvas.
•	Main Application Window: The MainWindow class serves as the central window, organizing the packet analysis results and user interactions.

Installation 🚀
To set up the DFIR project:
1.	Clone the Repository:
git clone https://github.com/yourusername/DFIR.git
2.	Navigate to the Project Directory:
cd DFIR


3.	Install Dependencies:
pip install -r requirements.txt
4.	Run the Application:
python main.py

Usage 💻
The DFIR tool can be used for analyzing network traffic captured in PCAP files and generating various visualizations.
Example Usage
•	Start Real-Time Analysis: Select the network interface and click on "Start Capture" to begin real-time packet capture and analysis.
•	Load a PCAP File: Open a PCAP file using the file dialog to analyze previously captured network data.
•	View Packet Details: Detailed information about each packet is available by clicking on it in the packet list.

Visualizations
•	Traffic Volume Histogram: Shows communication patterns between IPs.
•	Protocol Distribution: Displays the distribution of protocols within the network traffic.
•	Traffic by Ports: Analyzes traffic volume across different network ports.
•	Packet Length Distribution: Visualizes the frequency of packet lengths within the captured data.

Results 🏆
•	Main Window: Provides an overview of the network traffic and options to start capturing or load PCAP files.
•	Real-Time Analysis: Allows selection of network interfaces and start of real-time data capture.
•	Detailed Protocol and Traffic Analysis: Provides in-depth analysis of protocols, packet lengths, and traffic patterns.

Contributing 🤝
We welcome contributions to enhance the DFIR project! To contribute:
1.	Fork the Repository: Click "Fork" on the GitHub repository page.
2.	Create a Branch:
git checkout -b feature-branch
3.	Make Changes: Implement your feature or fix a bug, then commit and push your changes to your fork.
4.	Submit a Pull Request: Provide a detailed description of your changes and submit a pull request.
   
License 📜
This project is licensed under the MIT License - see the LICENSE file for details.

Contact 📧
For questions or support, contact:
Pradeep Y N – pradeep.trin@gmail.com

