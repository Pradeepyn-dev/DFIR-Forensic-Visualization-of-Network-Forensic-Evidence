from ast import dump
import sys
from scapy.all import sniff
from PyQt5.QtWidgets import QApplication, QMainWindow, QVBoxLayout, QLabel, QPushButton, QWidget, QScrollArea, QDialog, QTextEdit
from PyQt5.QtCore import Qt, QThread, pyqtSignal
import tempfile

class PacketCaptureThread(QThread):
    packet_captured = pyqtSignal(str)

    def __init__(self):
        super().__init__()

    def run(self):
        # Capture packets on the default network interface
        sniff(prn=self.handle_packet, count=0)

    def handle_packet(self, packet):
        # Process the captured packet
        packet_info = packet.show(dump=True)
        self.packet_captured.emit(packet_info)

class PacketInfoWindow(QDialog):
    def __init__(self, packet_info):
        super().__init__()

        self.setWindowTitle("Packet Information")
        self.setGeometry(200, 200, 400, 300)

        layout = QVBoxLayout()

        # Create label for packet info
        self.packet_label = QTextEdit()
        self.packet_label.setReadOnly(True)
        self.packet_label.setText(packet_info)
        layout.addWidget(self.packet_label)

        self.setLayout(layout)

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Real-Time Packet Capture")
        self.setGeometry(100, 100, 800, 600)

        layout = QVBoxLayout()

        # Create scroll area
        self.scroll_area = QScrollArea()
        self.scroll_area.setWidgetResizable(True)

        # Create widget for packet buttons
        self.packet_buttons_widget = QWidget()
        self.packet_buttons_layout = QVBoxLayout(self.packet_buttons_widget)

        # Add widget to scroll area
        self.scroll_area.setWidget(self.packet_buttons_widget)
        layout.addWidget(self.scroll_area)

        # Create buttons
        self.start_button = QPushButton("Start Capture")
        self.start_button.clicked.connect(self.start_capture)
        layout.addWidget(self.start_button)

        self.stop_button = QPushButton("Stop Capture")
        self.stop_button.clicked.connect(self.stop_capture)
        layout.addWidget(self.stop_button)

        # Set layout
        central_widget = QWidget()
        central_widget.setLayout(layout)
        self.setCentralWidget(central_widget)

        # Initialize packet capture thread
        self.packet_capture_thread = PacketCaptureThread()
        self.packet_capture_thread.packet_captured.connect(self.update_packet_display)

    def start_capture(self):
        # Start packet capture thread
        # self.packet_info_dict.clear()
        while self.packet_buttons_layout.count():
            button = self.packet_buttons_layout.takeAt(0)
            if button.widget():
                button.widget().deleteLater()
        self.packet_capture_thread.start()

    def stop_capture(self):
        # Stop packet capture thread
        self.packet_capture_thread.terminate()
        self.packet_capture_thread.wait()

    def update_packet_display(self, packet_info):
        # Create button for each captured packet
        button = QPushButton(f"Packet {len(self.packet_buttons_layout)}")
        button.clicked.connect(lambda: self.show_packet_info(packet_info))
        self.packet_buttons_layout.addWidget(button)

    def show_packet_info(self, packet_info):
        # Open new window to display packet info
        packet_info_window = PacketInfoWindow(packet_info)
        packet_info_window.exec_()

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
