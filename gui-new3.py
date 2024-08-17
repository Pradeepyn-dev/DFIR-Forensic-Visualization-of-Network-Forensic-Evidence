import sys
from PyQt5.QtGui import QCloseEvent
from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
from PyQt5.QtCore import *
import psutil
import pywinstyles
import packets
from scapy.all import *
from scapy.layers.l2 import *
from scapy.layers.inet import *
import matplotlib.pyplot as plt
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
import features

pcapfile = "temp.pcap"

class TabHolder:
    tabs = []

class PacketWindow(QMainWindow):
    def __init__(self, path, row):
        super().__init__()
        self.setWindowTitle("Packet details")
        self.path = path
        self.row = row
        self.setGeometry(350, 350, 1000, 500)
        self.setStyleSheet("background-color: black;")
        pywinstyles.apply_style(self,"dark")

        self.layout1 = QVBoxLayout()
        
        scroll_area = QScrollArea(self)
        scroll_area.setWidgetResizable(True)
        self.scroll_content = QWidget()
        self.scroll_content.setLayout(self.layout1)
        scroll_area.setWidget(self.scroll_content)
        scroll_area.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.setCentralWidget(scroll_area)        

        k = packets.packet_details(self.path, row)
        self.label = QLabel(k)
        self.label.setStyleSheet("color: white; font-size: 20px; width: 100%;")
        self.layout1.addWidget(self.label)

class PacketInfoWindow(QMainWindow):
    def __init__(self, packet):
        super().__init__()
        self.setWindowTitle("Packet details")
        self.setGeometry(350, 350, 1000, 500)

        layout = QVBoxLayout()
        self.setStyleSheet("background-color: black;")
        pywinstyles.apply_style(self,"dark")

        scroll_area = QScrollArea(self)
        scroll_area.setWidgetResizable(True)
        self.scroll_content = QWidget()
        self.scroll_content.setLayout(layout)
        scroll_area.setWidget(self.scroll_content)
        scroll_area.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.setCentralWidget(scroll_area)

        self.packet_label = QLabel(packet)
        self.packet_label.setStyleSheet("color: white; font-size: 20px; width: 100%;")
        layout.addWidget(self.packet_label)

        # self.setLayout(layout)

class PacketCaptureThread(QThread):
    packet_captured = pyqtSignal(object)

    def __init__(self, interface):
        super().__init__()
        self.interface = interface

    def run(self):
        sniff(prn=self.handle_packet, count=0, iface=self.interface)

    def handle_packet(self, packet):
        self.packet_captured.emit(packet)
        wrpcap(pcapfile, packet, append=True)

class RealtimeAnalyze(QWidget):
    def __init__(self):
        super().__init__()
        self.layout1 = QVBoxLayout()
        self.scroll_area = QScrollArea()
        self.scroll_area.setWidgetResizable(True)
        self.scroll_area.setStyleSheet("border: 1px solid white; border-radius: 5px;")
        self.scroll_area.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)

        self.packet_labels_widget = QWidget()
        self.packet_labels_layout = QVBoxLayout(self.packet_labels_widget)

        stylesheet = """
                background-color: black; 
                color: white; 
                font-family: cursive; 
                border: 2px solid white;
                height: 50px;
                border-radius: 5px;
                font-size: 20px;
            """

        layout2 = QHBoxLayout()

        name = QLabel("Realtime Monitoring")
        name.setStyleSheet("width: 300px; color: white; font-size: 25px;")
        name.setAlignment(Qt.AlignCenter)
        layout2.addWidget(name)

        save_button = QPushButton("Save")
        save_button.setStyleSheet(stylesheet)
        save_button.clicked.connect(self.savepcap)
        layout2.addWidget(save_button)

        self.layout1.addLayout(layout2)

        self.interface_combo = QComboBox()
        self.interface_combo.setStyleSheet("color: white; height: 50px; font-size: 23px; border: 2px solid white; padding: 4px; padding-left: 10px; border-radius: 5px;")
        self.interface_combo.addItems(psutil.net_if_addrs())
        self.layout1.addWidget(self.interface_combo)

        self.scroll_area.setWidget(self.packet_labels_widget)
        self.layout1.addWidget(self.scroll_area)
        self.scroll_area.setAlignment(Qt.AlignTop)

        self.start_button = QPushButton("Start Capture")
        self.start_button.clicked.connect(self.start_capture)
        self.layout1.addWidget(self.start_button)

        self.stop_button = QPushButton("Stop Capture")
        self.stop_button.clicked.connect(self.stop_capture)
        self.layout1.addWidget(self.stop_button)

        self.start_button.setStyleSheet(stylesheet)
        self.stop_button.setStyleSheet(stylesheet)

        self.setLayout(self.layout1)

    def start_capture(self):
        interface = self.interface_combo.currentText()
        self.packet_capture_thread = PacketCaptureThread(interface)
        self.packet_capture_thread.packet_captured.connect(self.update_packet_display)
        for i in range(TabHolder.tabs.count() - 1, 1, -1):
            TabHolder.tabs.removeTab(i)
        self.packet_capture_thread.start()

    def stop_capture(self):
        self.packet_capture_thread.terminate()
        self.packet_capture_thread.wait()
        if(os.path.exists(pcapfile)):
            TabHolder.tabs.addTab(Tab1(pcapfile), "Analyze")
            TabHolder.tabs.addTab(Tab2(pcapfile), "Protocol")
            TabHolder.tabs.addTab(Tab3(pcapfile), "Traffic Volume")
            TabHolder.tabs.addTab(Tab4(pcapfile), "Top Talkers")
            TabHolder.tabs.addTab(Tab5(pcapfile), "Length")
            TabHolder.tabs.addTab(Tab6(pcapfile), "Port")

    def savepcap(self):
        msg = QMessageBox()
        if not os.path.exists(pcapfile):
            msg.setText("<font color='black'>There is nothing to save!!!</font>")
            msg.setWindowTitle("Error")
            msg.setIcon(QMessageBox.Critical)
            msg.exec_()
            return
        elif self.packet_capture_thread.isRunning():
            msg.setText("<font color='black'>Stop capturing to be able to save the file</font>")
            msg.setWindowTitle("Error")
            msg.setIcon(QMessageBox.Critical)
            msg.exec_()
            return

        with open(pcapfile, 'rb') as file:
            file_contents = file.read()

        destination_file, _ = QFileDialog.getSaveFileName(self, "Save File As", filter="PCAP (*.pcap)")

        if destination_file:
            if not destination_file.endswith(".pcap"):
                destination_file += ".pcap"
            with open(destination_file, 'wb') as file:
                file.write(file_contents)
                file.flush()
                msg.setText("<font color='black'>File saved successfully</font>")
                msg.setWindowTitle("Success")
                msg.setIcon(QMessageBox.Information)
                msg.exec_()

    def update_packet_display(self, packet):
        hbox = QHBoxLayout()
        label = QLabel(str(len(self.packet_labels_layout)))
        label.setStyleSheet("background-color: black; color: white; font-size: 20px; padding: 10px; border: 5px solid black;")
        label.mousePressEvent = lambda event: self.show_packet_info(packet.show(dump=True))
        hbox.addWidget(label)
        if IP in packet:
            label = QLabel(f"{packet[IP].src}")
            label.setStyleSheet("background-color: black; color: white; font-size: 20px; padding: 10px; border: 5px solid black;")
            label.mousePressEvent = lambda event: self.show_packet_info(packet.show(dump=True))
            hbox.addWidget(label)
            label = QLabel(f"{packet[IP].dst}")
            label.setStyleSheet("background-color: black; color: white; font-size: 20px; padding: 10px; border: 5px solid black;")
            label.mousePressEvent = lambda event: self.show_packet_info(packet.show(dump=True))
            hbox.addWidget(label)
        elif Ether in packet:
            label = QLabel(f"{packet[Ether].src}")
            label.setStyleSheet("background-color: black; color: white; font-size: 20px; padding: 10px; border: 5px solid black;")
            label.mousePressEvent = lambda event: self.show_packet_info(packet.show(dump=True))
            hbox.addWidget(label)
            label = QLabel(f"{packet[Ether].dst}")
            label.setStyleSheet("background-color: black; color: white; font-size: 20px; padding: 10px; border: 5px solid black;")
            label.mousePressEvent = lambda event: self.show_packet_info(packet.show(dump=True))
            hbox.addWidget(label)
        else:
            label = QLabel("N/A")
            label.setStyleSheet("background-color: black; color: white; font-size: 20px; padding: 10px; border: 5px solid black;")
            label.mousePressEvent = lambda event: self.show_packet_info(packet.show(dump=True))
            hbox.addWidget(label)
            label = QLabel("N/A")
            label.setStyleSheet("background-color: black; color: white; font-size: 20px; padding: 10px; border: 5px solid black;")
            label.mousePressEvent = lambda event: self.show_packet_info(packet.show(dump=True))
            hbox.addWidget(label)
        
        self.packet_labels_layout.addLayout(hbox)
        self.scroll_area.verticalScrollBar().setValue(self.scroll_area.verticalScrollBar().maximum())

    def show_packet_info(self, packet_info):
        self.packet_info_window = PacketInfoWindow(packet_info)
        self.packet_info_window.show()

    def thread_health(self):
        return self.packet_capture_thread.isRunning()

class Tab1(QScrollArea):
    def __init__(self, filepath):
        super().__init__()
        self.filepath = filepath
        self.tab1_layout = QVBoxLayout()

        details = QLabel("Detailed Analysis")
        details.setStyleSheet("background-color: black; color: white; font-size: 30px; padding: 10px; border: 5px solid black;")
        details.setAlignment(Qt.AlignCenter)
        self.tab1_layout.addWidget(details)
       
        self.setWidgetResizable(True)
        self.scroll_content = QWidget()
        self.scroll_content.setLayout(self.tab1_layout)
        self.setWidget(self.scroll_content)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)

        index, srclist, dstlist, proto = packets.print_packet_ip_mappings(self.filepath)
        for i in index:
            hbox = QHBoxLayout()
            label = QLabel(str(i))
            label.setStyleSheet("background-color: black; color: white; font-size: 22px; padding: 10px; border: 5px solid black;")
            label.mousePressEvent = lambda event, row=i: self.rowClick(row)
            hbox.addWidget(label)
            label = QLabel(str(srclist[i-1]))
            label.setStyleSheet("background-color: black; color: white; font-size: 22px; padding: 10px; border: 5px solid black;")
            label.mousePressEvent = lambda event, row=i: self.rowClick(row)
            hbox.addWidget(label)
            label = QLabel(str(dstlist[i-1]))
            label.setStyleSheet("background-color: black; color: white; font-size: 22px; padding: 10px; border: 5px solid black;")
            label.mousePressEvent = lambda event, row=i: self.rowClick(row)
            hbox.addWidget(label)
            label = QLabel(str(proto[i-1]))
            label.setStyleSheet("background-color: black; color: white; font-size: 22px; padding: 10px; border: 5px solid black;")
            label.mousePressEvent = lambda event, row=i: self.rowClick(row)
            hbox.addWidget(label)
            self.tab1_layout.addLayout(hbox)

    def rowClick(self, row):
        # print(f"Row {row} clicked!")
        self.packet = PacketWindow(self.filepath, row)
        self.packet.show()

class ProtocolInfoWindow(QMainWindow):
    def __init__(self, src_ips, dst_ips, index, protocols, value, filepath):
        super().__init__()
        self.filepath = filepath
        self.setWindowTitle("Protocol Based Information")
        self.setGeometry(350, 350, 1000, 700)
        self.setStyleSheet("background-color: black;")
        pywinstyles.apply_style(self, "dark")

        layouts = QVBoxLayout()

        details = QLabel(f"Packets belonging to protocol: {value}")
        details.setStyleSheet("background-color: black; color: white; font-size: 30px; padding: 10px; border: 5px solid black;")
        details.setAlignment(Qt.AlignCenter)
        details.setAlignment(Qt.AlignTop)
        layouts.addWidget(details)

        for i in range(len(index)):
            if protocols[i] == value:
                layout = QHBoxLayout()
                index_label = QLabel(f"{i+1}")
                index_label.setAlignment(Qt.AlignTop)
                index_label.setStyleSheet("background-color: black; color: white; font-size: 22px; padding: 10px; border: 5px solid black;")
                index_label.mousePressEvent = lambda event, row=int(index[i]): self.rowClick(row)
                src_ip_label = QLabel(f"{src_ips[i]}")
                src_ip_label.setAlignment(Qt.AlignTop)
                src_ip_label.setStyleSheet("background-color: black; color: white; font-size: 22px; padding: 10px; border: 5px solid black;")
                src_ip_label.mousePressEvent = lambda event, row=int(index[i]): self.rowClick(row)
                dst_ip_label = QLabel(f"{dst_ips[i]}")
                dst_ip_label.setAlignment(Qt.AlignTop)
                dst_ip_label.setStyleSheet("background-color: black; color: white; font-size: 22px; padding: 10px; border: 5px solid black;")
                dst_ip_label.mousePressEvent = lambda event, row=int(index[i]): self.rowClick(row)

                layout.addWidget(index_label)
                layout.addWidget(src_ip_label)
                layout.addWidget(dst_ip_label)

                layouts.addLayout(layout)

        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setStyleSheet("background-color: black;")
        scroll_widget = QWidget()
        scroll_widget.setLayout(layouts)
        scroll_area.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll_area.setWidget(scroll_widget)

        self.setCentralWidget(scroll_area)

    def rowClick(self, row):
        self.packet = PacketWindow(self.filepath, row)
        self.packet.show()


class Tab2(QWidget):
    def __init__(self, filepath):
        super().__init__()
        self.filepath = filepath
        self.figure = plt.figure(figsize=(12, 10), facecolor="black")
        self.canvas = FigureCanvas(self.figure)

        self.layout1 = QVBoxLayout()
        self.setLayout(self.layout1)

        self.layout1.addWidget(self.canvas)

        self.index, self.src_ips, self.dst_ips, self.protocols = packets.print_packet_ip_mappings(self.filepath)

        self.sorted_protocol_counts, self.sorted_protocols, colors = features.protocol_distribution(filepath)

        self.pie = plt.pie(self.sorted_protocol_counts.values(), labels=None, autopct=None, colors=colors, wedgeprops={'linewidth': 2})

        legend_labels = [f'{protocol} ({self.sorted_protocol_counts[protocol]} packets, {100*self.sorted_protocol_counts[protocol]/sum(self.sorted_protocol_counts.values()):.1f}%)' for protocol in self.sorted_protocols]
        handles = [plt.Rectangle((0,0),1,1, color=colors[i]) for i in range(len(self.sorted_protocols))]
        legend = plt.legend(handles, legend_labels, loc=(-0.45, 0.25), prop={'family': 'cursive', 'size': 14}, facecolor='black')
        for text in legend.get_texts():
            text.set_color('white')

        plt.gcf().canvas.mpl_connect('button_press_event', self.on_click)
        plt.title('Protocol Distribution (Lowermost Layer)', color='white', fontname='cursive', fontsize=20)

    def on_click(self, event):
        if event.inaxes == plt.gca(): 
            for i, pie_wedge in enumerate(self.pie[0]): 
                if pie_wedge.contains_point([event.x, event.y]):  
                    self.protocolwindow = ProtocolInfoWindow(self.src_ips, self.dst_ips, self.index, self.protocols, self.sorted_protocols[i], self.filepath)
                    self.protocolwindow.show()

class Tab3(QWidget):
    def __init__(self, filepath):
        super().__init__()
        self.figure = plt.figure(facecolor="black")
        self.canvas = FigureCanvas(self.figure)

        self.layout1 = QVBoxLayout()
        self.setLayout(self.layout1)

        self.layout1.addWidget(self.canvas)

        ax = plt.axes()
        ax.set_facecolor('black')
        ax.spines['top'].set_color('white')
        ax.spines['bottom'].set_color('white')
        ax.spines['left'].set_color('white')
        ax.spines['right'].set_color('white')
        ax.tick_params(axis='both', which='both', direction='in')

        traffic_volume = features.traffic_volume(filepath)

        plt.hist(traffic_volume.index, weights=traffic_volume.values, bins=25, edgecolor='black', color='#e7ba52')  # Add bin color
        plt.xlabel('Time (milliseconds)', color='white', fontsize=18, fontfamily='cursive')
        plt.ylabel('Traffic Volume (bytes)', color='white', fontsize=18, fontfamily='cursive')
        plt.title('Traffic Volume Histogram', color='white', fontsize=20, fontfamily='cursive')

        plt.xticks(color='white', fontfamily='cursive', fontsize=15)
        plt.yticks(color='white', fontfamily='cursive', fontsize=15)

class Tab4(QWidget):
    def __init__(self, filepath):
        super().__init__()
        self.figure = plt.figure(facecolor="black")
        self.canvas = FigureCanvas(self.figure)

        self.layout1 = QVBoxLayout()
        self.setLayout(self.layout1)

        self.layout1.addWidget(self.canvas)
        ax = plt.axes()
        ax.set_facecolor('black')
        ax.spines['top'].set_color('white')
        ax.spines['bottom'].set_color('white')
        ax.spines['left'].set_color('white')
        ax.spines['right'].set_color('white')
        ax.tick_params(axis='both', which='both', direction='in')

        plt.rcParams['font.family'] = 'cursive'
        plt.rcParams['font.size'] = 14

        plt.xlabel("Source IP", color='white', fontsize=14, fontfamily='cursive')
        plt.xticks([])

        top_talkers = features.top_talkers(filepath)

        bars = top_talkers.plot(kind='bar', color='#843c39', edgecolor='black')

        for i, (index, value) in enumerate(top_talkers.items()):
            bars.text(i, 50, index, color='white', fontweight='bold', ha='center', va='bottom', rotation=90)

        plt.ylabel('Total Traffic (bytes)', color='white', fontsize=18, fontfamily='cursive')
        plt.title('Top Talkers', color='white', fontsize=18, fontfamily='cursive')

        plt.yticks(color='white', fontsize=15, fontfamily='cursive')

class Tab5(QWidget):
    def __init__(self, filepath):
        super().__init__()
        self.figure = plt.figure(facecolor="black")
        self.canvas = FigureCanvas(self.figure)

        self.layout1 = QVBoxLayout()
        self.setLayout(self.layout1)

        self.layout1.addWidget(self.canvas)
        ax = plt.axes()
        ax.set_facecolor('black')
        ax.spines['top'].set_color('white')
        ax.spines['bottom'].set_color('white')
        ax.spines['left'].set_color('white')
        ax.spines['right'].set_color('white')
        ax.tick_params(axis='both', which='both', direction='in')

        packet_lengths = features.packet_length_distribution(filepath)

        plt.hist(packet_lengths, bins=50, color='lightgreen', edgecolor='black')
        plt.xlabel('Packet Length', color='white', fontsize=18, fontfamily='cursive')
        plt.ylabel('Frequency', color='white', fontsize=18, fontfamily='cursive')
        plt.title('Packet Length Distribution', color='white', fontsize=18, fontfamily='cursive')
        plt.xticks(color='white', fontfamily='cursive', fontsize=15)
        plt.yticks(color='white', fontfamily='cursive', fontsize=15)

class Tab6(QWidget):
    def __init__(self, filepath):
        super().__init__()
        self.figure = plt.figure(figsize=(12, 8), facecolor="black")
        self.canvas = FigureCanvas(self.figure)

        self.layout1 = QVBoxLayout()
        self.setLayout(self.layout1)

        self.layout1.addWidget(self.canvas)

        ax = plt.subplot(3, 2, 1)
        ax.set_facecolor('black')
        ax.spines['top'].set_color('white')
        ax.spines['bottom'].set_color('white')
        ax.spines['left'].set_color('white')
        ax.spines['right'].set_color('white')
        ax.tick_params(axis='both', which='both', direction='in')

        port_counts, ports_low, ports_high, sorted_ports_low, sorted_ports_high = features.traffic_ports(filepath)

        plt.hist(ports_low, weights=[port_counts[port] for port in ports_low], bins=50, color='skyblue', edgecolor='black')
        plt.xlabel('Port Number (1-1024)', color='white', fontsize=12, fontfamily='cursive')  # Change label font to cursive and size to 16
        plt.ylabel('Frequency', color='white', fontsize=12, fontfamily='cursive')  # Change label font to cursive and size to 16
        plt.title('Traffic by Port (1-1024)', color='white', fontsize=12, fontfamily='cursive')  # Change title font to cursive and size to 16
        plt.xticks(rotation=0, color='white', fontsize=10, fontfamily='cursive')  # Change xticks to cursive and size to 12
        plt.yticks(color='white', fontsize=10, fontfamily='cursive')  # Change yticks to cursive and size to 12
        
        ax = plt.subplot(3, 2, 2)
        ax.set_facecolor('black')
        ax.spines['top'].set_color('white')
        ax.spines['bottom'].set_color('white')
        ax.spines['left'].set_color('white')
        ax.spines['right'].set_color('white')
        ax.tick_params(axis='both', which='both', direction='in')

        plt.bar([str(port[0]) for port in sorted_ports_low], [port[1] for port in sorted_ports_low], color='skyblue')
        plt.xlabel('Port Number', color='white', fontsize=12, fontfamily='cursive')  # Change label font to cursive and size to 16
        plt.ylabel('Frequency', color='white', fontsize=12, fontfamily='cursive')  # Change label font to cursive and size to 16
        plt.title('Top 10 Ports by Traffic (1-1024)', color='white', fontsize=12, fontfamily='cursive')  # Change title font to cursive and size to 16
        plt.xticks(rotation=45, color='white', fontsize=10, fontfamily='cursive')  # Change xticks to cursive and size to 12
        plt.yticks(color='white', fontsize=10, fontfamily='cursive')  # Change yticks to cursive and size to 12
        
        ax = plt.subplot(2, 2, 3)
        ax.set_facecolor('black')
        ax.spines['top'].set_color('white')
        ax.spines['bottom'].set_color('white')
        ax.spines['left'].set_color('white')
        ax.spines['right'].set_color('white')
        ax.tick_params(axis='both', which='both', direction='in')

        plt.hist(ports_high, weights=[port_counts[port] for port in ports_high], bins=50, color='skyblue', edgecolor='black')
        plt.xlabel('Port Number (>1024)', color='white', fontsize=12, fontfamily='cursive')  # Change label font to cursive and size to 16
        plt.ylabel('Frequency', color='white', fontsize=12, fontfamily='cursive')  # Change label font to cursive and size to 16
        plt.title('Traffic by Port (>1024)', color='white', fontsize=12, fontfamily='cursive')  # Change title font to cursive and size to 16
        plt.xticks(rotation=0, color='white', fontsize=10, fontfamily='cursive')  # Change xticks to cursive and size to 12
        plt.yticks(color='white', fontsize=10, fontfamily='cursive')  # Change yticks to cursive and size to 12
        
        ax = plt.subplot(2, 2, 4)
        ax.set_facecolor('black')
        ax.spines['top'].set_color('white')
        ax.spines['bottom'].set_color('white')
        ax.spines['left'].set_color('white')
        ax.spines['right'].set_color('white')
        ax.tick_params(axis='both', which='both', direction='in')

        plt.bar([str(port[0]) for port in sorted_ports_high], [port[1] for port in sorted_ports_high], color='skyblue')
        plt.xlabel('Port Number', color='white', fontsize=12, fontfamily='cursive')  # Change label font to cursive and size to 16
        plt.ylabel('Frequency', color='white', fontsize=12, fontfamily='cursive')  # Change label font to cursive and size to 16
        plt.title('Top 10 Ports by Traffic (>1024)', color='white', fontsize=12, fontfamily='cursive')  # Change title font to cursive and size to 16
        plt.xticks(rotation=45, color='white', fontsize=10, fontfamily='cursive')  # Change xticks to cursive and size to 12
        plt.yticks(color='white', fontsize=10, fontfamily='cursive')  # Change yticks to cursive and size to 12

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Tab Example")
        self.setGeometry(100, 100, 1400, 900)
        self.setStyleSheet("background-color: black;")

        TabHolder.tabs = QTabWidget()
        self.setCentralWidget(TabHolder.tabs)

        self.create_tabs()
        pywinstyles.apply_style(self,"dark")

    def create_tabs(self):
        for i in range(5):
            tab = QWidget()
            tab.setStyleSheet("background-color: black;")
            # self.tabs.addTab(tab, f"Tab {i + 1}")
            TabHolder.tabs.tabBar().setStyleSheet("""
                QTabBar::tab { 
                    background-color: black;
                    color: white;
                    border: 1px solid #33373c; 
                    border-radius: 2px; 
                    width: 150px; 
                    height: 40px; 
                    font-family: cursive;
                    font-size: 20px;
                }
                QTabBar::tab:selected {
                    background-color: white;
                    font-size: 20px;
                    color: black;
                }
                """
            )

        self.open = QWidget()
        self.open_layout = QVBoxLayout()
        self.open.setLayout(self.open_layout)

        TabHolder.tabs.addTab(self.open, "Open file")
        TabHolder.tabs.addTab(RealtimeAnalyze(), "Realtime")

        s = "Packet visualizer\nClick on 'Open File' to visualize the file\nSelect the Realtime tab to capture and analyze packets in realtime"
        self.details = QLabel(s)
        self.details.setStyleSheet("color: white; font-size: 30px; font-family: cursive")
        self.details.setAlignment(Qt.AlignTop)
        self.open_layout.addWidget(self.details)

        # Create button to open folder in tab 1
        self.open_file_button = QPushButton("Open File")
        self.open_file_button.setStyleSheet("""
                background-color: black; 
                color: white; 
                font-family: cursive; 
                border: 2px solid white;
                height: 50px;
                border-radius: 5px;
                font-size: 20px;
            """)
        self.open_file_button.clicked.connect(self.open_folder)
        self.open_layout.addWidget(self.open_file_button)

    def open_folder(self):
        self.filepath = QFileDialog.getOpenFileName(self, "Select file", filter="*.pcap")
        if self.filepath:
            self.open_layout.removeWidget(self.open_file_button)
            self.open_file_button.deleteLater()

            s = "File has been selected \n\n"+self.filepath[0]+"\n"
            self.filenames = QLabel(s)
            self.filenames.setStyleSheet("color: white; font-size: 25px;")
            self.filenames.setAlignment(Qt.AlignTop)
            self.open_layout.addWidget(self.filenames)

            self.close_button = QPushButton("Close File")
            self.close_button.setStyleSheet("""
                background-color: black; 
                color: white; 
                font-family: cursive; 
                border: 2px solid white;
                height: 50px;
                width: 100px;
                border-radius: 5px;
                font-size: 20px;
            """)
            self.close_button.clicked.connect(self.closefile)
            self.open_layout.addWidget(self.close_button)

            TabHolder.tabs.addTab(Tab1(self.filepath[0]), "Analyze")
            TabHolder.tabs.addTab(Tab2(self.filepath[0]), "Protocol")
            TabHolder.tabs.addTab(Tab3(self.filepath[0]), "Traffic Volume")
            TabHolder.tabs.addTab(Tab4(self.filepath[0]), "Top Talkers")
            TabHolder.tabs.addTab(Tab5(self.filepath[0]), "Length")
            TabHolder.tabs.addTab(Tab6(self.filepath[0]), "Port")

    def closefile(self):
        for i in range(TabHolder.tabs.count() - 1, 1, -1):
            TabHolder.tabs.removeTab(i)

        self.open_layout.removeWidget(self.filenames)
        self.filenames.deleteLater()
        self.open_layout.removeWidget(self.close_button)
        self.close_button.deleteLater()

        self.open_file_button = QPushButton("Open File")
        self.open_file_button.setStyleSheet("""
                background-color: black; 
                color: white; 
                font-family: cursive; 
                border: 2px solid white;
                height: 50px;
                border-radius: 5px;
                font-size: 20px;
            """)
        self.open_file_button.clicked.connect(self.open_folder)
        self.open_layout.addWidget(self.open_file_button)

    def closeEvent(self, event):
        if os.path.exists(pcapfile):
            os.remove(pcapfile)
            
def main():
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
