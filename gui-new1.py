import sys
from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
from PyQt5.QtCore import *
import pywinstyles
import packets
import matplotlib.pyplot as plt
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
import features

class PacketWindow(QMainWindow):
    def __init__(self, path, row):
        super().__init__()
        self.setWindowTitle("Packet details")
        self.path = path
        self.row = row
        self.setGeometry(350, 350, 1000, 500)
        self.setStyleSheet("background-color: black;")
        pywinstyles.apply_style(self,"dark")

        # self.widget = QWidget()
        self.layout1 = QVBoxLayout()
        # self.widget.setLayout(self.layout1)
        
        scroll_area = QScrollArea(self)
        scroll_area.setWidgetResizable(True)
        self.scroll_content = QWidget()
        self.scroll_content.setLayout(self.layout1)
        scroll_area.setWidget(self.scroll_content)
        scroll_area.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.setCentralWidget(scroll_area)

        k = packets.packet_details(self.path, row)
        # print(k)
        self.label = QLabel(k)
        self.label.setStyleSheet("color: white; font-size: 20px; width: 100%;")
        self.layout1.addWidget(self.label)

class Tab2(QWidget):
    def __init__(self):
        super().__init__()
        self.figure = plt.figure(figsize=(12, 10), facecolor="black")
        self.canvas = FigureCanvas(self.figure)

        self.layout1 = QVBoxLayout()
        self.setLayout(self.layout1)

        self.layout1.addWidget(self.canvas)

        sorted_protocol_counts, sorted_protocols, colors = features.protocol_distribution("example.pcap")

        pie = plt.pie(sorted_protocol_counts.values(), labels=None, autopct=None, colors=colors, wedgeprops={'linewidth': 2})

        # Create legend with consistent colors and white font color
        legend_labels = [f'{protocol} ({sorted_protocol_counts[protocol]} packets, {100*sorted_protocol_counts[protocol]/sum(sorted_protocol_counts.values()):.1f}%)' for protocol in sorted_protocols]
        handles = [plt.Rectangle((0,0),1,1, color=colors[i]) for i in range(len(sorted_protocols))]
        legend = plt.legend(handles, legend_labels, loc=(-0.45, 0.25), prop={'family': 'cursive', 'size': 14}, facecolor='black')
        for text in legend.get_texts():
            text.set_color('white')

        plt.title('Protocol Distribution (Lowermost Layer)', color='white', fontname='cursive', fontsize=20)

class Tab3(QWidget):
    def __init__(self):
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

        traffic_volume = features.traffic_volume('example.pcap')

        # Plot traffic volume histogram with bin color
        plt.hist(traffic_volume.index, weights=traffic_volume.values, bins=25, edgecolor='black', color='#843c39')  # Add bin color
        plt.xlabel('Time (milliseconds)', color='white', fontsize=18, fontfamily='cursive')
        plt.ylabel('Traffic Volume (bytes)', color='white', fontsize=18, fontfamily='cursive')
        plt.title('Traffic Volume Histogram', color='white', fontsize=20, fontfamily='cursive')

        # Set the color of xticks and yticks to white
        plt.xticks(color='white', fontfamily='cursive', fontsize=15)
        plt.yticks(color='white', fontfamily='cursive', fontsize=15)

        # plt.show()

class Tab4(QWidget):
    def __init__(self):
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

        # Set font properties
        plt.rcParams['font.family'] = 'cursive'
        plt.rcParams['font.size'] = 14

        # Remove x label and ticks
        plt.xlabel("Source IP", color='white', fontsize=14, fontfamily='cursive')
        plt.xticks([])

        top_talkers = features.top_talkers("example.pcap")

        # Plot the bar chart with white bars and black borders
        bars = top_talkers.plot(kind='bar', color='#e7ba52', edgecolor='black')

        # Add IP labels inside bars vertically
        for i, (index, value) in enumerate(top_talkers.items()):
            bars.text(i, 50, index, color='black', fontweight='bold', ha='center', va='bottom', rotation=90)

        # Set y label and title
        plt.ylabel('Total Traffic (bytes)', color='white', fontsize=18, fontfamily='cursive')
        plt.title('Top Talkers', color='white', fontsize=18, fontfamily='cursive')

        # Adjust label colors to white
        plt.yticks(color='white', fontsize=15, fontfamily='cursive')

        # Show the plot
        # plt.show()

class Tab5(QWidget):
    def __init__(self):
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

        packet_lengths = features.packet_length_distribution("example.pcap")

        plt.hist(packet_lengths, bins=50, color='lightgreen', edgecolor='black')
        plt.xlabel('Packet Length', color='white', fontsize=18, fontfamily='cursive')
        plt.ylabel('Frequency', color='white', fontsize=18, fontfamily='cursive')
        plt.title('Packet Length Distribution', color='white', fontsize=18, fontfamily='cursive')
        plt.xticks(color='white', fontfamily='cursive', fontsize=15)
        plt.yticks(color='white', fontfamily='cursive', fontsize=15)

class Tab6(QWidget):
    def __init__(self):
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

        port_counts, ports_low, ports_high, sorted_ports_low, sorted_ports_high = features.traffic_ports('example.pcap')

        plt.hist(ports_low, weights=[port_counts[port] for port in ports_low], bins=50, color='skyblue', edgecolor='black')
        plt.xlabel('Port Number (1-1024)', color='white', fontsize=12, fontfamily='cursive')  # Change label font to cursive and size to 16
        plt.ylabel('Frequency', color='white', fontsize=12, fontfamily='cursive')  # Change label font to cursive and size to 16
        plt.title('Traffic by Port (1-1024)', color='white', fontsize=12, fontfamily='cursive')  # Change title font to cursive and size to 16
        plt.xticks(rotation=0, color='white', fontsize=10, fontfamily='cursive')  # Change xticks to cursive and size to 12
        plt.yticks(color='white', fontsize=10, fontfamily='cursive')  # Change yticks to cursive and size to 12
        # plt.axes  # Change axis color to black

        # Plot bar graph for top 10 ports in ports_low
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
        # plt.axis(color='black')  # Change axis color to black

        # Plot histogram for ports beyond 1024
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
        # plt.axis(color='black')  # Change axis color to black

        # Plot bar graph for top 10 ports in ports_high
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
        # plt.axis(color='black')  # Change axis color to black

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Tab Example")
        self.setGeometry(100, 100, 1400, 900)
        self.setStyleSheet("background-color: black;")

        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)

        self.create_tabs()
        pywinstyles.apply_style(self,"dark")

    def create_tabs(self):
        for i in range(5):
            tab = QWidget()
            tab.setStyleSheet("background-color: black;")
            # self.tabs.addTab(tab, f"Tab {i + 1}")
            self.tabs.tabBar().setStyleSheet("""
                QTabBar::tab { 
                    background-color: black;
                    color: white;
                    border: 1px solid #33373c; 
                    border-radius: 2px; 
                    width: 100px; 
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

        self.tab1 = QWidget()
        self.tab1_layout = QVBoxLayout()
        self.tab1.setLayout(self.tab1_layout)

        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        self.scroll_content = QWidget()  # Create a widget to hold the layout
        self.scroll_content.setLayout(self.tab1_layout)  # Set the layout of the scrollable widget
        scroll_area.setWidget(self.scroll_content)
        scroll_area.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)

        self.tabs.addTab(scroll_area, "Analyze")
        self.tabs.addTab(Tab2(), "Tab 2")
        self.tabs.addTab(Tab3(), "Tab 3")
        self.tabs.addTab(Tab4(), "Tab 4")
        self.tabs.addTab(Tab5(), "Tab 5")
        self.tabs.addTab(Tab6(), "Tab 6")

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
        self.tab1_layout.addWidget(self.open_file_button)

    def open_folder(self):
        self.file_path = QFileDialog.getOpenFileName(self, "Select file", filter="*.pcap")
        if self.file_path:
            print("Selected file:", self.file_path[0])
            # self.tab1_layout.removeWidget(self.open_file_button)
            # self.open_file_button.deleteLater()
            # k = test.analyze_pcap(file_path[0])
            index, srclist, dstlist, proto = packets.print_packet_ip_mappings(self.file_path[0])
            # print(type(k))
            for i in index:
                hbox = QHBoxLayout()
                label = QLabel(str(i))
                label.setStyleSheet("color: white; font-size: 20px;")
                label.mousePressEvent = lambda event, row=i: self.rowClick(row)
                hbox.addWidget(label)
                label = QLabel(str(srclist[i-1]))
                label.setStyleSheet("color: white; font-size: 20px;")
                label.mousePressEvent = lambda event, row=i: self.rowClick(row)
                hbox.addWidget(label)
                label = QLabel(str(dstlist[i-1]))
                label.setStyleSheet("color: white; font-size: 20px;")
                label.mousePressEvent = lambda event, row=i: self.rowClick(row)
                hbox.addWidget(label)
                label = QLabel(str(proto[i-1]))
                label.setStyleSheet("color: white; font-size: 20px;")
                label.mousePressEvent = lambda event, row=i: self.rowClick(row)
                hbox.addWidget(label)
                self.tab1_layout.addLayout(hbox)

    def rowClick(self, row):
        # print(f"Row {row} clicked!")
        self.packet = PacketWindow(self.file_path[0], row)
        self.packet.show()
                
def main():
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
