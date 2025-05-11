import sys
import psutil
import socket
from datetime import datetime
import platform
from collections import defaultdict
from PyQt5.QtWidgets import (QApplication, QMainWindow, QTableWidget, QTableWidgetItem, 
                            QVBoxLayout, QWidget, QLabel, QPushButton, QComboBox, 
                            QCheckBox, QHeaderView, QSplitter, QTextEdit, QLineEdit,
                            QHBoxLayout)
from PyQt5.QtCore import QTimer, Qt, QSortFilterProxyModel
from PyQt5.QtGui import QColor, QBrush

class NetworkMonitorGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Netmoon")
        self.setGeometry(100, 100, 1200, 800)
        
        # Data storage
        self.connection_history = {}
        self.stats = {
            'total_connections': 0,
            'connections_by_protocol': defaultdict(int),
            'connections_by_program': defaultdict(int)
        }
        self.all_connections = []
        
        # Settings
        self.refresh_interval = 2000  # ms
        self.show_all = False
        self.resolve_dns = False
        self.show_closed = False
        
        self.init_ui()
        self.init_timer()
        
    def init_ui(self):
        # Main layout
        main_widget = QWidget()
        main_layout = QVBoxLayout()
        
        # Control panel
        control_panel = QWidget()
        control_layout = QVBoxLayout()
        
        # Settings row
        settings_row = QWidget()
        settings_layout = QVBoxLayout()
        
        # Refresh controls
        refresh_row = QWidget()
        refresh_layout = QHBoxLayout()
        self.refresh_label = QLabel("Refresh interval (ms):")
        self.refresh_input = QComboBox()
        self.refresh_input.addItems(["500", "1000", "2000", "5000", "10000"])
        self.refresh_input.setCurrentText("2000")
        self.refresh_input.currentTextChanged.connect(self.update_refresh_interval)
        self.refresh_button = QPushButton("Refresh Now")
        self.refresh_button.clicked.connect(self.refresh_data)
        
        refresh_layout.addWidget(self.refresh_label)
        refresh_layout.addWidget(self.refresh_input)
        refresh_layout.addWidget(self.refresh_button)
        refresh_row.setLayout(refresh_layout)
        
        # Filter controls
        filter_row = QWidget()
        filter_layout = QHBoxLayout()
        self.show_all_check = QCheckBox("Show listening ports")
        self.show_all_check.stateChanged.connect(self.toggle_show_all)
        self.resolve_dns_check = QCheckBox("Resolve DNS")
        self.resolve_dns_check.stateChanged.connect(self.toggle_resolve_dns)
        self.show_closed_check = QCheckBox("Show closed connections")
        self.show_closed_check.stateChanged.connect(self.toggle_show_closed)
        
        filter_layout.addWidget(self.show_all_check)
        filter_layout.addWidget(self.resolve_dns_check)
        filter_layout.addWidget(self.show_closed_check)
        filter_row.setLayout(filter_layout)
        
        # Search controls
        search_row = QWidget()
        search_layout = QHBoxLayout()
        self.search_label = QLabel("Search Process:")
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Enter process name...")
        self.search_input.textChanged.connect(self.filter_processes)
        self.clear_search_button = QPushButton("Clear")
        self.clear_search_button.clicked.connect(self.clear_search)
        
        search_layout.addWidget(self.search_label)
        search_layout.addWidget(self.search_input)
        search_layout.addWidget(self.clear_search_button)
        search_row.setLayout(search_layout)
        
        # Add to settings
        settings_layout.addWidget(refresh_row)
        settings_layout.addWidget(filter_row)
        settings_layout.addWidget(search_row)
        settings_row.setLayout(settings_layout)
        
        # Stats display
        stats_row = QWidget()
        stats_layout = QVBoxLayout()
        self.stats_label = QLabel()
        self.stats_label.setStyleSheet("font-weight: bold;")
        stats_layout.addWidget(self.stats_label)
        stats_row.setLayout(stats_layout)
        
        # Add to control panel
        control_layout.addWidget(settings_row)
        control_layout.addWidget(stats_row)
        control_panel.setLayout(control_layout)
        
        # Connection table
        self.connection_table = QTableWidget()
        self.connection_table.setColumnCount(9)
        self.connection_table.setHorizontalHeaderLabels([
            "PID", "Program", "User", "Protocol", "Local IP", 
            "Local Port", "Remote IP", "Remote Port", "Status"
        ])
        self.connection_table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.connection_table.verticalHeader().setVisible(False)
        self.connection_table.setSortingEnabled(True)
        self.connection_table.setSelectionBehavior(QTableWidget.SelectRows)
        
        # Details panel
        self.details_text = QTextEdit()
        self.details_text.setReadOnly(True)
        
        # Splitter for table and details
        splitter = QSplitter(Qt.Vertical)
        splitter.addWidget(self.connection_table)
        splitter.addWidget(self.details_text)
        splitter.setSizes([600, 200])
        
        # Add to main layout
        main_layout.addWidget(control_panel)
        main_layout.addWidget(splitter)
        main_widget.setLayout(main_layout)
        
        self.setCentralWidget(main_widget)
        
        # Connect table selection change
        self.connection_table.itemSelectionChanged.connect(self.show_connection_details)
        
    def init_timer(self):
        self.timer = QTimer()
        self.timer.timeout.connect(self.refresh_data)
        self.timer.start(self.refresh_interval)
        
    def update_refresh_interval(self, interval):
        self.refresh_interval = int(interval)
        self.timer.setInterval(self.refresh_interval)
        
    def toggle_show_all(self, state):
        self.show_all = state == Qt.Checked
        self.refresh_data()
        
    def toggle_resolve_dns(self, state):
        self.resolve_dns = state == Qt.Checked
        self.refresh_data()
        
    def toggle_show_closed(self, state):
        self.show_closed = state == Qt.Checked
        self.refresh_data()
        
    def filter_processes(self, text):
        if not text:
            self.refresh_data()
            return
            
        text = text.lower()
        for row in range(self.connection_table.rowCount()):
            program_item = self.connection_table.item(row, 1)
            if program_item:
                program_name = program_item.text().lower()
                self.connection_table.setRowHidden(row, text not in program_name)
        
    def clear_search(self):
        self.search_input.clear()
        for row in range(self.connection_table.rowCount()):
            self.connection_table.setRowHidden(row, False)
        
    def refresh_data(self):
        connections = psutil.net_connections(kind='inet')
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Clear table
        self.connection_table.setRowCount(0)
        self.all_connections = []
        
        current_conns = set()
        
        for conn in connections:
            conn_info = self.get_connection_info(conn)
            if not conn_info:
                continue
                
            if not self.show_all and conn_info['remote_ip'] in ['N/A', '0.0.0.0', '::']:
                continue
                
            if not self.show_closed and conn_info['status'] == 'NONE':
                continue
                
            prog_info = self.get_program_info(conn_info['pid'])
            conn_key = (conn_info['pid'], conn_info['local_ip'], conn_info['local_port'], 
                       conn_info['remote_ip'], conn_info['remote_port'], conn_info['type'])
            
            current_conns.add(conn_key)
            self.all_connections.append((conn_info, prog_info, conn_key))
            
            # Update connection history
            if conn_key not in self.connection_history:
                self.connection_history[conn_key] = {
                    'first_seen': current_time,
                    'last_seen': current_time,
                    'program': prog_info['name'],
                    'count': 1,
                    'cmdline': prog_info['cmdline'],
                    'exe': prog_info['exe'],
                    'username': prog_info['username']
                }
            else:
                self.connection_history[conn_key]['last_seen'] = current_time
                self.connection_history[conn_key]['count'] += 1
            
            # Update statistics
            self.stats['total_connections'] += 1
            self.stats['connections_by_protocol'][conn_info['type']] += 1
            self.stats['connections_by_program'][prog_info['name']] += 1
            
            # Add to table
            row = self.connection_table.rowCount()
            self.connection_table.insertRow(row)
            
            # Color rows based on status
            color = self.get_status_color(conn_info['status'])
            
            # PID
            pid_item = QTableWidgetItem(str(conn_info['pid']))
            pid_item.setData(Qt.UserRole, conn_key)  # Store connection key for details
            pid_item.setBackground(color)
            self.connection_table.setItem(row, 0, pid_item)
            
            # Program
            program_item = QTableWidgetItem(prog_info['name'][:20])
            program_item.setBackground(color)
            program_item.setData(Qt.UserRole, prog_info['name'].lower())  # For searching
            self.connection_table.setItem(row, 1, program_item)
            
            # User
            user_item = QTableWidgetItem(prog_info['username'][:15])
            user_item.setBackground(color)
            self.connection_table.setItem(row, 2, user_item)
            
            # Protocol
            protocol_item = QTableWidgetItem(conn_info['type'])
            protocol_item.setBackground(color)
            self.connection_table.setItem(row, 3, protocol_item)
            
            # Local IP
            local_ip_item = QTableWidgetItem(conn_info['local_ip'])
            local_ip_item.setBackground(color)
            self.connection_table.setItem(row, 4, local_ip_item)
            
            # Local Port
            local_port_item = QTableWidgetItem(str(conn_info['local_port']))
            local_port_item.setBackground(color)
            self.connection_table.setItem(row, 5, local_port_item)
            
            # Remote IP
            remote_ip = conn_info['remote_ip']
            if self.resolve_dns and remote_ip not in ['N/A', '0.0.0.0', '::']:
                hostname = self.resolve_ip(remote_ip)
                if hostname != remote_ip:
                    remote_ip = f"{remote_ip} ({hostname})"
            
            remote_ip_item = QTableWidgetItem(remote_ip)
            remote_ip_item.setBackground(color)
            self.connection_table.setItem(row, 6, remote_ip_item)
            
            # Remote Port
            remote_port_item = QTableWidgetItem(str(conn_info['remote_port']))
            remote_port_item.setBackground(color)
            self.connection_table.setItem(row, 7, remote_port_item)
            
            # Status
            status_item = QTableWidgetItem(conn_info['status'])
            status_item.setBackground(color)
            self.connection_table.setItem(row, 8, status_item)
        
        # Apply search filter if active
        search_text = self.search_input.text().lower()
        if search_text:
            for row in range(self.connection_table.rowCount()):
                program_item = self.connection_table.item(row, 1)
                if program_item:
                    program_name = program_item.data(Qt.UserRole)
                    self.connection_table.setRowHidden(row, search_text not in program_name)
        
        # Update stats display
        self.update_stats_display(len(current_conns))
        
    def get_status_color(self, status):
        if status == 'ESTABLISHED':
            return QBrush(QColor(200, 255, 200))  # Light green
        elif status == 'LISTEN':
            return QBrush(QColor(200, 200, 255))  # Light blue
        elif status == 'TIME_WAIT' or status == 'CLOSE_WAIT':
            return QBrush(QColor(255, 255, 200))  # Light yellow
        elif status == 'NONE':
            return QBrush(QColor(255, 200, 200))  # Light red
        else:
            return QBrush(QColor(255, 255, 255))  # White
        
    def update_stats_display(self, active_connections):
        stats_text = f"""
        <b>Statistics:</b>
        <table>
        <tr><td>Total connections observed:</td><td>{self.stats['total_connections']}</td></tr>
        <tr><td>Active connections:</td><td>{active_connections}</td></tr>
        <tr><td>Unique connections tracked:</td><td>{len(self.connection_history)}</td></tr>
        </table>
        
        <b>Connections by protocol:</b>
        <table>
        """
        
        for proto, count in self.stats['connections_by_protocol'].items():
            stats_text += f"<tr><td>{proto}:</td><td>{count}</td></tr>"
            
        stats_text += "</table>"
        
        stats_text += """
        <b>Top programs:</b>
        <table>
        """
        
        for program, count in sorted(self.stats['connections_by_program'].items(), 
                                   key=lambda x: x[1], reverse=True)[:5]:
            stats_text += f"<tr><td>{program}:</td><td>{count}</td></tr>"
            
        stats_text += "</table>"
        
        self.stats_label.setText(stats_text)
        
    def show_connection_details(self):
        selected_items = self.connection_table.selectedItems()
        if not selected_items:
            return
            
        row = selected_items[0].row()
        conn_key_item = self.connection_table.item(row, 0)
        conn_key = conn_key_item.data(Qt.UserRole)
        
        if conn_key in self.connection_history:
            conn_info = self.connection_history[conn_key]
            details = f"""
            <b>Connection Details:</b>
            <table>
            <tr><td><b>Program:</b></td><td>{conn_info['program']}</td></tr>
            <tr><td><b>PID:</b></td><td>{conn_key[0]}</td></tr>
            <tr><td><b>User:</b></td><td>{conn_info['username']}</td></tr>
            <tr><td><b>Executable:</b></td><td>{conn_info['exe']}</td></tr>
            <tr><td><b>Command line:</b></td><td>{conn_info['cmdline']}</td></tr>
            <tr><td><b>Protocol:</b></td><td>{conn_key[5]}</td></tr>
            <tr><td><b>Local address:</b></td><td>{conn_key[1]}:{conn_key[2]}</td></tr>
            <tr><td><b>Remote address:</b></td><td>{conn_key[3]}:{conn_key[4]}</td></tr>
            <tr><td><b>First seen:</b></td><td>{conn_info['first_seen']}</td></tr>
            <tr><td><b>Last seen:</b></td><td>{conn_info['last_seen']}</td></tr>
            <tr><td><b>Connection count:</b></td><td>{conn_info['count']}</td></tr>
            </table>
            """
            self.details_text.setHtml(details)
        
    def get_connection_info(self, conn):
        try:
            remote_ip = conn.raddr.ip if conn.raddr else "N/A"
            remote_port = conn.raddr.port if conn.raddr else "N/A"
            local_ip = conn.laddr.ip if conn.laddr else "N/A"
            local_port = conn.laddr.port if conn.laddr else "N/A"
            
            return {
                'pid': conn.pid,
                'status': conn.status,
                'local_ip': local_ip,
                'local_port': local_port,
                'remote_ip': remote_ip,
                'remote_port': remote_port,
                'family': 'IPv4' if conn.family == socket.AF_INET else 'IPv6' if conn.family == socket.AF_INET6 else 'UNIX',
                'type': 'TCP' if conn.type == socket.SOCK_STREAM else 'UDP' if conn.type == socket.SOCK_DGRAM else 'OTHER'
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return None
            
    def get_program_info(self, pid):
        try:
            process = psutil.Process(pid)
            return {
                'name': process.name(),
                'exe': process.exe(),
                'cmdline': ' '.join(process.cmdline()),
                'username': process.username()
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return {
                'name': 'N/A',
                'exe': 'N/A',
                'cmdline': 'N/A',
                'username': 'N/A'
            }
            
    def resolve_ip(self, ip):
        if ip in ['N/A', '0.0.0.0', '::']:
            return ip
        try:
            return socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror):
            return ip

if __name__ == "__main__":
    app = QApplication(sys.argv)
    monitor = NetworkMonitorGUI()
    monitor.show()
    sys.exit(app.exec_())
