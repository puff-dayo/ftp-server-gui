import configparser
import logging
import os
import socket
import sys
import ctypes as ct

import darkdetect
import qdarktheme
from PySide6.QtCore import QThread, Signal
from PySide6.QtGui import QIcon, QAction
from PySide6.QtWidgets import (QApplication, QWidget, QLabel, QPushButton,
                               QVBoxLayout, QHBoxLayout, QLineEdit, QTextEdit,
                               QFormLayout, QSpinBox, QFileDialog, QSystemTrayIcon, QMenu, QCheckBox)
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer

BASE_PATH = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE_NAME = "ftp_config.cfg"
CONFIG_FILE = os.path.join(BASE_PATH, CONFIG_FILE_NAME)


class FTPServerThread(QThread):
    log_signal = Signal(str)

    def __init__(self, port, username, password, ftp_directory, log_file, parent=None):
        super(FTPServerThread, self).__init__(parent)
        self.port = port
        self.username = username
        self.password = password
        self.ftp_directory = ftp_directory
        self.log_file = log_file
        self.server = None
        self.running = False
        self.setup_logger()

    def setup_logger(self):
        self.logger = logging.getLogger("FTPServer")
        self.logger.setLevel(logging.INFO)
        file_handler = logging.FileHandler(self.log_file)
        file_handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
        self.logger.addHandler(file_handler)

    def run(self):
        if not os.path.exists(self.ftp_directory):
            os.makedirs(self.ftp_directory)

        authorizer = DummyAuthorizer()
        authorizer.add_user(self.username, self.password, self.ftp_directory, perm="elradfmw")

        handler = FTPHandler
        handler.authorizer = authorizer
        handler.log = self.log

        self.server = FTPServer(("0.0.0.0", self.port), handler)
        self.running = True
        self.server.serve_forever()

    def log(self, message, logfun=None):
        self.log_signal.emit(message)
        self.logger.info(message)

    def stop(self):
        if self.server:
            self.server.close_all()
            self.running = False


class FTPGuiApp(QWidget):
    def __init__(self, config):
        super().__init__()
        self.setWindowTitle("Simple FTP Server")
        self.server_thread = None
        self.ftp_directory = config['FTP']['ftp_directory']
        self.run_as_daemon = config.getboolean('FTP', 'run_as_daemon')
        self.log_file = config['FTP'].get('log_file', 'ftp_log.txt')
        self.username = config['FTP']['username']
        self.password = config['FTP']['password']
        self.port = config.getint('FTP', 'port')

        self.tray_icon = None
        self.init_ui()

        if self.run_as_daemon:
            self.start_server()
            self.hide_to_tray()

    def init_ui(self):
        layout = QVBoxLayout()
        form_layout = QFormLayout()

        self.username_input = QLineEdit()
        self.username_input.setText(self.username)
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setText(self.password)
        self.password_input.installEventFilter(self)

        self.port_input = QSpinBox()
        self.port_input.setRange(1, 65535)
        self.port_input.setValue(self.port)

        form_layout.addRow("Username:", self.username_input)
        form_layout.addRow("Password:", self.password_input)
        form_layout.addRow("Port:", self.port_input)

        self.directory_input = QLineEdit()
        self.directory_input.setText(self.ftp_directory)
        self.directory_button = QPushButton("Browse FTP Folder")
        self.directory_button.clicked.connect(self.select_directory)

        directory_layout = QHBoxLayout()
        directory_layout.addWidget(self.directory_input)
        directory_layout.addWidget(self.directory_button)

        layout.addLayout(form_layout)
        layout.addLayout(directory_layout)

        self.log_file_input = QLineEdit()
        self.log_file_input.setText(self.log_file)
        self.log_file_button = QPushButton("Browse Log File")
        self.log_file_button.clicked.connect(self.select_log_file)

        log_layout = QHBoxLayout()
        log_layout.addWidget(self.log_file_input)
        log_layout.addWidget(self.log_file_button)

        layout.addLayout(log_layout)

        self.daemon_checkbox = QCheckBox("Minimize to Tray after closing")
        self.daemon_checkbox.setChecked(self.run_as_daemon)
        layout.addWidget(self.daemon_checkbox)

        self.start_button = QPushButton("Start FTP Server")
        self.start_button.clicked.connect(self.start_server)
        self.stop_button = QPushButton("Stop FTP Server")
        self.stop_button.clicked.connect(self.stop_server)
        self.stop_button.setEnabled(False)

        button_layout = QHBoxLayout()
        button_layout.addWidget(self.start_button)
        button_layout.addWidget(self.stop_button)
        layout.addLayout(button_layout)

        self.log_view = QTextEdit()
        self.log_view.setReadOnly(True)
        layout.addWidget(self.log_view)

        self.ip_label = QLabel("Listening on:")
        layout.addWidget(self.ip_label)

        self.setLayout(layout)
        self.setup_tray_icon()

    def eventFilter(self, obj, event):
        if obj == self.password_input:
            if event.type() == event.Type.FocusIn:
                self.password_input.setEchoMode(QLineEdit.Normal)
            elif event.type() == event.Type.FocusOut:
                self.password_input.setEchoMode(QLineEdit.Password)
        return super().eventFilter(obj, event)

    def adjust_window_size(self, dx, dy):
        current_geometry = self.geometry()
        new_width = current_geometry.width() + dx
        new_height = current_geometry.height() + dy
        self.setGeometry(current_geometry.x(), current_geometry.y(), new_width, new_height)

    def setup_tray_icon(self):
        icon_path = os.path.join(BASE_PATH, 'ftp.png')
        self.tray_icon = QSystemTrayIcon(self)
        self.tray_icon.setIcon(QIcon(icon_path))

        tray_menu = QMenu()
        restore_action = QAction("Restore", self)
        restore_action.triggered.connect(self.show)
        tray_menu.addAction(restore_action)

        quit_action = QAction("Quit", self)
        quit_action.triggered.connect(self.close)
        tray_menu.addAction(quit_action)

        self.tray_icon.setContextMenu(tray_menu)
        self.tray_icon.activated.connect(self.on_tray_icon_activated)
        self.tray_icon.show()

    def on_tray_icon_activated(self, reason):
        if reason == QSystemTrayIcon.ActivationReason.Trigger:
            self.show()

    def hide_to_tray(self):
        self.hide()
        self.tray_icon.showMessage("FTP Server", "Running in background", QSystemTrayIcon.Information, 3000)

    def select_directory(self):
        folder = QFileDialog.getExistingDirectory(self, "Select FTP Folder", self.ftp_directory)
        if folder:
            self.ftp_directory = folder
            self.directory_input.setText(folder)

    def select_log_file(self):
        log_file, _ = QFileDialog.getSaveFileName(self, "Select Log File", self.log_file, "Log Files (*.txt)")
        if log_file:
            self.log_file = log_file
            self.log_file_input.setText(log_file)

    def start_server(self):
        username = self.username_input.text()
        password = self.password_input.text()
        port = self.port_input.value()
        ftp_directory = self.directory_input.text()
        log_file = self.log_file_input.text()

        self.server_thread = FTPServerThread(port, username, password, ftp_directory, log_file)
        self.server_thread.log_signal.connect(self.log_message)
        self.server_thread.start()

        self.update_ip_addresses()
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)

        if self.daemon_checkbox.isChecked():
            self.hide_to_tray()

        config['FTP'] = {
            'username': username,
            'password': password,
            'port': f'{port}',
            'ftp_directory': fr'{ftp_directory}',
            'run_as_daemon': '1' if self.daemon_checkbox.isChecked() else '0',
            'log_file': fr'{log_file}'
        }
        save_config(config)

    def stop_server(self):
        if self.server_thread:
            self.server_thread.stop()
            self.server_thread.wait()

        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)

    def log_message(self, message):
        self.log_view.append(message)

    def update_ip_addresses(self):
        ip_addresses = self.get_ip_addresses()
        self.ip_label.setText(f"Listening on: {', '.join(ip_addresses)}")

    def get_ip_addresses(self):
        ip_list = []
        for ip in socket.gethostbyname_ex(socket.gethostname())[2]:
            if not ip.startswith("127."):
                ip_list.append(ip)
        return ip_list

    def closeEvent(self, event):
        if self.daemon_checkbox.isChecked():
            event.ignore()
            self.hide_to_tray()
        else:
            event.accept()


def load_config():
    config = configparser.ConfigParser()
    if not os.path.exists(CONFIG_FILE):
        config['FTP'] = {
            'username': 'ftp_user',
            'password': 'very_safe@2025',
            'port': '33921',
            'ftp_directory': r'C:\Temp\FTP',
            'run_as_daemon': '0',
            'log_file': 'ftp_log.txt'
        }
        with open(CONFIG_FILE, 'w') as configfile:
            config.write(configfile)
    else:
        config.read(CONFIG_FILE)
    return config


def save_config(config):
    with open(CONFIG_FILE, 'w') as configfile:
        config.write(configfile)


def dark_title_bar(hwnd, use_dark_mode=False):
    DWMWA_USE_IMMERSIVE_DARK_MODE = 20
    set_window_attribute = ct.windll.dwmapi.DwmSetWindowAttribute
    rendering_policy = DWMWA_USE_IMMERSIVE_DARK_MODE
    value = 1 if use_dark_mode else 0
    value = ct.c_int(value)
    result = set_window_attribute(hwnd, rendering_policy, ct.byref(value), ct.sizeof(value))
    if result != 0:
        print(f"Failed to set dark mode: {result}")


if __name__ == '__main__':
    config = load_config()

    app = QApplication(sys.argv)
    app.setWindowIcon(QIcon('./ftp.png'))
    qdarktheme.setup_theme("auto")
    gui = FTPGuiApp(config)

    if not config.getboolean('FTP', 'run_as_daemon'):
        gui.show()
        winId = gui.winId()
        dark_title_bar(winId, use_dark_mode=darkdetect.isDark())
        gui.adjust_window_size(1, 1)  # to trigger dark refresh on screen

    sys.exit(app.exec())
