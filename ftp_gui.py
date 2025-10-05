import configparser
import ctypes as ct
import datetime
import ipaddress
import logging
import os
import secrets
import socket
import string
import sys

import darkdetect
import qdarktheme
from PySide6.QtCore import QThread, Signal, Qt, QTimer
from PySide6.QtGui import QIcon, QAction, QTextCursor, QKeySequence
from PySide6.QtWidgets import (
    QApplication, QWidget, QLabel, QPushButton,
    QVBoxLayout, QHBoxLayout, QLineEdit, QTextEdit,
    QFormLayout, QSpinBox, QFileDialog, QSystemTrayIcon,
    QMenu, QCheckBox, QSplitter, QSizePolicy, QFrame
)
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler, TLS_FTPHandler
from pyftpdlib.servers import FTPServer

EXE_PATH = os.path.dirname(os.path.abspath(sys.argv[0]))
TEMP_PATH = os.path.dirname(os.path.abspath(__file__))

ICON_PATH = os.path.join(TEMP_PATH, 'ftp.png')
CONFIG_FILE_NAME = "ftp_config.cfg"
CONFIG_FILE = os.path.join(EXE_PATH, CONFIG_FILE_NAME)


def choose_bind_ip(preferred_nets=None):
    def in_any(ip, nets):
        return any(ip in n for n in nets) if nets else False

    RFC1918 = [ipaddress.ip_network(n) for n in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16')]
    AVOID = [ipaddress.ip_network(n) for n in ('198.18.0.0/15', '169.254.0.0/16')]

    candidates = []

    try:
        for ip in socket.gethostbyname_ex(socket.gethostname())[2]:
            try:
                a = ipaddress.ip_address(ip)
                if not a.is_loopback and not a.is_link_local:
                    candidates.append(a)
            except ValueError:
                pass
    except Exception:
        pass

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        a = ipaddress.ip_address(ip)
        if not a.is_loopback and not a.is_link_local and a not in candidates:
            candidates.append(a)
    except Exception:
        pass

    picks = []
    if preferred_nets:
        picks.append(lambda a: in_any(a, preferred_nets) and in_any(a, RFC1918))
        picks.append(lambda a: in_any(a, preferred_nets) and not in_any(a, AVOID))

    picks.append(lambda a: in_any(a, RFC1918))
    picks.append(lambda a: a.is_private and not in_any(a, AVOID))
    picks.append(lambda a: a.is_private)

    for cond in picks:
        for a in candidates:
            if cond(a):
                return str(a)
    return None


def generate_username(prefix="ftp"):
    return f"{prefix}_{secrets.token_hex(4)}"


def generate_password(length=24):
    alphabet = string.ascii_letters + string.digits + "-_@#%"
    while True:
        pwd = ''.join(secrets.choice(alphabet) for _ in range(length))
        if (any(c.islower() for c in pwd) and any(c.isupper() for c in pwd)
                and any(c.isdigit() for c in pwd) and any(c in "-_@#%" for c in pwd)):
            return pwd


def _port_free(port, host="0.0.0.0"):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((host, port))
            return True
        except OSError:
            return False


def pick_random_port(preferred=(), low=20000, high=65535, attempts=100):
    for p in preferred:
        if _port_free(p):
            return p

    span = high - low + 1
    tried = set()
    for _ in range(min(attempts, span)):
        p = secrets.randbelow(span) + low
        if p in tried:
            continue
        tried.add(p)
        if _port_free(p):
            return p

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("0.0.0.0", 0))
        p = s.getsockname()[1]
        s.close()
        return p
    except Exception:
        return 33921


class LANFilteredFTPHandler(FTPHandler):
    allowed_networks = None

    def on_connect(self):
        try:
            ip = ipaddress.ip_address(self.remote_ip)
        except ValueError:
            if self.allowed_networks:
                self.respond("421 Service not available, access denied.")
                try:
                    self.close()
                finally:
                    return
            return super().on_connect()

        nets = getattr(self, "allowed_networks", None)
        if nets:
            if not any(ip in n for n in nets):
                if hasattr(self, "log"):
                    self.log(f"Blocked connection from {ip} (not in allowed networks)")
                self.respond("421 Service not available, access denied.")
                try:
                    self.close()
                finally:
                    return
        return super().on_connect()


class FTPServerThread(QThread):
    log_signal = Signal(str)

    def __init__(self, port, username, password, ftp_directory, log_file,
                 allow_lan_only=False, allowed_nets_text="auto",
                 bind_host="auto", read_only=True, parent=None,
                 ftps_enabled=False, cert_file="", key_file="",
                 tls_require_ctrl=True, tls_require_data=True):
        super(FTPServerThread, self).__init__(parent)
        self.port = port
        self.username = username
        self.password = password
        self.ftp_directory = ftp_directory
        self.log_file = log_file
        self.allow_lan_only = allow_lan_only
        self.allowed_nets_text = (allowed_nets_text or "").strip()
        self.bind_host = bind_host
        self.read_only = read_only

        self.ftps_enabled = ftps_enabled
        self.cert_file = cert_file
        self.key_file = key_file
        self.tls_require_ctrl = tls_require_ctrl
        self.tls_require_data = tls_require_data

        self.server = None
        self.running = False
        self.setup_logger()

    def setup_logger(self):
        self.logger = logging.getLogger("FTPServer")
        self.logger.setLevel(logging.INFO)
        if not any(isinstance(h, logging.FileHandler) and h.baseFilename == os.path.abspath(self.log_file)
                   for h in self.logger.handlers):
            file_handler = logging.FileHandler(self.log_file)
            file_handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
            self.logger.addHandler(file_handler)

    def _parse_allowed_networks(self):
        if not self.allow_lan_only:
            return None
        txt = (self.allowed_nets_text or "").strip().lower()
        auto = ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
        cidrs = auto if txt in ("", "auto") else [p.strip() for p in txt.replace(";", ",").split(",") if p.strip()]
        nets = []
        for c in cidrs:
            try:
                nets.append(ipaddress.ip_network(c, strict=False))
            except ValueError:
                self.log(f"Invalid CIDR skipped: {c}")
        if not nets:
            raise ValueError("LAN-only is enabled but no valid CIDRs were provided.")
        return nets

    def _get_bind_addr(self, preferred_nets=None):
        bh = (self.bind_host or "").strip().lower()
        if bh in ("", "0.0.0.0", "all"):
            if self.allow_lan_only:
                raise ValueError("Refusing to bind 0.0.0.0 in LAN-only mode. Set a LAN IP explicitly.")
            return "0.0.0.0"
        if bh == "auto":
            ip = choose_bind_ip(preferred_nets)
            if not ip:
                if self.allow_lan_only:
                    raise ValueError("Could not determine a LAN IP in LAN-only mode.")
                return "0.0.0.0"
            return ip
        return self.bind_host

    def run(self):
        if not os.path.exists(self.ftp_directory):
            os.makedirs(self.ftp_directory)

        perms = "elr" if self.read_only else "elradfmw"
        authorizer = DummyAuthorizer()
        authorizer.add_user(self.username, self.password, self.ftp_directory, perm=perms)

        if self.ftps_enabled:
            handler = type("LANFilteredTLSHandler", (LANFilteredFTPHandler, TLS_FTPHandler), {})
            handler.certfile = self.cert_file
            handler.keyfile = self.key_file
            if self.tls_require_ctrl:
                handler.tls_control_required = True
            if self.tls_require_data:
                handler.tls_data_required = True
            self.log("FTPS: ENABLED")
            self.log(f"  cert: {self.cert_file}")
            self.log(f"  key : {self.key_file}")
        else:
            handler = LANFilteredFTPHandler
            self.log("FTPS: DISABLED")

        handler.authorizer = authorizer
        handler.log = self.log
        self.log(f"Read-only mode: {'ON' if self.read_only else 'OFF'}")

        nets = self._parse_allowed_networks()
        handler.allowed_networks = nets

        bind_addr = self._get_bind_addr(nets)
        if handler.allowed_networks:
            self.log(f"LAN-only filtering enabled; allowed nets = {handler.allowed_networks}")
        self.log(f"Binding FTP server to {bind_addr}:{self.port}")

        self.server = FTPServer((bind_addr, self.port), handler)
        self.server.max_cons = 64
        self.server.max_cons_per_ip = 5
        handler.max_login_attempts = 3
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
        self.allow_lan_only = config['FTP'].getboolean('allow_lan_only', True)
        self.allowed_nets = config['FTP'].get('allowed_nets', 'auto')
        self.bind_host = config['FTP'].get('bind_host', 'auto')
        self.read_only = config['FTP'].getboolean('read_only', True)
        self.ftps_enabled = config['FTP'].getboolean('ftps_enabled', False)
        self.tls_require_ctrl = config['FTP'].getboolean('tls_require_ctrl', True)
        self.tls_require_data = config['FTP'].getboolean('tls_require_data', True)
        self.cert_file = config['FTP'].get('cert_file', os.path.join(EXE_PATH, 'ftpd.crt'))
        self.key_file = config['FTP'].get('key_file', os.path.join(EXE_PATH, 'ftpd.key'))
        self.cert_common_name = config['FTP'].get('cert_common_name', 'localhost')

        self.tray_icon = None
        self.log_buffer = []

        self.init_ui()

        self.resize(800, 532)

        if self.run_as_daemon:
            self.start_server()
            self.hide_to_tray()

    def init_ui(self):
        # ===== LR Split =====
        splitter = QSplitter(Qt.Horizontal)
        left_panel = QWidget()
        right_panel = QWidget()
        splitter.addWidget(left_panel)
        splitter.addWidget(right_panel)
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 2)

        # ===== Left panel =====
        left_layout = QVBoxLayout(left_panel)

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
        left_layout.addLayout(form_layout)

        self.directory_input = QLineEdit()
        self.directory_input.setText(self.ftp_directory)
        self.directory_button = QPushButton("Browse FTP Folder")
        self.directory_button.clicked.connect(self.select_directory)
        directory_layout = QHBoxLayout()
        directory_layout.addWidget(self.directory_input)
        directory_layout.addWidget(self.directory_button)
        left_layout.addLayout(directory_layout)

        self.log_file_input = QLineEdit()
        self.log_file_input.setText(self.log_file)
        self.log_file_button = QPushButton("Browse Log File")
        self.log_file_button.clicked.connect(self.select_log_file)
        log_layout = QHBoxLayout()
        log_layout.addWidget(self.log_file_input)
        log_layout.addWidget(self.log_file_button)
        left_layout.addLayout(log_layout)

        self.daemon_checkbox = QCheckBox("Minimize to Tray after closing")
        self.daemon_checkbox.setChecked(self.run_as_daemon)
        left_layout.addWidget(self.daemon_checkbox)

        self.read_only_checkbox = QCheckBox("Read-only mode")
        self.read_only_checkbox.setChecked(self.read_only)
        left_layout.addWidget(self.read_only_checkbox)

        self.lan_only_checkbox = QCheckBox("LAN only")
        self.lan_only_checkbox.setChecked(self.allow_lan_only)
        left_layout.addWidget(self.lan_only_checkbox)

        nets_form = QFormLayout()
        self.allowed_nets_input = QLineEdit()
        self.allowed_nets_input.setPlaceholderText("192.168.1.0/24")
        self.allowed_nets_input.setText(self.allowed_nets)
        nets_form.addRow("Allowed networks:", self.allowed_nets_input)

        self.bind_host_input = QLineEdit()
        self.bind_host_input.setPlaceholderText("auto / 0.0.0.0 / <LAN IP>")
        self.bind_host_input.setText(self.bind_host)
        nets_form.addRow("Bind host:", self.bind_host_input)
        left_layout.addLayout(nets_form)

        self.ftps_enable_checkbox = QCheckBox("Enable FTPS (TLS)")
        self.ftps_enable_checkbox.setChecked(self.ftps_enabled)
        left_layout.addWidget(self.ftps_enable_checkbox)

        self.tls_ctrl_checkbox = QCheckBox("Require TLS for control channel")
        self.tls_ctrl_checkbox.setChecked(self.tls_require_ctrl)
        left_layout.addWidget(self.tls_ctrl_checkbox)

        self.tls_data_checkbox = QCheckBox("Require TLS for data channel")
        self.tls_data_checkbox.setChecked(self.tls_require_data)
        left_layout.addWidget(self.tls_data_checkbox)

        self.cert_file_input = QLineEdit()
        self.cert_file_input.setText(self.cert_file)
        self.cert_browse_btn = QPushButton("Browse Cert (.crt/.pem)")
        self.cert_browse_btn.clicked.connect(self.browse_cert)
        cert_row = QHBoxLayout()
        cert_row.addWidget(self.cert_file_input)
        cert_row.addWidget(self.cert_browse_btn)
        left_layout.addLayout(cert_row)

        self.key_file_input = QLineEdit()
        self.key_file_input.setText(self.key_file)
        self.key_browse_btn = QPushButton("Browse Key (.key)")
        self.key_browse_btn.clicked.connect(self.browse_key)
        key_row = QHBoxLayout()
        key_row.addWidget(self.key_file_input)
        key_row.addWidget(self.key_browse_btn)
        left_layout.addLayout(key_row)

        self.cn_input = QLineEdit()
        self.cn_input.setPlaceholderText("Common Name (e.g. hostname or IP)")
        self.cn_input.setText(self.cert_common_name)
        cn_form = QFormLayout()
        cn_form.addRow("Certificate CN:", self.cn_input)
        left_layout.addLayout(cn_form)

        self.btn_gen_cert = QPushButton("Generate Self-Signed FTPS Certificate")
        self.btn_gen_cert.clicked.connect(self.on_generate_cert)
        left_layout.addWidget(self.btn_gen_cert)

        self.btn_show_cert = QPushButton("Show Certificate Info / Verify")
        self.btn_show_cert.clicked.connect(self.on_show_cert_info)
        left_layout.addWidget(self.btn_show_cert)

        left_layout.addStretch(1)
        self.setup_tray_icon()

        # ===== Right panel =====
        right_layout = QVBoxLayout(right_panel)

        self.ip_label = QLabel("Listening on:")
        right_layout.addWidget(self.ip_label)

        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("Filter logs (case-insensitive)...")
        self.filter_input.setClearButtonEnabled(True)
        self.filter_input.textChanged.connect(self.apply_log_filter)
        right_layout.addWidget(self.filter_input)

        self.log_view = QTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setLineWrapMode(QTextEdit.WidgetWidth)
        self.log_view.setPlaceholderText("Server logs will appear here...")
        self.log_view.setStyleSheet("QTextEdit { font-family: Consolas, 'Courier New', monospace; }")
        self.log_view.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.log_view.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.log_view.setContextMenuPolicy(Qt.ActionsContextMenu)
        act_copy = QAction("Copy", self)
        act_copy.setShortcut(QKeySequence.Copy)
        act_copy.triggered.connect(self.log_view.copy)
        act_copy_all = QAction("Copy all", self)
        act_copy_all.setShortcut(QKeySequence(Qt.CTRL | Qt.SHIFT | Qt.Key_C))
        act_copy_all.triggered.connect(lambda: QApplication.clipboard().setText(self.log_view.toPlainText()))
        act_select_all = QAction("Select all", self)
        act_select_all.setShortcut(QKeySequence.SelectAll)
        act_select_all.triggered.connect(self.log_view.selectAll)
        act_clear = QAction("Clear all", self)
        act_clear.triggered.connect(self.clear_display_logs)
        sep1 = QAction(self)
        sep1.setSeparator(True)
        sep2 = QAction(self)
        sep2.setSeparator(True)
        self.log_view.addAction(act_copy)
        self.log_view.addAction(act_copy_all)
        self.log_view.addAction(act_select_all)
        self.log_view.addAction(sep1)
        self.log_view.addAction(act_clear)
        right_layout.addWidget(self.log_view, 1)

        footer = QFrame()
        footer.setFrameShape(QFrame.NoFrame)
        footer_layout = QHBoxLayout(footer)
        footer_layout.setContentsMargins(0, 6, 0, 0)

        self.start_button = QPushButton("Start FTP Server")
        self.stop_button = QPushButton("Stop FTP Server")
        self.stop_button.setEnabled(False)

        self.start_button.setStyleSheet("""
        QPushButton {
            background: #2ecc71;
            color: white;
            font-weight: 600;
            padding: 8px 14px;
            border-radius: 6px;
        }
        QPushButton:hover:enabled {
            filter: brightness(1.05);
        }
        QPushButton:disabled {
            background: #555555;
            color: #aaaaaa;
            border: 1px solid #444;
        }
        """)

        self.stop_button.setStyleSheet("""
        QPushButton {
            background: #e74c3c;
            color: white;
            font-weight: 600;
            padding: 8px 14px;
            border-radius: 6px;
        }
        QPushButton:hover:enabled {
            filter: brightness(1.05);
        }
        QPushButton:disabled {
            background: #555555;
            color: #aaaaaa;
            border: 1px solid #444;
        }
        """)

        self.start_button.clicked.connect(self.start_server)
        self.stop_button.clicked.connect(self.stop_server)

        footer_layout.addStretch(1)
        footer_layout.addWidget(self.start_button)
        footer_layout.addWidget(self.stop_button)

        right_layout.addWidget(footer, 0)

        # ===== End LR =====
        root = QVBoxLayout(self)
        root.addWidget(splitter)
        self.setLayout(root)

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
        self.tray_icon = QSystemTrayIcon(self)
        self.tray_icon.setIcon(QIcon(ICON_PATH))

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

    def browse_cert(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select Certificate", self.cert_file_input.text(),
                                              "Certificate Files (*.crt *.pem *.cer);;All Files (*)")
        if path:
            self.cert_file_input.setText(path)

    def browse_key(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select Private Key", self.key_file_input.text(),
                                              "Key Files (*.key *.pem);;All Files (*)")
        if path:
            self.key_file_input.setText(path)

    def on_generate_cert(self):
        cert_path = self.cert_file_input.text().strip() or os.path.join(EXE_PATH, "ftpd.crt")
        key_path = self.key_file_input.text().strip() or os.path.join(EXE_PATH, "ftpd.key")
        cn = self.cn_input.text().strip() or "localhost"
        try:
            os.makedirs(os.path.dirname(cert_path), exist_ok=True)
            os.makedirs(os.path.dirname(key_path), exist_ok=True)
        except Exception:
            pass
        try:
            generate_self_signed_cert(cert_path, key_path, common_name=cn, days_valid=3650)
            self.log_message(f"Generated self-signed certificate:\n  cert: {cert_path}\n  key : {key_path}\n  CN  : {cn}")
            self.cert_file_input.setText(cert_path)
            self.key_file_input.setText(key_path)
            self.ftps_enable_checkbox.setChecked(True)
            self.on_show_cert_info()
        except Exception as e:
            self.log_message(f"ERROR generating certificate: {e}")

    def on_show_cert_info(self):
        cert_path = self.cert_file_input.text().strip()
        if not os.path.exists(cert_path):
            self.log_message(f"Certificate not found: {cert_path}")
            return
        try:
            info = read_cert_info(cert_path)
            self.log_message(
                "Certificate info:\n"
                f"  Subject : {info['subject']}\n"
                f"  Issuer  : {info['issuer']}\n"
                f"  Valid   : {info['not_before']}  ~  {info['not_after']}\n"
                f"  SHA256  : {info['sha256_fingerprint']}"
            )
        except Exception as e:
            self.log_message(f"ERROR reading certificate: {e}")

    def start_server(self):
        username = self.username_input.text()
        password = self.password_input.text()
        port = self.port_input.value()
        ftp_directory = self.directory_input.text()
        log_file = self.log_file_input.text()
        allow_lan_only = self.lan_only_checkbox.isChecked()
        allowed_nets_text = self.allowed_nets_input.text()
        bind_host = self.bind_host_input.text().strip() or "auto"
        read_only = self.read_only_checkbox.isChecked()

        ftps_enabled = self.ftps_enable_checkbox.isChecked()
        tls_require_ctrl = self.tls_ctrl_checkbox.isChecked()
        tls_require_data = self.tls_data_checkbox.isChecked()
        cert_file = self.cert_file_input.text().strip()
        key_file = self.key_file_input.text().strip()
        cert_common_name = self.cn_input.text().strip() or "localhost"

        if ftps_enabled:
            missing = []
            if not cert_file or not os.path.exists(cert_file):
                missing.append("certificate file")
            if not key_file or not os.path.exists(key_file):
                missing.append("private key")
            if missing:
                self.log_message("FTPS enabled but missing: " + ", ".join(missing))
                return

        self.server_thread = FTPServerThread(
            port, username, password, ftp_directory, log_file,
            allow_lan_only=allow_lan_only,
            allowed_nets_text=allowed_nets_text,
            bind_host=bind_host,
            read_only=read_only,
            ftps_enabled=ftps_enabled,
            cert_file=cert_file,
            key_file=key_file,
            tls_require_ctrl=tls_require_ctrl,
            tls_require_data=tls_require_data
        )
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
            'log_file': fr'{log_file}',
            'allow_lan_only': '1' if allow_lan_only else '0',
            'allowed_nets': allowed_nets_text or 'auto',
            'bind_host': bind_host or 'auto',
            'read_only': '1' if read_only else '0',
            'ftps_enabled': '1' if ftps_enabled else '0',
            'tls_require_ctrl': '1' if tls_require_ctrl else '0',
            'tls_require_data': '1' if tls_require_data else '0',
            'cert_file': cert_file or os.path.join(EXE_PATH, 'ftpd.crt'),
            'key_file': key_file or os.path.join(EXE_PATH, 'ftpd.key'),
            'cert_common_name': cert_common_name
        }
        save_config(config)

    def stop_server(self):
        if self.server_thread:
            self.server_thread.stop()
            self.server_thread.wait()

        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.ip_label.setText(f"Listening on: ")

    def clear_display_logs(self):
        self.log_view.clear()
        self.log_buffer.clear()
        self.filter_input.clear()

    def log_message(self, message):
        self.log_buffer.append(message)

        if not self.filter_input.text().strip():
            bar = self.log_view.verticalScrollBar()
            at_bottom = bar.value() == bar.maximum()

            self.log_view.moveCursor(QTextCursor.End)
            if self.log_view.toPlainText():
                self.log_view.insertPlainText("\n")
            self.log_view.insertPlainText(message)

            if at_bottom:
                bar.setValue(bar.maximum())
        else:
            self.apply_log_filter()

    def apply_log_filter(self):
        text = self.filter_input.text().strip().lower()
        if not text:
            return

        bar = self.log_view.verticalScrollBar()
        at_bottom = bar.value() == bar.maximum()

        display = "\n".join(m for m in self.log_buffer if text in m.lower())
        self.log_view.setPlainText(display)

        if at_bottom:
            QTimer.singleShot(0, lambda: bar.setValue(bar.maximum()))

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
        gen_user = generate_username()
        gen_pass = generate_password()
        gen_port = pick_random_port()

        config['FTP'] = {
            'username': gen_user,
            'password': gen_pass,
            'port': f'{gen_port}',
            'ftp_directory': r'C:\Temp\FTP',
            'run_as_daemon': '0',
            'log_file': os.path.join(EXE_PATH, 'ftp_log.txt'),
            'allow_lan_only': '1',
            'allowed_nets': 'auto',
            'bind_host': 'auto',
            'read_only': '1',
            'ftps_enabled': '0',
            'tls_require_ctrl': '1',
            'tls_require_data': '1',
            'cert_file': os.path.join(EXE_PATH, 'ftpd.crt'),
            'key_file': os.path.join(EXE_PATH, 'ftpd.key'),
            'cert_common_name': 'localhost'
        }
        with open(CONFIG_FILE, 'w') as configfile:
            config.write(configfile)
    else:
        config.read(CONFIG_FILE)
    return config


def save_config(config):
    with open(CONFIG_FILE, 'w') as configfile:
        config.write(configfile)


def generate_self_signed_cert(cert_path, key_path, common_name="localhost", days_valid=3650):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=days_valid))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(common_name)]),
            critical=False,
        )
        .sign(key, hashes.SHA256(), default_backend())
    )

    with open(key_path, "wb") as f:
        f.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    return cert_path, key_path


def read_cert_info(cert_path):
    with open(cert_path, "rb") as f:
        data = f.read()
    cert = x509.load_pem_x509_certificate(data, default_backend())

    subject = cert.subject.rfc4514_string()
    issuer = cert.issuer.rfc4514_string()
    not_before = cert.not_valid_before
    not_after = cert.not_valid_after

    fp = cert.fingerprint(hashes.SHA256()).hex().upper()
    fingerprint = ":".join(fp[i:i+2] for i in range(0, len(fp), 2))

    return {
        "subject": subject,
        "issuer": issuer,
        "not_before": not_before,
        "not_after": not_after,
        "sha256_fingerprint": fingerprint
    }


def dark_title_bar(hwnd, use_dark_mode=False):
    DWMWA_USE_IMMERSIVE_DARK_MODE = 20
    try:
        set_window_attribute = ct.windll.dwmapi.DwmSetWindowAttribute
        rendering_policy = DWMWA_USE_IMMERSIVE_DARK_MODE
        value = 1 if use_dark_mode else 0
        value = ct.c_int(value)
        result = set_window_attribute(hwnd, rendering_policy, ct.byref(value), ct.sizeof(value))
        if result != 0:
            print(f"Failed to set dark mode: {result}")
    except Exception:
        pass


if __name__ == '__main__':
    config = load_config()

    app = QApplication(sys.argv)
    app.setWindowIcon(QIcon(ICON_PATH))
    qdarktheme.setup_theme("auto")
    gui = FTPGuiApp(config)

    if not config.getboolean('FTP', 'run_as_daemon'):
        gui.show()
        try:
            winId = gui.winId()
            dark_title_bar(winId, use_dark_mode=darkdetect.isDark())
        except Exception:
            pass
        gui.adjust_window_size(1, 1)

    sys.exit(app.exec())
