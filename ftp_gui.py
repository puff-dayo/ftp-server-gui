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
import tempfile

import darkdetect
import qdarktheme
from PySide6.QtCore import QThread, Signal, Qt, QTimer, QSize
from PySide6.QtGui import QIcon, QAction, QTextCursor, QKeySequence
from PySide6.QtWidgets import (
    QApplication, QWidget, QLabel, QPushButton, QVBoxLayout, QHBoxLayout,
    QLineEdit, QTextEdit, QFormLayout, QSpinBox, QFileDialog,
    QSystemTrayIcon, QMenu, QCheckBox, QSizePolicy, QFrame, QListWidget,
    QListWidgetItem, QStackedWidget, QGroupBox, QMessageBox, QStyle,
)
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler, TLS_FTPHandler
from pyftpdlib.servers import FTPServer

from vfs import (
    MappedVirtualFS,
    VirtualMapping,
    mappings_from_json,
    mappings_to_json,
    normalize_mappings,
)
from vfs_editor import VirtualDirectoryEditor

EXE_PATH = os.path.dirname(os.path.abspath(sys.argv[0]))
TEMP_PATH = os.path.dirname(os.path.abspath(__file__))

ICON_PATH = os.path.join(TEMP_PATH, "ftp.png")
CONFIG_FILE_NAME = "ftp_config.cfg"
CONFIG_FILE = os.path.join(EXE_PATH, CONFIG_FILE_NAME)
VFS_NAMESPACE = os.path.join(tempfile.gettempdir(), "simple_ftp_server_vfs")


def choose_bind_ip(preferred_nets=None):
    def in_any(ip, nets):
        return any(ip in n for n in nets) if nets else False

    rfc1918 = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]
    avoid = [ipaddress.ip_network(n) for n in ("198.18.0.0/15", "169.254.0.0/16")]
    candidates = []

    try:
        for ip in socket.gethostbyname_ex(socket.gethostname())[2]:
            try:
                address = ipaddress.ip_address(ip)
                if not address.is_loopback and not address.is_link_local:
                    candidates.append(address)
            except ValueError:
                pass
    except Exception:
        pass

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("8.8.8.8", 80))
        ip = sock.getsockname()[0]
        sock.close()
        address = ipaddress.ip_address(ip)
        if not address.is_loopback and not address.is_link_local and address not in candidates:
            candidates.append(address)
    except Exception:
        pass

    picks = []
    if preferred_nets:
        picks.append(lambda a: in_any(a, preferred_nets) and in_any(a, rfc1918))
        picks.append(lambda a: in_any(a, preferred_nets) and not in_any(a, avoid))
    picks.append(lambda a: in_any(a, rfc1918))
    picks.append(lambda a: a.is_private and not in_any(a, avoid))
    picks.append(lambda a: a.is_private)

    for condition in picks:
        for address in candidates:
            if condition(address):
                return str(address)
    return None


def generate_username(prefix="ftp"):
    return f"{prefix}_{secrets.token_hex(4)}"


def generate_password(length=24):
    alphabet = string.ascii_letters + string.digits + "-_@#%"
    while True:
        password = "".join(secrets.choice(alphabet) for _ in range(length))
        if (
                any(c.islower() for c in password)
                and any(c.isupper() for c in password)
                and any(c.isdigit() for c in password)
                and any(c in "-_@#%" for c in password)
        ):
            return password


def _port_free(port, host="0.0.0.0"):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((host, port))
            return True
        except OSError:
            return False


def pick_random_port(preferred=(), low=20000, high=65535, attempts=100):
    for port in preferred:
        if _port_free(port):
            return port

    span = high - low + 1
    tried = set()
    for _ in range(min(attempts, span)):
        port = secrets.randbelow(span) + low
        if port in tried:
            continue
        tried.add(port)
        if _port_free(port):
            return port

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("0.0.0.0", 0))
        port = sock.getsockname()[1]
        sock.close()
        return port
    except Exception:
        return 33921


class LANFilterMixin:
    allowed_networks = None

    def on_connect(self):
        try:
            ip = ipaddress.ip_address(self.remote_ip)
        except ValueError:
            if self.allowed_networks:
                self.respond("421 Service not available, access denied.")
                self.close()
                return
            return super().on_connect()

        nets = getattr(self, "allowed_networks", None)
        if nets and not any(ip in network for network in nets):
            if hasattr(self, "log"):
                self.log(f"Blocked connection from {ip} (not in allowed networks)")
            self.respond("421 Service not available, access denied.")
            self.close()
            return
        return super().on_connect()


class LANFilteredFTPHandler(LANFilterMixin, FTPHandler):
    pass


class LANFilteredTLSHandler(LANFilterMixin, TLS_FTPHandler):
    pass


class FTPServerThread(QThread):
    log_signal = Signal(str)
    status_signal = Signal(bool, str)

    def __init__(
            self,
            port,
            username,
            password,
            virtual_mappings,
            log_file,
            allow_lan_only=False,
            allowed_nets_text="auto",
            bind_host="auto",
            read_only=True,
            parent=None,
            ftps_enabled=False,
            cert_file="",
            key_file="",
            tls_require_ctrl=True,
            tls_require_data=True,
    ):
        super().__init__(parent)
        self.port = port
        self.username = username
        self.password = password
        self.virtual_mappings = list(virtual_mappings)
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
        self.logger = None

    def setup_logger(self):
        os.makedirs(os.path.dirname(os.path.abspath(self.log_file)), exist_ok=True)
        self.logger = logging.getLogger(f"FTPServer.{id(self)}")
        self.logger.setLevel(logging.INFO)
        self.logger.propagate = False
        self.logger.handlers.clear()
        handler = logging.FileHandler(self.log_file, encoding="utf-8")
        handler.setFormatter(logging.Formatter("%(asctime)s - %(message)s"))
        self.logger.addHandler(handler)

    def _parse_allowed_networks(self):
        if not self.allow_lan_only:
            return None
        text = (self.allowed_nets_text or "").strip().lower()
        auto = ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
        cidrs = auto if text in ("", "auto") else [p.strip() for p in text.replace(";", ",").split(",") if p.strip()]
        nets = []
        for cidr in cidrs:
            try:
                nets.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                self.log(f"Invalid CIDR skipped: {cidr}")
        if not nets:
            raise ValueError("LAN-only is enabled but no valid CIDRs were provided.")
        return nets

    def _get_bind_addr(self, preferred_nets=None):
        bind_host = (self.bind_host or "").strip().lower()
        if bind_host in ("", "0.0.0.0", "all"):
            if self.allow_lan_only:
                raise ValueError("Refusing to bind 0.0.0.0 in LAN-only mode. Set a LAN IP explicitly.")
            return "0.0.0.0"
        if bind_host == "auto":
            ip = choose_bind_ip(preferred_nets)
            if not ip:
                if self.allow_lan_only:
                    raise ValueError("Could not determine a LAN IP in LAN-only mode.")
                return "0.0.0.0"
            return ip
        return self.bind_host

    def run(self):
        try:
            self.setup_logger()
            mappings = normalize_mappings(self.virtual_mappings, require_existing=True)
            if not mappings:
                raise ValueError("At least one virtual directory mapping is required.")

            os.makedirs(VFS_NAMESPACE, exist_ok=True)
            perms = "elr" if self.read_only else "elradfmw"
            authorizer = DummyAuthorizer()
            authorizer.add_user(self.username, self.password, VFS_NAMESPACE, perm=perms)

            handler = LANFilteredTLSHandler if self.ftps_enabled else LANFilteredFTPHandler
            if self.ftps_enabled:
                handler.certfile = self.cert_file
                handler.keyfile = self.key_file
                handler.tls_control_required = self.tls_require_ctrl
                handler.tls_data_required = self.tls_require_data
                self.log("FTPS: ENABLED")
                self.log(f"  cert: {self.cert_file}")
                self.log(f"  key : {self.key_file}")
            else:
                self.log("FTPS: DISABLED")

            configured_fs = type(
                "ConfiguredMappedVirtualFS",
                (MappedVirtualFS,),
                {"configured_mappings": mappings},
            )
            handler.abstracted_fs = configured_fs
            handler.authorizer = authorizer
            handler.log = self.log
            handler.max_login_attempts = 3
            self.log(f"Read-only mode: {'ON' if self.read_only else 'OFF'}")
            for mapping in sorted(mappings, key=lambda m: m.virtual_path):
                self.log(f"VFS: {mapping.virtual_path} -> {mapping.local_path}")

            nets = self._parse_allowed_networks()
            handler.allowed_networks = nets
            bind_addr = self._get_bind_addr(nets)
            if nets:
                self.log(f"LAN-only filtering enabled; allowed nets = {nets}")
            self.log(f"Binding FTP server to {bind_addr}:{self.port}")

            self.server = FTPServer((bind_addr, self.port), handler)
            self.server.max_cons = 64
            self.server.max_cons_per_ip = 5
            self.running = True
            self.status_signal.emit(True, f"{bind_addr}:{self.port}")
            self.server.serve_forever()
        except Exception as exc:
            self.log(f"ERROR: {exc}")
            self.status_signal.emit(False, str(exc))
        finally:
            self.running = False
            self.server = None
            if self.logger:
                for file_handler in list(self.logger.handlers):
                    try:
                        file_handler.close()
                    finally:
                        self.logger.removeHandler(file_handler)

    def log(self, message, logfun=None):
        self.log_signal.emit(str(message))
        if self.logger:
            self.logger.info(str(message))

    def stop(self):
        if self.server:
            self.server.close_all()
        self.running = False


class FTPGuiApp(QWidget):
    PAGE_NAMES = ["Overview", "Account", "Folders", "Network", "FTPS", "Logs"]

    def __init__(self, config):
        super().__init__()
        self.config = config
        self.setWindowTitle("Simple FTP Server")
        self.server_thread = None
        self.force_quit = False
        self.tray_icon = None
        self.log_buffer = []
        self.runtime_lock_widgets = []

        section = config["FTP"]
        legacy_dir = section.get("ftp_directory", r"C:\Temp\FTP")
        raw_virtual_mappings = section.get("virtual_mappings", "").strip()
        if not raw_virtual_mappings and legacy_dir:
            try:
                os.makedirs(legacy_dir, exist_ok=True)
            except Exception:
                pass
        self.virtual_mappings = mappings_from_json(raw_virtual_mappings, fallback_local=legacy_dir)
        self.run_as_daemon = section.getboolean("run_as_daemon", False)
        self.log_file = section.get("log_file", os.path.join(EXE_PATH, "ftp_log.txt"))
        self.username = section.get("username", generate_username())
        self.password = section.get("password", generate_password())
        self.port = section.getint("port", pick_random_port())
        self.allow_lan_only = section.getboolean("allow_lan_only", True)
        self.allowed_nets = section.get("allowed_nets", "auto")
        self.bind_host = section.get("bind_host", "auto")
        self.read_only = section.getboolean("read_only", True)
        self.ftps_enabled = section.getboolean("ftps_enabled", False)
        self.tls_require_ctrl = section.getboolean("tls_require_ctrl", True)
        self.tls_require_data = section.getboolean("tls_require_data", True)
        self.cert_file = section.get("cert_file", os.path.join(EXE_PATH, "ftpd.crt"))
        self.key_file = section.get("key_file", os.path.join(EXE_PATH, "ftpd.key"))
        self.cert_common_name = section.get("cert_common_name", "localhost")

        self.init_ui()
        self.setup_tray_icon()
        self.resize(640, 450)
        self.setMinimumSize(480, 380)

        if self.run_as_daemon:
            self.start_server()
            if self.server_thread:
                self.hide_to_tray()

    # ---------- UI construction ----------
    def init_ui(self):
        root = QHBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        nav_panel = QFrame()
        nav_panel.setObjectName("navPanel")
        nav_panel.setFixedWidth(190)
        nav_layout = QVBoxLayout(nav_panel)
        nav_layout.setContentsMargins(14, 18, 10, 14)

        app_title = QLabel("Menu")
        app_title.setStyleSheet("font-size: 16px; font-weight: 600; padding: 0 6px 10px 6px;")
        nav_layout.addWidget(app_title)

        self.nav_list = QListWidget()
        self.nav_list.setFrameShape(QFrame.NoFrame)
        self.nav_list.setSpacing(3)
        self.nav_list.setIconSize(QSize(20, 20))
        self.nav_list.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.nav_list.setStyleSheet("QListWidget { background: transparent; border: none; outline: none; }")
        nav_layout.addWidget(self.nav_list, 1)

        normal_icon = self.style().standardIcon(QStyle.StandardPixmap.SP_FileDialogDetailedView)

        for name in self.PAGE_NAMES:
            item = QListWidgetItem(normal_icon, name)
            item.setSizeHint(QSize(160, 42))
            self.nav_list.addItem(item)

        content = QFrame()
        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(22, 16, 22, 18)
        content_layout.setSpacing(12)

        header = QHBoxLayout()
        title_box = QVBoxLayout()
        self.page_title = QLabel(self.PAGE_NAMES[0])
        self.page_title.setStyleSheet("font-size: 20px; font-weight: 600;")
        self.status_label = QLabel("Stopped")
        self.status_label.setStyleSheet("color: palette(mid);")
        title_box.addWidget(self.page_title)
        title_box.addWidget(self.status_label)
        header.addLayout(title_box)
        header.addStretch(1)

        self.save_button = QPushButton("Save")
        self.start_button = QPushButton("Start")
        self.stop_button = QPushButton("Stop")
        self.stop_button.setEnabled(False)
        self.save_button.setStyleSheet(
            "QPushButton { background: #ebc700; color: white; font-weight: 600; padding: 7px 13px; border-radius: 0px; }"
            "QPushButton:hover { background: #f4d83c; }"
            "QPushButton:pressed { background: #d6b500; }"
            "QPushButton:disabled { background: #666; color: #bbb; }"
        )
        self.start_button.setStyleSheet(
            "QPushButton { background: #369650; color: white; font-weight: 600; padding: 7px 13px; border-radius: 0px; }"
            "QPushButton:hover { background: #39b967; }"
            "QPushButton:pressed { background: #247d46; }"
            "QPushButton:disabled { background: #666; color: #bbb; }"
        )
        self.stop_button.setStyleSheet(
            "QPushButton { background: #e55765; color: white; font-weight: 600; padding: 7px 13px; border-radius: 0px; }"
            "QPushButton:hover { background: #e15c55; }"
            "QPushButton:pressed { background: #a93d38; }"
            "QPushButton:disabled { background: #666; color: #bbb; }"
        )
        self.save_button.clicked.connect(self.save_settings)
        self.start_button.clicked.connect(self.start_server)
        self.stop_button.clicked.connect(self.stop_server)
        header.addWidget(self.save_button)
        header.addWidget(self.start_button)
        header.addWidget(self.stop_button)
        content_layout.addLayout(header)

        separator = QFrame()
        separator.setFrameShape(QFrame.HLine)
        separator.setFrameShadow(QFrame.Sunken)
        content_layout.addWidget(separator)

        self.stack = QStackedWidget()
        self.stack.addWidget(self._build_overview_page())
        self.stack.addWidget(self._build_account_page())
        self.stack.addWidget(self._build_virtual_directories_page())
        self.stack.addWidget(self._build_network_page())
        self.stack.addWidget(self._build_ftps_page())
        self.stack.addWidget(self._build_logs_page())
        content_layout.addWidget(self.stack, 1)

        root.addWidget(nav_panel)
        root.addWidget(content, 1)

        self.nav_list.currentRowChanged.connect(self._switch_page)
        self.nav_list.setCurrentRow(0)

        self.toast = QFrame(self)
        self.toast.setObjectName("toast")
        self.toast.setStyleSheet("QFrame#toast { background: #30343b; border: 1px solid #555c65; }"
                                 "QLabel { color: #fff; background: transparent; border: none; }")
        toast_layout = QHBoxLayout(self.toast)
        toast_layout.setContentsMargins(16, 11, 16, 11)
        self.toast_label = QLabel()
        self.toast_label.setWordWrap(True)
        toast_layout.addWidget(self.toast_label)
        self.toast.hide()
        self.toast_timer = QTimer(self)
        self.toast_timer.setSingleShot(True)
        self.toast_timer.timeout.connect(self.toast.hide)

    def _page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)
        return page, layout

    def _build_overview_page(self):
        page, layout = self._page()

        status_group = QGroupBox("Status")
        status_layout = QFormLayout(status_group)
        self.server_state_value = QLabel("Stopped")
        self.listen_value = QLabel("—")
        self.protocol_value = QLabel("FTP")
        self.mapping_count_value = QLabel(str(len(self.virtual_mappings)))
        status_layout.addRow("State:", self.server_state_value)
        status_layout.addRow("Listening on:", self.listen_value)
        status_layout.addRow("Protocol:", self.protocol_value)
        status_layout.addRow("Mapped folders:", self.mapping_count_value)
        layout.addWidget(status_group)

        layout.addStretch(1)
        return page

    def _build_account_page(self):
        page, layout = self._page()
        group = QGroupBox("Login and access")
        form = QFormLayout(group)

        self.username_input = QLineEdit(self.username)
        self.password_input = QLineEdit(self.password)
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.installEventFilter(self)
        self.port_input = QSpinBox()
        self.port_input.setRange(1, 65535)
        self.port_input.setValue(self.port)
        self.read_only_checkbox = QCheckBox("Read-only mode")
        self.read_only_checkbox.setChecked(self.read_only)

        form.addRow("Username:", self.username_input)
        form.addRow("Password:", self.password_input)
        form.addRow("Port:", self.port_input)
        form.addRow("", self.read_only_checkbox)
        layout.addWidget(group)

        note = QLabel(
            "Read-only mode allows directory listing and downloads, but blocks uploads, deletion, rename, and directory creation.")
        note.setWordWrap(True)
        note.setStyleSheet("color: palette(mid);")
        layout.addWidget(note)
        layout.addStretch(1)
        self.runtime_lock_widgets += [self.username_input, self.password_input, self.port_input,
                                      self.read_only_checkbox]
        return page

    def _build_virtual_directories_page(self):
        page, layout = self._page()
        self.mapping_editor = VirtualDirectoryEditor(self.virtual_mappings)
        self.mapping_editor.mappings_changed.connect(self._on_mappings_changed)
        layout.addWidget(self.mapping_editor, 1)
        self.runtime_lock_widgets.append(self.mapping_editor)
        return page

    def _build_network_page(self):
        page, layout = self._page()
        group = QGroupBox("Binding and LAN restrictions")
        form = QFormLayout(group)

        self.lan_only_checkbox = QCheckBox("Allow LAN clients only")
        self.lan_only_checkbox.setChecked(self.allow_lan_only)
        self.allowed_nets_input = QLineEdit(self.allowed_nets)
        self.allowed_nets_input.setPlaceholderText("auto or 192.168.1.0/24, 10.0.0.0/8")
        self.bind_host_input = QLineEdit(self.bind_host)
        self.bind_host_input.setPlaceholderText("auto / 0.0.0.0 / specific LAN IP")

        form.addRow("", self.lan_only_checkbox)
        form.addRow("Allowed networks:", self.allowed_nets_input)
        form.addRow("Bind host:", self.bind_host_input)
        layout.addWidget(group)

        note = QLabel(
            "With LAN-only enabled, 'auto' selects a private interface and rejects clients outside the configured CIDR ranges."
        )
        note.setWordWrap(True)
        note.setStyleSheet("color: palette(mid);")
        layout.addWidget(note)
        layout.addStretch(1)
        self.runtime_lock_widgets += [self.lan_only_checkbox, self.allowed_nets_input, self.bind_host_input]
        return page

    def _build_ftps_page(self):
        page, layout = self._page()
        group = QGroupBox("Encryption")
        form = QFormLayout(group)

        self.ftps_enable_checkbox = QCheckBox("Enable FTPS")
        self.ftps_enable_checkbox.setChecked(self.ftps_enabled)
        self.tls_ctrl_checkbox = QCheckBox("Require TLS for control channel")
        self.tls_ctrl_checkbox.setChecked(self.tls_require_ctrl)
        self.tls_data_checkbox = QCheckBox("Require TLS for data channel")
        self.tls_data_checkbox.setChecked(self.tls_require_data)

        self.cert_file_input = QLineEdit(self.cert_file)
        cert_row = QHBoxLayout()
        cert_row.addWidget(self.cert_file_input, 1)
        self.cert_browse_btn = QPushButton("Browse")
        self.cert_browse_btn.clicked.connect(self.browse_cert)
        cert_row.addWidget(self.cert_browse_btn)

        self.key_file_input = QLineEdit(self.key_file)
        key_row = QHBoxLayout()
        key_row.addWidget(self.key_file_input, 1)
        self.key_browse_btn = QPushButton("Browse")
        self.key_browse_btn.clicked.connect(self.browse_key)
        key_row.addWidget(self.key_browse_btn)

        self.cn_input = QLineEdit(self.cert_common_name)
        self.cn_input.setPlaceholderText("hostname or IP")

        form.addRow("", self.ftps_enable_checkbox)
        form.addRow("", self.tls_ctrl_checkbox)
        form.addRow("", self.tls_data_checkbox)
        form.addRow("Certificate:", cert_row)
        form.addRow("Private key:", key_row)
        form.addRow("Certificate CN:", self.cn_input)
        layout.addWidget(group)

        actions = QHBoxLayout()
        self.btn_gen_cert = QPushButton("Generate self-signed certificate")
        self.btn_show_cert = QPushButton("Show certificate info")
        self.btn_gen_cert.clicked.connect(self.on_generate_cert)
        self.btn_show_cert.clicked.connect(self.on_show_cert_info)
        actions.addWidget(self.btn_gen_cert)
        actions.addWidget(self.btn_show_cert)
        actions.addStretch(1)
        layout.addLayout(actions)
        layout.addStretch(1)

        self.runtime_lock_widgets += [
            self.ftps_enable_checkbox, self.tls_ctrl_checkbox, self.tls_data_checkbox,
            self.cert_file_input, self.cert_browse_btn, self.key_file_input,
            self.key_browse_btn, self.cn_input, self.btn_gen_cert,
        ]
        return page

    def _build_logs_page(self):
        page, layout = self._page()

        options = QGroupBox("Other configs")
        options_form = QFormLayout(options)
        self.log_file_input = QLineEdit(self.log_file)
        log_row = QHBoxLayout()
        log_row.addWidget(self.log_file_input, 1)
        self.log_file_button = QPushButton("Browse")
        self.log_file_button.clicked.connect(self.select_log_file)
        log_row.addWidget(self.log_file_button)
        self.daemon_checkbox = QCheckBox("Hide to the system tray")
        self.daemon_checkbox.setChecked(self.run_as_daemon)
        options_form.addRow("Log file:", log_row)
        options_form.addRow("", self.daemon_checkbox)
        layout.addWidget(options)

        filter_row = QHBoxLayout()
        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("Filter logs")
        self.filter_input.setClearButtonEnabled(True)
        self.filter_input.textChanged.connect(self.apply_log_filter)
        clear_button = QPushButton("Clear display")
        clear_button.clicked.connect(self.clear_display_logs)
        filter_row.addWidget(self.filter_input, 1)
        filter_row.addWidget(clear_button)
        layout.addLayout(filter_row)

        self.log_view = QTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setLineWrapMode(QTextEdit.WidgetWidth)
        self.log_view.setPlaceholderText("Server logs will appear here.")
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
        act_clear = QAction("Clear display", self)
        act_clear.triggered.connect(self.clear_display_logs)
        self.log_view.addAction(act_copy)
        self.log_view.addAction(act_copy_all)
        self.log_view.addAction(act_select_all)
        separator = QAction(self)
        separator.setSeparator(True)
        self.log_view.addAction(separator)
        self.log_view.addAction(act_clear)
        layout.addWidget(self.log_view, 1)

        self.runtime_lock_widgets += [self.log_file_input, self.log_file_button]
        return page

    def _switch_page(self, index):
        if not 0 <= index < self.stack.count():
            return

        self.stack.setCurrentIndex(index)
        self.page_title.setText(self.PAGE_NAMES[index])

        selected_icon = self.style().standardIcon(QStyle.StandardPixmap.SP_ArrowRight)
        normal_icon = self.style().standardIcon(QStyle.StandardPixmap.SP_FileDialogDetailedView)

        for i in range(self.nav_list.count()):
            item = self.nav_list.item(i)
            item.setIcon(selected_icon if i == index else normal_icon)

    # ---------- settings ----------
    def _collect_settings(self, validate_for_start=False):
        username = self.username_input.text().strip()
        password = self.password_input.text()
        if not username:
            raise ValueError("Username cannot be empty.")
        if not password:
            raise ValueError("Password cannot be empty.")

        mappings = normalize_mappings(self.mapping_editor.mappings(), require_existing=True)
        if not mappings:
            raise ValueError("Add at least one virtual directory mapping.")

        cert_file = self.cert_file_input.text().strip()
        key_file = self.key_file_input.text().strip()
        ftps_enabled = self.ftps_enable_checkbox.isChecked()
        if validate_for_start and ftps_enabled:
            missing = []
            if not cert_file or not os.path.isfile(cert_file):
                missing.append("certificate file")
            if not key_file or not os.path.isfile(key_file):
                missing.append("private key")
            if missing:
                raise ValueError("FTPS is enabled but missing: " + ", ".join(missing))

        return {
            "username": username,
            "password": password,
            "port": self.port_input.value(),
            "virtual_mappings": mappings,
            "run_as_daemon": self.daemon_checkbox.isChecked(),
            "log_file": self.log_file_input.text().strip() or os.path.join(EXE_PATH, "ftp_log.txt"),
            "allow_lan_only": self.lan_only_checkbox.isChecked(),
            "allowed_nets": self.allowed_nets_input.text().strip() or "auto",
            "bind_host": self.bind_host_input.text().strip() or "auto",
            "read_only": self.read_only_checkbox.isChecked(),
            "ftps_enabled": ftps_enabled,
            "tls_require_ctrl": self.tls_ctrl_checkbox.isChecked(),
            "tls_require_data": self.tls_data_checkbox.isChecked(),
            "cert_file": cert_file or os.path.join(EXE_PATH, "ftpd.crt"),
            "key_file": key_file or os.path.join(EXE_PATH, "ftpd.key"),
            "cert_common_name": self.cn_input.text().strip() or "localhost",
        }

    def _write_settings(self, settings):
        mappings = settings["virtual_mappings"]
        root_mapping = next((m for m in mappings if m.virtual_path == "/"), None)
        legacy_dir = root_mapping.local_path if root_mapping else mappings[0].local_path
        self.config["FTP"] = {
            "username": settings["username"],
            "password": settings["password"],
            "port": str(settings["port"]),
            "ftp_directory": legacy_dir,
            "virtual_mappings": mappings_to_json(mappings),
            "run_as_daemon": "1" if settings["run_as_daemon"] else "0",
            "log_file": settings["log_file"],
            "allow_lan_only": "1" if settings["allow_lan_only"] else "0",
            "allowed_nets": settings["allowed_nets"],
            "bind_host": settings["bind_host"],
            "read_only": "1" if settings["read_only"] else "0",
            "ftps_enabled": "1" if settings["ftps_enabled"] else "0",
            "tls_require_ctrl": "1" if settings["tls_require_ctrl"] else "0",
            "tls_require_data": "1" if settings["tls_require_data"] else "0",
            "cert_file": settings["cert_file"],
            "key_file": settings["key_file"],
            "cert_common_name": settings["cert_common_name"],
        }
        save_config(self.config)

    def save_settings(self):
        try:
            settings = self._collect_settings(validate_for_start=False)
            self._write_settings(settings)
            self.status_label.setText("Settings saved")
            self.show_toast("Settings saved successfully")
            QTimer.singleShot(2200, self._restore_header_status)
        except Exception as exc:
            QMessageBox.warning(self, "Cannot save settings", str(exc))

    def _restore_header_status(self):
        if self.server_thread and self.server_thread.running:
            self.status_label.setText("Server is running")
        else:
            self.status_label.setText("Stopped")

    def _on_mappings_changed(self):
        self.mapping_count_value.setText(str(len(self.mapping_editor.mappings())))

    # ---------- server controls ----------
    def start_server(self):
        if self.server_thread and self.server_thread.isRunning():
            return
        try:
            settings = self._collect_settings(validate_for_start=True)
            self._write_settings(settings)
        except Exception as exc:
            QMessageBox.warning(self, "Cannot start server", str(exc))
            self.log_message(f"ERROR: {exc}")
            return

        self.server_thread = FTPServerThread(
            settings["port"],
            settings["username"],
            settings["password"],
            settings["virtual_mappings"],
            settings["log_file"],
            allow_lan_only=settings["allow_lan_only"],
            allowed_nets_text=settings["allowed_nets"],
            bind_host=settings["bind_host"],
            read_only=settings["read_only"],
            ftps_enabled=settings["ftps_enabled"],
            cert_file=settings["cert_file"],
            key_file=settings["key_file"],
            tls_require_ctrl=settings["tls_require_ctrl"],
            tls_require_data=settings["tls_require_data"],
            parent=self,
        )
        self.server_thread.log_signal.connect(self.log_message)
        self.server_thread.status_signal.connect(self._on_server_status)
        self.server_thread.finished.connect(self._on_server_thread_finished)

        self.status_label.setText("Starting server…")
        self.server_state_value.setText("Starting")
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self._set_runtime_locked(True)
        self.server_thread.start()

        if settings["run_as_daemon"]:
            self.hide_to_tray()

        self.show_toast("FTP server started")

    def stop_server(self):
        thread = self.server_thread
        if thread and thread.isRunning():
            self.status_label.setText("Stopping server…")
            self.stop_button.setEnabled(False)
            thread.stop()
            thread.wait()
        self._set_stopped_state()
        self.show_toast("FTP server stopped")

    def _on_server_status(self, running, detail):
        if running:
            self.status_label.setText("Server is running")
            self.server_state_value.setText("Running")
            self.protocol_value.setText("FTPS" if self.ftps_enable_checkbox.isChecked() else "FTP")
            if detail.startswith("0.0.0.0:"):
                self.update_ip_addresses()
            else:
                self.listen_value.setText(detail)
        else:
            self.status_label.setText("Server stopped")
            self.server_state_value.setText("Stopped")
            if detail:
                self.log_message(f"Server stopped: {detail}")

    def _on_server_thread_finished(self):
        self._set_stopped_state()

    def _set_stopped_state(self):
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.server_state_value.setText("Stopped")
        self.listen_value.setText("—")
        self.status_label.setText("Stopped")
        self._set_runtime_locked(False)

    def _set_runtime_locked(self, locked):
        for widget in self.runtime_lock_widgets:
            widget.setEnabled(not locked)

    # ---------- logs ----------
    def log_message(self, message):
        message = str(message)
        self.log_buffer.append(message)
        if self.filter_input.text().strip():
            self.apply_log_filter()
            return

        bar = self.log_view.verticalScrollBar()
        at_bottom = bar.value() == bar.maximum()
        self.log_view.moveCursor(QTextCursor.End)
        if self.log_view.toPlainText():
            self.log_view.insertPlainText("\n")
        self.log_view.insertPlainText(message)
        if at_bottom:
            QTimer.singleShot(0, lambda: bar.setValue(bar.maximum()))

    def apply_log_filter(self, _text=None):
        text = self.filter_input.text().strip().lower()
        messages = self.log_buffer if not text else [m for m in self.log_buffer if text in m.lower()]
        self.log_view.setPlainText("\n".join(messages))
        bar = self.log_view.verticalScrollBar()
        QTimer.singleShot(0, lambda: bar.setValue(bar.maximum()))

    def clear_display_logs(self):
        self.log_view.clear()
        self.log_buffer.clear()
        self.filter_input.clear()

    # ---------- dialogs and FTPS helpers ----------
    def select_log_file(self):
        log_file, _ = QFileDialog.getSaveFileName(self, "Select log file", self.log_file_input.text(),
                                                  "Log Files (*.txt);;All Files (*)")
        if log_file:
            self.log_file_input.setText(log_file)

    def browse_cert(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Select certificate", self.cert_file_input.text(),
            "Certificate Files (*.crt *.pem *.cer);;All Files (*)"
        )
        if path:
            self.cert_file_input.setText(path)

    def browse_key(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Select private key", self.key_file_input.text(), "Key Files (*.key *.pem);;All Files (*)"
        )
        if path:
            self.key_file_input.setText(path)

    def on_generate_cert(self):
        cert_path = self.cert_file_input.text().strip() or os.path.join(EXE_PATH, "ftpd.crt")
        key_path = self.key_file_input.text().strip() or os.path.join(EXE_PATH, "ftpd.key")
        common_name = self.cn_input.text().strip() or "localhost"
        try:
            cert_dir = os.path.dirname(os.path.abspath(cert_path))
            key_dir = os.path.dirname(os.path.abspath(key_path))
            os.makedirs(cert_dir, exist_ok=True)
            os.makedirs(key_dir, exist_ok=True)
            generate_self_signed_cert(cert_path, key_path, common_name=common_name, days_valid=3650)
            self.log_message(
                f"Generated self-signed certificate:\n  cert: {cert_path}\n  key : {key_path}\n  CN  : {common_name}"
            )
            self.cert_file_input.setText(cert_path)
            self.key_file_input.setText(key_path)
            self.ftps_enable_checkbox.setChecked(True)
            self.on_show_cert_info()
        except Exception as exc:
            self.log_message(f"ERROR generating certificate: {exc}")
            QMessageBox.warning(self, "Certificate generation failed", str(exc))

    def on_show_cert_info(self):
        cert_path = self.cert_file_input.text().strip()
        if not os.path.exists(cert_path):
            QMessageBox.warning(self, "Certificate not found", cert_path or "No certificate path selected.")
            return
        try:
            info = read_cert_info(cert_path)
            text = (
                f"Subject: {info['subject']}\n"
                f"Issuer: {info['issuer']}\n"
                f"Valid: {info['not_before']}  ~  {info['not_after']}\n"
                f"SHA256: {info['sha256_fingerprint']}"
            )
            self.log_message("Certificate info:\n  " + text.replace("\n", "\n  "))
            QMessageBox.information(self, "Certificate information", text)
        except Exception as exc:
            self.log_message(f"ERROR reading certificate: {exc}")
            QMessageBox.warning(self, "Cannot read certificate", str(exc))

    # ---------- tray / window ----------
    def setup_tray_icon(self):
        self.tray_icon = QSystemTrayIcon(self)
        self.tray_icon.setIcon(QIcon(ICON_PATH))
        tray_menu = QMenu()
        restore_action = QAction("Restore", self)
        restore_action.triggered.connect(self.show_and_raise)
        tray_menu.addAction(restore_action)
        quit_action = QAction("Quit", self)
        quit_action.triggered.connect(self.quit_application)
        tray_menu.addAction(quit_action)
        self.tray_icon.setContextMenu(tray_menu)
        self.tray_icon.activated.connect(self.on_tray_icon_activated)
        self.tray_icon.show()

    def on_tray_icon_activated(self, reason):
        if reason == QSystemTrayIcon.ActivationReason.Trigger:
            self.show_and_raise()

    def show_and_raise(self):
        self.show()
        self.raise_()
        self.activateWindow()

    def hide_to_tray(self):
        self.hide()
        if self.tray_icon:
            self.tray_icon.showMessage("FTP Server", "Running in background", QSystemTrayIcon.Information, 2500)

    def quit_application(self):
        self.force_quit = True
        if self.server_thread and self.server_thread.isRunning():
            self.server_thread.stop()
            self.server_thread.wait()
        if self.tray_icon:
            self.tray_icon.hide()
        QApplication.instance().quit()

    def show_toast(self, message):
        self.toast_timer.stop()
        self.toast_label.setText(message)
        self.toast.setFixedWidth(min(320, max(180, self.width() - 32)))
        self.toast.adjustSize()
        self._position_toast()
        self.toast.raise_()
        self.toast.show()
        self.toast_timer.start(2500)

    def _position_toast(self):
        self.toast.move(self.width() - self.toast.width() - 16, self.height() - self.toast.height() - 16)

    def closeEvent(self, event):
        if self.force_quit:
            event.accept()
            return
        if self.daemon_checkbox.isChecked():
            event.ignore()
            self.hide_to_tray()
            return
        if self.server_thread and self.server_thread.isRunning():
            self.server_thread.stop()
            self.server_thread.wait()
        event.accept()

    def resizeEvent(self, event):
        super().resizeEvent(event)
        if hasattr(self, "toast"):
            self._position_toast()

    def eventFilter(self, obj, event):
        if obj == self.password_input:
            if event.type() == event.Type.FocusIn:
                self.password_input.setEchoMode(QLineEdit.Normal)
            elif event.type() == event.Type.FocusOut:
                self.password_input.setEchoMode(QLineEdit.Password)
        return super().eventFilter(obj, event)

    def update_ip_addresses(self):
        port = self.port_input.value()
        bind_host = self.bind_host_input.text().strip().lower() or "auto"
        if bind_host not in ("auto", "all", "0.0.0.0"):
            endpoints = [f"{bind_host}:{port}"]
        else:
            endpoints = [f"{ip}:{port}" for ip in self.get_ip_addresses()]
            if not endpoints:
                endpoints = [f"0.0.0.0:{port}"]
        self.listen_value.setText(", ".join(endpoints))

    @staticmethod
    def get_ip_addresses():
        result = []
        try:
            for ip in socket.gethostbyname_ex(socket.gethostname())[2]:
                if not ip.startswith("127.") and ip not in result:
                    result.append(ip)
        except Exception:
            pass
        return result


def load_config():
    config = configparser.ConfigParser()
    if not os.path.exists(CONFIG_FILE):
        gen_user = generate_username()
        gen_pass = generate_password()
        gen_port = pick_random_port()
        default_ftp_dir = r"C:\Temp\FTP" if os.name == "nt" else os.path.join(EXE_PATH, "FTP")
        try:
            os.makedirs(default_ftp_dir, exist_ok=True)
        except Exception:
            pass

        default_mappings = [VirtualMapping("/", default_ftp_dir)]
        config["FTP"] = {
            "username": gen_user,
            "password": gen_pass,
            "port": str(gen_port),
            "ftp_directory": default_ftp_dir,
            "virtual_mappings": mappings_to_json(default_mappings),
            "run_as_daemon": "0",
            "log_file": os.path.join(EXE_PATH, "ftp_log.txt"),
            "allow_lan_only": "1",
            "allowed_nets": "auto",
            "bind_host": "auto",
            "read_only": "1",
            "ftps_enabled": "0",
            "tls_require_ctrl": "1",
            "tls_require_data": "1",
            "cert_file": os.path.join(EXE_PATH, "ftpd.crt"),
            "key_file": os.path.join(EXE_PATH, "ftpd.key"),
            "cert_common_name": "localhost",
        }
        save_config(config)
    else:
        config.read(CONFIG_FILE, encoding="utf-8")
        if "FTP" not in config:
            config["FTP"] = {}
    return config


def save_config(config):
    with open(CONFIG_FILE, "w", encoding="utf-8") as configfile:
        config.write(configfile)


def generate_self_signed_cert(cert_path, key_path, common_name="localhost", days_valid=3650):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=days_valid))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(common_name)]), critical=False)
        .sign(key, hashes.SHA256(), default_backend())
    )

    with open(key_path, "wb") as file:
        file.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    with open(cert_path, "wb") as file:
        file.write(cert.public_bytes(serialization.Encoding.PEM))
    return cert_path, key_path


def read_cert_info(cert_path):
    with open(cert_path, "rb") as file:
        data = file.read()
    cert = x509.load_pem_x509_certificate(data, default_backend())
    fingerprint_hex = cert.fingerprint(hashes.SHA256()).hex().upper()
    fingerprint = ":".join(fingerprint_hex[i:i + 2] for i in range(0, len(fingerprint_hex), 2))
    return {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "not_before": cert.not_valid_before,
        "not_after": cert.not_valid_after,
        "sha256_fingerprint": fingerprint,
    }


def dark_title_bar(hwnd, use_dark_mode=False):
    dwmwa_use_immersive_dark_mode = 20
    try:
        set_window_attribute = ct.windll.dwmapi.DwmSetWindowAttribute
        value = ct.c_int(1 if use_dark_mode else 0)
        set_window_attribute(
            hwnd,
            dwmwa_use_immersive_dark_mode,
            ct.byref(value),
            ct.sizeof(value),
        )
    except Exception:
        pass


if __name__ == "__main__":
    config = load_config()
    app = QApplication(sys.argv)
    app.setWindowIcon(QIcon(ICON_PATH))
    qdarktheme.setup_theme("auto")
    gui = FTPGuiApp(config)

    if not config.getboolean("FTP", "run_as_daemon", fallback=False):
        gui.show()
        try:
            dark_title_bar(gui.winId(), use_dark_mode=darkdetect.isDark())
        except Exception:
            pass

    sys.exit(app.exec())
