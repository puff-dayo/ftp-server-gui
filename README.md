# Simple FTP Server with GUI for Windows
- Choose a single folder to serve
- Option to select port (ports <1024 may require permissions or firewall access)
- Logging to the GUI and to a file (file with timestamps)
- With system tray icon to restore daemon FTP server after is minimized
- It can run in background from launch if you set `run_as_daemon = 1` in `ftp_config.cfg`

The [original repository](https://github.com/ghostersk/ftp-server-gui) is forked here with the intention of updating it to use the newer PySide6, making some improvements and adding new features. Additionally, this project has abandoned support for Linux and has not undergone security testing. Please do not expose it to any public network.

![image](https://github.com/user-attachments/assets/4fba0521-b1b7-4c6a-b85e-623cab6f62e4)

#### Default ftp config
```
username: ftp_user
password: very_safe@2025
port: 33921
ftp_directory: C:\Temp\FTP
run_as_daemon: false
log_file: ftp_log.txt in the same directory as .exe
```

#### Requirements
```
# see pyproject.toml and uv.lock
requires-python = ">=3.12"
dependencies = [
    "pillow>=11.1.0",
    "pyftpdlib>=2.0.1",
    "pyinstaller>=6.11.1",
    "pyqtdarktheme-fork>=2.3.4",
    "pyside6>=6.8.2.1",
]
```

##### Windows
- This was built for windows, as currently there is no simple non install FTP Server solution
- On Windows you do not need admin rights, only to allow traffic on ports <1024 through windows firewall
- You can select FTP folder location
- It keeps logged access in file

Windows building is simple as

`pyinstaller --onefile --windowed --add-data "ftp.png;." --icon=ftp.png ftp_gui.py`

##### Linux
- It doesn't currently work on linux unlike the origin [repo](https://github.com/ghostersk/ftp-server-gui)


### Issues and todos
1. To fix: quit from system tray does not work when daemon mod is ON
2. Add feature: read only mode
3. Add feature: only allow LAN

### contribution:
FTP.png icon: <a href="https://www.flaticon.com/free-icons/ftp" title="ftp icons">Ftp icons created by andinur - Flaticon</a>
