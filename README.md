# Simple FTP Server with GUI for Windows
- Choose a single folder to serve
- FTPS, LAN-only mode and Read-only mode
- Logging to the GUI and to a file (file with timestamps)
- With system tray icon after is minimized

The [original repository](https://github.com/ghostersk/ftp-server-gui) is forked here with the intention of updating it to use the newer PySide6, making some improvements and adding new features. Additionally, [this project](https://github.com/puff-dayo/ftp-server-gui) has abandoned support for Linux and has not undergone security testing. Please do not expose it to any public network.

<img width="800" height="auto" alt="" src="https://github.com/user-attachments/assets/48fa7b4a-fe45-4a6b-b0e0-e50e35e64353" />

Download a compiled binary from [Release](https://github.com/puff-dayo/ftp-server-gui/releases).

#### Requirements
```
requires-python = ">=3.12"
dependencies = [
    "cryptography>=46.0.2",
    "imageio>=2.37.0",
    "nuitka==2.7.14",
    "pillow>=11.1.0",
    "pyftpdlib==2.1.0",
    "pyinstaller>=6.11.1",
    "pyopenssl>=25.3.0",
    "pyqtdarktheme-fork>=2.3.4",
    "pyside6>=6.8.2.1",
]
```

##### Windows
- This was built for windows, as currently there is no simple non install FTP Server solution
- On Windows you do not need admin rights, only to allow traffic on ports through windows firewall

Windows building is simple as

`build.bat`

##### Linux
- It doesn't currently work on linux unlike the origin [repo](https://github.com/ghostersk/ftp-server-gui)


### Issues and todos
To fix: quit from system tray does not work when daemon is ON

### contribution:
FTP.png icon: <a href="https://www.flaticon.com/free-icons/ftp" title="ftp icons">Ftp icons created by andinur - Flaticon</a>
