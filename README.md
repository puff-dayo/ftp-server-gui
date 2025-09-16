# Simple FTP Server with GUI for Windows
- Choose a single folder to serve
- LAN-only mode and Read-only mode
- Logging to the GUI and to a file (file with timestamps)
- With system tray icon after is minimized

The [original repository](https://github.com/ghostersk/ftp-server-gui) is forked here with the intention of updating it to use the newer PySide6, making some improvements and adding new features. Additionally, this project has abandoned support for Linux and has not undergone security testing. Please do not expose it to any public network.

<img width="800" height="auto" alt="" src="https://github.com/user-attachments/assets/6cb4e5bf-9bdc-4af1-97c7-9fd8779b5dae" />

Download a compiled binary from [Release](https://github.com/puff-dayo/ftp-server-gui/releases).

#### Requirements
```
requires-python = ">=3.12"
dependencies = [
    "imageio>=2.37.0",
    "nuitka==2.7.14",
    "pillow>=11.1.0",
    "pyftpdlib>=2.0.1",
    "pyinstaller>=6.11.1",
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
