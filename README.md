# Simple FTP Server with GUI for Windows

The [original repository](https://github.com/ghostersk/ftp-server-gui) is forked here with the intention of updating it to use the newer PySide6, making some improvements and adding new features. Additionally, [this project](https://github.com/puff-dayo/ftp-server-gui) has abandoned support for Linux and has not undergone security testing. Please do not expose it to any public network.

Download a compiled binary from [Release](https://github.com/puff-dayo/ftp-server-gui/releases).

#### Requirements

Contrary to what the pyftpdlib benchmark claims, it could only barely achieve speeds of 10–12 MB/s on Windows, so the backend was switched to a different FTP library.

```
requires-python = ">=3.12"
dependencies = [
    "cryptography>=50.0.0",
    "imageio>=2.37.3",
    "nuitka>=4.3.1",
    "pillow>=13.0.0",
    "aioftp>=0.28.3",
    "pyinstaller>=6.22.0",
    "pyqtdarktheme-fork>=2.3.6",
    "pyside6>=6.12.0",
]
```

##### Windows
Check `build.bat`.

##### Linux
- It doesn't currently work on linux unlike the origin [repo](https://github.com/ghostersk/ftp-server-gui).

### contribution:
FTP.png icon: <a href="https://www.flaticon.com/free-icons/ftp" title="ftp icons">Ftp icons created by andinur - Flaticon</a>
