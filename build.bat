nuitka --mode=standalone --windows-console-mode=disable --enable-plugin=pyside6 ^
  --include-package-data=qdarktheme ^
  --include-data-files=./ftp.png=ftp.png ^
  --windows-icon-from-ico=./ftp.png ^
  --output-dir=build ^
  ftp_gui.py