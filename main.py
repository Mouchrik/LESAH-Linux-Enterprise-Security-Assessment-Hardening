#!/usr/bin/env python3
"""LESAH Security Toolkit — Desktop Fleet Control Panel.

Launches the PySide6 GUI on top of the existing security_audit_rhel.sh
RHEL hardening/audit script. See README.md for setup and usage.
"""
import sys

from PySide6.QtWidgets import QApplication

from app.main_window import MainWindow


def main():
    app = QApplication(sys.argv)
    app.setApplicationName("LESAH Security Toolkit")
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
