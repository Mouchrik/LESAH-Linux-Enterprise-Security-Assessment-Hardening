from __future__ import annotations

from PySide6.QtWidgets import (
    QDialog, QFormLayout, QLineEdit, QSpinBox, QDialogButtonBox, QPushButton,
    QHBoxLayout, QFileDialog, QWidget, QVBoxLayout, QLabel
)

from .models import Host, Settings


class HostDialog(QDialog):
    def __init__(self, host: Host | None = None, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Edit Host" if host else "Add Host")
        self.setMinimumWidth(380)

        self.name_edit = QLineEdit(host.name if host else "")
        self.host_edit = QLineEdit(host.host if host else "")
        self.port_spin = QSpinBox()
        self.port_spin.setRange(1, 65535)
        self.port_spin.setValue(host.port if host else 22)
        self.user_edit = QLineEdit(host.user if host else "root")
        self.group_edit = QLineEdit(host.group if host else "default")

        self.key_edit = QLineEdit(host.key_path if host else "")
        browse_btn = QPushButton("Browse...")
        browse_btn.clicked.connect(self._browse_key)
        key_row = QWidget()
        key_layout = QHBoxLayout(key_row)
        key_layout.setContentsMargins(0, 0, 0, 0)
        key_layout.addWidget(self.key_edit)
        key_layout.addWidget(browse_btn)

        form = QFormLayout()
        form.addRow("Name:", self.name_edit)
        form.addRow("Host / IP:", self.host_edit)
        form.addRow("Port:", self.port_spin)
        form.addRow("SSH User:", self.user_edit)
        form.addRow("SSH Key (optional):", key_row)
        form.addRow("Group:", self.group_edit)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)

        layout = QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(buttons)

    def _browse_key(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select SSH private key")
        if path:
            self.key_edit.setText(path)

    def get_host(self) -> Host:
        return Host(
            name=self.name_edit.text().strip() or self.host_edit.text().strip(),
            host=self.host_edit.text().strip(),
            port=self.port_spin.value(),
            user=self.user_edit.text().strip() or "root",
            key_path=self.key_edit.text().strip(),
            group=self.group_edit.text().strip() or "default",
        )


class SettingsDialog(QDialog):
    def __init__(self, settings: Settings, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Settings")
        self.setMinimumWidth(460)

        self.script_edit = QLineEdit(settings.local_script_path)
        browse_btn = QPushButton("Browse...")
        browse_btn.clicked.connect(self._browse_script)
        script_row = QWidget()
        script_layout = QHBoxLayout(script_row)
        script_layout.setContentsMargins(0, 0, 0, 0)
        script_layout.addWidget(self.script_edit)
        script_layout.addWidget(browse_btn)

        self.remote_dir_edit = QLineEdit(settings.remote_dir)
        self.concurrency_spin = QSpinBox()
        self.concurrency_spin.setRange(1, 50)
        self.concurrency_spin.setValue(settings.max_concurrency)
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(1, 300)
        self.timeout_spin.setValue(settings.connect_timeout)

        form = QFormLayout()
        form.addRow("Local audit script:", script_row)
        form.addRow("Remote deploy dir:", self.remote_dir_edit)
        form.addRow("Max concurrent hosts:", self.concurrency_spin)
        form.addRow("SSH connect timeout (s):", self.timeout_spin)

        note = QLabel(
            "The audit script is deployed to each host automatically on first run\n"
            "(matches the behaviour of the original lunch_check.sh)."
        )
        note.setStyleSheet("color: #666; font-size: 11px;")

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)

        layout = QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(note)
        layout.addWidget(buttons)

    def _browse_script(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select security_audit_rhel.sh", filter="Shell scripts (*.sh)")
        if path:
            self.script_edit.setText(path)

    def get_settings(self) -> Settings:
        return Settings(
            local_script_path=self.script_edit.text().strip(),
            remote_dir=self.remote_dir_edit.text().strip() or "/root/LESAH/",
            max_concurrency=self.concurrency_spin.value(),
            connect_timeout=self.timeout_spin.value(),
        )
