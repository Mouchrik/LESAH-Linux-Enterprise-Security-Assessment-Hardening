from __future__ import annotations

import datetime as dt
import webbrowser
from pathlib import Path
from typing import Dict, List, Tuple

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QTableWidget, QTableWidgetItem,
    QPushButton, QToolBar, QTabWidget, QTextEdit, QSplitter, QFileDialog, QMessageBox,
    QHeaderView, QComboBox, QLabel, QAbstractItemView
)

import matplotlib
matplotlib.use("QtAgg")
from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg
from matplotlib.figure import Figure

from .models import (
    Host, Settings, load_inventory, save_inventory, load_settings, save_settings,
    load_reports_db, save_reports_db, import_legacy_inventory,
)
from .dialogs import HostDialog, SettingsDialog
from .ssh_worker import AuditWorker

HOST_COLUMNS = ["Name", "Host", "Group", "Last Score", "Last Run"]


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("LESAH Security Toolkit — Fleet Control Panel")
        self.resize(1180, 720)

        self.hosts: List[Host] = load_inventory()
        self.settings: Settings = load_settings()
        self.reports_db: List[dict] = load_reports_db()

        self.active_workers: Dict[str, AuditWorker] = {}
        self.pending_queue: List[Tuple[Host, str]] = []

        self._build_ui()
        self._refresh_host_table()
        self._refresh_reports_table()
        self._refresh_trends()

    # ------------------------------------------------------------------ UI
    def _build_ui(self):
        toolbar = QToolBar("Main")
        toolbar.setMovable(False)
        self.addToolBar(toolbar)

        add_btn = QPushButton("＋ Add Host")
        add_btn.clicked.connect(self._add_host)
        edit_btn = QPushButton("Edit")
        edit_btn.clicked.connect(self._edit_host)
        remove_btn = QPushButton("Remove")
        remove_btn.clicked.connect(self._remove_host)
        import_btn = QPushButton("Import server.txt")
        import_btn.clicked.connect(self._import_inventory)
        settings_btn = QPushButton("Settings")
        settings_btn.clicked.connect(self._open_settings)

        run_audit_btn = QPushButton("▶ Run Audit")
        run_audit_btn.setStyleSheet("font-weight:bold;")
        run_audit_btn.clicked.connect(lambda: self._run_selected("audit"))
        run_fix_btn = QPushButton("🛠 Run Fix")
        run_fix_btn.setStyleSheet("font-weight:bold; color:#b35c00;")
        run_fix_btn.clicked.connect(lambda: self._run_selected("fix"))

        for w in (add_btn, edit_btn, remove_btn, import_btn, settings_btn):
            toolbar.addWidget(w)
        toolbar.addSeparator()
        toolbar.addWidget(run_audit_btn)
        toolbar.addWidget(run_fix_btn)

        # Left: host table
        self.host_table = QTableWidget(0, len(HOST_COLUMNS))
        self.host_table.setHorizontalHeaderLabels(HOST_COLUMNS)
        self.host_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.host_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.host_table.setEditTriggers(QAbstractItemView.NoEditTriggers)

        left = QWidget()
        left_layout = QVBoxLayout(left)
        left_layout.addWidget(QLabel("Hosts  (select rows, Ctrl/Shift for multiple)"))
        left_layout.addWidget(self.host_table)

        # Right: tabs
        self.tabs = QTabWidget()

        self.console = QTextEdit()
        self.console.setReadOnly(True)
        self.console.setStyleSheet("font-family: Consolas, monospace; font-size: 12px; background:#111; color:#ddd;")
        self.tabs.addTab(self.console, "Live Console")

        self.reports_table = QTableWidget(0, 6)
        self.reports_table.setHorizontalHeaderLabels(["Host", "Mode", "Score", "Critical", "Date", "File"])
        self.reports_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.reports_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.reports_table.itemDoubleClicked.connect(self._open_report_row)
        reports_widget = QWidget()
        rl = QVBoxLayout(reports_widget)
        rl.addWidget(QLabel("Double-click a row to open the HTML report."))
        rl.addWidget(self.reports_table)
        self.tabs.addTab(reports_widget, "Reports")

        trends_widget = QWidget()
        tl = QVBoxLayout(trends_widget)
        top_row = QHBoxLayout()
        top_row.addWidget(QLabel("Host:"))
        self.trend_combo = QComboBox()
        self.trend_combo.addItem("All hosts (average)")
        self.trend_combo.currentIndexChanged.connect(self._refresh_trends)
        top_row.addWidget(self.trend_combo)
        top_row.addStretch()
        tl.addLayout(top_row)
        self.trend_figure = Figure(figsize=(5, 3))
        self.trend_canvas = FigureCanvasQTAgg(self.trend_figure)
        tl.addWidget(self.trend_canvas)
        self.tabs.addTab(trends_widget, "Trends")

        splitter = QSplitter()
        splitter.addWidget(left)
        splitter.addWidget(self.tabs)
        splitter.setStretchFactor(0, 2)
        splitter.setStretchFactor(1, 3)
        self.setCentralWidget(splitter)

        self.statusBar().showMessage("Ready.")

    # ---------------------------------------------------------- host CRUD
    def _refresh_host_table(self):
        self.host_table.setRowCount(len(self.hosts))
        for row, h in enumerate(self.hosts):
            values = [h.name, f"{h.user}@{h.host}:{h.port}", h.group,
                      str(h.last_score) if h.last_score is not None else "—",
                      h.last_run or "never"]
            for col, val in enumerate(values):
                item = QTableWidgetItem(val)
                if col == 3 and h.last_score is not None:
                    item.setForeground(QColor("#28a745" if h.last_score >= 80 else
                                               "#ffc107" if h.last_score >= 60 else "#dc3545"))
                self.host_table.setItem(row, col, item)
        self._refresh_trend_combo()

    def _selected_hosts(self) -> List[Host]:
        rows = sorted({idx.row() for idx in self.host_table.selectedIndexes()})
        return [self.hosts[r] for r in rows]

    def _add_host(self):
        dlg = HostDialog(parent=self)
        if dlg.exec():
            h = dlg.get_host()
            if not h.host:
                QMessageBox.warning(self, "Missing host", "Host/IP is required.")
                return
            self.hosts.append(h)
            save_inventory(self.hosts)
            self._refresh_host_table()

    def _edit_host(self):
        sel = self._selected_hosts()
        if len(sel) != 1:
            QMessageBox.information(self, "Select one host", "Select exactly one host to edit.")
            return
        idx = self.hosts.index(sel[0])
        dlg = HostDialog(host=sel[0], parent=self)
        if dlg.exec():
            self.hosts[idx] = dlg.get_host()
            save_inventory(self.hosts)
            self._refresh_host_table()

    def _remove_host(self):
        sel = self._selected_hosts()
        if not sel:
            return
        if QMessageBox.question(self, "Remove hosts", f"Remove {len(sel)} host(s)?") != QMessageBox.Yes:
            return
        self.hosts = [h for h in self.hosts if h not in sel]
        save_inventory(self.hosts)
        self._refresh_host_table()

    def _import_inventory(self):
        path, _ = QFileDialog.getOpenFileName(self, "Import legacy server.txt", filter="Text files (*.txt);;All files (*)")
        if not path:
            return
        imported = import_legacy_inventory(path)
        existing_hosts = {h.host for h in self.hosts}
        added = 0
        for h in imported:
            if h.host not in existing_hosts:
                self.hosts.append(h)
                added += 1
        save_inventory(self.hosts)
        self._refresh_host_table()
        QMessageBox.information(self, "Import complete", f"Imported {added} new host(s).")

    def _open_settings(self):
        dlg = SettingsDialog(self.settings, parent=self)
        if dlg.exec():
            self.settings = dlg.get_settings()
            save_settings(self.settings)

    # ---------------------------------------------------------- job queue
    def _run_selected(self, mode: str):
        sel = self._selected_hosts()
        if not sel:
            QMessageBox.information(self, "No hosts selected", "Select one or more hosts first.")
            return
        if not self.settings.local_script_path or not Path(self.settings.local_script_path).exists():
            QMessageBox.warning(self, "Missing script", "Set a valid local audit script path in Settings first.")
            return
        for h in sel:
            self.pending_queue.append((h, mode))
        self._log_line("queue", f"Queued {len(sel)} host(s) for '{mode}'.")
        self._pump_queue()

    def _pump_queue(self):
        while self.pending_queue and len(self.active_workers) < self.settings.max_concurrency:
            host, mode = self.pending_queue.pop(0)
            if host.name in self.active_workers:
                self.pending_queue.append((host, mode))
                break
            worker = AuditWorker(host, mode, self.settings)
            worker.line_received.connect(self._log_line)
            worker.job_finished.connect(self._on_job_finished)
            self.active_workers[host.name] = worker
            self._log_line(host.name, f"=== starting {mode} ===")
            worker.start()
        self.statusBar().showMessage(
            f"Active: {len(self.active_workers)}  |  Queued: {len(self.pending_queue)}"
        )

    def _on_job_finished(self, host_name: str, success: bool, result: dict):
        self._log_line(host_name, f"=== finished ({'OK' if success else 'FAILED'}) ===")
        self.active_workers.pop(host_name, None)

        for h in self.hosts:
            if h.name == host_name:
                if result.get("score") is not None:
                    h.last_score = result["score"]
                h.last_run = dt.datetime.now().strftime("%Y-%m-%d %H:%M")
                break
        save_inventory(self.hosts)
        self._refresh_host_table()

        if result.get("local_path"):
            entry = {
                "host": host_name,
                "mode": result.get("mode", ""),
                "score": result.get("score"),
                "critical_count": result.get("critical_count"),
                "date": dt.datetime.now().isoformat(timespec="seconds"),
                "path": result["local_path"],
            }
            self.reports_db.append(entry)
            save_reports_db(self.reports_db)
            self._refresh_reports_table()
            self._refresh_trends()

        self._pump_queue()

    def _log_line(self, host_name: str, text: str):
        self.console.append(f"[{host_name}] {text}")
        self.console.verticalScrollBar().setValue(self.console.verticalScrollBar().maximum())

    # -------------------------------------------------------------- reports
    def _refresh_reports_table(self):
        self.reports_table.setRowCount(len(self.reports_db))
        for row, entry in enumerate(reversed(self.reports_db)):
            values = [
                entry.get("host", ""),
                entry.get("mode", ""),
                str(entry.get("score", "—")),
                str(entry.get("critical_count", "—")),
                entry.get("date", "")[:16].replace("T", " "),
                Path(entry.get("path", "")).name,
            ]
            for col, val in enumerate(values):
                item = QTableWidgetItem(val)
                item.setData(Qt.UserRole, entry.get("path", ""))
                self.reports_table.setItem(row, col, item)

    def _open_report_row(self, item: QTableWidgetItem):
        row = item.row()
        path_item = self.reports_table.item(row, 0)
        path = self.reports_table.item(row, 5)
        full_path = self.reports_table.item(row, 0).data(Qt.UserRole)
        if full_path and Path(full_path).exists():
            webbrowser.open(f"file://{full_path}")
        else:
            QMessageBox.warning(self, "Report missing", "The report file could not be found on disk.")

    # --------------------------------------------------------------- trends
    def _refresh_trend_combo(self):
        current = self.trend_combo.currentText()
        self.trend_combo.blockSignals(True)
        self.trend_combo.clear()
        self.trend_combo.addItem("All hosts (average)")
        for h in self.hosts:
            self.trend_combo.addItem(h.name)
        idx = self.trend_combo.findText(current)
        self.trend_combo.setCurrentIndex(idx if idx >= 0 else 0)
        self.trend_combo.blockSignals(False)

    def _refresh_trends(self):
        self.trend_figure.clear()
        ax = self.trend_figure.add_subplot(111)
        choice = self.trend_combo.currentText() if self.trend_combo.count() else "All hosts (average)"

        entries = [e for e in self.reports_db if e.get("score") is not None]
        entries.sort(key=lambda e: e.get("date", ""))

        if choice.startswith("All hosts"):
            by_date: Dict[str, List[int]] = {}
            for e in entries:
                d = e["date"][:10]
                by_date.setdefault(d, []).append(e["score"])
            dates = sorted(by_date.keys())
            scores = [sum(by_date[d]) / len(by_date[d]) for d in dates]
            ax.set_title("Fleet average security score over time")
        else:
            filtered = [e for e in entries if e.get("host") == choice]
            dates = [e["date"][:16].replace("T", " ") for e in filtered]
            scores = [e["score"] for e in filtered]
            ax.set_title(f"Security score over time — {choice}")

        if dates:
            ax.plot(dates, scores, marker="o", color="#667eea")
            ax.set_ylim(0, 100)
            ax.set_ylabel("Score")
            ax.tick_params(axis="x", rotation=45, labelsize=7)
        else:
            ax.text(0.5, 0.5, "No data yet — run an audit first.", ha="center", va="center")
            ax.axis("off")

        self.trend_figure.tight_layout()
        self.trend_canvas.draw()
