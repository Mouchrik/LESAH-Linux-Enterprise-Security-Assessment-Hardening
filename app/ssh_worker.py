"""Background SSH worker: deploys the audit script if missing, runs audit/fix,
streams live output back to the GUI, then fetches the resulting HTML report."""
from __future__ import annotations

import os
import re
import time
from pathlib import Path
from typing import Optional

import paramiko
from PySide6.QtCore import QThread, Signal

from .models import Host, Settings, LOCAL_REPORTS_DIR

SCORE_RE = re.compile(r"Final Security Score:\s*(\d+)\s*/\s*100")
CRITICAL_HTML_RE = re.compile(
    r'<div class="score" style="color:#dc3545;">(\d+)</div>\s*<div>Critical Issues</div>'
)


class AuditWorker(QThread):
    """Runs one audit/fix job against a single host over SSH."""

    line_received = Signal(str, str)          # host_name, output line
    job_finished = Signal(str, bool, dict)     # host_name, success, result info

    def __init__(self, host: Host, mode: str, settings: Settings, parent=None):
        super().__init__(parent)
        self.host = host
        self.mode = mode  # "audit" or "fix"
        self.settings = settings
        self._client: Optional[paramiko.SSHClient] = None

    def _connect(self) -> paramiko.SSHClient:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        kwargs = dict(
            hostname=self.host.host,
            port=self.host.port,
            username=self.host.user,
            timeout=self.settings.connect_timeout,
        )
        if self.host.key_path:
            kwargs["key_filename"] = self.host.key_path
        client.connect(**kwargs)
        return client

    def _emit(self, text: str) -> None:
        self.line_received.emit(self.host.name, text)

    def run(self) -> None:
        result = {"local_path": None, "score": None, "critical_count": None, "mode": self.mode}
        try:
            client = self._connect()
            self._client = client
            sftp = client.open_sftp()

            remote_dir = self.settings.remote_dir.rstrip("/")
            remote_script = f"{remote_dir}/security_audit_rhel.sh"

            _, stdout, _ = client.exec_command(f"test -x '{remote_script}' && echo OK || echo MISSING")
            present = stdout.read().decode().strip() == "OK"

            if not present:
                self._emit("[setup] Deploying security_audit_rhel.sh...")
                client.exec_command(f"mkdir -p '{remote_dir}'")
                time.sleep(0.3)
                sftp.put(self.settings.local_script_path, remote_script)
                client.exec_command(f"chmod +x '{remote_script}'")
                self._emit("[setup] Script deployed.")
            else:
                self._emit("[setup] Remote script already present.")

            flag = "--fix" if self.mode == "fix" else "--audit"
            cmd = f"bash -lc \"cd '{remote_dir}' && ./security_audit_rhel.sh {flag}\""
            self._emit(f"[run] {cmd}")

            _, stdout, stderr = client.exec_command(cmd, get_pty=True)
            channel = stdout.channel
            buf = ""
            while True:
                if channel.recv_ready():
                    chunk = channel.recv(4096).decode(errors="replace")
                    buf += chunk
                    while "\n" in buf:
                        line, buf = buf.split("\n", 1)
                        clean = re.sub(r"\x1b\[[0-9;]*m", "", line).rstrip("\r")
                        if clean:
                            self._emit(clean)
                if channel.exit_status_ready() and not channel.recv_ready():
                    break
                time.sleep(0.05)
            if buf.strip():
                self._emit(re.sub(r"\x1b\[[0-9;]*m", "", buf).strip())
            exit_status = channel.recv_exit_status()

            # locate newest report remotely
            find_cmd = f"ls -t '{remote_dir}/reports'/security_report_*.html 2>/dev/null | head -1"
            _, out, _ = client.exec_command(find_cmd)
            remote_report = out.read().decode().strip()

            if remote_report:
                LOCAL_REPORTS_DIR.mkdir(parents=True, exist_ok=True)
                base = os.path.basename(remote_report)
                local_path = str(LOCAL_REPORTS_DIR / f"{self.host.name}_{base}")
                sftp.get(remote_report, local_path)
                result["local_path"] = local_path

                html = Path(local_path).read_text(errors="replace")
                m = CRITICAL_HTML_RE.search(html)
                if m:
                    result["critical_count"] = int(m.group(1))

            self._emit("[run] Full stdout scan for score...")
            _, stdout2, _ = client.exec_command(
                f"tail -n 50 '{self.settings.remote_dir.rstrip('/')}/audit.log' 2>/dev/null || true"
            )
            tail_text = stdout2.read().decode(errors="replace")
            matches = SCORE_RE.findall(tail_text)
            if matches:
                result["score"] = int(matches[-1])
            elif result["local_path"]:
                m = re.search(r'class="score[^"]*">(\d+)</div>', Path(result["local_path"]).read_text(errors="replace"))
                if m:
                    result["score"] = int(m.group(1))

            sftp.close()
            client.close()
            self.job_finished.emit(self.host.name, exit_status == 0, result)
        except Exception as exc:  # noqa: BLE001
            self._emit(f"[ERROR] {exc}")
            self.job_finished.emit(self.host.name, False, result)
