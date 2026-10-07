# LESAH Security Toolkit — Desktop Fleet Control Panel (v2)

A PySide6 (Qt) desktop GUI built on top of your original `security_audit_rhel.sh`
and `lunch_check.sh`. It replaces the manual SSH loop with a control panel that
can manage an inventory of RHEL hosts, run audits/fixes on many of them in
parallel, watch live output, browse collected reports, and chart score trends
over time.

## What it does

- **Inventory management** — add/edit/remove hosts (name, IP, port, SSH user,
  optional key file, group). You can also import your old `server.txt` file
  directly (File toolbar → *Import server.txt*).
- **Run Audit / Run Fix** — select one or more hosts and run either mode.
  Jobs run in parallel (bounded by *Max concurrent hosts* in Settings) using
  background threads, so the UI never freezes.
- **Auto-deploy** — if `security_audit_rhel.sh` isn't present on a host yet,
  it's uploaded and `chmod +x`'d automatically, exactly like `lunch_check.sh`
  used to do — just without needing a shell loop or SSH keys accepted manually
  ahead of time (host keys are auto-accepted on first connect).
- **Live Console** — combined, prefixed-by-host streaming output from every
  running job, ANSI colour codes stripped for readability.
- **Reports tab** — every report pulled back from a host is logged with its
  score and critical-finding count; double-click a row to open the actual
  HTML report in your browser.
- **Trends tab** — a chart of security score over time, either for one host
  or averaged across the whole fleet, built from the reports you've already
  collected — no server or database needed.

## Requirements

```
pip install PySide6 paramiko matplotlib
```

Python 3.10+ recommended. Works on Linux, macOS, and Windows (the SSH layer
uses `paramiko`, not the `ssh`/`scp` CLI, so there's no dependency on
OpenSSH client tools on the machine running the GUI).

## Running it

```
python3 main.py
```

On first launch, go to **Settings** and confirm the *Local audit script*
path points at `scripts/security_audit_rhel.sh` (bundled in this folder —
it's your original v1.2 script, unmodified) and set the *Remote deploy dir*
(defaults to `/root/LESAH/`, matching the original).

Then:
1. **Add Host** (or **Import server.txt** to bring in your old inventory).
2. Select one or more hosts in the table.
3. Click **Run Audit** or **Run Fix**.
4. Watch progress in **Live Console**; when a job finishes, its row in the
   host table updates with the latest score, and the report appears under
   **Reports**.

## Where things are stored

Everything the GUI needs (inventory, settings, collected reports, score
history) lives under `~/.lesah_toolkit/`:

```
~/.lesah_toolkit/
├── inventory.json      # your host list
├── settings.json        # script path, remote dir, concurrency
├── reports_db.json      # index of every report ever collected (feeds Trends)
└── reports/              # the actual downloaded HTML reports
```

This directory is separate from the app's own folder, so re-running or
updating the GUI code never touches your data.

## Project layout

```
lesah_gui/
├── main.py                  # entry point
├── app/
│   ├── models.py             # Host/Settings dataclasses + JSON persistence
│   ├── ssh_worker.py          # QThread: SSH deploy + run + fetch report
│   ├── dialogs.py              # Add/Edit Host and Settings dialogs
│   └── main_window.py           # main window: table, queue, console, tabs
└── scripts/
    └── security_audit_rhel.sh    # your original v1.2 audit/fix engine
```

## Extending this for your PFE writeup

Ideas that build naturally on this base (see the earlier roadmap discussion):

- Tag findings with CIS Benchmark control IDs in the bash script; surface
  them as an extra column in the Reports tab.
- Add a `--dry-run` flag to `security_audit_rhel.sh` and a corresponding
  checkbox in the GUI before "Run Fix", so remediations can be previewed.
  first.
- Add a "Rollback" button per host that lists files under `backups/` on
  that host and restores a chosen one via SFTP.
- Export the Trends chart and Reports table to PDF for inclusion in your
  PFE report (matplotlib's `savefig` makes the chart export trivial).
