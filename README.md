# SysGuard

A terminal dashboard for Linux admins. SysGuard shows a live view of a single host:
resources, network listeners and connections, processes, login and sudo activity,
SUID binaries, services and cron. It is built with [Textual](https://textual.textualize.io/)
and [psutil](https://github.com/giampaolo/psutil).

**What it is not:** SysGuard is a read-only viewer. It does not block, alert, remediate,
or monitor in the background, and it is not an intrusion detection system. It shows
what the host reports at the moment you look.

**Status:** v0.1, early and unaudited. Linux only.

## Install

Requires Python 3.12+ on Linux and [pipx](https://pipx.pypa.io/). On Debian/Ubuntu:

```bash
sudo apt install pipx && pipx ensurepath
```

Then install SysGuard:

```bash
pipx install git+https://github.com/Gypsy-82/sysguard.git
```

pipx creates a private virtual environment for SysGuard, installs its dependencies there,
and puts a `sysguard` command in `~/.local/bin`. System Python is not touched.

Upgrade with `pipx upgrade sysguard`, remove with `pipx uninstall sysguard`.

<details>
<summary>Without pipx (plain venv)</summary>

```bash
sudo apt install python3-venv
git clone https://github.com/Gypsy-82/sysguard.git && cd sysguard && python3 -m venv .venv && .venv/bin/pip install .
```

Run with `.venv/bin/sysguard`. Removing the folder uninstalls it.
</details>

## Run

```bash
sysguard
```

Several panels need root to show complete data (iptables rules, `/var/log/auth.log`,
other users' processes and sockets, the system journal). `sudo` uses its own PATH,
which usually does not include `~/.local/bin`, so give it the full path:

```bash
sudo ~/.local/bin/sysguard
```

Without root, those panels show what your user can see or an "insufficient permissions" note.

## Tabs and keys

| Key | Tab | Shows |
|---|---|---|
| `1` | Overview | Hostname, uptime, CPU, memory, swap, disk usage |
| `2` | Network | Listening ports, established connections, ufw/iptables rules |
| `3` | Processes | Top 50 processes by CPU, zombie processes |
| `4` | Security | Logged-in users, recent logins (`last`), failed SSH logins, sudo history, SUID binaries |
| `5` | System Info | Kernel, OS, CPU model, versions of common tools |
| `6` | Services | Running, failed and enabled systemd services, cron jobs |

`r` refreshes all tabs, `q` quits. The active tab auto-refreshes every 5 seconds.

## How it handles data

- All data is read live from psutil and standard system commands (`last`, `journalctl`,
  `systemctl`, `ufw`, `iptables`, `find`, `crontab`) on each refresh.
- SysGuard writes no cache, log or history files of its own.
- What it displays can still end up elsewhere: your terminal's scrollback, and the
  system's own logs of the commands it runs (for example, the journal records `sudo` use).

## Security notes

- Running as root means the script and its imported packages run with full privileges.
  The install above is owned by your user, so anything that can write to your home folder
  can change what root runs. If you run SysGuard with `sudo` regularly, install a copy only
  root can write to:

  ```bash
  sudo python3 -m venv /opt/sysguard
  sudo /opt/sysguard/bin/pip install git+https://github.com/Gypsy-82/sysguard.git
  sudo /opt/sysguard/bin/sysguard
  ```
- The security panels read existing logs. If those logs were tampered with, SysGuard
  shows the tampered version.

## License

MIT. See [LICENSE](LICENSE).
