#!/usr/bin/env python3
"""
SysGuard — Live Linux Admin TUI Dashboard
All data is read live on each refresh. SysGuard writes no cache or log files of its own.
"""

import socket
import subprocess
from datetime import datetime

import psutil
from textual.app import App
from textual.binding import Binding
from textual.containers import VerticalScroll
from textual.reactive import reactive
from textual.widgets import (
    Footer,
    Header,
    Static,
    TabbedContent,
    TabPane,
)


# ---------------------------------------------------------------------------
# Data collection helpers — all live, no caching
# ---------------------------------------------------------------------------

def esc(text):
    """Escape Rich markup characters in text so brackets are displayed literally."""
    if not isinstance(text, str):
        text = str(text)
    return text.replace("[", "\\[")


def run_cmd(cmd, timeout=5):
    """Run a shell command and return stdout. Returns empty string on failure."""
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=timeout
        )
        return result.stdout.strip()
    except Exception:
        return ""


def get_hostname():
    return socket.gethostname()


def get_uptime():
    boot = datetime.fromtimestamp(psutil.boot_time())
    delta = datetime.now() - boot
    days = delta.days
    hours, remainder = divmod(delta.seconds, 3600)
    minutes, _ = divmod(remainder, 60)
    return f"{days}d {hours}h {minutes}m"


def get_cpu_summary():
    percent = psutil.cpu_percent(interval=0.1)
    count = psutil.cpu_count(logical=True)
    physical = psutil.cpu_count(logical=False)
    freq = psutil.cpu_freq()
    freq_str = f"{freq.current:.0f}MHz" if freq else "N/A"
    return {
        "usage": f"{percent}%",
        "cores": f"{physical} physical / {count} logical",
        "freq": freq_str,
    }


def get_memory_summary():
    mem = psutil.virtual_memory()
    swap = psutil.swap_memory()
    return {
        "total": f"{mem.total / (1024**3):.1f} GB",
        "used": f"{mem.used / (1024**3):.1f} GB ({mem.percent}%)",
        "available": f"{mem.available / (1024**3):.1f} GB",
        "swap": f"{swap.used / (1024**3):.1f} / {swap.total / (1024**3):.1f} GB ({swap.percent}%)",
    }


def get_disk_summary():
    partitions = psutil.disk_partitions()
    disks = []
    for p in partitions:
        # Skip snap/loop mounts for cleaner output
        if p.mountpoint.startswith("/snap") or p.device.startswith("/dev/loop"):
            continue
        try:
            usage = psutil.disk_usage(p.mountpoint)
            disks.append({
                "mount": p.mountpoint,
                "device": p.device,
                "total": f"{usage.total / (1024**3):.1f}G",
                "used": f"{usage.used / (1024**3):.1f}G",
                "free": f"{usage.free / (1024**3):.1f}G",
                "percent": f"{usage.percent}%",
            })
        except PermissionError:
            pass
    return disks


def get_open_ports():
    connections = psutil.net_connections(kind="inet")
    listening = []
    seen = set()
    for c in connections:
        if c.status == "LISTEN":
            addr = f"{c.laddr.ip}:{c.laddr.port}"
            if addr not in seen:
                seen.add(addr)
                try:
                    proc = psutil.Process(c.pid) if c.pid else None
                    name = proc.name() if proc else "unknown"
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    name = "unknown"
                listening.append({
                    "address": c.laddr.ip,
                    "port": c.laddr.port,
                    "pid": c.pid or "N/A",
                    "process": name,
                })
    listening.sort(key=lambda x: x["port"])
    return listening


def get_active_connections():
    connections = psutil.net_connections(kind="inet")
    active = []
    for c in connections:
        if c.status == "ESTABLISHED":
            try:
                proc = psutil.Process(c.pid) if c.pid else None
                name = proc.name() if proc else "unknown"
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                name = "unknown"
            active.append({
                "local": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "N/A",
                "remote": f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "N/A",
                "pid": c.pid or "N/A",
                "process": name,
            })
    return active


def get_firewall_rules():
    ufw = run_cmd("ufw status verbose 2>/dev/null")
    if ufw and "Status:" in ufw:
        return ("ufw", ufw)
    iptables = run_cmd("iptables -L -n 2>/dev/null || echo 'Requires root'")
    if iptables:
        return ("iptables", iptables)
    return ("none", "No firewall detected or insufficient permissions")


def get_processes():
    procs = []
    for p in psutil.process_iter(["pid", "name", "username", "cpu_percent", "memory_percent", "status"]):
        try:
            info = p.info
            procs.append({
                "pid": info["pid"],
                "name": info["name"] or "unknown",
                "user": info["username"] or "N/A",
                "cpu": info["cpu_percent"] or 0.0,
                "mem": info["memory_percent"] or 0.0,
                "status": info["status"] or "unknown",
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    procs.sort(key=lambda x: x["cpu"], reverse=True)
    return procs[:50]


def get_zombie_processes():
    zombies = []
    for p in psutil.process_iter(["pid", "name", "status"]):
        try:
            if p.info["status"] == psutil.STATUS_ZOMBIE:
                zombies.append({"pid": p.info["pid"], "name": p.info["name"]})
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return zombies


def get_ssh_history():
    output = run_cmd("last -n 20 -a 2>/dev/null")
    return output if output else "No SSH history available"


def get_failed_logins():
    output = run_cmd("journalctl _SYSTEMD_UNIT=sshd.service --no-pager -n 30 --grep='Failed' 2>/dev/null")
    if not output:
        output = run_cmd("grep 'Failed password' /var/log/auth.log 2>/dev/null | tail -20")
    return output if output else "No failed login attempts found (or insufficient permissions)"


def get_sudo_history():
    output = run_cmd("journalctl _COMM=sudo --no-pager -n 30 2>/dev/null")
    if not output:
        output = run_cmd("grep 'sudo' /var/log/auth.log 2>/dev/null | tail -20")
    return output if output else "No sudo history available (or insufficient permissions)"


def get_logged_in_users():
    output = run_cmd("w")
    return output if output else "No users logged in"


def get_suid_binaries():
    output = run_cmd("find /usr/bin /usr/sbin /bin /sbin -perm -4000 2>/dev/null | head -30", timeout=10)
    return output if output else "No SUID binaries found (or insufficient permissions)"


def get_system_info():
    kernel = run_cmd("uname -r")
    os_info = run_cmd("cat /etc/os-release 2>/dev/null | head -5")
    arch = run_cmd("uname -m")
    return {"kernel": kernel, "os": os_info, "arch": arch}


def get_installed_software():
    """Check for notable software installations."""
    software = {}
    checks = {
        "Docker": "docker --version 2>/dev/null",
        "Podman": "podman --version 2>/dev/null",
        "ngrok": "ngrok version 2>/dev/null",
        "Nginx": "nginx -v 2>&1",
        "Apache": "apache2 -v 2>/dev/null || httpd -v 2>/dev/null",
        "Node.js": "node --version 2>/dev/null",
        "Python": "python3 --version 2>/dev/null",
        "Go": "go version 2>/dev/null",
        "Rust": "rustc --version 2>/dev/null",
        "Java": "java --version 2>/dev/null | head -1",
        "Git": "git --version 2>/dev/null",
        "curl": "curl --version 2>/dev/null | head -1",
        "wget": "wget --version 2>/dev/null | head -1",
        "nmap": "nmap --version 2>/dev/null | head -1",
        "Wireshark": "wireshark --version 2>/dev/null | head -1",
        "OpenSSH": "ssh -V 2>&1",
        "UFW": "ufw version 2>/dev/null",
        "Fail2Ban": "fail2ban-client --version 2>/dev/null",
        "Snap": "snap version 2>/dev/null | head -1",
        "Flatpak": "flatpak --version 2>/dev/null",
    }
    for name, cmd in checks.items():
        result = run_cmd(cmd, timeout=3)
        if result:
            software[name] = result.split("\n")[0]
        else:
            software[name] = "Not installed"
    return software


def get_systemd_services():
    output = run_cmd("systemctl list-units --type=service --state=running --no-pager --no-legend 2>/dev/null | head -40")
    return output if output else "Unable to list services"


def get_failed_services():
    output = run_cmd("systemctl list-units --type=service --state=failed --no-pager --no-legend 2>/dev/null")
    return output if output else "No failed services"


def get_cron_jobs():
    user_cron = run_cmd("crontab -l 2>/dev/null")
    system_cron = run_cmd("cat /etc/crontab 2>/dev/null")
    result = ""
    if user_cron:
        result += "=== User Crontab ===\n" + user_cron + "\n\n"
    if system_cron:
        result += "=== System Crontab ===\n" + system_cron
    return result if result else "No cron jobs found"


def get_enabled_services():
    output = run_cmd("systemctl list-unit-files --type=service --state=enabled --no-pager --no-legend 2>/dev/null | head -40")
    return output if output else "Unable to list enabled services"


# ---------------------------------------------------------------------------
# TUI Widgets
# ---------------------------------------------------------------------------

class PanelBox(Static):
    """A styled panel with a title and content."""

    def __init__(self, title: str, content: str = "", **kwargs):
        super().__init__(**kwargs)
        self.panel_title = title
        self.panel_content = content

    def compose(self):
        yield Static(self.panel_content, id="panel-content")

    def render(self):
        return f"[bold cyan]{'─' * 2} {self.panel_title} {'─' * 40}[/]\n{self.panel_content}"


# ---------------------------------------------------------------------------
# Tab Screens
# ---------------------------------------------------------------------------

class OverviewTab(VerticalScroll):
    """Overview dashboard tab."""

    def compose(self):
        yield Static("Loading...", id="overview-content")

    def refresh_data(self):
        cpu = get_cpu_summary()
        mem = get_memory_summary()
        disks = get_disk_summary()
        hostname = get_hostname()
        uptime = get_uptime()

        disk_lines = ""
        for d in disks:
            disk_lines += f"    {esc(d['mount']):<20} {d['used']:>8} / {d['total']:>8}  ({d['percent']:>5})  {esc(d['device'])}\n"

        content = (
            f"[bold cyan]{'─' * 2} Host {'─' * 60}[/]\n"
            f"  Hostname:    [bold white]{hostname}[/]\n"
            f"  Uptime:      [bold white]{uptime}[/]\n"
            f"  Time:        [bold white]{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/]\n"
            f"\n"
            f"[bold cyan]{'─' * 2} CPU {'─' * 61}[/]\n"
            f"  Usage:       [bold {'red' if float(cpu['usage'].strip('%')) > 80 else 'green'}]{cpu['usage']}[/]\n"
            f"  Cores:       [bold white]{cpu['cores']}[/]\n"
            f"  Frequency:   [bold white]{cpu['freq']}[/]\n"
            f"\n"
            f"[bold cyan]{'─' * 2} Memory {'─' * 58}[/]\n"
            f"  Total:       [bold white]{mem['total']}[/]\n"
            f"  Used:        [bold {'red' if float(mem['used'].split('(')[1].strip('%)')) > 80 else 'green'}]{mem['used']}[/]\n"
            f"  Available:   [bold white]{mem['available']}[/]\n"
            f"  Swap:        [bold white]{mem['swap']}[/]\n"
            f"\n"
            f"[bold cyan]{'─' * 2} Disk {'─' * 60}[/]\n"
            f"  {'Mount':<20} {'Used':>8}   {'Total':>8}  {'Usage':>7}   Device\n"
            f"{disk_lines}"
        )

        self.query_one("#overview-content", Static).update(content)


class NetworkTab(VerticalScroll):
    """Network information tab."""

    def compose(self):
        yield Static("Loading...", id="network-content")

    def refresh_data(self):
        ports = get_open_ports()
        connections = get_active_connections()
        fw_type, fw_rules = get_firewall_rules()

        port_lines = ""
        for p in ports:
            port_lines += f"    {str(p['port']):<8} {esc(p['address']):<20} {str(p['pid']):<8} {esc(p['process'])}\n"
        if not ports:
            port_lines = "    No listening ports found\n"

        conn_lines = ""
        for c in connections:
            conn_lines += f"    {esc(c['local']):<25} {esc(c['remote']):<25} {str(c['pid']):<8} {esc(c['process'])}\n"
        if not connections:
            conn_lines = "    No active connections\n"

        content = (
            f"[bold cyan]{'─' * 2} Open Ports (Listening) {'─' * 43}[/]\n"
            f"    {'Port':<8} {'Address':<20} {'PID':<8} Process\n"
            f"{port_lines}\n"
            f"[bold cyan]{'─' * 2} Active Connections {'─' * 47}[/]\n"
            f"    {'Local':<25} {'Remote':<25} {'PID':<8} Process\n"
            f"{conn_lines}\n"
            f"[bold cyan]{'─' * 2} Firewall ({esc(fw_type)}) {'─' * (52 - len(fw_type))}[/]\n"
            f"    {esc(fw_rules)}\n"
        )

        self.query_one("#network-content", Static).update(content)


class ProcessesTab(VerticalScroll):
    """Running processes tab."""

    def compose(self):
        yield Static("Loading...", id="processes-content")

    def refresh_data(self):
        procs = get_processes()
        zombies = get_zombie_processes()

        proc_lines = ""
        for p in procs:
            cpu_color = "red" if p["cpu"] > 50 else "yellow" if p["cpu"] > 20 else "green"
            mem_color = "red" if p["mem"] > 50 else "yellow" if p["mem"] > 20 else "green"
            proc_lines += (
                f"    {str(p['pid']):<8} {esc(p['name']):<25} {esc(p['user']):<15} "
                f"[{cpu_color}]{p['cpu']:>6.1f}%[/] [{mem_color}]{p['mem']:>6.1f}%[/]  {esc(p['status'])}\n"
            )

        zombie_lines = ""
        if zombies:
            for z in zombies:
                zombie_lines += f"    [bold red]PID {z['pid']}: {esc(z['name'])}[/]\n"
        else:
            zombie_lines = "    [green]None[/]\n"

        content = (
            f"[bold cyan]{'─' * 2} Top Processes (by CPU) {'─' * 43}[/]\n"
            f"    {'PID':<8} {'Name':<25} {'User':<15} {'CPU':>7} {'MEM':>7}   Status\n"
            f"{proc_lines}\n"
            f"[bold cyan]{'─' * 2} Zombie Processes {'─' * 48}[/]\n"
            f"{zombie_lines}"
        )

        self.query_one("#processes-content", Static).update(content)


class SecurityTab(VerticalScroll):
    """Security information tab."""

    def compose(self):
        yield Static("Loading...", id="security-content")

    def refresh_data(self):
        users = get_logged_in_users()
        ssh = get_ssh_history()
        failed = get_failed_logins()
        sudo = get_sudo_history()
        suid = get_suid_binaries()

        content = (
            f"[bold cyan]{'─' * 2} Logged-In Users {'─' * 49}[/]\n"
            f"    {esc(users)}\n\n"
            f"[bold cyan]{'─' * 2} SSH Login History (last 20) {'─' * 38}[/]\n"
            f"    {esc(ssh)}\n\n"
            f"[bold cyan]{'─' * 2} Failed Login Attempts {'─' * 43}[/]\n"
            f"    {esc(failed)}\n\n"
            f"[bold cyan]{'─' * 2} Recent Sudo Commands {'─' * 45}[/]\n"
            f"    {esc(sudo)}\n\n"
            f"[bold cyan]{'─' * 2} SUID Binaries {'─' * 51}[/]\n"
            f"    {esc(suid)}\n"
        )

        self.query_one("#security-content", Static).update(content)


class SystemInfoTab(VerticalScroll):
    """System information tab."""

    def compose(self):
        yield Static("Loading...", id="sysinfo-content")

    def refresh_data(self):
        info = get_system_info()
        cpu = get_cpu_summary()
        mem = get_memory_summary()
        software = get_installed_software()

        sw_lines = ""
        for name, version in sorted(software.items()):
            color = "green" if version != "Not installed" else "dim"
            sw_lines += f"    [{color}]{esc(name):<15} {esc(version)}[/]\n"

        content = (
            f"[bold cyan]{'─' * 2} System {'─' * 58}[/]\n"
            f"  Kernel:      [bold white]{esc(info['kernel'])}[/]\n"
            f"  Arch:        [bold white]{esc(info['arch'])}[/]\n"
            f"  {esc(info['os'])}\n\n"
            f"[bold cyan]{'─' * 2} CPU Details {'─' * 53}[/]\n"
            f"  Cores:       [bold white]{cpu['cores']}[/]\n"
            f"  Frequency:   [bold white]{cpu['freq']}[/]\n"
            f"  Model:       [bold white]{esc(run_cmd('lscpu | grep \"Model name\" | cut -d: -f2 | xargs'))}[/]\n\n"
            f"[bold cyan]{'─' * 2} Memory Details {'─' * 51}[/]\n"
            f"  Total:       [bold white]{mem['total']}[/]\n"
            f"  Used:        [bold white]{mem['used']}[/]\n"
            f"  Swap:        [bold white]{mem['swap']}[/]\n\n"
            f"[bold cyan]{'─' * 2} Installed Software {'─' * 46}[/]\n"
            f"{sw_lines}"
        )

        self.query_one("#sysinfo-content", Static).update(content)


class ServicesTab(VerticalScroll):
    """System services tab."""

    def compose(self):
        yield Static("Loading...", id="services-content")

    def refresh_data(self):
        running = get_systemd_services()
        failed = get_failed_services()
        enabled = get_enabled_services()
        cron = get_cron_jobs()

        content = (
            f"[bold cyan]{'─' * 2} Running Services {'─' * 48}[/]\n"
            f"    {esc(running)}\n\n"
            f"[bold cyan]{'─' * 2} Failed Services {'─' * 49}[/]\n"
            f"    [bold {'red' if failed != 'No failed services' else 'green'}]{esc(failed)}[/]\n\n"
            f"[bold cyan]{'─' * 2} Enabled Services (startup) {'─' * 39}[/]\n"
            f"    {esc(enabled)}\n\n"
            f"[bold cyan]{'─' * 2} Cron Jobs {'─' * 56}[/]\n"
            f"    {esc(cron)}\n"
        )

        self.query_one("#services-content", Static).update(content)


# ---------------------------------------------------------------------------
# Main App
# ---------------------------------------------------------------------------

CSS = """
Screen {
    background: $surface;
}

TabbedContent {
    height: 1fr;
}

TabPane {
    padding: 1 2;
}

VerticalScroll {
    height: 1fr;
}

Static {
    width: 1fr;
}

#status-bar {
    dock: bottom;
    height: 1;
    background: $primary-background;
    color: $text;
    padding: 0 2;
}
"""


class SysGuardApp(App):
    """SysGuard — Live Linux Admin Dashboard"""

    TITLE = "SysGuard"
    SUB_TITLE = "Live Admin Dashboard"
    CSS = CSS

    BINDINGS = [
        Binding("r", "refresh", "Refresh Now"),
        Binding("q", "quit", "Quit"),
        Binding("1", "tab_1", "Overview", show=False),
        Binding("2", "tab_2", "Network", show=False),
        Binding("3", "tab_3", "Processes", show=False),
        Binding("4", "tab_4", "Security", show=False),
        Binding("5", "tab_5", "System Info", show=False),
        Binding("6", "tab_6", "Services", show=False),
    ]

    auto_refresh_interval = reactive(5)

    def compose(self):
        yield Header()
        with TabbedContent(
            "Overview",
            "Network",
            "Processes",
            "Security",
            "System Info",
            "Services",
        ):
            with TabPane("Overview", id="tab-overview"):
                yield OverviewTab()
            with TabPane("Network", id="tab-network"):
                yield NetworkTab()
            with TabPane("Processes", id="tab-processes"):
                yield ProcessesTab()
            with TabPane("Security", id="tab-security"):
                yield SecurityTab()
            with TabPane("System Info", id="tab-sysinfo"):
                yield SystemInfoTab()
            with TabPane("Services", id="tab-services"):
                yield ServicesTab()
        yield Static(
            "[bold]SysGuard[/] | Auto-refresh: 5s | Press [bold]r[/] to refresh | [bold]q[/] to quit",
            id="status-bar",
        )
        yield Footer()

    def on_mount(self):
        """Initial data load and start auto-refresh timer."""
        self.refresh_all_tabs()
        self.set_interval(self.auto_refresh_interval, self.auto_refresh)

    def auto_refresh(self):
        """Auto-refresh the currently active tab."""
        try:
            active = self.query_one(TabbedContent).active
            self._refresh_tab(active)
        except Exception:
            pass

    def action_refresh(self):
        """Manual refresh of all tabs."""
        self.refresh_all_tabs()
        self.query_one("#status-bar", Static).update(
            f"[bold]SysGuard[/] | [green]Refreshed at {datetime.now().strftime('%H:%M:%S')}[/] | Press [bold]r[/] to refresh | [bold]q[/] to quit"
        )

    def refresh_all_tabs(self):
        """Refresh data in all tabs."""
        for tab in self.query(OverviewTab):
            tab.refresh_data()
        for tab in self.query(NetworkTab):
            tab.refresh_data()
        for tab in self.query(ProcessesTab):
            tab.refresh_data()
        for tab in self.query(SecurityTab):
            tab.refresh_data()
        for tab in self.query(SystemInfoTab):
            tab.refresh_data()
        for tab in self.query(ServicesTab):
            tab.refresh_data()

    def _refresh_tab(self, tab_id: str):
        """Refresh a specific tab by ID."""
        tab_map = {
            "tab-overview": OverviewTab,
            "tab-network": NetworkTab,
            "tab-processes": ProcessesTab,
            "tab-security": SecurityTab,
            "tab-sysinfo": SystemInfoTab,
            "tab-services": ServicesTab,
        }
        tab_class = tab_map.get(tab_id)
        if tab_class:
            for tab in self.query(tab_class):
                tab.refresh_data()

    def action_tab_1(self):
        self.query_one(TabbedContent).active = "tab-overview"

    def action_tab_2(self):
        self.query_one(TabbedContent).active = "tab-network"

    def action_tab_3(self):
        self.query_one(TabbedContent).active = "tab-processes"

    def action_tab_4(self):
        self.query_one(TabbedContent).active = "tab-security"

    def action_tab_5(self):
        self.query_one(TabbedContent).active = "tab-sysinfo"

    def action_tab_6(self):
        self.query_one(TabbedContent).active = "tab-services"

    def action_quit(self):
        """Quit."""
        self.exit()


def main():
    app = SysGuardApp()
    app.run()


if __name__ == "__main__":
    main()
