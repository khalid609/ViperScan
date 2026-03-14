import socket
import json
import threading
import sys
import time


class HostDiscovery:

    def __init__(self, domain, ip, mode, file):
        self.domain = domain
        self.ip = ip
        self.mode = mode if mode else "default"
        self.file_path = file

        # You can't set both a domain and an IP — pick one
        if self.domain and self.ip:
            print("Error: Set only one value (domain or IP).")
            exit()

        if self.domain:
            # Resolve the domain name to an IP address
            try:
                self.ipaddress = socket.gethostbyname(self.domain)
                print(f"Resolved '{self.domain}' → {self.ipaddress}")
            except socket.gaierror:
                print(f"Error: Could not resolve domain '{self.domain}'.")
                exit()

        elif self.ip:
            self.ipaddress = self.ip

        else:
            # No input given — fall back to the machine's own IP
            try:
                hostname = socket.gethostname()
                self.ipaddress = socket.gethostbyname(hostname)
            except socket.error as e:
                print(f"Error: {e}")
                exit()

        self.ips = []
        self.lst_found = []
        self.lock = threading.Lock()  # protects shared data when threads write simultaneously

        # Progress counters — threads update these, the progress bar reads them
        self._total_tasks = 0
        self._done_tasks = 0
        self._found_count = 0

    # ─────────────────────────────────────────────
    #  Subnet Calculator
    # ─────────────────────────────────────────────
    def cal_subnet(self, subnetmask=24):
        """
        Given the already-resolved IP and a CIDR prefix length (8/16/24/32),
        calculates the network range and fills self.ips with every usable host.
        Supports only classful masks to keep things simple and fast.
        """
        if subnetmask not in [8, 16, 24, 32]:
            print("Error: Subnet mask must be 8, 16, 24, or 32")
            return []

        octets = list(map(int, self.ipaddress.split(".")))

        # Work out the network address and usable host range for each mask size
        if subnetmask == 8:
            network_ip = f"{octets[0]}.0.0.0"
            start_ip   = f"{octets[0]}.0.0.1"
            end_ip     = f"{octets[0]}.255.255.254"

        elif subnetmask == 16:
            network_ip = f"{octets[0]}.{octets[1]}.0.0"
            start_ip   = f"{octets[0]}.{octets[1]}.0.1"
            end_ip     = f"{octets[0]}.{octets[1]}.255.254"

        elif subnetmask == 24:
            network_ip = f"{octets[0]}.{octets[1]}.{octets[2]}.0"
            start_ip   = f"{octets[0]}.{octets[1]}.{octets[2]}.1"
            end_ip     = f"{octets[0]}.{octets[1]}.{octets[2]}.254"

        elif subnetmask == 32:
            # /32 means just the single host — no range to expand
            network_ip = self.ipaddress
            start_ip   = self.ipaddress
            end_ip     = self.ipaddress

        print(f"  Network : {network_ip}/{subnetmask}")
        print(f"  Range   : {start_ip}  →  {end_ip}")

        # Build the full list of IPs between start and end
        start = list(map(int, start_ip.split(".")))
        end   = list(map(int, end_ip.split(".")))

        ips = []
        for i in range(start[0], end[0] + 1):
            for j in range(start[1], end[1] + 1):
                for k in range(start[2], end[2] + 1):
                    for l in range(start[3], end[3] + 1):
                        ips.append(f"{i}.{j}.{k}.{l}")

        print(f"  Hosts   : {len(ips)} address(es) generated\n")
        self.ips = ips  # hand the list off to scanning()
        return ips

    # ─────────────────────────────────────────────
    #  IP Handler (single / multi / subnet modes)
    # ─────────────────────────────────────────────
    def Ip_handler(self, start=0, end=255, subnetmask=None):
        print(f"Mode: {self.mode.upper()}")

        if self.mode == "subnet":
            # Use the subnet calculator instead of the simple range
            if subnetmask is None:
                print("Error: --subnet mode requires --subnetmask (8/16/24/32)")
                exit()
            self.cal_subnet(subnetmask=subnetmask)

        elif self.mode == "multi":
            # Scan a simple .0–.254 range on the same /24
            ip_base = ".".join(self.ipaddress.split(".")[:3])
            for i in range(start, end):
                self.ips.append(f"{ip_base}.{i}")
            print(f"Targets: {len(self.ips)} IP(s)  |  Base: {self.ipaddress}\n")

        elif self.mode in ["single", "default"]:
            self.ips.append(self.ipaddress)
            print(f"Targets: 1 IP  |  {self.ipaddress}\n")

    # ─────────────────────────────────────────────
    #  Live progress bar (runs in background thread)
    # ─────────────────────────────────────────────
    def _draw_progress(self, common_ports):
        # Redraws a single line every 0.2 s so the terminal stays readable
        total     = self._total_tasks
        bar_width = 30

        while True:
            done  = self._done_tasks
            found = self._found_count

            filled = int(bar_width * done / total) if total else 0
            arrow  = ">" if filled < bar_width else ""
            bar    = "=" * filled + arrow + " " * (bar_width - filled - len(arrow))
            pct    = int(100 * done / total) if total else 0

            line = f"\r  [{bar}] {pct:3d}%  |  {done}/{total} checks  |  {found} host(s) found"
            sys.stdout.write(line)
            sys.stdout.flush()

            if done >= total:
                break
            time.sleep(0.2)

        sys.stdout.write("\n")
        sys.stdout.flush()

    # ─────────────────────────────────────────────
    #  Port Scanner
    # ─────────────────────────────────────────────
    def scanning(self):
        common_ports = [
            20, 21,    # FTP
            22,        # SSH
            23,        # Telnet
            25,        # SMTP
            53,        # DNS
            67, 68,    # DHCP
            69,        # TFTP
            80,        # HTTP
            110,       # POP3
            123,       # NTP
            137, 138, 139,  # NetBIOS
            143,       # IMAP
            161,       # SNMP
            389,       # LDAP
            443,       # HTTPS
            445,       # SMB
            465,       # SMTPS
            587,       # SMTP submission
            636,       # LDAPS
            993,       # IMAPS
            995,       # POP3S
            1433,      # MSSQL
            1521,      # Oracle DB
            1935,      # RTMP
            2049,      # NFS
            2181,      # Zookeeper
            2375, 2376,  # Docker
            2379, 2380,  # etcd (Kubernetes)
            3000,      # Grafana / Node.js
            3306,      # MySQL
            3389,      # RDP
            5000,      # Docker Registry
            5060, 5061,  # SIP
            5222, 5223,  # XMPP
            554,       # RTSP
            5432,      # PostgreSQL
            5672,      # RabbitMQ
            5900, 5901, 5902,  # VNC
            5984,      # CouchDB
            6379,      # Redis
            6443,      # Kubernetes API
            8000,      # Django / HTTP alt
            8080,      # HTTP alt (Tomcat / Jenkins)
            8081, 8082,  # Nexus / Artifactory
            8086,      # InfluxDB
            8443,      # HTTPS alt
            8888,      # Jupyter / HTTP alt
            9000,      # SonarQube
            9042,      # Cassandra
            9090,      # Prometheus
            9092,      # Kafka
            9200, 9300,  # Elasticsearch
            10250,     # Kubelet API
            11211,     # Memcached
            15672,     # RabbitMQ management
            27017,     # MongoDB
        ]

        self._total_tasks = len(self.ips) * len(common_ports)
        self._done_tasks  = 0
        self._found_count = 0

        print(f"Scanning {len(self.ips)} IP(s) × {len(common_ports)} ports = {self._total_tasks} total checks")
        print(f"All IPs run in parallel — sit back, this will be fast.\n")

        def scan_ip_worker(ip, ip_index):
            open_ports = []

            for port in common_ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.5)
                    if sock.connect_ex((ip, port)) == 0:
                        open_ports.append(port)
                    sock.close()
                except Exception:
                    pass
                finally:
                    with self.lock:
                        self._done_tasks += 1

            if open_ports:
                with self.lock:
                    self.lst_found.append({"IP Address": ip, "Open Ports": open_ports})
                    self._found_count += 1

        # Start the live progress bar in the background
        progress_thread = threading.Thread(
            target=self._draw_progress, args=(common_ports,), daemon=True
        )
        progress_thread.start()

        # One scanner thread per IP — all run at the same time
        threads = []
        for idx, ip in enumerate(self.ips, 1):
            t = threading.Thread(target=scan_ip_worker, args=(ip, idx))
            threads.append(t)
            t.start()

        for t in threads:
            t.join()
        progress_thread.join(timeout=1)

        # Print a clean summary table of what was found
        print()
        if self.lst_found:
            print("  ┌─────────────────────┬──────────────────────────────────────────────┐")
            print("  │ IP Address           │ Open Ports                                   │")
            print("  ├─────────────────────┼──────────────────────────────────────────────┤")
            for entry in sorted(self.lst_found, key=lambda x: x["IP Address"]):
                ip_str    = entry["IP Address"].ljust(19)
                ports_str = ", ".join(str(p) for p in entry["Open Ports"])
                if len(ports_str) > 44:
                    ports_str = ports_str[:41] + "..."
                print(f"  │ {ip_str} │ {ports_str.ljust(44)} │")
            print("  └─────────────────────┴──────────────────────────────────────────────┘")
        else:
            print("  No hosts with open ports found.")
        print()

    def dumpfile(self):
        # Save results to JSON so BannerScanner and Report can use them
        with open(self.file_path, "w") as f:
            json.dump(self.lst_found, f, indent=4)
        print(f"Results saved → {self.file_path}")