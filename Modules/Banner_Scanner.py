import socket
import json
import threading
import sys


class BannerScanner:
    def __init__(self, json_file="file.json"):
        self.json_file = json_file
        self.data = []
        self.timeout = 5
        self.lock = threading.Lock()  # keeps threads from tripping over each other when printing/writing

        # Load the JSON file that HostDiscovery produced
        try:
            with open(self.json_file, "r") as f:
                self.data = json.load(f)
            print(f"Loaded {len(self.data)} host(s) from {self.json_file}")
        except FileNotFoundError:
            print(f"Error: File '{self.json_file}' not found.")
            return
        except json.JSONDecodeError:
            print(f"Error: Invalid JSON in '{self.json_file}'.")
            return

    def grab_banner(self, ip, port, timeout=5):
        # Connect to the port and try a few common protocol commands to get a response
        banner = "No Banner"
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((ip, port))

            # Try each command — stop as soon as one gets a real response back
            commands = [
                b"",                                  # just listen (some services talk first)
                b"GET / HTTP/1.0\r\n\r\n",            # basic HTTP
                b"HEAD / HTTP/1.0\r\n\r\n",           # lighter HTTP
                b"GET / HTTP/1.1\r\nHost: \r\n\r\n",  # HTTP/1.1
                b"QUIT\r\n",                          # FTP / IMAP
                b"USER anonymous\r\n",                # FTP login attempt
                b"SYST\r\n",                          # FTP system info
                b"LIST\r\n",                          # FTP directory
                b"HELP\r\n",                          # SMTP
                b"AUTH LOGIN\r\n",                    # SMTP auth
                b"NOOP\r\n",                          # SMTP ping
                b"VERSION\r\n",                       # generic probe
                b"SSH-2.0-\r\n",                      # SSH handshake
                b"AUTH\r\n",                          # IMAP
                b"CAPABILITY\r\n",                    # IMAP capabilities
            ]

            for cmd in commands:
                try:
                    if cmd:
                        sock.send(cmd)
                    response = sock.recv(1024)
                    if response:
                        banner = response.decode('utf-8', errors='ignore').strip()
                        break
                except Exception:
                    continue

        except socket.timeout:
            banner = "Timeout"
        except socket.error as e:
            banner = f"Connection Failed ({e})"
        except Exception as e:
            banner = f"Error: {e}"
        finally:
            # Always close the socket no matter what happened above
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass

        return banner

    def analyze_banner(self, banner):
        # Read the banner text and guess what service and OS is behind it
        service = "Unknown"
        os_info = "Unknown"
        banner_lower = banner.lower()

        if "ssh" in banner_lower:
            service = "SSH"
            if "openssh" in banner_lower:    os_info = "Linux/Unix"
            elif "putty" in banner_lower:    os_info = "Windows"
            elif "bitvise" in banner_lower:  os_info = "Windows"
            elif "libssh" in banner_lower:   os_info = "Linux/Unix"

        elif "http" in banner_lower or "200" in banner or "404" in banner:
            service = "HTTP"
            if "apache" in banner_lower:     os_info = "Linux/Unix"
            elif "nginx" in banner_lower:    os_info = "Linux/Unix"
            elif "iis" in banner_lower:      os_info = "Windows"
            elif "microsoft" in banner_lower: os_info = "Windows"
            elif "tomcat" in banner_lower:   os_info = "Linux/Unix"
            elif "node" in banner_lower:     os_info = "Linux/Unix"
            elif "express" in banner_lower:  os_info = "Linux/Unix"
            elif "django" in banner_lower:   os_info = "Linux/Unix"
            elif "flask" in banner_lower:    os_info = "Linux/Unix"
            elif "php" in banner_lower:      os_info = "Linux/Unix"
            elif "python" in banner_lower:   os_info = "Linux/Unix"

        elif "ftp" in banner_lower:
            service = "FTP"
            if "vsftpd" in banner_lower:     os_info = "Linux"
            elif "proftpd" in banner_lower:  os_info = "Linux/Unix"
            elif "filezilla" in banner_lower: os_info = "Windows"
            elif "pure-ftpd" in banner_lower: os_info = "Linux"
            elif "wftp" in banner_lower:     os_info = "Windows"

        elif "smtp" in banner_lower or "220" in banner:
            service = "SMTP"
            if "postfix" in banner_lower:    os_info = "Linux"
            elif "exim" in banner_lower:     os_info = "Linux"
            elif "microsoft" in banner_lower: os_info = "Windows"
            elif "sendmail" in banner_lower: os_info = "Linux/Unix"
            elif "qmail" in banner_lower:    os_info = "Linux/Unix"

        elif "telnet" in banner_lower or "\xff\xfd" in banner:
            service = "Telnet"
            if "linux" in banner_lower:      os_info = "Linux"
            elif "windows" in banner_lower:  os_info = "Windows"
            elif "cisco" in banner_lower:    os_info = "Cisco IOS"

        elif "pop3" in banner_lower or "+ok" in banner_lower:
            service = "POP3"
            if "dovecot" in banner_lower:    os_info = "Linux/Unix"
            elif "microsoft" in banner_lower: os_info = "Windows"

        elif "imap" in banner_lower or "* ok" in banner_lower:
            service = "IMAP"
            if "dovecot" in banner_lower:    os_info = "Linux/Unix"
            elif "microsoft" in banner_lower: os_info = "Windows"

        elif "mysql" in banner_lower or "mariadb" in banner_lower:
            service = "MySQL/MariaDB"
            os_info = "Linux/Unix"

        elif "rdp" in banner_lower or "remote desktop" in banner_lower:
            service = "RDP"
            os_info = "Windows"

        elif "redis" in banner_lower:
            service = "Redis"
            os_info = "Linux/Unix"

        elif "mongodb" in banner_lower:
            service = "MongoDB"
            os_info = "Linux/Unix"

        return service, os_info

    def _print_host_result(self, ip, port_results):
        # Print a tidy block for one host right after its thread finishes
        # The lock makes sure two threads don't print at the same time and mix up the lines
        with self.lock:
            print(f"\n  ┌─ {ip}")
            for r in port_results:
                status_icon = "✓" if r["Service"] != "Unknown" else "·"
                print(f"  │  {status_icon}  Port {str(r['Port']).ljust(6)}  {r['Service'].ljust(16)}  OS: {r['OS']}")
                # Show a short preview of the banner if it has real content
                if r["Banner"] not in ("No Banner", "Timeout") and not r["Banner"].startswith(("Connection Failed", "Error")):
                    preview = r["Banner"].replace("\n", " ").replace("\r", "")[:70]
                    print(f"  │       Banner: {preview}")
            print(f"  └{'─' * 50}")

    def _scan_entry(self, entry, results):
        # Worker function — one thread per IP entry runs this
        ip = entry.get("IP Address", "")
        open_ports = entry.get("Open Ports", [])

        if not ip or not open_ports:
            return

        port_results = []
        for port in open_ports:
            banner = self.grab_banner(ip, port, self.timeout)
            service, os_info = self.analyze_banner(banner)
            port_results.append({
                "Port": port,
                "Banner": banner,
                "Service": service,
                "OS": os_info
            })

        # Print this host's results as soon as it's done (looks much cleaner than queuing everything)
        self._print_host_result(ip, port_results)

        with self.lock:
            results.append({"IP Address": ip, "Ports": port_results})

    def run_scan(self):
        if not self.data:
            print("No data to scan. Is the JSON file empty?")
            return

        total_hosts = len(self.data)
        total_ports = sum(len(e.get("Open Ports", [])) for e in self.data)
        print(f"\nBanner scanning {total_hosts} host(s), {total_ports} open port(s) total...")
        print(f"Each host runs in its own thread — results appear as they finish.\n")

        results = []
        threads = []

        for entry in self.data:
            t = threading.Thread(target=self._scan_entry, args=(entry, results))
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        # Save the enriched results back to the JSON file
        with open(self.json_file, "w") as f:
            json.dump(results, f, indent=4)

        print(f"\n  Done. {len(results)} host(s) scanned. Results saved to '{self.json_file}'.")