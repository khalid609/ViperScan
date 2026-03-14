from Modules.Host_Discovery import HostDiscovery
from Modules.Banner_Scanner import BannerScanner
from Modules.Report import Report
import os
import argparse


def main():
    parser = argparse.ArgumentParser(
        description="Host Discovery & Banner Scanning Tool",
        formatter_class=argparse.RawTextHelpFormatter
    )

    # Target — pick one
    parser.add_argument("--ip",         type=str, default="", help="Target IP address")
    parser.add_argument("--domain",     type=str, default="", help="Target domain name")

    # Scan mode
    parser.add_argument("--mode",       type=str, default="",
                        help="Scan mode:\n"
                             "  single  — scan just the one IP (default)\n"
                             "  multi   — scan .0–.254 of the same /24\n"
                             "  subnet  — scan every host in the given subnet")

    # multi mode range
    parser.add_argument("--start",      type=int, default=0,   help="Last-octet start for multi mode (default: 0)")
    parser.add_argument("--end",        type=int, default=255, help="Last-octet end   for multi mode (default: 255)")

    # subnet mode mask
    parser.add_argument("--subnetmask", type=int, default=None,
                        help="CIDR prefix for subnet mode — must be 8, 16, 24, or 32\n"
                             "  Example: --mode subnet --ip 192.168.1.1 --subnetmask 24")

    # Banner grabbing timeout
    parser.add_argument("--timeout",    type=int, default=5,   help="Timeout in seconds for banner grabbing (default: 5)")

    # Report-only mode — skip scanning, just regenerate the report from existing JSON
    parser.add_argument("--report-only", action="store_true",
                        help="Skip scanning — just generate a report from an existing result.json")

    args = parser.parse_args()

    # Make sure our output folders exist before writing anything
    base_dir      = os.path.dirname(os.path.abspath(__file__))
    folder_json   = os.path.join(base_dir, "Json")
    folder_report = os.path.join(base_dir, "Report")
    file_path     = os.path.join(folder_json, "result.json")

    for folder in [folder_json, folder_report]:
        if not os.path.exists(folder):
            os.makedirs(folder)
            print(f"Created folder: {folder}")

    # ── Report-only shortcut ────────────────────────────────────────────────
    if args.report_only:
        print("\n===== Report Generation (from existing JSON) =====")
        report = Report(json_file=file_path, report_dir=folder_report)
        report.generate()
        print("\nDone!")
        return

    # ── Phase 1: Host Discovery ─────────────────────────────────────────────
    print("\n===== Phase 1: Host Discovery =====")
    discovery = HostDiscovery(
        domain=args.domain,
        ip=args.ip,
        mode=args.mode,
        file=file_path
    )
    discovery.Ip_handler(start=args.start, end=args.end, subnetmask=args.subnetmask)
    discovery.scanning()
    discovery.dumpfile()

    # ── Phase 2: Banner Scanning ────────────────────────────────────────────
    print("\n===== Phase 2: Banner Scanning =====")
    scanner = BannerScanner(file_path)
    scanner.timeout = args.timeout
    scanner.run_scan()

    # ── Phase 3: Report Generation ──────────────────────────────────────────
    print("\n===== Phase 3: Report Generation =====")
    report = Report(json_file=file_path, report_dir=folder_report)
    report.generate()

    print("\nAll done!")


if __name__ == "__main__":
    main()