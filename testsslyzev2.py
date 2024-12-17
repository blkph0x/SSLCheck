from datetime import datetime, UTC
from pathlib import Path
from typing import List
from colorama import init, Fore, Style
from docx import Document
from docx.shared import RGBColor, Pt
from docx.oxml.ns import nsdecls
from docx.oxml import parse_xml
from sslyze import (
    Scanner,
    ServerScanRequest,
    SslyzeOutputAsJson,
    ServerNetworkLocation,
    ScanCommandAttemptStatusEnum,
    ServerScanStatusEnum,
    ServerScanResult,
    ServerScanResultAsJson,
)
from sslyze.errors import ServerHostnameCouldNotBeResolved
from sslyze.scanner.scan_command_attempt import ScanCommandAttempt
import warnings
from cryptography.utils import CryptographyDeprecationWarning

# Suppress cryptography deprecation warnings
warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)

# Initialize colorama for colored terminal output
init(autoreset=True)

# Define Mozilla's recommended cipher suites
MOZILLA_SAFE_CIPHERS = {
    "TLS_AES_256_GCM_SHA384",
    "TLS_AES_128_GCM_SHA256",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
}

def print_ascii_banner():
    banner = r"""
    ==========================================
      ____          _                 ____  
     / ___|   ___  | |  ___    __ _  |  _ \ 
     \___ \  / _ \ | | / _ \  / _` | | |_) |
      ___) ||  __/ | || (_) || (_| | |  __/ 
     |____/  \___| |_| \___/  \__, | |_|    
                              |___/        
    Custom SSL Scan by BlkPh0x
    ==========================================
    """
    print(Fore.CYAN + banner + Style.RESET_ALL)

def _print_failed_scan_command_attempt(scan_command_attempt: ScanCommandAttempt) -> None:
    print(
        f"\nError when running scan command: {scan_command_attempt.error_reason}:\n"
        f"{scan_command_attempt.error_trace}"
    )

def mark_and_sort_cipher_suites(cipher_suites):
    """
    Sort and mark cipher suites as SAFE or UNSAFE based on Mozilla's recommendations.
    SAFE suites are printed in green, UNSAFE in red.
    Returns sorted lists of safe and unsafe cipher suites.
    """
    safe_suites = []
    unsafe_suites = []

    for suite in cipher_suites:
        cipher_name = suite.cipher_suite.name
        if cipher_name in MOZILLA_SAFE_CIPHERS:
            safe_suites.append(cipher_name)
        else:
            unsafe_suites.append(cipher_name)

    # Print SAFE suites first in green
    for suite in sorted(safe_suites):
        print(f"{Fore.GREEN}* {suite} - SAFE{Style.RESET_ALL}")

    # Print UNSAFE suites next in red
    for suite in sorted(unsafe_suites):
        print(f"{Fore.RED}* {suite} - UNSAFE{Style.RESET_ALL}")

    return sorted(safe_suites), sorted(unsafe_suites)

def write_results_to_docx(results: dict, output_file: str):
    """
    Write scan results to a formatted DOCX file with color coding and clean tables.
    """
    doc = Document()
    doc.add_heading(f"SSL/TLS Scan Results for {results['hostname']}", level=1)

    def set_cell_color(cell, rgb_color):
        """Set cell background color."""
        cell._element.get_or_add_tcPr().append(
            parse_xml(f'<w:shd {nsdecls("w")} w:fill="{rgb_color}"/>'
        ))

    for tls_version, ciphers in results["ciphers"].items():
        doc.add_heading(f"{tls_version} Cipher Suites", level=2)
        table = doc.add_table(rows=1, cols=2)
        table.autofit = True
        table.allow_autofit = False
        table.cell_spacing = 0
        table.style = "Table Grid"
        
        hdr_cells = table.rows[0].cells
        hdr_cells[0].text = "Cipher Suite"
        hdr_cells[1].text = "Status"

        for cipher, status in ciphers:
            row_cells = table.add_row().cells
            row_cells[0].text = cipher
            row_cells[1].text = status

            # Set text color
            for cell in row_cells:
                for paragraph in cell.paragraphs:
                    for run in paragraph.runs:
                        run.font.size = Pt(10)
                        if status == "SAFE":
                            run.font.color.rgb = RGBColor(34, 139, 34)  # Green
                        else:
                            run.font.color.rgb = RGBColor(255, 0, 0)  # Red

            # Optional: Highlight rows for visual clarity
            set_cell_color(row_cells[1], "FFFFFF")

    doc.save(output_file)
    print(f"\nResults saved to {output_file}")

def main() -> None:
    print_ascii_banner()
    print("=> Starting the scans")
    date_scans_started = datetime.now(UTC)

    # User input for server hostnames
    servers_input = input("Enter server hostnames separated by commas: ")
    server_list = [host.strip() for host in servers_input.split(",") if host.strip()]

    if not server_list:
        print("No servers provided. Exiting.")
        return

    # Prepare scan requests
    all_scan_requests = []
    for server in server_list:
        try:
            all_scan_requests.append(ServerScanRequest(server_location=ServerNetworkLocation(hostname=server)))
        except ServerHostnameCouldNotBeResolved:
            print(f"Error: Could not resolve hostname '{server}'")
            return

    scanner = Scanner()
    scanner.queue_scans(all_scan_requests)

    for server_scan_result in scanner.get_results():
        hostname = server_scan_result.server_location.hostname
        print(f"\n\n****Results for {hostname}****")

        if server_scan_result.scan_status == ServerScanStatusEnum.ERROR_NO_CONNECTIVITY:
            print(
                f"Error: Could not connect to {hostname}: {server_scan_result.connectivity_error_trace}"
            )
            continue

        assert server_scan_result.scan_result

        result_entry = {"hostname": hostname, "ciphers": {}}

        # Check each TLS version
        for version, attempt in [
            ("TLS 1.3", server_scan_result.scan_result.tls_1_3_cipher_suites),
            ("TLS 1.2", server_scan_result.scan_result.tls_1_2_cipher_suites),
            ("TLS 1.1", server_scan_result.scan_result.tls_1_1_cipher_suites),
            ("TLS 1.0", server_scan_result.scan_result.tls_1_0_cipher_suites),
            ("SSL 2.0", server_scan_result.scan_result.ssl_2_0_cipher_suites),
        ]:
            if attempt.status == ScanCommandAttemptStatusEnum.COMPLETED:
                print(f"\nAccepted cipher suites for {version}:")
                safe, unsafe = mark_and_sort_cipher_suites(attempt.result.accepted_cipher_suites)
                result_entry["ciphers"][version] = [(suite, "SAFE") for suite in safe] + [
                    (suite, "UNSAFE") for suite in unsafe
                ]

        # Write individual results to DOCX
        output_file = f"{hostname}_ssl_scan_results.docx"
        write_results_to_docx(result_entry, output_file)

if __name__ == "__main__":
    main()
