#!/usr/bin/env python3

"""
CIS Cisco ASA Firewall v8.x Configuration Auditor
=================================================

This script audits a Cisco ASA configuration file against a subset of controls 
from the CIS Cisco Firewall v8 Benchmark v4.1.0.

Below controls are not included in the script:
    - 1.2.4 Ensure 'Unused Interfaces' is disable (Scored)
    - 1.3.1 Ensure 'Image Integrity' is correct (Not Scored)
    - 1.3.2 Ensure 'Image Authenticity' is correct (Scored)
    - 1.6.3 Ensure 'RSA key pair' is greater than or equal to 2048 bits (Scored)

Usage:
    python cis_asa_auditor.py /path/to/your/asa-config.conf

"""

# It is recommended to double check all the output of the controls from the script against Firewall configuration file.

import sys
import re
import argparse

# --- Color Coding (ANSI Escape Codes) ---
# These will work on Linux/macOS. On Windows, use 'colorama'
# or run in a modern terminal that supports ANSI.
class Colors:
    """Class to hold ANSI color codes for terminal output."""
    GREEN = '\033[92m'   # Pass
    RED = '\033[91m'     # Fail
    YELLOW = '\033[93m'  # Warning / Not Applicable
    BLUE = '\033[94m'    # Info / Section Header
    RESET = '\033[0m'    # Reset to default color

def print_pass(control_id, message):
    """Prints a passing result in green."""
    print(f"  [{Colors.GREEN}PASS{Colors.RESET}] {control_id}: {message}")

def print_fail(control_id, message):
    """Prints a failing result in red."""
    print(f"  [{Colors.RED}FAIL{Colors.RESET}] {control_id}: {message}")

def print_warn(control_id, message):
    """Prints a warning/NA result in yellow."""
    print(f"  [{Colors.YELLOW}WARN{Colors.RESET}] {control_id}: {message}")

def print_header(title):
    """Prints a blue section header."""
    print(f"\n{Colors.BLUE}--- {title} ---{Colors.RESET}")

# --- Configuration Check Functions ---
# Each function audits one CIS control.
# It takes the full config text as input and prints its result.
#
# To add more checks:
# 1. Create a new function (e.g., `check_X_Y_Z(config_text)`).
# 2. Use `re.search()` to find (or not find) the required config line(s).
# 3. Call `print_pass()`, `print_fail()`, or `print_warn()` with the result.
# 4. Add your new function's name to the `run_all_checks` function below.

# --- 1.1 Password Management ---

def check_1_1_1_logon_password(config_text):
    """
    1.1.1 Ensure 'Logon Password' is set (Scored)
    Audit: Checks for the 'passwd' command.
    """
    control_id = "1.1.1 (Logon Password)"
    if re.search(r"^passwd\s+.+", config_text, re.MULTILINE):
        print_pass(control_id, "'Logon Password' (passwd) is set.")
    else:
        print_fail(control_id, "'Logon Password' (passwd) is not set.")

def check_1_1_2_enable_password(config_text):
    """
    1.1.2 Ensure 'Enable Password' is set (Scored)
    Audit: Checks for the 'enable password' command.
    """
    control_id = "1.1.2 (Enable Password)"
    if re.search(r"^enable password\s+.+", config_text, re.MULTILINE):
        print_pass(control_id, "'Enable Password' is set.")
    else:
        print_fail(control_id, "'Enable Password' is not set.")

def check_1_1_3_master_key(config_text):
    """
    1.1.3 Ensure 'Master Key Passphrase' is set (Scored)
    Audit: Checks for 'password encryption aes' or 'key config-key password-encryption'.
    """
    control_id = "1.1.3 (Master Key)"
    if re.search(r"^(password encryption aes|key config-key password-encryption)", config_text, re.MULTILINE):
        print_pass(control_id, "'Master Key Passphrase' appears to be set (AES encryption enabled).")
    else:
        print_fail(control_id, "'Master Key Passphrase' is not set (no 'password encryption aes').")

def check_1_1_4_password_recovery(config_text):
    """
    1.1.4 Ensure 'Password Recovery' is disabled (Scored)
    Audit: Checks for 'no service password-recovery'.
    """
    control_id = "1.1.4 (Password Recovery)"
    if re.search(r"^no service password-recovery", config_text, re.MULTILINE):
        print_pass(control_id, "'Password Recovery' is disabled.")
    else:
        print_fail(control_id, "'Password Recovery' is enabled (default).")

def check_1_1_5_password_policy(config_text):
    """
    1.1.5 Ensure 'Password Policy' is enabled (Scored)
    Audit: Checks for any 'password-policy' command.
    """
    control_id = "1.1.5 (Password Policy)"
    if re.search(r"^password-policy\s+.+", config_text, re.MULTILINE):
        print_pass(control_id, "'Password Policy' is configured.")
    else:
        print_fail(control_id, "'Password Policy' is not configured.")

# --- 1.2 Device Management ---

def check_1_2_1_domain_name(config_text):
    """
    1.2.1 Ensure 'Domain Name' is set (Scored)
    Audit: Checks for the 'domain-name' command.
    """
    control_id = "1.2.1 (Domain Name)"
    if re.search(r"^domain-name\s+.+", config_text, re.MULTILINE):
        print_pass(control_id, "'Domain Name' is set.")
    else:
        print_fail(control_id, "'Domain Name' is not set.")

def check_1_2_2_host_name(config_text):
    """
    1.2.2 Ensure 'Host Name' is set (Scored)
    Audit: Checks that hostname is not 'ciscoasa' or 'asa'.
    """
    control_id = "1.2.2 (Host Name)"
    match = re.search(r"^hostname\s+(.+)", config_text, re.MULTILINE)
    if match:
        hostname = match.group(1).strip()
        if hostname.lower() in ['ciscoasa', 'asa']:
            print_fail(control_id, f"Hostname is set to a default value: '{hostname}'.")
        else:
            print_pass(control_id, f"Hostname is set to: '{hostname}'.")
    else:
        print_fail(control_id, "Hostname is not set.")

def check_1_2_3_failover(config_text):
    """
    1.2.3 Ensure 'Failover' is enabled (Scored)
    Audit: Checks for 'failover' (excluding 'no failover').
    """
    control_id = "1.2.3 (Failover)"
    if re.search(r"^failover lan unit\s+", config_text, re.MULTILINE) and not re.search(r"^no failover", config_text, re.MULTILINE):
        print_pass(control_id, "Failover appears to be enabled.")
    else:
        print_fail(control_id, "Failover is not enabled.")

def check_1_2_4_unused_interfaces(config_text):
    """
    1.2.4 Ensure 'Unused Interfaces' is disable (Scored)
    Audit: Warns user to check manually.
    """
    control_id = "1.2.4 (Unused Interfaces)"
    print_warn(control_id, "Cannot audit from 'show run'. Manually run 'show interface ip brief' and check for interfaces that are 'up' but 'unassigned'.")

# --- 1.3 Image Security ---

def check_1_3_1_image_integrity(config_text):
    """
    1.3.1 Ensure 'Image Integrity' is correct (Not Scored)
    Audit: Warns user to check manually.
    """
    control_id = "1.3.1 (Image Integrity)"
    print_warn(control_id, "Cannot audit from 'show run'. Manually run 'verify /md5 <image_file_path> <md5_hash>' before upgrade.")

def check_1_3_2_image_authenticity(config_text):
    """
    1.3.2 Ensure 'Image Authenticity' is correct (Scored)
    Audit: Warns user to check manually.
    """
    control_id = "1.3.2 (Image Authenticity)"
    print_warn(control_id, "Cannot audit from 'show run'. Manually run 'show software authenticity running' and check for 'CiscoSystems'.")

# --- 1.4 AAA ---

def check_1_4_1_1_aaa_max_failed(config_text):
    """
    1.4.1.1 Ensure 'aaa local authentication max failed attempts' is set to <= '3' (Scored)
    Audit: Checks for 'aaa local authentication attempts max-fail'.
    """
    control_id = "1.4.1.1 (AAA Max Failed)"
    match = re.search(r"^aaa local authentication attempts max-fail\s+(\d+)", config_text, re.MULTILINE)
    if match:
        attempts = int(match.group(1))
        if attempts <= 3:
            print_pass(control_id, f"'aaa local authentication max failed attempts' is set to {attempts}.")
        else:
            print_fail(control_id, f"'aaa local authentication max failed attempts' is {attempts} (must be <= 3).")
    else:
        print_fail(control_id, "'aaa local authentication max failed attempts' is not configured.")

def check_1_4_1_2_local_user(config_text):
    """
    1.4.1.2 Ensure 'local username and password' is set (Scored)
    Audit: Checks for 'username ... password ...'.
    """
    control_id = "1.4.1.2 (Local User)"
    if re.search(r"^username\s+.+\s+password\s+.+", config_text, re.MULTILINE):
        print_pass(control_id, "At least one local user account is configured.")
    else:
        print_fail(control_id, "No local user accounts are configured.")

def check_1_4_1_3_default_accounts(config_text):
    """
    1.4.1.3 Ensure known default accounts do not exist (Scored)
    Audit: Checks for default usernames 'admin', 'asa', 'cisco', 'pix', 'root'.
    """
    control_id = "1.4.1.3 (Default Accounts)"
    defaults_found = []
    for account in ['admin', 'asa', 'cisco', 'pix', 'root']:
        if re.search(fr"^username {account}\s+", config_text, re.MULTILINE):
            defaults_found.append(account)
    
    if defaults_found:
        print_fail(control_id, f"Known default accounts exist: {', '.join(defaults_found)}.")
    else:
        print_pass(control_id, "No known default accounts (admin, asa, cisco, pix, root) found.")

def check_1_4_2_1_remote_aaa(config_text):
    """
    1.4.2.1 Ensure 'TACACS+/RADIUS' is configured correctly (Scored)
    Audit: Checks for 'aaa-server ... protocol (tacacs|radius)'.
    """
    control_id = "1.4.2.1 (Remote AAA)"
    if re.search(r"^aaa-server\s+.+\s+protocol\s+(tacacs|radius)", config_text, re.MULTILINE):
        print_pass(control_id, "A remote TACACS+ or RADIUS server is configured.")
    else:
        print_fail(control_id, "No remote AAA (TACACS+/RADIUS) servers are configured.")

def check_1_4_3_1_aaa_enable_console(config_text):
    """
    1.4.3.1 Ensure 'aaa authentication enable console' is configured correctly (Scored)
    Audit: Checks for 'aaa authentication enable console ...'.
    """
    control_id = "1.4.3.1 (AAA Enable Console)"
    if re.search(r"^aaa authentication enable console\s+", config_text, re.MULTILINE):
        print_pass(control_id, "AAA authentication for 'enable' is configured.")
    else:
        print_fail(control_id, "AAA authentication for 'enable' is not configured.")

def check_1_4_3_2_aaa_http_console(config_text):
    """
    1.4.3.2 Ensure 'aaa authentication http console' is configured correctly (Scored)
    Audit: Checks for 'aaa authentication http console ...'.
    """
    control_id = "1.4.3.2 (AAA HTTP Console)"
    if re.search(r"^aaa authentication http console\s+", config_text, re.MULTILINE):
        print_pass(control_id, "AAA authentication for HTTP is configured.")
    else:
        print_fail(control_id, "AAA authentication for HTTP is not configured.")

def check_1_4_3_3_aaa_secure_http(config_text):
    """
    1.4.3.3 Ensure 'aaa authentication secure-http-client' is configured correctly (Scored)
    Audit: Checks for 'aaa authentication secure-http-client'.
    """
    control_id = "1.4.3.3 (AAA Secure HTTP)"
    if re.search(r"^aaa authentication secure-http-client", config_text, re.MULTILINE):
        print_pass(control_id, "AAA 'secure-http-client' (SSL for AAA) is configured.")
    else:
        print_fail(control_id, "AAA 'secure-http-client' (SSL for AAA) is not configured.")

def check_1_4_3_4_aaa_serial_console(config_text):
    """
    1.4.3.4 Ensure 'aaa authentication serial console' is configured correctly (Scored)
    Audit: Checks for 'aaa authentication serial console ...'.
    """
    control_id = "1.4.3.4 (AAA Serial Console)"
    if re.search(r"^aaa authentication serial console\s+", config_text, re.MULTILINE):
        print_pass(control_id, "AAA authentication for Serial Console is configured.")
    else:
        print_fail(control_id, "AAA authentication for Serial Console is not configured.")

def check_1_4_3_5_aaa_ssh(config_text):
    """
    1.4.3.5 Ensure 'aaa authentication ssh console' is configured correctly (Scored)
    Audit: Checks for 'aaa authentication ssh console ...'.
    """
    control_id = "1.4.3.5 (AAA for SSH)"
    if re.search(r"^aaa authentication ssh console\s+", config_text, re.MULTILINE):
        print_pass(control_id, "AAA authentication for SSH is configured.")
    else:
        print_fail(control_id, "AAA authentication for SSH is not configured.")

def check_1_4_3_6_aaa_telnet_console(config_text):
    """
    1.4.3.6 Ensure 'aaa authentication telnet console' is configured correctly (Scored)
    Audit: Checks for 'aaa authentication telnet console ...'.
    """
    control_id = "1.4.3.6 (AAA Telnet Console)"
    if re.search(r"^aaa authentication telnet console\s+", config_text, re.MULTILINE):
        print_pass(control_id, "AAA authentication for Telnet is configured.")
    else:
        print_fail(control_id, "AAA authentication for Telnet is not configured.")

def check_1_4_4_1_aaa_cmd_authorization(config_text):
    """
    1.4.4.1 Ensure 'aaa command authorization' is configured correctly (Scored)
    Audit: Checks for 'aaa authorization command ...'.
    """
    control_id = "1.4.4.1 (AAA Command Auth)"
    if re.search(r"^aaa authorization command\s+", config_text, re.MULTILINE):
        print_pass(control_id, "AAA command authorization is configured.")
    else:
        print_fail(control_id, "AAA command authorization is not configured.")

def check_1_4_4_2_aaa_exec_authorization(config_text):
    """
    1.4.4.2 Ensure 'aaa authorization exec' is configured correctly (Scored)
    Audit: Checks for 'aaa authorization exec ...'.
    """
    control_id = "1.4.4.2 (AAA Exec Auth)"
    if re.search(r"^aaa authorization exec\s+", config_text, re.MULTILINE):
        print_pass(control_id, "AAA exec authorization is configured.")
    else:
        print_fail(control_id, "AAA exec authorization is not configured.")

def check_1_4_5_1_aaa_cmd_accounting(config_text):
    """
    1.4.5.1 Ensure 'aaa command accounting' is configured correctly (Scored)
    Audit: Checks for 'aaa accounting command ...'.
    """
    control_id = "1.4.5.1 (AAA Command Acct)"
    if re.search(r"^aaa accounting command\s+", config_text, re.MULTILINE):
        print_pass(control_id, "AAA command accounting is configured.")
    else:
        print_fail(control_id, "AAA command accounting is not configured.")

def check_1_4_5_2_aaa_ssh_accounting(config_text):
    """
    1.4.5.2 Ensure 'aaa accounting for SSH' is configured correctly (Scored)
    Audit: Checks for 'aaa accounting ssh console ...'.
    """
    control_id = "1.4.5.2 (AAA SSH Acct)"
    if re.search(r"^aaa accounting ssh console\s+", config_text, re.MULTILINE):
        print_pass(control_id, "AAA SSH accounting is configured.")
    else:
        print_fail(control_id, "AAA SSH accounting is not configured.")

def check_1_4_5_3_aaa_serial_accounting(config_text):
    """
    1.4.5.3 Ensure 'aaa accounting for Serial console' is configured correctly (Scored)
    Audit: Checks for 'aaa accounting serial console ...'.
    """
    control_id = "1.4.5.3 (AAA Serial Acct)"
    if re.search(r"^aaa accounting serial console\s+", config_text, re.MULTILINE):
        print_pass(control_id, "AAA Serial accounting is configured.")
    else:
        print_fail(control_id, "AAA Serial accounting is not configured.")

def check_1_4_5_4_aaa_exec_accounting(config_text):
    """
    1.4.5.4 Ensure 'aaa accounting for EXEC mode' is configured correctly (Scored)
    Audit: Checks for 'aaa accounting enable console ...'.
    """
    control_id = "1.4.5.4 (AAA Exec Acct)"
    if re.search(r"^aaa accounting enable console\s+", config_text, re.MULTILINE):
        print_pass(control_id, "AAA EXEC accounting ('enable console') is configured.")
    else:
        print_fail(control_id, "AAA EXEC accounting ('enable console') is not configured.")


# --- 1.5 Banners ---

def check_1_5_1_asdm_banner(config_text):
    """
    1.5.1 Ensure 'ASDM banner' is set (Scored)
    Audit: Checks for 'banner asdm ...'.
    """
    control_id = "1.5.1 (ASDM Banner)"
    if re.search(r"^banner asdm\s+", config_text, re.MULTILINE):
        print_pass(control_id, "ASDM banner is set.")
    else:
        print_fail(control_id, "ASDM banner is not set.")

def check_1_5_2_exec_banner(config_text):
    """
    1.5.2 Ensure 'EXEC banner' is set (Scored)
    Audit: Checks for 'banner exec ...'.
    """
    control_id = "1.5.2 (EXEC Banner)"
    if re.search(r"^banner exec\s+", config_text, re.MULTILINE):
        print_pass(control_id, "EXEC banner is set.")
    else:
        print_fail(control_id, "EXEC banner is not set.")

def check_1_5_3_login_banner(config_text):
    """
    1.5.3 Ensure 'LOGIN banner' is set (Scored)
    Audit: Checks for 'banner login ...'.
    """
    control_id = "1.5.3 (Login Banner)"
    if re.search(r"^banner login\s+", config_text, re.MULTILINE):
        print_pass(control_id, "LOGIN banner is set.")
    else:
        print_fail(control_id, "LOGIN banner is not set.")

def check_1_5_4_motd_banner(config_text):
    """
    1.5.4 Ensure 'MOTD banner' is set (Scored)
    Audit: Checks for 'banner motd ...'.
    """
    control_id = "1.5.4 (MOTD Banner)"
    if re.search(r"^banner motd\s+", config_text, re.MULTILINE):
        print_pass(control_id, "MOTD banner is set.")
    else:
        print_fail(control_id, "MOTD banner is not set.")

# --- 1.6 SSH Rules ---

def check_1_6_1_ssh_source(config_text):
    """
    1.6.1 Ensure 'SSH source restriction' is set (Scored)
    Audit: Checks for 'ssh <ip> <netmask> <interface>'.
    """
    control_id = "1.6.1 (SSH Source)"
    if re.search(r"^ssh\s+([0-9]{1,3}\.){3}[0-9]{1,3}\s+([0-9]{1,3}\.){3}[0-9]{1,3}\s+", config_text, re.MULTILINE):
        print_pass(control_id, "SSH source restriction is configured.")
    else:
        print_fail(control_id, "SSH access is not restricted by source IP (open to all).")

def check_1_6_2_ssh_version_2(config_text):
    """
    1.6.2 Ensure 'SSH version 2' is enabled (Scored)
    Audit: Checks for 'ssh version 2'.
    """
    control_id = "1.6.2 (SSH Version 2)"
    if re.search(r"^ssh version 2", config_text, re.MULTILINE):
        print_pass(control_id, "SSH Version 2 is explicitly enabled.")
    else:
        print_fail(control_id, "SSH Version 2 is not enabled (may allow v1).")

def check_1_6_3_rsa_key_size(config_text):
    """
    1.6.3 Ensure 'RSA key pair' is >= 2048 bits (Scored)
    Audit: Warns user to check manually.
    """
    control_id = "1.6.3 (RSA Key Size)"
    print_warn(control_id, "Cannot audit from 'show run'. Manually run 'show crypto key mypubkey rsa' and check 'Modulus Size' is >= 2048.")

def check_1_6_4_scp(config_text):
    """
    1.6.4 Ensure 'SCP protocol' is set to Enable for files transfers (Scored)
    Audit: Checks for 'ssh scopy enable'.
    """
    control_id = "1.6.4 (SCP Enabled)"
    if re.search(r"^ssh scopy enable", config_text, re.MULTILINE):
        print_pass(control_id, "SCP (ssh scopy enable) is enabled.")
    else:
        print_fail(control_id, "SCP (ssh scopy enable) is not enabled.")

def check_1_6_5_telnet_disabled(config_text):
    """
    1.6.5 Ensure 'Telnet' is disabled (Scored)
    Audit: Checks for any 'telnet' command that permits access.
    """
    control_id = "1.6.5 (Telnet Disabled)"
    # This regex looks for 'telnet' followed by an IP address or '0.0.0.0'
    if re.search(r"^telnet\s+([0-9]{1,3}\.){3}[0-9]{1,3}", config_text, re.MULTILINE):
        print_fail(control_id, "Telnet access is enabled for at least one IP.")
    else:
        print_pass(control_id, "Telnet is disabled (no 'telnet <ip>' rules found).")

# --- 1.7 HTTP Rules ---

def check_1_7_1_http_source(config_text):
    """
    1.7.1 Ensure 'HTTP source restriction' is set (Scored)
    Audit: Checks for 'http <ip> <netmask> <interface>'.
    """
    control_id = "1.7.1 (HTTP Source)"
    if re.search(r"^http\s+([0-9]{1,3}\.){3}[0-9]{1,3}\s+([0-9]{1,3}\.){3}[0-9]{1,3}\s+", config_text, re.MULTILINE):
        print_pass(control_id, "HTTP source restriction is configured.")
    else:
        print_fail(control_id, "HTTP access is not restricted by source IP (open to all).")

def check_1_7_2_tls_1_0(config_text):
    """
    1.7.2 Ensure 'TLS 1.0' is set for HTTPS access (Scored)
    Audit: Checks for 'ssl cipher tlsv1'. (Benchmark title is misleading, v8.x uses 'ssl encryption', v9.x uses 'ssl cipher')
    """
    control_id = "1.7.2 (TLS 1.0)"
    if re.search(r"^ssl cipher tlsv1\s+", config_text, re.MULTILINE):
        print_pass(control_id, "TLSv1 cipher suite is configured (ssl cipher tlsv1).")
    elif re.search(r"^ssl encryption\s+", config_text, re.MULTILINE):
         print_pass(control_id, "SSL encryption (v8.x style) is configured.")
    else:
        print_fail(control_id, "No 'ssl cipher tlsv1' or 'ssl encryption' found.")

def check_1_7_3_ssl_aes_256(config_text):
    """
    1.7.3 Ensure 'SSL AES 256 encryption' is set for HTTPS access (Scored)
    Audit: Checks for 'aes256-sha1' (v8.x) or 'AES256-SHA' (v9.x).
    """
    control_id = "1.7.3 (SSL AES-256)"
    if re.search(r"aes256-sha1|AES256-SHA", config_text, re.MULTILINE):
        print_pass(control_id, "AES-256 encryption cipher is configured for SSL.")
    else:
        print_fail(control_id, "AES-256 encryption cipher not found in SSL config.")

# --- 1.8 Session Timeout ---

def check_1_8_1_console_timeout(config_text):
    """
    1.8.1 Ensure 'console session timeout' is <= '5' minutes (Scored)
    Audit: Checks for 'console timeout'.
    """
    control_id = "1.8.1 (Console Timeout)"
    match = re.search(r"^console timeout\s+(\d+)", config_text, re.MULTILINE)
    if match:
        timeout = int(match.group(1))
        if 0 < timeout <= 5:
            print_pass(control_id, f"Console timeout is set to {timeout} minutes.")
        else:
            print_fail(control_id, f"Console timeout is {timeout} minutes (must be 1-5). '0' means no timeout.")
    else:
        print_fail(control_id, "Console timeout is not configured (defaults to 0 - no timeout).")

def check_1_8_2_ssh_timeout(config_text):
    """
    1.8.2 Ensure 'SSH session timeout' is <= '5' minutes (Scored)
    Audit: Checks for 'ssh timeout'.
    """
    control_id = "1.8.2 (SSH Timeout)"
    match = re.search(r"^ssh timeout\s+(\d+)", config_text, re.MULTILINE)
    if match:
        timeout = int(match.group(1))
        if 0 < timeout <= 5:
            print_pass(control_id, f"SSH timeout is set to {timeout} minutes.")
        else:
            print_fail(control_id, f"SSH timeout is {timeout} minutes (must be 1-5).")
    else:
        # Default is 5, so this is a PASS.
        print_pass(control_id, "SSH timeout is not explicitly configured (defaults to 5 minutes).")

def check_1_8_3_http_timeout(config_text):
    """
    1.8.3 Ensure 'HTTP session timeout' is <= '5' minutes (Scored)
    Audit: Checks for 'http server session-timeout'.
    """
    control_id = "1.8.3 (HTTP Timeout)"
    match = re.search(r"^http server session-timeout\s+(\d+)", config_text, re.MULTILINE)
    if match:
        timeout = int(match.group(1))
        if 0 < timeout <= 5:
            print_pass(control_id, f"HTTP session timeout is set to {timeout} minutes.")
        else:
            print_fail(control_id, f"HTTP session timeout is {timeout} minutes (must be 1-5).")
    else:
        print_fail(control_id, "HTTP session timeout is not configured (defaults to 20).")

# --- 1.9 Clock Rules ---

def check_1_9_1_1_ntp_auth_enabled(config_text):
    """
    1.9.1.1 Ensure 'NTP authentication' is enabled (Scored)
    Audit: Checks for 'ntp authenticate'.
    """
    control_id = "1.9.1.1 (NTP Auth)"
    if re.search(r"^ntp authenticate", config_text, re.MULTILINE):
        print_pass(control_id, "NTP authentication is enabled.")
    else:
        print_fail(control_id, "NTP authentication is not enabled.")

def check_1_9_1_2_ntp_auth_key(config_text):
    """
    1.9.1.2 Ensure 'NTP authentication key' is configured correctly (Scored)
    Audit: Checks for 'ntp authentication-key ...'.
    """
    control_id = "1.9.1.2 (NTP Auth Key)"
    if re.search(r"^ntp authentication-key\s+", config_text, re.MULTILINE):
        print_pass(control_id, "NTP authentication key is configured.")
    else:
        print_fail(control_id, "NTP authentication key is not configured.")

def check_1_9_1_3_trusted_ntp_server(config_text):
    """
    1.9.1.3 Ensure 'trusted NTP server' exists (Scored)
    Audit: Checks for 'ntp server ... key ...'.
    """
    control_id = "1.9.1.3 (Trusted NTP Server)"
    if re.search(r"^ntp server\s+.+\s+key\s+", config_text, re.MULTILINE):
        print_pass(control_id, "A trusted (authenticated) NTP server is configured.")
    else:
        print_fail(control_id, "No trusted (authenticated) NTP server is configured.")

def check_1_9_2_timezone(config_text):
    """
    1.9.2 Ensure 'local timezone' is properly configured (Scored)
    Audit: Checks for 'clock timezone ...'.
    """
    control_id = "1.9.2 (Timezone)"
    if re.search(r"^clock timezone\s+", config_text, re.MULTILINE):
        print_pass(control_id, "Local timezone is configured.")
    else:
        print_fail(control_id, "Local timezone is not configured (defaults to UTC).")

# --- 1.10 Logging Rules ---

def check_1_10_1_logging_enabled(config_text):
    """
    1.10.1 Ensure 'logging' is enabled (Scored)
    Audit: Checks for 'logging enable'.
    """
    control_id = "1.10.1 (Logging Enabled)"
    if re.search(r"^logging enable", config_text, re.MULTILINE):
        print_pass(control_id, "Logging is enabled.")
    else:
        print_fail(control_id, "Logging is not enabled.")

def check_1_10_2_logging_console(config_text):
    """
    1.10.2 Ensure 'logging to Serial console' is disabled (Scored)
    Audit: Checks for 'logging console ...'.
    """
    control_id = "1.10.2 (Logging Console)"
    if re.search(r"^logging console\s+", config_text, re.MULTILINE):
        print_fail(control_id, "Logging to serial console is enabled.")
    else:
        print_pass(control_id, "Logging to serial console is disabled.")

def check_1_10_3_logging_monitor(config_text):
    """
    1.10.3 Ensure 'logging to monitor' is disabled (Scored)
    Audit: Checks for 'logging monitor ...'.
    """
    control_id = "1.10.3 (Logging Monitor)"
    if re.search(r"^logging monitor\s+", config_text, re.MULTILINE):
        print_fail(control_id, "Logging to monitor (VTY) is enabled.")
    else:
        print_pass(control_id, "Logging to monitor (VTY) is disabled.")

def check_1_10_4_syslog_host(config_text):
    """
    1.10.4 Ensure 'syslog hosts' is configured correctly (Scored)
    Audit: Checks for 'logging host ...'.
    """
    control_id = "1.10.4 (Syslog Host)"
    if re.search(r"^logging host\s+", config_text, re.MULTILINE):
        print_pass(control_id, "At least one remote syslog host is configured.")
    else:
        print_fail(control_id, "No remote syslog host is configured.")

def check_1_10_5_logging_device_id(config_text):
    """
    1.10.5 Ensure 'logging with the device ID' is configured correctly (Scored)
    Audit: Checks for 'logging device-id (hostname|context-name)'.
    """
    control_id = "1.10.5 (Logging Device ID)"
    if re.search(r"^logging device-id\s+(hostname|context-name)", config_text, re.MULTILINE):
        print_pass(control_id, "Logging with device ID is configured.")
    else:
        print_fail(control_id, "Logging with device ID is not configured.")

def check_1_10_6_logging_history(config_text):
    """
    1.10.6 Ensure 'logging history severity level' is set to >= '5' (Scored)
    Audit: Checks for 'logging history'.
    """
    control_id = "1.10.6 (Logging History Level)"
    match = re.search(r"^logging history\s+(\d+|[a-zA-Z]+)", config_text, re.MULTILINE)
    if match:
        level = match.group(1)
        # Numerical levels: 5 (notifications), 6 (informational), 7 (debugging)
        # Word levels: notifications, informational, debugging
        if level.isdigit() and int(level) >= 5:
            print_pass(control_id, f"Logging history level is set to {level} (>= 5).")
        elif level in ['notifications', 'informational', 'debugging']:
             print_pass(control_id, f"Logging history level is set to {level} (>= 5).")
        else:
            print_fail(control_id, f"Logging history level is {level} (must be >= 5).")
    else:
        print_fail(control_id, "Logging history level is not configured.")

def check_1_10_7_logging_timestamp(config_text):
    """
    1.10.7 Ensure 'logging with timestamps' is enabled (Scored)
    Audit: Checks for 'logging timestamp'.
    """
    control_id = "1.10.7 (Logging Timestamp)"
    if re.search(r"^logging timestamp", config_text, re.MULTILINE):
        print_pass(control_id, "Logging with timestamps is enabled.")
    else:
        print_fail(control_id, "Logging with timestamps is not enabled.")

def check_1_10_8_logging_facility(config_text):
    """
    1.10.8 Ensure 'syslog logging facility' is equal to '23' (Scored)
    Audit: Checks for 'logging facility 23'.
    """
    control_id = "1.10.8 (Logging Facility)"
    if re.search(r"^logging facility 23", config_text, re.MULTILINE):
        print_pass(control_id, "Logging facility is set to 23 (LOCAL7).")
    else:
        match = re.search(r"^logging facility\s+(\d+)", config_text, re.MULTILINE)
        if match:
            print_fail(control_id, f"Logging facility is {match.group(1)} (should be 23).")
        else:
            print_fail(control_id, "Logging facility is not set (defaults to 20).")

def check_1_10_9_logging_buffer_size(config_text):
    """
    1.10.9 Ensure 'logging buffer size' is >= '524288' bytes (512kb) (Scored)
    Audit: Checks for 'logging buffer-size'.
    """
    control_id = "1.10.9 (Logging Buffer Size)"
    match = re.search(r"^logging buffer-size\s+(\d+)", config_text, re.MULTILINE)
    if match:
        size = int(match.group(1))
        if size >= 524288:
            print_pass(control_id, f"Logging buffer size is {size} bytes (>= 524288).")
        else:
            print_fail(control_id, f"Logging buffer size is {size} bytes (< 524288).")
    else:
        print_fail(control_id, "Logging buffer size is not set (defaults to 4096).")

def check_1_10_10_logging_buffered_level(config_text):
    """
    1.10.10 Ensure 'logging buffered severity level' is >= '3' (Scored)
    Audit: Checks for 'logging buffered'.
    """
    control_id = "1.10.10 (Logging Buffered Level)"
    match = re.search(r"^logging buffered\s+(\d+|[a-zA-Z]+)", config_text, re.MULTILINE)
    if match:
        level = match.group(1)
        # Levels >= 3: errors, warnings, notifications, informational, debugging
        if level.isdigit() and int(level) >= 3:
            print_pass(control_id, f"Logging buffered level is {level} (>= 3).")
        elif level in ['errors', 'warnings', 'notifications', 'informational', 'debugging']:
             print_pass(control_id, f"Logging buffered level is {level} (>= 3).")
        else:
            print_fail(control_id, f"Logging buffered level is {level} (must be >= 3).")
    else:
        print_fail(control_id, "Logging buffered level is not set (defaults to 7).")

def check_1_10_11_logging_trap_level(config_text):
    """
    1.10.11 Ensure 'logging trap severity level' is >= '5' (Scored)
    Audit: Checks for 'logging trap'.
    """
    control_id = "1.10.11 (Logging Trap Level)"
    match = re.search(r"^logging trap\s+(\d+|[a-zA-Z]+)", config_text, re.MULTILINE)
    if match:
        level = match.group(1)
        if level.isdigit() and int(level) >= 5:
            print_pass(control_id, f"Logging trap level is set to {level} (>= 5).")
        elif level in ['notifications', 'informational', 'debugging']:
             print_pass(control_id, f"Logging trap level is set to {level} (>= 5).")
        else:
            print_fail(control_id, f"Logging trap level is {level} (must be >= 5).")
    else:
        print_fail(control_id, "Logging trap level is not configured.")

def check_1_10_12_logging_email(config_text):
    """
    1.10.12 Ensure email logging is configured for critical to emergency (Scored)
    Audit: Checks for 'logging mail critical'.
    """
    control_id = "1.10.12 (Logging Email)"
    if re.search(r"^logging mail (critical|alerts|emergencies)", config_text, re.MULTILINE):
        print_pass(control_id, "Logging via email for critical+ events is configured.")
    else:
        print_fail(control_id, "Logging via email for critical+ events is not configured.")

# --- 1.11 SNMP Rules ---

def check_1_11_1_snmpv3_priv(config_text):
    """
    1.11.1 Ensure 'snmp-server group' is set to 'v3 priv' (Scored)
    Audit: Checks for 'snmp-server group ... v3 priv'.
    """
    control_id = "1.11.1 (SNMPv3 Priv)"
    if re.search(r"^snmp-server group\s+.+\s+v3 priv", config_text, re.MULTILINE):
        print_pass(control_id, "SNMPv3 group with 'priv' (AuthPriv) is configured.")
    else:
        print_fail(control_id, "No SNMPv3 group with 'priv' (AuthPriv) found.")

def check_1_11_2_snmpv3_user(config_text):
    """
    1.11.2 Ensure 'snmp-server user' is set to 'v3 auth SHA' (Scored)
    Audit: Checks for 'snmp-server user ... v3 auth sha'.
    """
    control_id = "1.11.2 (SNMPv3 User SHA)"
    if re.search(r"^snmp-server user\s+.+\s+v3 auth sha", config_text, re.IGNORECASE | re.MULTILINE):
        print_pass(control_id, "SNMPv3 user with 'auth sha' is configured.")
    else:
        print_fail(control_id, "No SNMPv3 user with 'auth sha' found.")

def check_1_11_3_snmpv3_host(config_text):
    """
    1.11.3 Ensure 'snmp-server host' is set to 'version 3' (Scored)
    Audit: Checks for 'snmp-server host ... version 3'.
    """
    control_id = "1.11.3 (SNMPv3 Host)"
    if re.search(r"^snmp-server host\s+.+\s+version 3\s+", config_text, re.IGNORECASE | re.MULTILINE):
        print_pass(control_id, "SNMPv3 host is configured.")
    else:
        print_fail(control_id, "No SNMPv3 host found.")

def check_1_11_4_snmp_traps(config_text):
    """
    1.11.4 Ensure 'SNMP traps' is enabled (Scored)
    Audit: Checks for 'snmp-server enable traps snmp'.
    """
    control_id = "1.11.4 (SNMP Traps)"
    if re.search(r"^snmp-server enable traps snmp", config_text, re.MULTILINE):
        print_pass(control_id, "SNMP traps are enabled.")
    else:
        print_fail(control_id, "SNMP traps are not enabled.")

def check_1_11_5_snmp_default_string(config_text):
    """
    1.11.5 Ensure 'SNMP community string' is not the default string (Scored)
    Audit: Checks for 'snmp-server community public'.
    """
    control_id = "1.11.5 (SNMP Default String)"
    if re.search(r"^snmp-server community\s+public\s", config_text, re.MULTILINE):
        print_fail(control_id, "Default SNMP community string 'public' is in use.")
    else:
        print_pass(control_id, "Default SNMP community string 'public' is not found.")

# --- 2.0 Control Plane ---

def check_2_1_1_rip_auth(config_text):
    """
    2.1.1 Ensure 'RIP authentication' is enabled (Scored)
    Audit: Checks for 'router rip' and 'rip authentication'.
    """
    control_id = "2.1.1 (RIP Auth)"
    if not re.search(r"^router rip", config_text, re.MULTILINE):
        print_warn(control_id, "RIP is not enabled, check is Not Applicable.")
        return
    
    if re.search(r"rip authentication", config_text, re.MULTILINE):
        print_pass(control_id, "RIP is enabled and authentication is configured.")
    else:
        print_fail(control_id, "RIP is enabled but authentication is not configured.")

def check_2_1_2_ospf_auth(config_text):
    """
    2.1.2 Ensure 'OSPF authentication' is enabled (Scored)
    Audit: Checks for 'router ospf' and 'ospf authentication'.
    """
    control_id = "2.1.2 (OSPF Auth)"
    if not re.search(r"^router ospf", config_text, re.MULTILINE):
        print_warn(control_id, "OSPF is not enabled, check is Not Applicable.")
        return
    
    if re.search(r"ospf authentication", config_text, re.MULTILINE):
        print_pass(control_id, "OSPF is enabled and authentication is configured.")
    else:
        print_fail(control_id, "OSPF is enabled but authentication is not configured.")

def check_2_1_3_eigrp_auth(config_text):
    """
    2.1.3 Ensure 'EIGRP authentication' is enabled (Scored)
    Audit: Checks for 'router eigrp' and 'authentication mode eigrp'.
    """
    control_id = "2.1.3 (EIGRP Auth)"
    if not re.search(r"^router eigrp", config_text, re.MULTILINE):
        print_warn(control_id, "EIGRP is not enabled, check is Not Applicable.")
        return
    
    if re.search(r"authentication mode eigrp", config_text, re.MULTILINE):
        print_pass(control_id, "EIGRP is enabled and authentication is configured.")
    else:
        print_fail(control_id, "EIGRP is enabled but authentication is not configured.")

def check_2_2_noproxyarp(config_text):
    """
    2.2 Ensure 'noproxyarp' is enabled for untrusted interfaces (Scored)
    Audit: Checks for 'sysopt noproxyarp'.
    """
    control_id = "2.2 (No Proxy ARP)"
    if re.search(r"^sysopt noproxyarp", config_text, re.MULTILINE):
        print_pass(control_id, "'sysopt noproxyarp' is configured for at least one interface.")
    else:
        print_fail(control_id, "'sysopt noproxyarp' is not configured.")

def check_2_3_dns_guard(config_text):
    """
    2.3 Ensure 'DNS Guard' is enabled (Scored)
    Audit: Checks for 'dns-guard'.
    """
    control_id = "2.3 (DNS Guard)"
    if re.search(r"^dns-guard", config_text, re.MULTILINE):
        print_pass(control_id, "DNS Guard is enabled.")
    else:
        print_fail(control_id, "DNS Guard is not enabled.")

def check_2_4_dhcp_disabled(config_text):
    """
    2.4 Ensure DHCP services are disabled for untrusted interfaces (Scored)
    Audit: Checks for 'dhcpd enable' or 'dhcprelay enable' on 'outside' interface.
    """
    control_id = "2.4 (DHCP Disabled)"
    if re.search(r"^(dhcpd|dhcprelay) enable outside", config_text, re.MULTILINE):
        print_fail(control_id, "DHCP service (dhcpd or dhcprelay) is enabled on 'outside' interface.")
    else:
        print_pass(control_id, "DHCP service (dhcpd or dhcprelay) is not enabled on 'outside' interface.")

def check_2_5_icmp_restricted(config_text):
    """
    2.5 Ensure ICMP is restricted for untrusted interfaces (Scored)
    Audit: Checks for 'icmp deny any <interface>'.
    NOTE: This is a simplified check. It looks for *any* 'icmp deny any'.
          A manual check is still advised for specific interfaces.
    """
    control_id = "2.5 (ICMP Restricted)"
    if re.search(r"^icmp deny any\s+", config_text, re.MULTILINE):
        print_pass(control_id, "Found 'icmp deny any' rule. (Manual check advised for specific interfaces).")
    else:
        print_fail(control_id, "No 'icmp deny any' rule found. ICMP may be unrestricted.")

# --- 3.0 Data Plane ---

def check_3_1_dns_services(config_text):
    """
    3.1 Ensure DNS services are configured correctly (Scored)
    Audit: Checks for 'dns domain-lookup' and 'dns server-group'.
    """
    control_id = "3.1 (DNS Services)"
    lookup = re.search(r"^dns domain-lookup\s+", config_text, re.MULTILINE)
    server = re.search(r"^dns server-group\s+", config_text, re.MULTILINE)
    if lookup and server:
        print_pass(control_id, "DNS domain-lookup and server-group are configured.")
    elif not lookup:
        print_fail(control_id, "DNS domain-lookup is not enabled.")
    elif not server:
        print_fail(control_id, "DNS server-group is not configured.")
def check_3_2_ips(config_text):
    """
    3.2 Ensure intrusion prevention is enabled for untrusted interfaces (Scored)
    Audit: Checks for 'ip audit interface'.
    """
    control_id = "3.2 (IPS Enabled)"
    if re.search(r"^ip audit interface", config_text, re.MULTILINE):
        print_pass(control_id, "Intrusion Prevention (ip audit interface) is enabled.")
    else:
        print_fail(control_id, "Intrusion Prevention (ip audit interface) is not enabled.")

def check_3_3_fragments(config_text):
    """
    3.3 Ensure packet fragments are restricted for untrusted interfaces (Scored)
    Audit: Checks for 'fragment chain 1'.
    """
    control_id = "3.3 (Fragment Restriction)"
    if re.search(r"^fragment chain 1\s+", config_text, re.MULTILINE):
        print_pass(control_id, "Packet fragment restriction ('fragment chain 1') is configured.")
    else:
        print_fail(control_id, "Packet fragment restriction ('fragment chain 1') is not configured.")

def check_3_4_app_inspection(config_text):
    """
    3.4 Ensure non-default application inspection is configured correctly (Not Scored)
    Audit: Checks for 'inspect' in 'policy-map global_policy'.
    """
    control_id = "3.4 (App Inspection)"
    # This is complex. We'll just check if a global policy-map exists.
    if re.search(r"^policy-map global_policy", config_text, re.MULTILINE):
        print_pass(control_id, "'policy-map global_policy' exists. (Manually verify inspections).")
    else:
        print_fail(control_id, "'policy-map global_policy' does not exist.")

def check_3_5_dos_protection(config_text):
    """
    3.5 Ensure DOS protection is enabled for untrusted interfaces (Not Scored)
    Audit: Checks for 'set connection' in a policy-map.
    """
    control_id = "3.5 (DoS Protection)"
    if re.search(r"set connection (conn-max|embryonic-conn-max)", config_text, re.MULTILINE):
        print_pass(control_id, "DoS Protection ('set connection') appears to be configured.")
    else:
        print_fail(control_id, "DoS Protection ('set connection') is not configured.")

def check_3_6_threat_detection(config_text):
    """
    3.6 Ensure 'threat-detection statistics' is set to 'tcp-intercept' (Scored)
    Audit: Checks for 'threat-detection statistics tcp-intercept'.
    """
    control_id = "3.6 (Threat Detection)"
    if re.search(r"^threat-detection statistics tcp-intercept", config_text, re.MULTILINE):
        print_pass(control_id, "Threat detection statistics for tcp-intercept is enabled.")
    else:
        print_fail(control_id, "Threat detection statistics for tcp-intercept is not enabled.")

def check_3_7_urpf(config_text):
    """
    3.7 Ensure 'ip verify' is set to 'reverse-path' for untrusted interfaces (Scored)
    Audit: Checks for 'ip verify reverse-path'.
    """
    control_id = "3.7 (uRPF)"
    if re.search(r"^ip verify reverse-path\s+", config_text, re.MULTILINE):
        print_pass(control_id, "Unicast RPF ('ip verify reverse-path') is configured on at least one interface.")
    else:
        print_fail(control_id, "Unicast RPF ('ip verify reverse-path') is not configured.")

def check_3_8_security_level_0(config_text):
    """
    3.8 Ensure 'security-level' is set to '0' for Internet-facing interface (Scored)
    Audit: Checks for 'security-level 0' on 'outside' interface.
    """
    control_id = "3.8 (Security Level 0)"
    try:
        # Split the config into sections, starting with "interface "
        # The [1:] skips any text before the first interface definition
        interface_blocks = re.split(r"^interface\s+", config_text, flags=re.MULTILINE)[1:]
        
        found_outside_level_0 = False
        found_outside_interface = False
        
        for block in interface_blocks:
            # Check if this block contains 'nameif outside'
            # Added ^\s* to match lines with leading whitespace
            if re.search(r"^\s*nameif outside", block, re.MULTILINE):
                found_outside_interface = True
                # If it is the 'outside' interface, check its security level
                if re.search(r"^\s*security-level 0", block, re.MULTILINE):
                    found_outside_level_0 = True
                break # Found the 'outside' interface, no need to check others
        
        if found_outside_level_0:
            print_pass(control_id, "Interface 'outside' is set to 'security-level 0'.")
        elif found_outside_interface:
            print_fail(control_id, "Interface 'outside' was found but is not set to 'security-level 0'.")
        else:
            print_fail(control_id, "Interface 'outside' was not found in the configuration.")

    except Exception as e:
        print_fail(control_id, f"Error during check: {e}. Regex may have failed.")

def check_3_9_botnet(config_text):
    """
    3.9 Ensure Botnet protection is enabled for untrusted interfaces (Scored)
    Audit: Checks for 'dynamic-filter enable'.
    """
    control_id = "3.9 (Botnet Filter)"
    if re.search(r"^dynamic-filter enable", config_text, re.MULTILINE):
        print_pass(control_id, "Botnet Traffic Filter ('dynamic-filter enable') is enabled.")
    else:
        print_fail(control_id, "Botnet Traffic Filter ('dynamic-filter enable') is not enabled.")

def check_3_10_activex_filter(config_text):
    """
    3.10 Ensure ActiveX filtering is enabled (Scored)
    Audit: Checks for 'filter activex'.
    """
    control_id = "3.10 (ActiveX Filter)"
    if re.search(r"^filter activex\s+", config_text, re.MULTILINE):
        print_pass(control_id, "ActiveX filtering is enabled.")
    else:
        print_fail(control_id, "ActiveX filtering is not enabled.")

def check_3_11_java_filter(config_text):
    """
    3.11 Ensure Java applet filtering is enabled (Scored)
    Audit: Checks for 'filter java'.
    """
    control_id = "3.11 (Java Filter)"
    if re.search(r"^filter java\s+", config_text, re.MULTILINE):
        print_pass(control_id, "Java applet filtering is enabled.")
    else:
        print_fail(control_id, "Java applet filtering is not enabled.")

def check_3_12_explicit_deny(config_text):
    """
    3.12 Ensure explicit deny in access lists is configured correctly (Scored)
    Audit: This is complex as it requires checking *all* ACLs.
           This script performs a basic check for *any* 'deny ip any any log'.
    """
    control_id = "3.12 (Explicit ACL Deny)"
    if re.search(r"deny ip any any log", config_text, re.MULTILINE):
        print_warn(control_id, "Found at least one 'deny ip any any log'. Manually verify all ACLs have an explicit deny.")
    else:
        print_fail(control_id, "Could not find a sample 'deny ip any any log' line. Verify all ACLs manually.")

# --- Main Audit Runner ---

def run_all_checks(config_text):
    """
    Runs all defined audit checks against the configuration text.
    
    *** TO ADD A NEW CHECK, ADD ITS FUNCTION NAME TO THIS LIST ***
    """
    checks_to_run = [
        # Section 1.1: Password Management
        (print_header, "1.1 Password Management"),
        check_1_1_1_logon_password,
        check_1_1_2_enable_password,
        check_1_1_3_master_key,
        check_1_1_4_password_recovery,
        check_1_1_5_password_policy,
        
        # Section 1.2: Device Management
        (print_header, "1.2 Device Management"),
        check_1_2_1_domain_name,
        check_1_2_2_host_name,
        check_1_2_3_failover,
        check_1_2_4_unused_interfaces,
        
        # Section 1.3: Image Security
        (print_header, "1.3 Image Security"),
        check_1_3_1_image_integrity,
        check_1_3_2_image_authenticity,
        
        # Section 1.4: Authentication, Authorization and Accounting (AAA)
        (print_header, "1.4 AAA"),
        check_1_4_1_1_aaa_max_failed,
        check_1_4_1_2_local_user,
        check_1_4_1_3_default_accounts,
        check_1_4_2_1_remote_aaa,
        check_1_4_3_1_aaa_enable_console,
        check_1_4_3_2_aaa_http_console,
        check_1_4_3_3_aaa_secure_http,
        check_1_4_3_4_aaa_serial_console,
        check_1_4_3_5_aaa_ssh,
        check_1_4_3_6_aaa_telnet_console,
        check_1_4_4_1_aaa_cmd_authorization,
        check_1_4_4_2_aaa_exec_authorization,
        check_1_4_5_1_aaa_cmd_accounting,
        check_1_4_5_2_aaa_ssh_accounting,
        check_1_4_5_3_aaa_serial_accounting,
        check_1_4_5_4_aaa_exec_accounting,

        # Section 1.5: Banner Rules
        (print_header, "1.5 Banner Rules"),
        check_1_5_1_asdm_banner,
        check_1_5_2_exec_banner,
        check_1_5_3_login_banner,
        check_1_5_4_motd_banner,
        
        # Section 1.6: SSH Rules
        (print_header, "1.6 SSH Rules"),
        check_1_6_1_ssh_source,
        check_1_6_2_ssh_version_2,
        check_1_6_3_rsa_key_size,
        check_1_6_4_scp,
        check_1_6_5_telnet_disabled,

        # Section 1.7: HTTP Rules
        (print_header, "1.7 HTTP Rules"),
        check_1_7_1_http_source,
        check_1_7_2_tls_1_0,
        check_1_7_3_ssl_aes_256,

        # Section 1.8: Session Timeout
        (print_header, "1.8 Session Timeout"),
        check_1_8_1_console_timeout,
        check_1_8_2_ssh_timeout,
        check_1_8_3_http_timeout,

        # Section 1.9: Clock Rules
        (print_header, "1.9 Clock Rules (NTP)"),
        check_1_9_1_1_ntp_auth_enabled,
        check_1_9_1_2_ntp_auth_key,
        check_1_9_1_3_trusted_ntp_server,
        check_1_9_2_timezone,

        # Section 1.10: Logging Rules
        (print_header, "1.10 Logging Rules"),
        check_1_10_1_logging_enabled,
        check_1_10_2_logging_console,
        check_1_10_3_logging_monitor,
        check_1_10_4_syslog_host,
        check_1_10_5_logging_device_id,
        check_1_10_6_logging_history,
        check_1_10_7_logging_timestamp,
        check_1_10_8_logging_facility,
        check_1_10_9_logging_buffer_size,
        check_1_10_10_logging_buffered_level,
        check_1_10_11_logging_trap_level,
        check_1_10_12_logging_email,

        # Section 1.11: SNMP Rules
        (print_header, "1.11 SNMP Rules"),
        check_1_11_1_snmpv3_priv,
        check_1_11_2_snmpv3_user,
        check_1_11_3_snmpv3_host,
        check_1_11_4_snmp_traps,
        check_1_11_5_snmp_default_string,

        # Section 2: Control Plane
        (print_header, "2.0 Control Plane"),
        check_2_1_1_rip_auth,
        check_2_1_2_ospf_auth,
        check_2_1_3_eigrp_auth,
        check_2_2_noproxyarp,
        check_2_3_dns_guard,
        check_2_4_dhcp_disabled,
        check_2_5_icmp_restricted,

        # Section 3: Data Plane
        (print_header, "3.0 Data Plane"),
        check_3_1_dns_services,
        check_3_2_ips,
        check_3_3_fragments,
        check_3_4_app_inspection,
        check_3_5_dos_protection,
        check_3_6_threat_detection,
        check_3_7_urpf,
        check_3_8_security_level_0,
        check_3_9_botnet,
        check_3_10_activex_filter,
        check_3_11_java_filter,
        check_3_12_explicit_deny,
    ]

    total_checks = 0
    
    print(f"{Colors.BLUE}Starting CIS Audit...{Colors.RESET}")
    
    for check in checks_to_run:
        if isinstance(check, tuple):
            # This is a header function
            check[0](check[1])
        else:
            # This is a check function
            try:
                check(config_text)
                total_checks += 1
            except Exception as e:
                print(f"  [{Colors.RED}ERROR{Colors.RESET}] Error running check {check.__name__}: {e}")
                
    print(f"\n{Colors.BLUE}Audit Complete.{Colors.RESET} Ran {total_checks} checks.")

def main():
    """
    Main function to parse arguments, read the file, and start the audit.
    """
    parser = argparse.ArgumentParser(
        description="CIS Cisco ASA v8.x Configuration Auditor",
        epilog="Example: python cis_asa_auditor.py my_asa_config.txt"
    )
    parser.add_argument(
        "config_file", 
        help="Path to the Cisco ASA configuration file (e.g., from 'show running-config')."
    )
    
    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)
        
    args = parser.parse_args()
    config_file_path = args.config_file

    try:
        with open(config_file_path, 'r', encoding='utf-8') as f:
            config_content = f.read()
        
        run_all_checks(config_content)

    except FileNotFoundError:
        print(f"{Colors.RED}Error: File not found at '{config_file_path}'{Colors.RESET}")
        sys.exit(1)
    except Exception as e:
        print(f"{Colors.RED}An unexpected error occurred: {e}{Colors.RESET}")
        sys.exit(1)

if __name__ == "__main__":
    main()



