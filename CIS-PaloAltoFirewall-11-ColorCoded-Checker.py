import argparse
from lxml import etree
import re
import sys

# To Execute: python CIS-PaloAltiFirewall-11-Checker.py <configfile.xml>

# Color codes for terminal output
class Colors:
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

class PaloAltoAuditor:
    """
    Audits a Palo Alto Firewall 11 XML configuration against the CIS v1.2.0 Benchmark.
    """
    def __init__(self, config_file):
        """
        Initializes the auditor with the path to the configuration file.
        """
        try:
            # The XMLParser is configured to remove blank text to make XPath navigation easier.
            xml_parser = etree.XMLParser(remove_blank_text=True)
            self.tree = etree.parse(config_file, xml_parser)
            self.results = []
        except IOError:
            print(f"{Colors.FAIL}Error: The file '{config_file}' was not found.{Colors.ENDC}")
            self.tree = None
        except etree.XMLSyntaxError as e:
            print(f"{Colors.FAIL}Error: Failed to parse the XML file. Please ensure it's a valid XML config. Details: {e}{Colors.ENDC}")
            self.tree = None

    def run_all_checks(self):
        """
        Runs all defined audit checks from the CIS Benchmark.
        """
        if not self.tree:
            return

        # Dynamically find all methods in this class that start with 'check_'
        check_methods = [getattr(self, func) for func in dir(self) if callable(getattr(self, func)) and func.startswith('check_')]
        
        # Sort checks based on the numeric parts of their names to follow the benchmark order
        check_methods.sort(key=lambda x: [int(c) for c in x.__name__.replace('check_', '').split('_')])

        for check_method in check_methods:
            try:
                result = check_method()
                self.results.append(result)
            except Exception as e:
                # This ensures that if one check fails, the entire audit doesn't stop.
                self.results.append({
                    'description': f"Error in check {check_method.__name__}",
                    'level': 'N/A',
                    'status': 'ERROR',
                    'output': f"An unexpected error occurred: {e}",
                    'expected': 'N/A'
                })
        
        return self.results

    def _generate_result(self, level, description, status, output, expected, info=None):
        """Helper function to create a standardized result dictionary."""
        return {
            'level': level,
            'description': description,
            'status': status,
            'output': output,
            'expected': expected,
            'info': info
        }

    # --- CIS BENCHMARK CONTROLS ---

    def check_1_1_1_1(self):
        level = 'L1'
        desc = "1.1.1.1 Syslog logging should be configured"
        nodes = self.tree.xpath("//log-settings/syslog/entry/server/entry/server")
        if nodes:
            servers = [elem.text for elem in nodes]
            return self._generate_result(level, desc, 'PASS', f"Syslog servers found: {', '.join(servers)}", "At least one syslog server configured.")
        else:
            return self._generate_result(level, desc, 'FAIL', "No syslog server configured.", "At least one syslog server configured.")

    def check_1_1_1_2(self):
        level = 'L2'
        desc = "1.1.1.2 SNMPv3 traps should be configured"
        nodes = self.tree.xpath("//log-settings/snmptrap/entry/version/v3/server/entry")
        if nodes:
            return self._generate_result(level, desc, 'PASS', "SNMPv3 trap server configuration found.", "SNMPv3 trap server configured.")
        else:
            return self._generate_result(level, desc, 'FAIL', "No SNMPv3 trap server configured.", "SNMPv3 trap server configured.")

    def check_1_1_2(self):
        level = 'L1'
        desc = "1.1.2 Ensure 'Login Banner' is set"
        nodes = self.tree.xpath("//login-banner")
        if nodes and nodes[0].text and nodes[0].text.strip():
            return self._generate_result(level, desc, 'PASS', f"Login banner is set:\n---\n{nodes[0].text.strip()}\n---", "A non-empty login banner.")
        else:
            return self._generate_result(level, desc, 'FAIL', "Login banner is not set or is empty.", "A non-empty login banner.")

    def check_1_1_3(self):
        level = 'L1'
        desc = "1.1.3 Ensure 'Enable Log on High DP Load' is enabled"
        nodes = self.tree.xpath("//setting/management/enable-log-high-dp-load[text()='yes']")
        if nodes:
            return self._generate_result(level, desc, 'PASS', "Log on High DP Load is enabled.", "Setting should be 'yes'.")
        else:
            return self._generate_result(level, desc, 'FAIL', "Log on High DP Load is not enabled.", "Setting should be 'yes'.")

    def check_1_2_1(self):
        return self._generate_result('L1', "1.2.1 Ensure 'Permitted IP Addresses' is set to those necessary for device management (Manual)", 'MANUAL REVIEW REQUIRED', "Navigate to Device > Setup > Interfaces > Management. Verify that Permitted IP Addresses is limited only to those necessary for device management.", "Manual verification.")

    def check_1_2_2(self):
        return self._generate_result('L1', "1.2.2 Ensure 'Permitted IP Addresses' is set for all management profiles where SSH, HTTPS, or SNMP is enabled (Manual)", 'MANUAL REVIEW REQUIRED', "Navigate to Network > Network Profiles > Interface Management. In each profile, for each of the target protocols (SNMP, HTTPS, SSH), verify that Permitted IP Addresses is limited to those necessary for device management.", "Manual verification.")

    def check_1_2_3(self):
        level = 'L1'
        desc = "1.2.3 Ensure HTTP and Telnet options are disabled for the management interface"
        failures = []
        if self.tree.xpath("//deviceconfig/system/service/disable-telnet[text()='no']"):
            failures.append("Telnet is enabled.")
        if self.tree.xpath("//deviceconfig/system/service/disable-http[text()='no']"):
            failures.append("HTTP is enabled.")
        
        if failures:
            return self._generate_result(level, desc, 'FAIL', " ".join(failures), "HTTP and Telnet should be disabled.")
        else:
            return self._generate_result(level, desc, 'PASS', "HTTP and Telnet are disabled.", "HTTP and Telnet should be disabled.")

    def check_1_2_4(self):
        return self._generate_result('L1', "1.2.4 Ensure HTTP and Telnet options are disabled for all management profiles (Manual)", 'MANUAL REVIEW REQUIRED', "Navigate to Network > Network Profiles > Interface Management. For each Interface Management profile verify that the HTTP and Telnet options are both unchecked.", "Manual verification.")

    def check_1_2_5(self):
        return self._generate_result('L2', "1.2.5 Ensure valid certificate is set for browser-based administrator interface (Manual)", 'MANUAL REVIEW REQUIRED', "Verify that the certificate used to secure HTTPS sessions meets the criteria by reviewing the appropriate certificate: Navigate to Device > Certificate Management > Certificates. Verify that this Certificate is properly applied to the Management Interface: Navigate to Device > Setup > Management > General Settings > SSL/TLS Service Profile.", "Manual verification.")

    def check_1_3_1(self):
        level = 'L1'
        desc = "1.3.1 Ensure 'Minimum Password Complexity' is enabled"
        nodes = self.tree.xpath("//password-complexity/enabled[text()='yes']")
        if nodes:
            return self._generate_result(level, desc, 'PASS', "Password complexity is enabled.", "Enabled.")
        else:
            return self._generate_result(level, desc, 'FAIL', "Password complexity is not enabled.", "Enabled.")

    def check_1_3_2(self):
        level = 'L1'
        desc = "1.3.2 Ensure 'Minimum Length' is greater than or equal to 12"
        nodes = self.tree.xpath("//password-complexity/minimum-length")
        if nodes and int(nodes[0].text) >= 12:
            return self._generate_result(level, desc, 'PASS', f"Minimum password length is {nodes[0].text}.", ">= 12.")
        elif nodes:
            return self._generate_result(level, desc, 'FAIL', f"Minimum password length is {nodes[0].text}.", ">= 12.")
        else:
            return self._generate_result(level, desc, 'FAIL', "Minimum password length is not set.", ">= 12.")

    def check_1_3_3(self):
        level = 'L1'
        desc = "1.3.3 Ensure 'Minimum Uppercase Letters' is greater than or equal to 1"
        nodes = self.tree.xpath("//password-complexity/minimum-uppercase-letters")
        if nodes and int(nodes[0].text) >= 1:
            return self._generate_result(level, desc, 'PASS', f"Minimum uppercase letters is {nodes[0].text}.", ">= 1.")
        elif nodes:
            return self._generate_result(level, desc, 'FAIL', f"Minimum uppercase letters is {nodes[0].text}.", ">= 1.")
        else:
            return self._generate_result(level, desc, 'FAIL', "Minimum uppercase letters is not set.", ">= 1.")

    def check_1_3_4(self):
        level = 'L1'
        desc = "1.3.4 Ensure 'Minimum Lowercase Letters' is greater than or equal to 1"
        nodes = self.tree.xpath("//password-complexity/minimum-lowercase-letters")
        if nodes and int(nodes[0].text) >= 1:
            return self._generate_result(level, desc, 'PASS', f"Minimum lowercase letters is {nodes[0].text}.", ">= 1.")
        elif nodes:
            return self._generate_result(level, desc, 'FAIL', f"Minimum lowercase letters is {nodes[0].text}.", ">= 1.")
        else:
            return self._generate_result(level, desc, 'FAIL', "Minimum lowercase letters is not set.", ">= 1.")

    def check_1_3_5(self):
        level = 'L1'
        desc = "1.3.5 Ensure 'Minimum Numeric Letters' is greater than or equal to 1"
        nodes = self.tree.xpath("//password-complexity/minimum-numeric-letters")
        if nodes and int(nodes[0].text) >= 1:
            return self._generate_result(level, desc, 'PASS', f"Minimum numeric characters is {nodes[0].text}.", ">= 1.")
        elif nodes:
            return self._generate_result(level, desc, 'FAIL', f"Minimum numeric characters is {nodes[0].text}.", ">= 1.")
        else:
            return self._generate_result(level, desc, 'FAIL', "Minimum numeric characters is not set.", ">= 1.")
            
    def check_1_3_6(self):
        level = 'L1'
        desc = "1.3.6 Ensure 'Minimum Special Characters' is greater than or equal to 1"
        nodes = self.tree.xpath("//password-complexity/minimum-special-characters")
        if nodes and int(nodes[0].text) >= 1:
            return self._generate_result(level, desc, 'PASS', f"Minimum special characters is {nodes[0].text}.", ">= 1.")
        elif nodes:
             return self._generate_result(level, desc, 'FAIL', f"Minimum special characters is {nodes[0].text}.", ">= 1.")
        else:
            return self._generate_result(level, desc, 'FAIL', "Minimum special characters is not set.", ">= 1.")

    def check_1_3_7(self):
        level = 'L1'
        desc = "1.3.7 Ensure 'Required Password Change Period' is less than or equal to 90 days"
        nodes = self.tree.xpath("//password-complexity/password-change/expiration-period")
        if nodes and int(nodes[0].text) <= 90 and int(nodes[0].text) > 0:
            return self._generate_result(level, desc, 'PASS', f"Password change period is {nodes[0].text} days.", "<= 90 days.")
        elif nodes:
             return self._generate_result(level, desc, 'FAIL', f"Password change period is {nodes[0].text} days.", "<= 90 days.")
        else:
            return self._generate_result(level, desc, 'FAIL', "Password change period not set.", "<= 90 days.")

    def check_1_3_8(self):
        level = 'L1'
        desc = "1.3.8 Ensure 'New Password Differs By Characters' is greater than or equal to 3"
        nodes = self.tree.xpath("//password-complexity/new-password-differs-by-characters")
        if nodes and int(nodes[0].text) >= 3:
            return self._generate_result(level, desc, 'PASS', f"New password must differ by {nodes[0].text} characters.", ">= 3.")
        elif nodes:
             return self._generate_result(level, desc, 'FAIL', f"New password must differ by {nodes[0].text} characters.", ">= 3.")
        else:
            return self._generate_result(level, desc, 'FAIL', "New password character difference is not set.", ">= 3.")

    def check_1_3_9(self):
        level = 'L1'
        desc = "1.3.9 Ensure 'Prevent Password Reuse Limit' is set to 24 or more passwords"
        nodes = self.tree.xpath("//password-complexity/password-history-count")
        if nodes and int(nodes[0].text) >= 24:
            return self._generate_result(level, desc, 'PASS', f"Password reuse limit is {nodes[0].text}.", ">= 24.")
        elif nodes:
             return self._generate_result(level, desc, 'FAIL', f"Password reuse limit is {nodes[0].text}.", ">= 24.")
        else:
            return self._generate_result(level, desc, 'FAIL', "Password reuse limit is not set.", ">= 24.")

    def check_1_3_10(self):
        level = 'L1'
        desc = "1.3.10 Ensure 'Password Profiles' do not exist"
        nodes = self.tree.xpath("//mgt-config/password-profile/entry")
        if nodes:
            profiles = [n.get('name') for n in nodes]
            return self._generate_result(level, desc, 'FAIL', f"Password profiles found: {', '.join(profiles)}", "No password profiles should exist.")
        else:
            return self._generate_result(level, desc, 'PASS', "No password profiles exist.", "No password profiles should exist.")

    def check_1_4_1(self):
        level = 'L1'
        desc = "1.4.1 Ensure 'Idle timeout' is less than or equal to 10 minutes for device management"
        nodes = self.tree.xpath("//setting/management/idle-timeout")
        if nodes and int(nodes[0].text) <= 10 and int(nodes[0].text) > 0:
            return self._generate_result(level, desc, 'PASS', f"Idle timeout is {nodes[0].text} minutes.", "<= 10 minutes.")
        elif nodes:
             return self._generate_result(level, desc, 'FAIL', f"Idle timeout is {nodes[0].text} minutes.", "<= 10 minutes.")
        else:
            return self._generate_result(level, desc, 'FAIL', "Idle timeout is not set.", "<= 10 minutes.")

    def check_1_4_2(self):
        level = 'L1'
        desc = "1.4.2 Ensure 'Failed Attempts' and 'Lockout Time' for Authentication Profile are properly configured"
        profiles = self.tree.xpath("//authentication-profile/entry")
        failures = []
        if not profiles:
            return self._generate_result(level, desc, 'PASS', "No authentication profiles found to check.", "Non-zero failed attempts and lockout time.")
        
        for profile in profiles:
            name = profile.get('name')
            failed_attempts = profile.find("./lockout/failed-attempts")
            lockout_time = profile.find("./lockout/lockout-time")
            if failed_attempts is None or int(failed_attempts.text) == 0:
                failures.append(f"Profile '{name}': Failed Attempts is not set or is 0.")
            if lockout_time is None or int(lockout_time.text) == 0:
                failures.append(f"Profile '{name}': Lockout Time is not set or is 0.")

        if failures:
            return self._generate_result(level, desc, 'FAIL', "\n".join(failures), "Non-zero failed attempts and lockout time for all profiles.")
        else:
            return self._generate_result(level, desc, 'PASS', "All authentication profiles have failed attempts and lockout time configured.", "Non-zero failed attempts and lockout time for all profiles.")

    def check_1_5_1(self):
        level = 'L1'
        desc = "1.5.1 Ensure 'V3' is selected for SNMP polling"
        nodes = self.tree.xpath("//snmp-setting/access-setting/version/v3")
        if nodes:
            return self._generate_result(level, desc, 'PASS', "SNMPv3 is configured.", "SNMPv3 should be configured.")
        else:
            return self._generate_result(level, desc, 'FAIL', "SNMPv3 is not configured.", "SNMPv3 should be configured.")

    def check_1_6_1(self):
        level = 'L1'
        desc = "1.6.1 Ensure 'Verify Update Server Identity' is enabled"
        nodes = self.tree.xpath("//deviceconfig/system/server-verification[text()='no']")
        if nodes:
            return self._generate_result(level, desc, 'FAIL', "Verify Update Server Identity is disabled.", "Should be enabled (or not present, which is default).")
        else:
            return self._generate_result(level, desc, 'PASS', "Verify Update Server Identity is enabled (default behavior).", "Should be enabled (or not present, which is default).")

    def check_1_6_2(self):
        level = 'L1'
        desc = "1.6.2 Ensure redundant NTP servers are configured appropriately"
        primary = self.tree.xpath("//ntp-servers/primary-ntp-server/ntp-server-address")
        secondary = self.tree.xpath("//ntp-servers/secondary-ntp-server/ntp-server-address")
        if primary and secondary:
            return self._generate_result(level, desc, 'PASS', f"Primary NTP: {primary[0].text}, Secondary NTP: {secondary[0].text}", "Both primary and secondary NTP servers configured.")
        else:
            failures = []
            if not primary: failures.append("Primary NTP server not configured.")
            if not secondary: failures.append("Secondary NTP server not configured.")
            return self._generate_result(level, desc, 'FAIL', " ".join(failures), "Both primary and secondary NTP servers configured.")

    def check_1_6_3(self):
        return self._generate_result('L2', "1.6.3 Ensure that the Certificate Securing Remote Access VPNs is Valid (Manual)", 'MANUAL REVIEW REQUIRED', "Verify the certificate for GlobalProtect Portals and Gateways is valid, from a trusted public CA, not expired, uses a key of 2048+ bits, and is signed with SHA-2 or better. Also check that minimum TLS version is 1.2.", "Manual verification.")

    def check_1_7_1(self):
        return self._generate_result('L2', "1.7.1 Enabling Post-Quantum (PQ) on IKEv2 VPNs (Manual)", 'MANUAL REVIEW REQUIRED', "For IKEv2 gateways, navigate to Advanced Options and ensure 'Enable Post-Quantum Pre-Shared Key (PPK)' is checked and configured appropriately.", "Manual verification.")
    
    def check_2_1(self):
        return self._generate_result('L2', "2.1 Ensure that IP addresses are mapped to usernames (Automated)", 'MANUAL REVIEW REQUIRED', "Review Monitor > Logs > Traffic logs. For traffic from trusted zones, verify that the 'Source User' column is populated with usernames, not just IP addresses.", "Manual verification.")

    def check_2_2(self):
        level = 'L2'
        desc = "2.2 Ensure that WMI probing is disabled"
        nodes = self.tree.xpath("//user-id-collector/setting/enable-probing[text()='yes']")
        if nodes:
            return self._generate_result(level, desc, 'FAIL', "WMI probing is enabled.", "WMI probing should be disabled.")
        else:
            return self._generate_result(level, desc, 'PASS', "WMI probing is disabled or not configured.", "WMI probing should be disabled.")

    def check_2_3(self):
        return self._generate_result('L1', "2.3 Ensure that User-ID is only enabled for internal trusted interfaces (Automated)", 'MANUAL REVIEW REQUIRED', "Navigate to Network > Zones. For each zone, check if 'Enable User Identification' is enabled. This should only be enabled for trusted, internal zones.", "Manual verification.")
    
    def check_2_4(self):
        level = 'L1'
        desc = "2.4 Ensure that 'Include/Exclude Networks' is used if User-ID is enabled"
        uid_enabled_on_zone = self.tree.xpath("//zone/entry/enable-user-identification[text()='yes']")
        include_exclude_configured = self.tree.xpath("//user-id-collector/include-exclude-network/entry")
        if uid_enabled_on_zone and not include_exclude_configured:
            return self._generate_result(level, desc, 'FAIL', "User-ID is enabled on at least one zone, but the Include/Exclude network list for User-ID is not configured.", "Include/Exclude list should be configured if User-ID is active.")
        else:
            return self._generate_result(level, desc, 'PASS', "User-ID Include/Exclude networks are configured, or User-ID is not enabled on any zone.", "Include/Exclude list should be configured if User-ID is active.")

    def check_2_5(self):
        return self._generate_result('L1', "2.5 Ensure that the User-ID Agent has minimal permissions if User-ID is enabled (Manual)", 'MANUAL REVIEW REQUIRED', "Verify in Active Directory that the User-ID service account only belongs to 'Event Log Readers', 'Distributed COM Users', and 'Domain Users' (for integrated agent) OR 'Event Log Readers', 'Server Operators', and 'Domain Users' (for Windows agent).", "Manual verification.")

    def check_2_6(self):
        return self._generate_result('L1', "2.6 Ensure that the User-ID service account does not have interactive logon rights (Automated)", 'MANUAL REVIEW REQUIRED', "This is an Active Directory setting and cannot be checked from the firewall configuration. Verify in Active Directory Group Policies that the User-ID service account is restricted from interactive logon.", "Manual verification.")
        
    def check_2_7(self):
        return self._generate_result('L1', "2.7 Ensure remote access capabilities for the User-ID service account are forbidden (Manual)", 'MANUAL REVIEW REQUIRED', "This check is manual. Verify in Active Directory and relevant remote access systems (VPN, Citrix, etc.) that the User-ID service account is not permitted to gain remote access.", "Manual verification.")

    def check_2_8(self):
        level = 'L1'
        desc = "2.8 Ensure that security policies restrict User-ID Agent traffic from crossing into untrusted zones"
        nodes = self.tree.xpath("//rulebase/security/rules/entry[application/member='msrpc' and action='deny']")
        if nodes:
            return self._generate_result(level, desc, 'PASS', f"Found {len(nodes)} security rule(s) denying 'msrpc'. Manual verification required to ensure they apply to untrusted zones.", "A security rule denying 'msrpc' to untrusted zones.")
        else:
            return self._generate_result(level, desc, 'MANUAL REVIEW REQUIRED', "No specific deny rule for 'msrpc' found. Please manually verify that policies prevent User-ID traffic to untrusted zones.", "A security rule denying 'msrpc' to untrusted zones.")

    def check_3_1(self):
        level = 'L1'
        desc = "3.1 Ensure a fully-synchronized High Availability peer is configured"
        ha_enabled = self.tree.xpath("//high-availability/enabled[text()='yes']")
        if not ha_enabled:
            return self._generate_result(level, desc, 'PASS', "High Availability is not enabled.", "N/A (HA not in use)")
        
        sync_enabled = self.tree.xpath("//high-availability/group/state-synchronization/enabled[text()='yes']")
        if sync_enabled:
            return self._generate_result(level, desc, 'PASS', "HA is enabled and session synchronization is enabled.", "Session synchronization should be enabled.")
        else:
            return self._generate_result(level, desc, 'FAIL', "HA is enabled but session synchronization is NOT enabled.", "Session synchronization should be enabled.")

    def check_3_2(self):
        level = 'L1'
        desc = "3.2 Ensure 'High Availability' requires Link Monitoring and/or Path Monitoring"
        ha_enabled = self.tree.xpath("//high-availability/enabled[text()='yes']")
        if not ha_enabled:
            return self._generate_result(level, desc, 'PASS', "High Availability is not enabled.", "N/A (HA not in use)")

        link_mon = self.tree.xpath("//high-availability/group/monitoring/link-monitoring/failure-condition[text()='any']")
        path_mon = self.tree.xpath("//high-availability/group/monitoring/path-monitoring/failure-condition[text()='any']")
        
        if link_mon or path_mon:
             return self._generate_result(level, desc, 'PASS', "Link or Path Monitoring is enabled with 'any' failure condition.", "Link and/or Path monitoring should be enabled.")
        else:
            return self._generate_result(level, desc, 'FAIL', "Neither Link Monitoring nor Path Monitoring is enabled with 'any' failure condition.", "Link and/or Path monitoring should be enabled.")

    def check_3_3(self):
        level = 'L1'
        desc = "3.3 Ensure 'Passive Link State' and 'Preemptive' are configured appropriately"
        ha_enabled = self.tree.xpath("//high-availability/enabled[text()='yes']")
        if not ha_enabled:
            return self._generate_result(level, desc, 'PASS', "High Availability is not enabled.", "N/A (HA not in use)")

        failures = []
        preemptive = self.tree.xpath("//high-availability/group/election-option/preemptive[text()='yes']")
        passive_link_state = self.tree.xpath("//high-availability/group/mode/active-passive/passive-link-state")

        if preemptive:
            failures.append("Preemptive mode is enabled.")
        if passive_link_state and passive_link_state[0].text != 'auto':
            failures.append(f"Passive Link State is set to '{passive_link_state[0].text}' instead of 'auto'.")

        if failures:
            return self._generate_result(level, desc, 'FAIL', " ".join(failures), "Preemptive disabled and Passive Link State set to 'auto'.")
        else:
            return self._generate_result(level, desc, 'PASS', "Preemptive is disabled and Passive Link State is 'auto'.", "Preemptive disabled and Passive Link State set to 'auto'.")

    def check_4_1(self):
        level = 'L1'
        desc = "4.1 Ensure 'Antivirus Update Schedule' is set to download and install updates hourly"
        nodes = self.tree.xpath("//update-schedule/anti-virus/recurring/hourly/action[text()='download-and-install']")
        if nodes:
            return self._generate_result(level, desc, 'PASS', "Antivirus updates are scheduled hourly to download and install.", "Hourly download and install.")
        else:
            return self._generate_result(level, desc, 'FAIL', "Antivirus updates are not scheduled hourly to download and install.", "Hourly download and install.")

    def check_4_2(self):
        level = 'L1'
        desc = "4.2 Ensure 'Applications and Threats Update Schedule' is set to daily or shorter"
        nodes = self.tree.xpath("//update-schedule/threats/recurring/*[self::daily or self::hourly or self::every-30-mins]/action[text()='download-and-install']")
        if nodes:
            return self._generate_result(level, desc, 'PASS', "Applications and Threats updates are scheduled for daily or shorter.", "Daily or shorter interval.")
        else:
            return self._generate_result(level, desc, 'FAIL', "Applications and Threats updates are not scheduled for daily or shorter.", "Daily or shorter interval.")

    def check_5_1(self):
        return self._generate_result('L1', "5.1 Ensure that WildFire file size upload limits are maximized (Automated)", 'MANUAL REVIEW REQUIRED', "Navigate to Device > Setup > WildFire and verify file size limits are at their maximums (e.g., pe: 50MB, pdf: 51200KB).", "Manual verification.")

    def check_5_2(self):
        return self._generate_result('L1', "5.2 Ensure a WildFire Analysis profile is enabled for all security policies (Automated)", 'MANUAL REVIEW REQUIRED', "For each Security Policy where the action is 'Allow', navigate to Actions > Profile Setting and ensure that a WildFire Analysis profile is set, either directly or via a Profile Group.", "Manual verification.")

    def check_5_3(self):
        level = 'L1'
        desc = "5.3 Ensure forwarding of decrypted content to WildFire is enabled"
        nodes = self.tree.xpath("//setting/ssl-decrypt/allow-forward-decrypted-content[text()='yes']")
        if nodes:
            return self._generate_result(level, desc, 'PASS', "Forwarding of decrypted content is enabled.", "Enabled.")
        else:
            return self._generate_result(level, desc, 'FAIL', "Forwarding of decrypted content is disabled.", "Enabled.")

    def check_5_4(self):
        level = 'L1'
        desc = "5.4 Ensure all WildFire session information settings are enabled"
        nodes = self.tree.xpath("//wildfire/session-info-select/*[text()='yes']")
        if nodes:
            excluded = [n.tag for n in nodes]
            return self._generate_result(level, desc, 'FAIL', f"The following session info fields are excluded: {', '.join(excluded)}", "All session information should be included (no 'yes' values in exclude-* fields).")
        else:
            return self._generate_result(level, desc, 'PASS', "All session information is included.", "All session information should be included.")

    def check_5_5(self):
        level = 'L1'
        desc = "5.5 Ensure alerts are enabled for malicious files detected by WildFire"
        nodes = self.tree.xpath("//log-settings/profiles/entry/match-list/entry[filter='(verdict neq benign)' and (send-snmptrap or send-syslog or send-email)]")
        if nodes:
            return self._generate_result(level, desc, 'PASS', "A log forwarding profile exists to send alerts for non-benign WildFire verdicts.", "Log forwarding profile for malicious verdicts should be configured.")
        else:
            return self._generate_result(level, desc, 'FAIL', "No log forwarding profile found to send alerts for non-benign WildFire verdicts.", "Log forwarding profile for malicious verdicts should be configured.")

    def check_5_6(self):
        level = 'L1'
        desc = "5.6 Ensure 'WildFire Update Schedule' is set to download and install updates in real-time"
        nodes = self.tree.xpath("//update-schedule/wildfire/recurring/real-time | //update-schedule/wildfire/recurring/realtime")
        if nodes:
            return self._generate_result(level, desc, 'PASS', "WildFire updates are set to real-time.", "Real-time updates.")
        else:
            return self._generate_result(level, desc, 'FAIL', "WildFire updates are not set to real-time.", "Real-time updates.")

    def check_5_7(self):
        return self._generate_result('L2', "5.7 Choosing Wildfire public cloud region (Manual)", 'MANUAL REVIEW REQUIRED', "Navigate to Device > Setup > WildFire > General Settings. Ensure the selected WildFire Public Cloud region complies with your organization's data residency and policy requirements.", "Manual verification.")

    def check_5_8(self):
        return self._generate_result('L1', "5.8 Ensure that 'Inline Cloud Analysis' on Wildfire profiles is enabled (Manual)", 'MANUAL REVIEW REQUIRED', "Navigate to Objects > Security Profiles > Wildfire. Verify that relevant profiles have 'Enable cloud inline analysis' checked and a rule to block PE files.", "Manual verification.")

    def check_6_1(self):
        level = 'L1'
        desc = "6.1 Ensure that antivirus profiles are set to reset-both on all decoders except 'imap' and 'pop3'"
        av_profiles = self.tree.xpath("//profiles/virus/entry")
        failures = []
        if not av_profiles:
            return self._generate_result(level, desc, 'FAIL', "No Antivirus profiles found.", "All Antivirus profiles should be configured securely.")
        for profile in av_profiles:
            name = profile.get('name')
            for decoder in ['ftp', 'http', 'smb', 'smtp']:
                action = profile.xpath(f"decoder/entry[@name='{decoder}']/action")
                if not action or action[0].text not in ['drop', 'reset-both']:
                    failures.append(f"Profile '{name}', decoder '{decoder}': action is not 'drop' or 'reset-both'.")
        if failures:
            return self._generate_result(level, desc, 'FAIL', "\n".join(failures), "Action 'reset-both' or 'drop' for all specified decoders.")
        else:
            return self._generate_result(level, desc, 'PASS', "All decoders in all AV profiles are set to 'drop' or 'reset-both'.", "Action 'reset-both' or 'drop' for all specified decoders.")

    def check_6_2(self):
        return self._generate_result('L1', "6.2 Ensure a secure antivirus profile is applied to all relevant security policies (Manual)", 'MANUAL REVIEW REQUIRED', "Review all security policies that could pass HTTP, SMTP, IMAP, POP3, FTP, or SMB traffic and ensure a secure antivirus profile is applied.", "Manual verification.")

    def check_6_3(self):
        level = 'L1'
        desc = "6.3 Ensure an anti-spyware profile is configured to block on specified spyware severity levels, categories, and threats"
        profiles = self.tree.xpath("//profiles/spyware/entry")
        failures = []
        if not profiles:
            return self._generate_result(level, desc, 'FAIL', "No Anti-spyware profiles found.", "Securely configured anti-spyware profiles should exist.")

        for profile in profiles:
            name = profile.get('name')
            rule = profile.xpath("rules/entry[severity/member='critical' and severity/member='high' and severity/member='medium' and (action/block-ip or action/drop or action/reset-both)]")
            if not rule:
                failures.append(f"Profile '{name}' does not have a rule to block critical, high, and medium severity threats.")
        
        if failures:
            return self._generate_result(level, desc, 'FAIL', "\n".join(failures), "A rule to block critical, high, and medium severity spyware.")
        else:
            return self._generate_result(level, desc, 'PASS', "All anti-spyware profiles have rules to block critical, high, and medium severity threats.", "A rule to block critical, high, and medium severity spyware.")

    def check_6_4(self):
        level = 'L1'
        desc = "6.4 Ensure DNS sinkholing is configured on all anti-spyware profiles in use"
        profiles = self.tree.xpath("//profiles/spyware/entry")
        failures = []
        if not profiles:
            return self._generate_result(level, desc, 'FAIL', "No Anti-spyware profiles found.", "DNS Sinkholing configured.")
            
        for profile in profiles:
            name = profile.get('name')
            sinkhole_action = profile.xpath("botnet-domains/lists/entry[@name='default-paloalto-dns']/action/sinkhole")
            sinkhole_ip = profile.xpath("botnet-domains/sinkhole/ipv4-address")
            if not sinkhole_action:
                failures.append(f"Profile '{name}': DNS sinkhole action not set for 'default-paloalto-dns' list.")
            if not sinkhole_ip:
                failures.append(f"Profile '{name}': Sinkhole IPv4 address is not configured.")
        
        if failures:
            return self._generate_result(level, desc, 'FAIL', "\n".join(failures), "DNS Sinkhole action and IP configured for all profiles.")
        else:
            return self._generate_result(level, desc, 'PASS', "DNS Sinkholing is configured for all anti-spyware profiles.", "DNS Sinkhole action and IP configured for all profiles.")

    def check_6_5(self):
        return self._generate_result('L1', "6.5 Ensure a secure anti-spyware profile is applied to all security policies permitting traffic to the Internet (Automated)", 'MANUAL REVIEW REQUIRED', "This check is complex. Manually verify that all security policies allowing traffic to an 'untrusted' zone have a secure Anti-Spyware profile applied.", "Manual Verification.")

    def check_6_6(self):
        return self._generate_result('L1', "6.6 Ensure a Vulnerability Protection Profile is set appropriately (Automated)", 'MANUAL REVIEW REQUIRED', "Verify Vulnerability Protection profiles block 'critical' and 'high' severity threats, and are set to 'default' for 'medium', 'low', and 'informational'.", "Manual Verification.")

    def check_6_7(self):
        return self._generate_result('L1', "6.7 Ensure a secure Vulnerability Protection Profile is applied to all security rules allowing traffic (Automated)", 'MANUAL REVIEW REQUIRED', "This check is complex. Manually verify that all 'allow' action security rules have a secure Vulnerability Protection profile applied.", "Manual Verification.")

    def check_6_8(self):
        level = 'L1'
        desc = "6.8 Ensure that PAN-DB URL Filtering is used"
        urldb = self.tree.xpath("/config/@urldb")
        if urldb and urldb[0] == 'paloaltonetworks':
            return self._generate_result(level, desc, 'PASS', "URL DB is 'paloaltonetworks'.", "'paloaltonetworks'")
        elif urldb:
            return self._generate_result(level, desc, 'FAIL', f"URL DB is '{urldb[0]}'.", "'paloaltonetworks'")
        else:
            return self._generate_result(level, desc, 'FAIL', "URL DB attribute not found.", "'paloaltonetworks'")
    
    def check_6_9(self):
        return self._generate_result('L1', "6.9 Ensure that URL Filtering uses the action of 'block' or 'override' on key URL categories (Automated)", 'MANUAL REVIEW REQUIRED', "Review URL Filtering profiles to ensure categories like 'adult', 'hacking', 'malware', 'phishing' are set to 'block' or 'override'.", "Manual Verification.")

    def check_6_10(self):
        level = 'L1'
        desc = "6.10 Ensure that access to every URL is logged"
        profiles = self.tree.xpath("//profiles/url-filtering/entry")
        failures = []
        for profile in profiles:
            if profile.xpath("allow"):
                failures.append(f"Profile '{profile.get('name')}' has categories with 'allow' action, which are not logged.")
        if failures:
            return self._generate_result(level, desc, 'FAIL', "\n".join(failures), "No URL categories should have the 'allow' action.")
        else:
            return self._generate_result(level, desc, 'PASS', "No URL Filtering profiles use the 'allow' action.", "No URL categories should have the 'allow' action.")

    def check_6_11(self):
        level = 'L1'
        desc = "6.11 Ensure all HTTP Header Logging options are enabled"
        profiles = self.tree.xpath("//profiles/url-filtering/entry")
        failures = []
        if not profiles:
            return self._generate_result(level, desc, 'PASS', "No URL filtering profiles to check.", "All options enabled.")

        for profile in profiles:
            name = profile.get('name')
            if profile.xpath("log-container-page-only[text()='yes']"):
                failures.append(f"Profile '{name}': 'Log container page only' is enabled.")
            if not profile.xpath("log-http-hdr-user-agent[text()='yes']"):
                failures.append(f"Profile '{name}': 'User-Agent' logging is disabled.")
            if not profile.xpath("log-http-hdr-referer[text()='yes']"):
                failures.append(f"Profile '{name}': 'Referer' logging is disabled.")
            if not profile.xpath("log-http-hdr-xff[text()='yes']"):
                failures.append(f"Profile '{name}': 'X-Forwarded-For' logging is disabled.")
        
        if failures:
            return self._generate_result(level, desc, 'FAIL', "\n".join(failures), "All HTTP header logging options enabled.")
        else:
            return self._generate_result(level, desc, 'PASS', "All HTTP header logging options are enabled in all profiles.", "All HTTP header logging options enabled.")

    def check_6_12(self):
        return self._generate_result('L1', "6.12 Ensure secure URL filtering is enabled for all security policies allowing traffic to the Internet (Automated)", "MANUAL REVIEW REQUIRED", "Manually verify that all security policies allowing traffic to an 'untrusted' or 'Internet' zone have a secure URL Filtering profile applied.", "Manual Verification")

    def check_6_13(self):
        return self._generate_result('L1', "6.13 Ensure alerting after a threshold of credit card or Social Security numbers is detected is enabled (Automated)", "MANUAL REVIEW REQUIRED", "Navigate to Objects > Security Profiles > Data Filtering. Verify a profile exists with an 'Alert Threshold' set for sensitive data patterns like credit card numbers.", "Manual Verification")

    def check_6_14(self):
        return self._generate_result('L1', "6.14 Ensure a secure Data Filtering profile is applied to all security policies allowing traffic to or from the Internet (Automated)", "MANUAL REVIEW REQUIRED", "Manually verify that all security policies allowing traffic to/from an 'untrusted' zone have a Data Filtering profile applied.", "Manual Verification")

    def check_6_15(self):
        level = 'L1'
        desc = "6.15 Ensure Zone Protection Profile with SYN Cookies is attached to all untrusted zones"
        nodes = self.tree.xpath("//profiles/zone-protection-profile/entry/flood/tcp-syn/syn-cookies")
        if nodes:
            return self._generate_result(level, desc, 'PASS', "At least one Zone Protection Profile is configured with SYN Cookies. Manually verify it is applied to all untrusted zones.", "SYN Cookies enabled on profiles for untrusted zones.")
        else:
            return self._generate_result(level, desc, 'FAIL', "No Zone Protection Profiles configured with SYN Cookies were found.", "SYN Cookies enabled on profiles for untrusted zones.")
            
    def check_6_16(self):
        level = 'L2'
        desc = "6.16 Ensure Zone Protection Profile with tuned Flood Protection is attached to untrusted zones"
        profiles = self.tree.xpath("//profiles/zone-protection-profile/entry")
        failures = []
        if not profiles:
             return self._generate_result(level, desc, 'MANUAL REVIEW REQUIRED', "No Zone Protection Profiles found. Manually verify flood protection for untrusted zones.", "Manual Verification")

        for profile in profiles:
            name = profile.get('name')
            if not profile.xpath("flood/icmp/enable[text()='yes']"):
                failures.append(f"Profile '{name}': ICMP flood protection is disabled.")
            if not profile.xpath("flood/udp/enable[text()='yes']"):
                failures.append(f"Profile '{name}': UDP flood protection is disabled.")
        
        if failures:
            return self._generate_result(level, desc, 'FAIL', "\n".join(failures) + "\nManually verify profiles are attached to untrusted zones.", "ICMP and UDP flood protection enabled.")
        else:
            return self._generate_result(level, desc, 'PASS', "All Zone Protection Profiles have ICMP and UDP flood protection enabled. Manually verify they are attached to untrusted zones.", "ICMP and UDP flood protection enabled.")
            
    def check_6_17(self):
        level = 'L1'
        desc = "6.17 Ensure all zones have Zone Protection Profiles with Reconnaissance Protection enabled"
        profiles = self.tree.xpath("//profiles/zone-protection-profile/entry")
        failures = []
        if not profiles:
            return self._generate_result(level, desc, 'FAIL', "No Zone Protection Profiles found.", "Reconnaissance Protection configured.")
        
        for profile in profiles:
            name = profile.get('name')
            if not profile.xpath("scan/entry/action"):
                failures.append(f"Profile '{name}' has no Reconnaissance Protection configured.")

        if failures:
            return self._generate_result(level, desc, 'FAIL', "\n".join(failures), "All profiles should have Reconnaissance Protection actions configured.")
        else:
            return self._generate_result(level, desc, 'PASS', "All Zone Protection Profiles have Reconnaissance Protection actions configured. Manually verify settings and zone attachment.", "All profiles should have Reconnaissance Protection actions configured.")

    def check_6_18(self):
        level = 'L1'
        desc = "6.18 Ensure all zones have Zone Protection Profiles that drop specially crafted packets"
        profiles = self.tree.xpath("//profiles/zone-protection-profile/entry")
        failures = []
        if not profiles:
            return self._generate_result(level, desc, 'FAIL', "No Zone Protection Profiles found.", "Packet Based Attack Protection enabled.")

        for profile in profiles:
            name = profile.get('name')
            if not profile.xpath("discard-ip-spoof[text()='yes']"): failures.append(f"Profile '{name}': 'Spoofed IP address' drop is disabled.")
            if not profile.xpath("discard-overlapping-tcp-segment-mismatch[text()='yes']"): failures.append(f"Profile '{name}': 'Mismatched overlapping TCP segment' drop is disabled.")
            if not profile.xpath("discard-strict-source-routing[text()='yes']"): failures.append(f"Profile '{name}': 'Strict Source Routing' drop is disabled.")
            if not profile.xpath("discard-loose-source-routing[text()='yes']"): failures.append(f"Profile '{name}': 'Loose Source Routing' drop is disabled.")
            if not profile.xpath("discard-malformed-option[text()='yes']"): failures.append(f"Profile '{name}': 'Malformed' option drop is disabled.")

        if failures:
            return self._generate_result(level, desc, 'FAIL', "\n".join(failures), "All specified packet-based drop options should be enabled.")
        else:
            return self._generate_result(level, desc, 'PASS', "All Zone Protection Profiles have the required packet-based drop options enabled. Manually verify zone attachment.", "All specified packet-based drop options should be enabled.")

    def check_6_19(self):
        return self._generate_result('L1', "6.19 Ensure that User Credential Submission uses the action of 'block' or 'continue' on the URL categories (Automated)", 'MANUAL REVIEW REQUIRED', "Navigate to Objects > Security Profiles > URL Filtering > Categories tab. Verify User Credential Submission action is 'block' or 'continue' for relevant categories.", "Manual Verification.")

    def check_6_20(self):
        return self._generate_result('L1', "6.20 Ensure that 'Wildfire Inline ML Action' on antivirus profiles are set to reset-both on all decoders except 'imap' and 'pop3' (Manual)", 'MANUAL REVIEW REQUIRED', "Navigate to Objects > Security Profiles > Antivirus. For each profile, under the Wildfire Inline ML tab, verify decoders (except imap/pop3) are set to 'reset-both'.", "Manual Verification.")

    def check_6_21(self):
        level = 'L1'
        desc = "6.21 Ensure that 'Wildfire Inline ML' on antivirus profiles are set to enable for all file types"
        profiles = self.tree.xpath("//profiles/virus/entry")
        failures = []
        if not profiles:
            return self._generate_result(level, desc, 'FAIL', "No antivirus profiles found.", "All file types enabled for Wildfire Inline ML.")
        
        for profile in profiles:
            name = profile.get('name')
            disabled_models = profile.xpath("mlav-engine-filebased-enabled/entry[mlav-policy-action='disable']")
            if disabled_models:
                models = [m.get('name') for m in disabled_models]
                failures.append(f"Profile '{name}': Wildfire Inline ML is disabled for: {', '.join(models)}")
        
        if failures:
            return self._generate_result(level, desc, 'FAIL', "\n".join(failures), "All file types enabled for Wildfire Inline ML.")
        else:
            return self._generate_result(level, desc, 'PASS', "All Wildfire Inline ML file types are enabled in all antivirus profiles.", "All file types enabled for Wildfire Inline ML.")

    def check_6_22(self):
        level = 'L1'
        desc = "6.22 Ensure that 'Inline Cloud Analysis' on Vulnerability Protection profiles are enabled"
        profiles = self.tree.xpath("//profiles/vulnerability/entry")
        failures = []
        if not profiles:
            return self._generate_result(level, desc, 'FAIL', "No Vulnerability Protection profiles found.", "Inline Cloud Analysis enabled.")

        for profile in profiles:
            name = profile.get('name')
            if not profile.xpath("mica-engine-vulnerability-enabled/entry[inline-policy-action='alert']"):
                 failures.append(f"Profile '{name}': No Inline Cloud Analysis rule is set to 'alert'.")

        if failures:
            return self._generate_result(level, desc, 'FAIL', "\n".join(failures), "Inline Cloud Analysis rule set to 'alert'.")
        else:
            return self._generate_result(level, desc, 'PASS', "All Vulnerability profiles have at least one Inline Cloud Analysis rule set to 'alert'.", "Inline Cloud Analysis rule set to 'alert'.")

    def check_6_23(self):
        level = 'L1'
        desc = "6.23 Ensure that 'Cloud Inline Categorization' on URL Filtering profiles are enabled"
        profiles = self.tree.xpath("//profiles/url-filtering/entry")
        failures = []
        if not profiles:
            return self._generate_result(level, desc, 'FAIL', "No URL Filtering profiles found.", "Cloud Inline Categorization enabled.")

        for profile in profiles:
            name = profile.get('name')
            if not profile.xpath("cloud-inline-cat[text()='yes']"):
                failures.append(f"Profile '{name}': Cloud Inline Categorization is not enabled.")
            # The PDF implies both should be enabled. The naming "Enable local..." suggests 'yes' is the correct state.
            if not profile.xpath("local-inline-cat[text()='yes']"):
                 failures.append(f"Profile '{name}': Local Inline Categorization is not enabled.")

        if failures:
            return self._generate_result(level, desc, 'FAIL', "\n".join(failures), "Cloud and Local Inline Categorization enabled.")
        else:
            return self._generate_result(level, desc, 'PASS', "Cloud and Local Inline Categorization is enabled on all URL Filtering profiles.", "Cloud and Local Inline Categorization enabled.")

    def check_6_24(self):
        return self._generate_result('L1', "6.24 Ensure that 'Inline Cloud Analysis' on Anti-Spyware profiles are enabled if 'Advanced Threat Prevention' is available (Manual)", "MANUAL REVIEW REQUIRED", "Navigate to Objects > Security Profiles > Anti-Spyware > Inline Cloud Analysis tab. Verify 'Enable cloud inline analysis' is checked and actions are set to 'reset-both'.", "Manual Verification.")

    def check_6_25(self):
        return self._generate_result('L1', "6.25 Ensure that 'DNS Policies' is configured on Anti-Spyware profiles if 'DNS Security' license is available (Manual)", "MANUAL REVIEW REQUIRED", "Navigate to Objects > Security Profiles > Anti-Spyware > DNS Policies tab. Verify policy action is 'sinkhole' for all DNS Security categories, and packet capture is 'extended-capture' for 'Command and Control'.", "Manual Verification.")

    def check_7_1(self):
        return self._generate_result('L2', "7.1 Ensure application security policies exist when allowing traffic from an untrusted zone to a more trusted zone (Automated)", 'MANUAL REVIEW REQUIRED', "Review security policies that allow traffic from an untrusted zone (e.g., 'Internet') to a trusted zone (e.g., 'Internal', 'DMZ'). Ensure that the 'application' is set to specific applications, not 'any'.", "Manual Verification.")

    def check_7_2(self):
        level = 'L1'
        desc = "7.2 Ensure 'Service setting of ANY' in a security policy allowing traffic does not exist"
        nodes = self.tree.xpath("//rulebase/security/rules/entry[action='allow' and service/member='any']")
        if nodes:
            failures = [f"Policy '{n.get('name')}' allows traffic with service 'any'." for n in nodes]
            return self._generate_result(level, desc, 'FAIL', "\n".join(failures), "No 'allow' rules should use service 'any'.")
        else:
            return self._generate_result(level, desc, 'PASS', "No 'allow' rules use service 'any'.", "No 'allow' rules should use service 'any'.")

    def check_7_3(self):
        level = 'L1'
        desc = "7.3 Ensure 'Security Policy' denying traffic to/from known malicious IPs Exists"
        # This is a simplified check. It looks for a deny rule that uses at least one of the known malicious lists.
        nodes = self.tree.xpath("//rulebase/security/rules/entry[action='deny' and (destination/member='Palo Alto Networks - Known malicious IP addresses' or source/member='Palo Alto Networks - Known malicious IP addresses')]")
        if nodes:
            return self._generate_result(level, desc, 'PASS', f"Found {len(nodes)} deny rule(s) referencing Palo Alto's malicious IP lists.", "At least one deny rule for malicious IPs.")
        else:
            return self._generate_result(level, desc, 'FAIL', "No deny rule found referencing 'Palo Alto Networks - Known malicious IP addresses'.", "At least one deny rule for malicious IPs.")
            
    def check_7_4(self):
        return self._generate_result('L1', "7.4 Ensure that logging is enabled on built-in default security policies (Manual)", 'MANUAL REVIEW REQUIRED', "Navigate to Policies > Security. For the default rules 'intrazone-default' and 'interzone-default', go to the Actions tab and verify that 'Log at Session End' is enabled.", "Manual verification.")

    def check_8_1(self):
        level = 'L1'
        desc = "8.1 Ensure 'SSL Forward Proxy Policy' for traffic destined to the Internet is configured"
        nodes = self.tree.xpath("//rulebase/decryption/rules/entry/type/ssl-forward-proxy")
        if nodes:
            return self._generate_result(level, desc, 'PASS', f"Found {len(nodes)} SSL Forward Proxy decryption rule(s).", "At least one SSL Forward Proxy rule should exist.")
        else:
            return self._generate_result(level, desc, 'FAIL', "No SSL Forward Proxy decryption rules found.", "At least one SSL Forward Proxy rule should exist.")
            
    def check_8_2(self):
        return self._generate_result('L1', "8.2 Ensure 'SSL Inbound Inspection' is required for all untrusted traffic destined for servers using SSL or TLS (Manual)", 'MANUAL REVIEW REQUIRED', "Navigate to Policies > Decryption. Verify that policies exist to perform 'SSL Inbound Inspection' on traffic from untrusted zones to internal servers that use SSL/TLS.", "Manual verification.")

    def check_8_3(self):
        return self._generate_result('L2', "8.3 Ensure that the Certificate used for Decryption is Trusted (Manual)", 'MANUAL REVIEW REQUIRED', "Navigate to Device > Certificate Management > Certificates. Verify that the certificate used for SSL Forward Proxy is a trusted CA certificate (either from an internal CA deployed to clients, or a public CA). Self-signed certificates that generate browser warnings should not be used.", "Manual verification.")

def print_report(results):
    """
    Prints the color-coded audit report to the console.
    """
    # This is a simple check to see if the script is running in a terminal that supports color.
    # It's not foolproof but covers many cases.
    is_a_tty = hasattr(sys.stdout, 'isatty') and sys.stdout.isatty()
    colors = {
        'PASS': Colors.OKGREEN if is_a_tty else '',
        'FAIL': Colors.FAIL if is_a_tty else '',
        'MANUAL REVIEW REQUIRED': Colors.WARNING if is_a_tty else '',
        'ERROR': Colors.FAIL if is_a_tty else '',
        'ENDC': Colors.ENDC if is_a_tty else '',
        'BOLD': Colors.BOLD if is_a_tty else ''
    }

    if not results:
        print("No audit results to display.")
        return

    print("="*80)
    print("Palo Alto Firewall Configuration Audit Report")
    print("="*80)

    for result in results:
        status_color = colors.get(result['status'], colors['ENDC'])

        print(f"\n[+] Control: {result['description']} (Level: {result['level']})")
        print(f"    Status: {status_color}{colors['BOLD']}{result['status']}{colors['ENDC']}")
        
        if result['status'] != 'MANUAL REVIEW REQUIRED':
            print(f"    Expected: {result['expected']}")
            print(f"    Current Value: \n---\n{result['output']}\n---")
        else:
            print(f"    Manual Check Required: {result['output']}")
        print("-"*80)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Audit a Palo Alto Firewall configuration file against the CIS v1.2.0 benchmark.')
    parser.add_argument('config_file', help='Path to the Palo Alto Firewall XML configuration file.')
    
    args = parser.parse_args()

    auditor = PaloAltoAuditor(args.config_file)
    audit_results = auditor.run_all_checks()
    
    if audit_results:
        print(f"Total controls processed: {len(audit_results)}")
        print_report(audit_results)


