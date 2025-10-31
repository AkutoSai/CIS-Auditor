import re
import argparse

"""
Below list of controls are not included in the scan:
2.1.3 & 2.1.4 (Timezone/NTP)
2.1.6 (Latest Firmware)
2.4.1 (Remove Default Admin)
2.4.2 & 2.4.3 (Trusted Hosts & Admin Profiles)
2.4.6 (Apply Local-in Policies)
3.1 (Unused Policies)
3.3 (Deny Tor/Malicious IPs)
4.4.1 (Web Filtering Profile)
6.1.1 (Trusted VPN Certificate)
7.3.1 (Centralized Logging)
"""
# It is also recommended to double check all the results for false posivites and other values

# Execution: python CIS-FortigateFirewall-7.4-Checker.py <configfile.conf>

# Helper class for terminal colors
class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def parse_fortigate_config(config_text):
    """
    Parses the FortiGate configuration text into a nested dictionary.
    This is a simplified parser and might need to be made more robust
    for highly complex configurations.
    """
    config_dict = {}
    path_stack = [config_dict]
    
    # Pre-process to handle multi-line entries like banners
    config_text = re.sub(r'<<--_EOF_--\n(.*?)\n_EOF_--', r'"\1"', config_text, flags=re.DOTALL)

    for line in config_text.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue

        config_match = re.match(r'^\s*config\s+([^\s]+)\s*(.*)', line)
        if config_match:
            keys = config_match.group(1).split()
            if config_match.group(2):
                keys.extend(config_match.group(2).replace('"', '').split())
            
            current_level = path_stack[-1]
            for key in keys:
                # Handle cases like 'config firewall policy'
                key = key.strip('"')
                if key not in current_level:
                    current_level[key] = {}
                current_level = current_level[key]
            path_stack.append(current_level)
            continue

        edit_match = re.match(r'^\s*edit\s+("?)([^"\s]+)("?)', line)
        if edit_match:
            key = edit_match.group(2)
            current_level = path_stack[-1]
            if not isinstance(current_level, dict):
                 # If we are in a list context, pop back to the parent dict
                 path_stack.pop()
                 current_level = path_stack[-1]

            if key not in current_level:
                current_level[key] = {}
            path_stack.append(current_level[key])
            continue

        set_match = re.match(r'^\s*set\s+([^\s]+)\s+(.*)', line)
        if set_match:
            key, value = set_match.groups()
            value = value.strip().strip('"')
            path_stack[-1][key] = value
            continue

        if line.strip() in ['next', 'end']:
            if len(path_stack) > 1:
                path_stack.pop()

    return config_dict


def check_result(passed, control_id, description, details, status="AUTOMATED"):
    """Formats a check result dictionary."""
    return {
        "passed": passed,
        "control_id": control_id,
        "description": description,
        "details": details,
        "status": status
    }

# --- CIS Benchmark Audit Checks ---

def check_dns_configured(config):
    """1.1 Ensure DNS server is configured"""
    dns_config = config.get('system', {}).get('dns', {})
    primary = dns_config.get('primary')
    secondary = dns_config.get('secondary')
    if primary and secondary and primary != "0.0.0.0" and secondary != "0.0.0.0":
        return check_result(True, "1.1", "DNS servers are configured.", f"Primary: {primary}, Secondary: {secondary}")
    else:
        return check_result(False, "1.1", "DNS servers are not configured correctly.", f"Primary: {primary or 'Not set'}, Secondary: {secondary or 'Not set'}")

def check_intrazone_traffic(config):
    """1.2 Ensure intra-zone traffic is not always allowed (Manual but Automatable)"""
    zones = config.get('system', {}).get('zone', {})
    allowed_zones = []
    for zone_name, zone_config in zones.items():
        if zone_config.get('intrazone', 'deny') == 'allow':
            allowed_zones.append(zone_name)
    if not allowed_zones:
        return check_result(True, "1.2", "Intra-zone traffic is blocked by default on all zones.", "All zones are set to deny.", "MANUAL (SCRIPTED)")
    else:
        return check_result(False, "1.2", "Intra-zone traffic is allowed on one or more zones.", f"Allowed zones: {', '.join(allowed_zones)}", "MANUAL (SCRIPTED)")

def check_no_mgmt_on_wan(config):
    """1.3 Disable all management related services on WAN port (Manual but Automatable)"""
    interfaces = config.get('system', {}).get('interface', {})
    offending_interfaces = []
    mgmt_services = ['https', 'ping', 'ssh', 'snmp', 'http', 'telnet']
    for if_name, if_config in interfaces.items():
        if if_config.get('role') == 'wan':
            allowaccess = if_config.get('allowaccess', '')
            found_services = [s for s in mgmt_services if s in allowaccess]
            if found_services:
                offending_interfaces.append(f"{if_name} (allows {', '.join(found_services)})")
    
    if not offending_interfaces:
        return check_result(True, "1.3", "No management services detected on WAN interfaces.", "All WAN interfaces are secure.", "MANUAL (SCRIPTED)")
    else:
        return check_result(False, "1.3", "Management services detected on one or more WAN interfaces.", f"Offending interfaces: {', '.join(offending_interfaces)}", "MANUAL (SCRIPTED)")

def check_pre_login_banner(config):
    """2.1.1 Ensure 'Pre-Login Banner' is set"""
    global_config = config.get('system', {}).get('global', {})
    banner_status = global_config.get('pre-login-banner', 'disable')
    if banner_status == 'enable':
        return check_result(True, "2.1.1", "Pre-login banner is enabled.", "Status: enable")
    else:
        return check_result(False, "2.1.1", "Pre-login banner is disabled.", "Status: disable")

def check_post_login_banner(config):
    """2.1.2 Ensure 'Post-Login-Banner' is set"""
    global_config = config.get('system', {}).get('global', {})
    banner_status = global_config.get('post-login-banner', 'disable')
    if banner_status == 'enable':
        return check_result(True, "2.1.2", "Post-login banner is enabled.", "Status: enable")
    else:
        return check_result(False, "2.1.2", "Post-login banner is disabled.", "Status: disable")

def check_hostname_set(config):
    """2.1.5 Ensure hostname is set"""
    global_config = config.get('system', {}).get('global', {})
    hostname = global_config.get('hostname')
    default_hostnames = ["FortiGate", "fortinet"]
    if hostname and not any(default in hostname for default in default_hostnames):
        return check_result(True, "2.1.5", "A custom hostname is set.", f"Hostname: {hostname}")
    else:
        return check_result(False, "2.1.5", "Hostname is not set or is default.", f"Hostname: {hostname or 'Not set'}")

def check_usb_auto_install(config):
    """2.1.7 Disable USB Firmware and configuration installation (Manual but Automatable)"""
    auto_install = config.get('system', {}).get('auto-install', {})
    config_status = auto_install.get('auto-install-config', 'disable')
    image_status = auto_install.get('auto-install-image', 'disable')
    if config_status == 'disable' and image_status == 'disable':
        return check_result(True, "2.1.7", "USB auto-install for config and firmware is disabled.", "Both settings are disabled.", "MANUAL (SCRIPTED)")
    else:
        return check_result(False, "2.1.7", "USB auto-install for config or firmware is enabled.", f"Config: {config_status}, Image: {image_status}", "MANUAL (SCRIPTED)")

def check_tls_static_keys(config):
    """2.1.8 Disable static keys for TLS"""
    global_config = config.get('system', {}).get('global', {})
    status = global_config.get('ssl-static-key-ciphers', 'enable')
    if status == 'disable':
        return check_result(True, "2.1.8", "Static keys for TLS are disabled.", "Status: disable")
    else:
        return check_result(False, "2.1.8", "Static keys for TLS are enabled.", "Status: enable")

def check_strong_crypto(config):
    """2.1.9 Enable Global Strong Encryption"""
    global_config = config.get('system', {}).get('global', {})
    status = global_config.get('strong-crypto', 'disable')
    if status == 'enable':
        return check_result(True, "2.1.9", "Global strong encryption is enabled.", "Status: enable")
    else:
        return check_result(False, "2.1.9", "Global strong encryption is disabled.", "Status: disable")

def check_secure_gui_tls(config):
    """2.1.10 Ensure management GUI listens on secure TLS version (Manual but Automatable)"""
    global_config = config.get('system', {}).get('global', {})
    tls_versions = global_config.get('admin-https-ssl-versions', '')
    if 'tlsv1-3' in tls_versions and 'tlsv1-1' not in tls_versions and 'tlsv1-0' not in tls_versions:
         return check_result(True, "2.1.10", "Management GUI is using secure TLS versions.", f"Configured: {tls_versions}", "MANUAL (SCRIPTED)")
    else:
         return check_result(False, "2.1.10", "Management GUI is using insecure or outdated TLS versions.", f"Configured: {tls_versions}", "MANUAL (SCRIPTED)")

def check_cdn_enabled(config):
    """2.1.11 Ensure CDN is enabled for improved GUI performance (Manual but Automatable)"""
    global_config = config.get('system', {}).get('global', {})
    status = global_config.get('gui-cdn-usage', 'disable')
    if status == 'enable':
        return check_result(True, "2.1.11", "GUI CDN usage is enabled.", "Status: enable", "MANUAL (SCRIPTED)")
    else:
        return check_result(False, "2.1.11", "GUI CDN usage is disabled.", "Status: disable", "MANUAL (SCRIPTED)")

def check_single_cpu_log(config):
    """2.1.12 Ensure single CPU core overloaded event is logged (Manual but Automatable)"""
    global_config = config.get('system', {}).get('global', {})
    status = global_config.get('log-single-cpu-high', 'disable')
    if status == 'enable':
        return check_result(True, "2.1.12", "Logging for single high CPU core is enabled.", "Status: enable", "MANUAL (SCRIPTED)")
    else:
        return check_result(False, "2.1.12", "Logging for single high CPU core is disabled.", "Status: disable", "MANUAL (SCRIPTED)")
        
def check_hide_hostname_gui(config):
    """2.1.13 Ensure Hostname is Not Displayed On Login GUI (Manual but Automatable)"""
    global_config = config.get('system', {}).get('global', {})
    status = global_config.get('gui-display-hostname', 'enable')
    if status == 'disable':
        return check_result(True, "2.1.13", "Hostname is hidden on the login GUI.", "Status: disable", "MANUAL (SCRIPTED)")
    else:
        return check_result(False, "2.1.13", "Hostname is displayed on the login GUI.", "Status: enable", "MANUAL (SCRIPTED)")

def check_password_policy_enabled(config):
    """2.2.1 Ensure 'Password Policy' is enabled"""
    pw_policy = config.get('system', {}).get('password-policy', {})
    status = pw_policy.get('status', 'disable')
    if status == 'enable':
        return check_result(True, "2.2.1", "Password policy is enabled.", "Status: enable")
    else:
        return check_result(False, "2.2.1", "Password policy is disabled.", "Status: disable")

def check_admin_lockout(config):
    """2.2.2 Ensure administrator password retries and lockout time are configured"""
    global_config = config.get('system', {}).get('global', {})
    threshold = int(global_config.get('admin-lockout-threshold', 0))
    duration = int(global_config.get('admin-lockout-duration', 0))
    if 1 <= threshold <= 3 and duration >= 60:
        return check_result(True, "2.2.2", "Admin lockout is configured securely.", f"Threshold: {threshold}, Duration: {duration}s")
    else:
        details = f"Threshold: {threshold} (CIS recommends <= 3), Duration: {duration}s (CIS recommends >= 60)"
        return check_result(False, "2.2.2", "Admin lockout is not configured securely.", details)

def check_snmpv3_only(config):
    """2.3.1 Ensure only SNMPv3 is enabled"""
    snmp_community = config.get('system', {}).get('snmp', {}).get('community', {})
    snmp_user = config.get('system', {}).get('snmp', {}).get('user', {})
    if not snmp_community and snmp_user:
        return check_result(True, "2.3.1", "SNMP is configured for v3 only.", "No v1/v2c communities found.")
    elif not snmp_community and not snmp_user:
        return check_result(True, "2.3.1", "SNMP is disabled.", "No SNMP communities or users configured.")
    else:
        return check_result(False, "2.3.1", "Insecure SNMPv1/v2c community is configured.", f"Found {len(snmp_community)} communities.")

def check_snmp_trusted_hosts(config):
    """2.3.2 Allow only trusted hosts in SNMPv3 (Manual but Automatable)"""
    snmp_users = config.get('system', {}).get('snmp', {}).get('user', {})
    unrestricted_users = []
    for user, user_config in snmp_users.items():
        if not user_config.get('notify-hosts') or '0.0.0.0' in user_config.get('notify-hosts', ''):
            unrestricted_users.append(user)
    if not unrestricted_users:
        return check_result(True, "2.3.2", "All SNMPv3 users are restricted to trusted hosts.", "No unrestricted users found.", "MANUAL (SCRIPTED)")
    else:
        return check_result(False, "2.3.2", "One or more SNMPv3 users are not restricted to trusted hosts.", f"Unrestricted users: {', '.join(unrestricted_users)}", "MANUAL (SCRIPTED)")

def check_snmp_queries_disabled(config):
    """2.3.3 Disable SNMPv3 Query Per User (Manual but Automatable)"""
    snmp_users = config.get('system', {}).get('snmp', {}).get('user', {})
    query_enabled_users = []
    for user, user_config in snmp_users.items():
        if user_config.get('queries', 'disable') == 'enable':
            query_enabled_users.append(user)
    if not query_enabled_users:
        return check_result(True, "2.3.3", "SNMPv3 queries are disabled for all users.", "No users with queries enabled.", "MANUAL (SCRIPTED)")
    else:
        return check_result(False, "2.3.3", "SNMPv3 queries are enabled for one or more users.", f"Query-enabled users: {', '.join(query_enabled_users)}", "MANUAL (SCRIPTED)")

def check_snmp_memory_trap(config):
    """2.3.4 Enabling SNMP trap for memory usage (Manual but Automatable)"""
    snmp_sysinfo = config.get('system', {}).get('snmp', {}).get('sysinfo', {})
    mem_threshold = int(snmp_sysinfo.get('trap-free-memory-threshold', 0))
    if mem_threshold >= 20:
        return check_result(True, "2.3.4", "SNMP trap for memory usage is configured.", f"Threshold: {mem_threshold}% free memory.", "MANUAL (SCRIPTED)")
    else:
        return check_result(False, "2.3.4", "SNMP trap for memory usage is not configured or too low.", f"Threshold: {mem_threshold}% (CIS recommends >= 20%).", "MANUAL (SCRIPTED)")

def check_admin_idle_timeout(config):
    """2.4.4 Ensure Admin idle timeout time is configured"""
    global_config = config.get('system', {}).get('global', {})
    timeout = int(global_config.get('admintimeout', 0))
    if 1 <= timeout <= 15:
        return check_result(True, "2.4.4", "Admin idle timeout is configured securely.", f"Timeout: {timeout} minutes")
    else:
        details = f"Timeout: {timeout} minutes (CIS recommends <= 15)"
        return check_result(False, "2.4.4", "Admin idle timeout is not configured securely.", details)

def check_encrypted_access_only(config):
    """2.4.5 Ensure only encrypted access channels are enabled (Manual but Automatable)"""
    interfaces = config.get('system', {}).get('interface', {})
    offending_interfaces = []
    insecure_services = ['http', 'telnet']
    for if_name, if_config in interfaces.items():
        allowaccess = if_config.get('allowaccess', '')
        found_services = [s for s in insecure_services if s in allowaccess]
        if found_services:
            offending_interfaces.append(f"{if_name} (allows {', '.join(found_services)})")

    if not offending_interfaces:
        return check_result(True, "2.4.5", "Only encrypted management protocols (HTTPS, SSH) are enabled.", "No HTTP or Telnet found.", "MANUAL (SCRIPTED)")
    else:
        return check_result(False, "2.4.5", "Insecure management protocols (HTTP, Telnet) are enabled.", f"Offending interfaces: {', '.join(offending_interfaces)}", "MANUAL (SCRIPTED)")

def check_default_ports_changed(config):
    """2.4.7 Ensure default Admin ports are changed (Manual but Automatable)"""
    global_config = config.get('system', {}).get('global', {})
    http_port = global_config.get('admin-port', '80')
    https_port = global_config.get('admin-sport', '443')

    if http_port != '80' and https_port != '443':
        return check_result(True, "2.4.7", "Default admin ports have been changed.", f"HTTP Port: {http_port}, HTTPS Port: {https_port}", "MANUAL (SCRIPTED)")
    else:
        return check_result(False, "2.4.7", "Default admin ports are in use.", f"HTTP Port: {http_port}, HTTPS Port: {https_port}", "MANUAL (SCRIPTED)")
        
def check_virtual_patching(config):
    """2.4.8 Virtual patching on the local-in management interface (Manual but Automatable)"""
    local_in_policies = config.get('firewall', {}).get('local-in-policy', {})
    patched = False
    for _, policy in local_in_policies.items():
        if policy.get('virtual-patch') == 'enable':
            patched = True
            break
    if patched:
        return check_result(True, "2.4.8", "Virtual patching is enabled on at least one local-in policy.", "Status: Enabled", "MANUAL (SCRIPTED)")
    else:
        return check_result(False, "2.4.8", "Virtual patching is not enabled on any local-in policies.", "Status: Disabled", "MANUAL (SCRIPTED)")

def check_ha_enabled(config):
    """2.6.1 Ensure High Availability configuration is enabled"""
    ha_config = config.get('system', {}).get('ha', {})
    mode = ha_config.get('mode', 'standalone')
    if mode in ['a-a', 'a-p']:
        return check_result(True, "2.6.1", "High Availability (HA) is enabled.", f"Mode: {mode}")
    else:
        return check_result(False, "2.6.1", "High Availability (HA) is not enabled.", "Mode: standalone")

def check_ha_monitoring(config):
    """2.6.2 Ensure HA 'Monitor Interfaces' is enabled"""
    ha_config = config.get('system', {}).get('ha', {})
    monitored = ha_config.get('monitor')
    if monitored:
        return check_result(True, "2.6.2", "HA interface monitoring is enabled.", f"Monitoring: {monitored}")
    else:
        return check_result(False, "2.6.2", "HA interface monitoring is not configured.", "No interfaces are being monitored for failover.")

def check_ha_mgmt_interface(config):
    """2.6.3 Ensure HA Reserved Management Interface is configured (Manual but Automatable)"""
    ha_config = config.get('system', {}).get('ha', {})
    status = ha_config.get('ha-mgmt-status', 'disable')
    if status == 'enable' and ha_config.get('ha-mgmt-interfaces'):
        return check_result(True, "2.6.3", "HA reserved management interface is configured.", "Status: Enabled", "MANUAL (SCRIPTED)")
    else:
        return check_result(False, "2.6.3", "HA reserved management interface is not configured.", "Status: Disabled", "MANUAL (SCRIPTED)")

def check_ha_group_id(config):
    """2.6.4 Ensure High Availability Group-ID is configured (Manual but Automatable)"""
    ha_config = config.get('system', {}).get('ha', {})
    group_id = ha_config.get('group-id', '0')
    if group_id != '0':
        return check_result(True, "2.6.4", "HA Group-ID is not set to the default value.", f"Group ID: {group_id}", "MANUAL (SCRIPTED)")
    else:
        return check_result(False, "2.6.4", "HA Group-ID is set to the default of 0.", f"Group ID: {group_id}", "MANUAL (SCRIPTED)")

def check_no_all_service_in_policies(config):
    """3.2 Ensure that policies do not use 'ALL' as Service"""
    firewall_policies = config.get('firewall', {}).get('policy', {})
    offending_policies = []
    if not firewall_policies:
        return check_result(True, "3.2", "No firewall policies found.", "Skipping check.")
        
    for policy_id, policy_config in firewall_policies.items():
        if policy_config.get('action', 'accept') == 'accept':
            service = policy_config.get('service')
            if service and 'ALL' in service:
                offending_policies.append(policy_id)
            
    if not offending_policies:
        return check_result(True, "3.2", "No firewall policies use 'ALL' as a service.", "All policies use specific services.")
    else:
        details = f"Policies using 'ALL' service: {', '.join(offending_policies)}"
        return check_result(False, "3.2", "One or more firewall policies use the insecure 'ALL' service.", details)

def check_policy_logging(config):
    """3.4 Ensure logging is enabled on all firewall policies (Manual but Automatable)"""
    firewall_policies = config.get('firewall', {}).get('policy', {})
    unlogged_policies = []
    for policy_id, policy_config in firewall_policies.items():
        if policy_config.get('logtraffic', 'disable') == 'disable':
            unlogged_policies.append(policy_id)
    if not unlogged_policies:
        return check_result(True, "3.4", "Logging is enabled on all firewall policies.", "No unlogged policies found.", "MANUAL (SCRIPTED)")
    else:
        return check_result(False, "3.4", "Logging is disabled on one or more firewall policies.", f"Unlogged policies: {', '.join(unlogged_policies)}", "MANUAL (SCRIPTED)")

def check_botnet_ips(config):
    """4.1.1 Detect Botnet connections (Manual but Automatable)"""
    ips_sensors = config.get('ips', {}).get('sensor', {})
    botnet_blocked = False
    for _, sensor_config in ips_sensors.items():
        if sensor_config.get('scan-botnet-connections') == 'block':
            botnet_blocked = True
            break
    if botnet_blocked:
        return check_result(True, "4.1.1", "An IPS sensor with botnet connection blocking is configured.", "Status: Enabled", "MANUAL (SCRIPTED)")
    else:
        return check_result(False, "4.1.1", "No IPS sensor is configured to block botnet connections.", "Status: Disabled", "MANUAL (SCRIPTED)")
        
def check_ips_profile_on_policies(config):
    """4.1.2 Apply IPS Security Profile to Policies (Manual but Automatable)"""
    firewall_policies = config.get('firewall', {}).get('policy', {})
    policies_without_ips = []
    for policy_id, policy_config in firewall_policies.items():
         if policy_config.get('action', 'accept') == 'accept' and 'wan' in policy_config.get('dstintf', ''):
            if not policy_config.get('ips-sensor'):
                policies_without_ips.append(policy_id)
    if not policies_without_ips:
        return check_result(True, "4.1.2", "IPS profiles are applied to all relevant outbound policies.", "All policies checked.", "MANUAL (SCRIPTED)")
    else:
        return check_result(False, "4.1.2", "IPS profiles are missing from one or more outbound policies.", f"Policies without IPS: {', '.join(policies_without_ips)}", "MANUAL (SCRIPTED)")

def check_av_push_updates(config):
    """4.2.1 Ensure Antivirus Definition Push Updates are Configured (Manual but Automatable)"""
    autoupdate_schedule = config.get('system', {}).get('autoupdate', {}).get('schedule', {})
    # Default is enabled, so an empty config is a pass.
    if not autoupdate_schedule or autoupdate_schedule.get('status', 'enable') == 'enable':
        return check_result(True, "4.2.1", "AV Push Updates are enabled.", "Status: Enabled/Default.", "MANUAL (SCRIPTED)")
    else:
        return check_result(False, "4.2.1", "AV Push Updates are disabled.", "Status: Disabled.", "MANUAL (SCRIPTED)")

def check_av_profile_on_policies(config):
    """4.2.2 Apply Antivirus Security Profile to Policies (Manual but Automatable)"""
    firewall_policies = config.get('firewall', {}).get('policy', {})
    policies_without_av = []
    for policy_id, policy_config in firewall_policies.items():
        if policy_config.get('action', 'accept') == 'accept' and 'wan' in policy_config.get('dstintf', ''):
            if not policy_config.get('av-profile'):
                policies_without_av.append(policy_id)
    if not policies_without_av:
        return check_result(True, "4.2.2", "AV profiles are applied to all relevant outbound policies.", "All policies checked.", "MANUAL (SCRIPTED)")
    else:
        return check_result(False, "4.2.2", "AV profiles are missing from one or more outbound policies.", f"Policies without AV: {', '.join(policies_without_av)}", "MANUAL (SCRIPTED)")

def check_outbreak_prevention(config):
    """4.2.3 Enable Outbreak Prevention Database (Manual but Automatable)"""
    av_profiles = config.get('antivirus', {}).get('profile', {})
    enabled = False
    for _, profile_config in av_profiles.items():
        if profile_config.get('outbreak-prevention') == 'block':
            enabled = True
            break
    if enabled:
        return check_result(True, "4.2.3", "Outbreak Prevention is enabled in an AV profile.", "Status: Enabled", "MANUAL (SCRIPTED)")
    else:
        return check_result(False, "4.2.3", "Outbreak Prevention is not enabled in any AV profile.", "Status: Disabled", "MANUAL (SCRIPTED)")

def check_ai_malware_detection(config):
    """4.2.4 Enable AI/heuristic based malware detection"""
    av_settings = config.get('antivirus', {}).get('settings', {})
    status = av_settings.get('machine-learning-detection', 'disable')
    if status == 'enable':
        return check_result(True, "4.2.4", "AI/heuristic malware detection is enabled.", "Status: enable")
    else:
        return check_result(False, "4.2.4", "AI/heuristic malware detection is disabled.", "Status: disable")

def check_grayware_detection(config):
    """4.2.5 Enable grayware detection on antivirus"""
    av_settings = config.get('antivirus', {}).get('settings', {})
    status = av_settings.get('grayware', 'disable')
    if status == 'enable':
        return check_result(True, "4.2.5", "Grayware detection is enabled.", "Status: enable")
    else:
        return check_result(False, "4.2.5", "Grayware detection is disabled.", "Status: disable")
        
def check_sandbox_inline_scan(config):
    """4.2.6 Ensure inline scanning with FortiGuard AI-Based Sandbox Service is enabled (Manual but Automatable)"""
    fortiguard_settings = config.get('system', {}).get('fortiguard', {})
    if fortiguard_settings.get('sandbox-inline-scan') == 'enable':
        return check_result(True, "4.2.6", "FortiSandbox inline scan is enabled globally.", "Status: Enabled", "MANUAL (SCRIPTED)")
    else:
        return check_result(False, "4.2.6", "FortiSandbox inline scan is not enabled globally.", "Status: Disabled", "MANUAL (SCRIPTED)")
        
def check_app_control_non_default_ports(config):
    """4.5.2 Block applications running on non-default ports (Manual but Automatable)"""
    app_lists = config.get('application', {}).get('list', {})
    enforced = False
    for _, list_config in app_lists.items():
        if list_config.get('enforce-default-app-port') == 'enable':
            enforced = True
            break
    if enforced:
        return check_result(True, "4.5.2", "An application control profile blocks non-default ports.", "Status: Enabled", "MANUAL (SCRIPTED)")
    else:
        return check_result(False, "4.5.2", "No application control profile blocks non-default ports.", "Status: Disabled", "MANUAL (SCRIPTED)")
        
def check_compromised_host_quarantine(config):
    """5.1.1 Enable Compromised Host Quarantine (Manual but Automatable)"""
    stitches = config.get('system', {}).get('automation-stitch', {})
    enabled = False
    for _, stitch_config in stitches.items():
        if stitch_config.get('trigger') == '"Compromised Host - High"' and stitch_config.get('status') == 'enable':
            enabled = True
            break
    if enabled:
        return check_result(True, "5.1.1", "Compromised Host Quarantine automation is enabled.", "Status: Enabled", "MANUAL (SCRIPTED)")
    else:
        return check_result(False, "5.1.1", "Compromised Host Quarantine automation is disabled.", "Status: Disabled", "MANUAL (SCRIPTED)")

def check_security_fabric(config):
    """5.2.1.1 Ensure Security Fabric is Configured (Manual but Automatable)"""
    csf_config = config.get('system', {}).get('csf', {})
    if csf_config.get('status') == 'enable':
        return check_result(True, "5.2.1.1", "Security Fabric (CSF) is enabled.", "Status: Enabled", "MANUAL (SCRIPTED)")
    else:
        return check_result(False, "5.2.1.1", "Security Fabric (CSF) is disabled.", "Status: Disabled", "MANUAL (SCRIPTED)")

def check_secure_vpn_tls(config):
    """6.1.2 Enable Limited TLS Versions for SSL VPN (Manual but Automatable)"""
    vpn_settings = config.get('vpn', {}).get('ssl', {}).get('settings', {})
    min_ver = vpn_settings.get('ssl-min-proto-ver', 'tlsv1-1')
    if min_ver in ['tlsv1-2', 'tlsv1-3']:
        return check_result(True, "6.1.2", "SSL VPN is using secure TLS versions.", f"Min Version: {min_ver}", "MANUAL (SCRIPTED)")
    else:
        return check_result(False, "6.1.2", "SSL VPN allows insecure TLS versions.", f"Min Version: {min_ver}", "MANUAL (SCRIPTED)")

def check_event_logging(config):
    """7.1.1 Enable Event Logging"""
    eventfilter = config.get('log', {}).get('eventfilter', {})
    status = eventfilter.get('event', 'disable')
    if status == 'enable':
        return check_result(True, "7.1.1", "Event logging is enabled.", "Status: enable")
    else:
        return check_result(False, "7.1.1", "Event logging is disabled.", "Status: disable")

def check_encrypted_log_transmission(config):
    """7.2.1 Encrypt Log Transmission to FortiAnalyzer (Manual but Automatable)"""
    faz_settings = config.get('log', {}).get('fortianalyzer', {}).get('setting', {})
    enc_algo = faz_settings.get('enc-algorithm', 'default')
    if enc_algo == 'high':
        return check_result(True, "7.2.1", "Log transmission to FortiAnalyzer is encrypted.", f"Algorithm: {enc_algo}", "MANUAL (SCRIPTED)")
    else:
        return check_result(False, "7.2.1", "Log transmission to FortiAnalyzer is not using strong encryption.", f"Algorithm: {enc_algo}", "MANUAL (SCRIPTED)")


def run_audit(config_data):
    """Runs all audit checks against the parsed configuration."""
    parsed_config = parse_fortigate_config(config_data)
    
    checks = [
        # Section 1
        check_dns_configured,
        check_intrazone_traffic,
        check_no_mgmt_on_wan,
        # Section 2
        check_pre_login_banner,
        check_post_login_banner,
        check_hostname_set,
        check_usb_auto_install,
        check_tls_static_keys,
        check_strong_crypto,
        check_secure_gui_tls,
        check_cdn_enabled,
        check_single_cpu_log,
        check_hide_hostname_gui,
        check_password_policy_enabled,
        check_admin_lockout,
        check_snmpv3_only,
        check_snmp_trusted_hosts,
        check_snmp_queries_disabled,
        check_snmp_memory_trap,
        check_admin_idle_timeout,
        check_encrypted_access_only,
        check_default_ports_changed,
        check_virtual_patching,
        check_ha_enabled,
        check_ha_monitoring,
        check_ha_mgmt_interface,
        check_ha_group_id,
        # Section 3
        check_no_all_service_in_policies,
        check_policy_logging,
        # Section 4
        check_botnet_ips,
        check_ips_profile_on_policies,
        check_av_push_updates,
        check_av_profile_on_policies,
        check_outbreak_prevention,
        check_ai_malware_detection,
        check_grayware_detection,
        check_sandbox_inline_scan,
        check_app_control_non_default_ports,
        # Section 5
        check_compromised_host_quarantine,
        check_security_fabric,
        # Section 6
        check_secure_vpn_tls,
        # Section 7
        check_event_logging,
        check_encrypted_log_transmission,
    ]
    
    results = []
    for check_func in checks:
        try:
            results.append(check_func(parsed_config))
        except Exception as e:
            # Fallback for parsing errors on specific checks
            func_name = check_func.__name__
            control_id = func_name.split('_')[1] if '_' in func_name else "N/A"
            results.append(check_result(False, control_id, f"Error running check '{func_name}'.", f"Error: {e}", "ERROR"))

    return results

def print_report(results):
    """Prints the audit report to the console."""
    print(f"{bcolors.HEADER}{bcolors.BOLD}FortiGate CIS Benchmark Audit Report{bcolors.ENDC}")
    print("-" * 75)
    
    passed_count = sum(1 for r in results if r['passed'])
    failed_count = len(results) - passed_count
    
    for result in results:
        if result.get('status') == 'ERROR':
            status_color = bcolors.FAIL
            status_text = "ERROR"
        elif result['passed']:
            status_color = bcolors.OKGREEN
            status_text = "PASSED"
        else:
            status_color = bcolors.FAIL
            status_text = "FAILED"
            
        print(f"[{status_color}{status_text.ljust(6)}{bcolors.ENDC}] {bcolors.BOLD}Control {result['control_id'].ljust(7)}:{bcolors.ENDC} {result['description']}")
        print(f"          {bcolors.OKCYAN}Details:{bcolors.ENDC} {result['details']}")
        if result['status'] not in ["AUTOMATED", "ERROR"]:
            print(f"          {bcolors.WARNING}Type:     {result['status']}{bcolors.ENDC}")
        print()
        
    print("-" * 75)
    print(f"{bcolors.HEADER}Summary:{bcolors.ENDC}")
    print(f"  {bcolors.OKGREEN}Passed Checks: {passed_count}{bcolors.ENDC}")
    print(f"  {bcolors.FAIL}Failed Checks: {failed_count}{bcolors.ENDC}")
    print("-" * 75)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Audit a FortiGate configuration file against CIS Benchmarks.")
    parser.add_argument("config_file", help="Path to the FortiGate configuration file.")
    args = parser.parse_args()

    try:
        with open(args.config_file, 'r') as f:
            config_content = f.read()
        
        audit_results = run_audit(config_content)
        print_report(audit_results)

    except FileNotFoundError:
        print(f"{bcolors.FAIL}Error: The file '{args.config_file}' was not found.{bcolors.ENDC}")
    except Exception as e:
        print(f"{bcolors.FAIL}An unexpected error occurred: {e}{bcolors.ENDC}")

