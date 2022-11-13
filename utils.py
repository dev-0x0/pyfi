import re
import os
import sys
import pickle
import curses
import traceback
from time import sleep
from subprocess import PIPE, Popen, check_output


def choice_string():
    choice_str = '\n'
    choice_str += "1) Deauthenticate ALL clients from AP\n"
    choice_str += "2) Deauthenticate specific client from AP (sniff clients)\n"
    choice_str += "[*] Enter choice: "

    return choice_str


def horizontal_rule(n):
    return '\n' + '-' * n + '\n'


def self_mac(iface):
    """
    returns the mac address of your NIC or None
    *not currently needed*
    """
    ifconfig = Popen(['ifconfig'], stdout=PIPE)
    out = ifconfig.communicate()[0]
    out = out[out.find(iface):]
    pattern = r'(\w\w:?){6}'
    try:
        mac = re.search(pattern, out).group()
    except AttributeError:
        mac = "Unavailable"
    return mac


def get_mac(iface):
    """
    returns the mac address of your NIC or None
    *not currently needed*
    """
    # call ifconfig and parse the output to find our iface
    ifconfig = Popen(['ifconfig'], stdout=PIPE)
    out = ifconfig.communicate()[0]
    out = out[out.find(iface):]

    # regex pattern to match a MAC address
    pattern = r'ether ((\w\w:?){6})'
    try:
        mac = re.search(pattern, out).groups()[0]
    except AttributeError:
        mac = "Unavailable"

    return mac


services = ['NetworkManager', 'wpa_supplicant']


def start_mon(iface):
    """
    Put wireless network interface into monitor mode
    """

    try:
        # Need to kill any processes that my change channels or put interface back into MANAGED mode
        for service in services:
            if service_is_active(service):
                service_control('stop', service)

        # Ex: ip link set wlan0 down
        iface_down = Popen(['ip', 'link', 'set', iface, 'down'])
        sleep(2)
        # Ex: iw wlan0 set monitor control
        set_monitor_mode = Popen(['iw', iface, 'set', 'monitor', 'control'])
        sleep(2)
        # Ex: ip link set wlan0 up
        iface_up = Popen(['ip', 'link', 'set', iface, 'up'])
        sleep(2)

        iface_down.communicate()
        set_monitor_mode.communicate()
        iface_up.communicate()

        return True

    except Exception as e:
        log_error_to_file(traceback.format_exc())
        return False


def stop_mon(iface):
    """
    Put wireless network interface back into managed mode
    """
    try:
        os.system(f"ifconfig {iface} down")
        os.system(f"iw {iface} set type managed")
        os.system(f"ifconfig {iface} up")

        # Restart any stopped services
        for service in services:
            service_control('start', service)

        return True

    except Exception as e:
        log_error_to_file(traceback.format_exc())
        return False


def service_is_active(service):
    # Will exit with status zero if service is active, non-zero otherwise
    return check_output(['systemctl', 'is-active', '--quiet', service]) == 0


def service_control(action, service):
    Popen(['systemctl', action, service]).communicate()


def print_headers():
    # Column headings
    return "\n::ID\t%-20s\t%-20s\t::CHANNEL\t\t%-20s\n" % ("::SSID", "::BSSID", "::VENDOR")


def compile_vendors():
    with open('vendors.pickle', 'rb') as f:
        # FORMAT -> {"XX:YY:ZZ": MANUFACTURER, "AA:BB:CC": MANUFACTURER, ... etc }
        vendors = pickle.load(f)
    return vendors


def log_error_to_file(error):
    with open('log', 'w') as f:
        f.write(str(error) + '\n')
