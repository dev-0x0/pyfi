
import re
import os
import sys
import pickle
from time import sleep
from subprocess import PIPE, Popen


class Colour:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def horizontal_rule(n):
    print("-" * n)


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


def start_mon(iface):
    """
    Put wireless network interface into monitor mode
    """

    try:
        print(f"Putting {iface} into MONITOR mode: ", end="")

        # Ex: ip link set wlan0 down
        iface_down = Popen(['ip', 'link', 'set', str(iface), 'down'])
        sleep(2)
        # Ex: iw wlan0 set monitor control
        set_monitor_mode = Popen(['iw', str(iface), 'set', 'monitor', 'control'])
        sleep(2)
        # Ex: ip link set wlan0 up
        iface_up = Popen(['ip', 'link', 'set', str(iface), 'up'])
        sleep(2)
        
        iface_down.communicate()
        set_monitor_mode.communicate()
        iface_up.communicate()

        print(f"{Colour.OKGREEN}SUCCESS{Colour.ENDC}")

    except Exception as e:
        print(f"{Colour.WARNING}FAILED")
        print(f"[!] Error putting {iface} into MONITOR mode.{Colour.ENDC}")
        print(f"{Colour.FAIL}[!] {e}{Colour.ENDC}")
        print("[-] Exiting...")
        sys.exit(0)


def stop_mon(iface):
    """
    Put wireless network interface back into managed mode
    """
    try:
        print(f"Putting {iface} back into MANAGED mode: ", end="")
        os.system(f"ifconfig {iface} down")
        os.system(f"iw {iface} set type managed")
        os.system(f"ifconfig {iface} up")

        # reconnect to any wifi network
        os.system("service NetworkManager restart")
        print(f"{Colour.OKGREEN}SUCCESS{Colour.ENDC}")

    except Exception as e:
        print(f"{Colour.WARNING}FAILED")
        print(f"[!] Error putting {iface} into MANAGED mode.{Colour.ENDC}")
        print(f"{Colour.FAIL}[!] Error: {e}{Colour.ENDC}")
        sys.exit(0)


def compile_vendors():
    with open('vendors.pickle', 'rb') as f:
        # FORMAT -> {"XX:YY:ZZ": MANUFACTURER, "AA:BB:CC": MANUFACTURER, ... etc }
        vendors = pickle.load(f)

    return vendors


def print_headers(self):
    # Print column headings
    print(f"\n{Colour.HEADER}::ID\t%-20s\t%-20s\t::CHANNEL\t\t%-20s\n{Colour.ENDC}" % (
        "::SSID", "::BSSID", "::VENDOR"))
    horizontal_rule(100)


def choose_mode():
    print("1) Deauthenticate ALL clients from AP")
    print("2) Deauthenticate specific client from AP (sniff clients)")
    choice = input("[*] Enter choice: ")

    while choice not in ('1', '2'):
        print("[!] Please enter a valid choice\n")

    return choice
