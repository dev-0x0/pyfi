import re
import os
import sys
import pickle
import curses
import argparse
import traceback
from time import sleep
from subprocess import PIPE, Popen, check_output


def parse_args():
    # Define arguments
    parser = argparse.ArgumentParser()

    parser.add_argument("-i",
                        "--interface",
                        help="Specify wireless interface. Example: -i wlan0")

    # parser.add_argument("-c",
    #                     "--channel",
    #                     help="Specify channel. Example: -c 1")

    parser.add_argument("-d",
                        "--delay",
                        dest="delay",
                        default=0.1,
                        help="Specify delay between sending packets.")

    parser.add_argument("-p",
                        "--packets",
                        dest="packets",
                        default=1,
                        help="Specify number of packets to send to each device. Defaults to 1. Example: -p 2")

    parser.add_argument("--targeted",
                        dest="targeted",
                        default=False,
                        action='store_true',
                        help="Program will prompt to select a target for deauthentication. \
                        Default is no enumeration of APs only, no deauth.")

    return parser.parse_args()


def get_wlan_interface():
    try:
        proc = Popen(['iwconfig'], stdout=PIPE, stderr=PIPE)
        output = [line.decode() for line in proc.communicate()]
        interfaces = [line.split(' ', 1)[0] for line in output if 'IEEE 802.11' in line]
        log_error_to_file('\n'.join(interfaces))

        if len(interfaces) == 0:
            print("[!] Error: No Wireless interfaces found.")
            sys.exit(0)

        if len(interfaces) == 1:
            return interfaces[0]

        # Find best interface
        return get_best_iface(interfaces)

    except OSError as e:
        print(f"[!] Error running 'iwconfig'\n{e}")
        log_error_to_file(traceback.format_exc())


def get_best_iface(interfaces):
    """
    Find most powerful interface
    """
    scans = dict()
    for iface in interfaces:
        scans[iface] = 0
        try:
            proc = Popen(['iwlist', iface, 'scan'], stdout=PIPE, stderr=PIPE)
            output = [line.decode() for line in proc.communicate()]

            if 'No scan results' in output[0]:
                continue

            for line in output:
                if 'Address: ' in line:
                    scans[iface] += 1

        except OSError as e:
            print(f"[!] Error scanning interface {iface}")
            log_error_to_file(traceback.format_exc())
            sys.exit(0)

    if sum(scans.values()) == 0:
        print("[!] Error: No APs detected on any interface")
        sys.exit(0)

    # Return the iface with the most APs detected
    return max(scans, key=scans.get)


def start_curses():
    # Setup curses
    screen = curses.initscr()
    curses.noecho()
    curses.cbreak()
    curses.curs_set(0)
    screen.keypad(True)

    # Use all the colours!
    # https://stackoverflow.com/questions/18551558/how-to-use-terminal-color-palette-with-curses
    curses.start_color()
    curses.use_default_colors()
    for i in range(0, curses.COLORS):
        curses.init_pair(i + 1, i, -1)

    HEIGHT, WIDTH = screen.getmaxyx()

    window = curses.newwin(HEIGHT - 2, WIDTH - 2, 1, 1)
    # window.border('|', '|', '-', '-', '+', '+', '+', '+')

    screen.noutrefresh()
    window.noutrefresh()
    curses.doupdate()

    return screen, window


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

        procs = [
            Popen(['ip', 'link', 'set', iface, 'down']),
            Popen(['iw', iface, 'set', 'monitor', 'control']),
            Popen(['ip', 'link', 'set', iface, 'up'])]

        for p in procs:
            p.communicate()

    except Exception as e:
        log_error_to_file(traceback.format_exc())
        return False


def stop_mon(iface):
    """
    Put wireless network interface back into managed mode
    """
    try:
        procs = [
            Popen(['ip', 'link', 'set', iface, 'down']),
            Popen(['iw', iface, 'set', 'type', 'managed']),
            Popen(['ip', 'link', 'set', iface, 'up'])]

        for p in procs:
            p.communicate()

        # Restart any stopped services
        for service in services:
            service_control('start', service)

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
    return "\n::ID\t%-20s\t%-20s\t::CHANNEL\t::VENDOR\n" % ("::SSID", "::BSSID")


def choice_string():
    choice_str = '\n'
    choice_str += "1) Deauthenticate ALL clients from AP\n"
    choice_str += "2) Deauthenticate specific client from AP (sniff clients)\n"
    choice_str += "[*] Enter choice: "

    return choice_str


def compile_vendors():
    with open('vendors.pickle', 'rb') as f:
        # FORMAT -> {"XX:YY:ZZ": MANUFACTURER, "AA:BB:CC": MANUFACTURER, ... etc }
        vendors = pickle.load(f)
    return vendors


def log_error_to_file(error):
    with open('log', 'w') as f:
        f.write(str(error) + '\n')
