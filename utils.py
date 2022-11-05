
import re
import os
import sys
import pickle
import curses
import traceback
from time import sleep
from subprocess import PIPE, Popen, check_output

# class Colour:
#     HEADER = '\033[95m'
#     OKBLUE = '\033[94m'
#     OKGREEN = '\033[92m'
#     WARNING = '\033[93m'
#     FAIL = '\033[91m'
#     ENDC = '\033[0m'
#     BOLD = '\033[1m'
#     UNDERLINE = '\033[4m'


class Utils:

    def __init__(self, iface, stdscr, window):
        
        self.iface = str(iface)
        self.stdscr = stdscr
        self.window = window
        self.services = ['NetworkManager', 'wpa_supplicant']


    def horizontal_rule(self, n):
        self.window.addstr("-" * n)
        self.window.addstr("\n")
        self.window.noutrefresh()
        curses.doupdate()


    def self_mac(self):
        """
        returns the mac address of your NIC or None
        *not currently needed*
        """
        ifconfig = Popen(['ifconfig'], stdout=PIPE)
        out = ifconfig.communicate()[0]
        out = out[out.find(self.iface):]
        pattern = r'(\w\w:?){6}'
        try:
            mac = re.search(pattern, out).group()
        except AttributeError:
            mac = "Unavailable"
        return mac


    def get_mac(self):
        """
        returns the mac address of your NIC or None
        *not currently needed*
        """
        # call ifconfig and parse the output to find our iface
        ifconfig = Popen(['ifconfig'], stdout=PIPE)
        out = ifconfig.communicate()[0]
        out = out[out.find(self.iface):]

        # regex pattern to match a MAC address
        pattern = r'ether ((\w\w:?){6})'
        try:
            mac = re.search(pattern, out).groups()[0]
        except AttributeError:
            mac = "Unavailable"

        return mac


    def service_is_active(self, service):
        # Will exit with status zero if service is active, non-zero otherwise
        return check_output(['systemctl', 'is-active', '--quiet', service]) == 0


    def service_control(self, action, service):
        Popen(['systemctl', action, service]).communicate()
        self.window.addstr(f"[+] {action}: {service}\n", curses.A_NORMAL)


    def start_mon(self):
        """
        Put wireless network interface into monitor mode
        """

        try:
            self.window.addstr(1, 1, f"[+] Putting {self.iface} into MONITOR mode\n", curses.color_pair(227))
            self.window.noutrefresh()
            curses.doupdate()

            # Need to kill any processes that my change channels or put interface back into MANAGED mode
            for service in self.services:
                if self.service_is_active(service):
                    self.debug(f"{service} is active")
                    self.service_control('stop', service)

            # Ex: ip link set wlan0 down
            iface_down = Popen(['ip', 'link', 'set', self.iface, 'down'])
            sleep(2)
            # Ex: iw wlan0 set monitor control
            set_monitor_mode = Popen(['iw', self.iface, 'set', 'monitor', 'control'])
            sleep(2)
            # Ex: ip link set wlan0 up
            iface_up = Popen(['ip', 'link', 'set', self.iface, 'up'])
            sleep(2)
            
            iface_down.communicate()
            set_monitor_mode.communicate()
            iface_up.communicate()

        except Exception as e:
            self.window.addstr(f"[+] Error start_mon: {e}\n", curses.A_NORMAL)
            Utils.log_error_to_file(traceback.format_exc())


    def stop_mon(self):
        """
        Put wireless network interface back into managed mode
        """
        try:
            self.window.erase()
            self.window.addstr(f"[+] Putting {self.iface} back into MANAGED mode\n", curses.color_pair(227))
            self.window.noutrefresh()
            curses.doupdate()

            os.system(f"ifconfig {self.iface} down")
            os.system(f"iw {self.iface} set type managed")
            os.system(f"ifconfig {self.iface} up")

            # Restart any stopped services
            for service in self.services:
                self.service_control('start', service)

        except Exception as e:
            Utils.log_error_to_file(traceback.format_exc())


    def print_headers(self):
        # Print column headings
        self.window.addstr("\n::ID\t%-20s\t%-20s\t::CHANNEL\t\t%-20s\n" % ("::SSID", "::BSSID", "::VENDOR"), curses.A_NORMAL)
        self.window.noutrefresh()
        curses.doupdate()
        self.horizontal_rule(100)

 
    def choose_mode(self):
        print('\n')
        print("1) Deauthenticate ALL clients from AP")
        print("2) Deauthenticate specific client from AP (sniff clients)\n")
        choice = input("[*] Enter choice: ")

        while choice not in ('1', '2'):
            print("[!] Please enter a valid choice\n")

        return choice


    def debug(self, msg):
        self.window.addstr(10, 2, f"{msg}", curses.A_NORMAL)

    @staticmethod
    def compile_vendors():
        with open('vendors.pickle', 'rb') as f:
            # FORMAT -> {"XX:YY:ZZ": MANUFACTURER, "AA:BB:CC": MANUFACTURER, ... etc }
            vendors = pickle.load(f)
        return vendors

    @staticmethod
    def log_error_to_file(error):
        with open('log', 'w') as f:
            f.write(str(error) + '\n')

