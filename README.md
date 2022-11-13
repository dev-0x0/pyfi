# PyFi

**Read disclaimer and warnings below before using this tool**

Default operation:
- Enumerates local wireless access points and sniffs for connected clients on all channels
- Selects most powerful wireless interface if one is not specified

Additional options:
- Allow for deauthentication of clients from a specified wireless access point
- This portion of the project is a proof-of-concept for demonstrating the vulnerability of some wireless networks 
- It is for educational purposes only, in order to learn about
WiFi vulnerabilites, and steps sometimes taken by malicious actors when performing certain types of attacks(e.g.
MITM)
- Read the disclaimer below before using this tool

### Technologies used:

- Python3
    - curses module (built in module) for terminal UI
    - scapy module for packet capture, analysis and forging
    - Makes use of a custom class which implements a list that triggers actions when items are added or removed
  
### TODO:
- Source most up-to-date vendor database. Find a way to keep it updated
- Incorporate all argparse parsed arguments from utils.py
- Fix bug when quitting during sniffing phase
- Add colours to UI

### DISCLAIMER:

1. This is a project I have created for educational, research and proof-of-concept purposes only.
The author does not condone or encourage malicious use of this tool.
Do not use this tool to influence any wireless networks or devices that you do not own.
You are responsible for being sure that your actions are not breaking the law in your jurisdiction.

2. Do not use this tool if you do not fully understand what it does.

3. The performance of this tool relies on your hardware. 
Some network cards or setups may not work, or may produce unexpected behaviour.


