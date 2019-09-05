#!/usr/bin/env python3
import os
import sys
import platform

from . import consts
from .modules import http, net, smtp
from .consts import ColorScheme as col

MODULES = {
    "http":     ["slowloris"],
    "net":      ["arpspoof", "pscan", "hosts"],
    "smtp":     ["smsbomb"]
}


HEADER = col.C + """
    .___         .___             .__         .__  __
  __| _/____   __| _/____________ |  |   ____ |__|/  |_
 / __ |/ __ \ / __ |/  ___/\____ \|  |  /  _ \|  \   __|
/ /_/ \  ___// /_/ |\___ \ |  |_> >  |_(  <_> )  ||  |
\____ |\___  >____ /____  >|   __/|____/\____/|__||__|
     \/    \/     \/    \/ |__|
\n""" + col.W


VERSION = col.LG + """\n
         [   Version: 3.0.0                     ]
         [   Modules: %s                         ]\n""" % len(MODULES) + col.W


HELP_OPTIONS = [
    ("help", "Display available commands and modules"),
    ("modules", "Show modules that can be used"),
    ("clear", "Move the screen up to clear it"),
    ("update", "Update dedsploit!"),
    ("exit", "Exit the program or current module"),
    ("use ...", "Select a module for use")
]



def get_key(value):
    """
    returns values from each sublist within a dict
    """
    return next(key for key, lst in MODULES.items() for item in lst if item == value)


def main():

    # check platform
    if platform.system() != "Linux":
        print(col.R + "[!] You are not using Linux! dedsploit may not work! [!]" + col.W)

    # print HEADER and info
    print(HEADER, VERSION)
    print(col.LC + "For available commands, type 'help'.\nFor available modules, enter 'modules'. Exit with Ctrl + C or 'exit'.\n")

    # input loop
    while True:
        options = input(col.LP + "[>>] " + col.W)

        if options == "help":
            print(col.LR + "\n[Commands Available:]\n" + col.LC)
            consts.print_command_help(HELP_OPTIONS)
            continue

        elif options == "modules":
            print(col.LR + "\n[There are currently " + col.LP + "{}".format(sum(len(lst) for lst in MODULES.values()))
                  + col.LR + " modules available:]\n" + col.LG)
            for protocol, module_list in MODULES.items():
                for mod in module_list:
                    print("{}\t\t({})\n".format(str(mod), str(protocol)))
            continue

        elif options.startswith("use"):

            # return a list of all concatenated sublists
            modname = options.split()[1]
            mod_list = [name for lst in MODULES.values() for name in lst]
            if modname in mod_list:
                print(col.LISTMSG)
                protocol = get_key(modname)
                if protocol == "http":
                    http.HTTP(modname).execute()
                elif protocol == "net":
                    net.Net(modname).execute()
                elif protocol == "smtp":
                    smtp.SMTP(modname).execute()
            else:
                print(col.WARNING)

        elif options == "clear":
            os.system("clear")
            continue

        elif options == "exit":
            break

        else:
            print(col.WARNING)
            continue


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print(col.LR + "\n[!] Goodbye! Remember to Hack the Gibson!" + col.W)
        exit()
    except IndexError:
        print(R + "[!] Module not found! [!]" + W)
