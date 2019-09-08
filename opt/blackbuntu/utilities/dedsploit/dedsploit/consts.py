"""
consts.py

Defines global module-wide constants and helpers 
to be used during execution
"""

def print_command_help(command_help):
    """
    unpacks each list, and create a help menu
    """
    help_map = dict(command_help)
    for h in help_map:
        print("{0}\t\t\t{1}".format(h, help_map[h]))


class ColorScheme:
    W = '\033[0m'           # white (normal)
    R = '\033[31m'          # red
    G = '\033[32m'          # green
    O = '\033[33m'          # orange
    B = '\033[34m'          # blue
    P = '\033[35m'          # purple
    C = '\033[36m'          # cyan
    LR = '\033[1;31m'       # light red
    LG = '\033[1;32m'       # light green
    LO = '\033[1;33m'       # light orange
    LB = '\033[1;34m'       # light blue
    LP = '\033[1;35m'       # light purple
    LC = '\033[1;36m'       # light cyan

    WARNING = R + "Not recognized!" + W
    LISTMSG =  LC + "Type 'list' to show all of available attack vectors" + W
