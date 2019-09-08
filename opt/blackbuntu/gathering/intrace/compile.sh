#!/bin/bash
#
# [Package]: Intrace
# [Release]: Blackbuntu Revive v1.0.1 Alpha
# [Website]: https://blackbuntu.org
# [Version]: Revive v1.0.1 Alpha
# [License]: http://www.gnu.org/licenses/gpl-3.0.html
# 
# Ascii Art : https://www.askapache.com/online-tools/figlet-ascii/

## ----------------- ##
## Define Parameters ##
## ----------------- ##

## Colour output
## -------------
TEXT_ERROR="\033[01;31m"	# Issues/Errors
TEXT_VALID="\033[01;32m"	# Success
TEXT_ALERT="\033[01;33m"	# Warnings/Information
TEXT_TITLE="\033[01;34m"	# Heading
TEXT_RESET="\033[00m"		# Normal

## ---------------- ##
## Define Functions ##
## ---------------- ##

## Display Header
## --------------
function set_banner
{
	clear
	echo -e "${TEXT_ERROR}   _     _            _    _                 _           ${TEXT_RESET}"
	echo -e "${TEXT_ERROR}  | |   | |          | |  | |               | |          ${TEXT_RESET}"
	echo -e "${TEXT_ERROR}  | |__ | | __ _  ___| | _| |__  _   _ _ __ | |_ _   _   ${TEXT_RESET}"
	echo -e "${TEXT_ERROR}  | '_ \| |/ _' |/ __| |/ / '_ \| | | | '_ \| __| | | |  ${TEXT_RESET}"
	echo -e "${TEXT_ERROR}  | |_) | | (_| | (__|   <| |_) | |_| | | | | |_| |_| |  ${TEXT_RESET}"
	echo -e "${TEXT_ERROR}  |_'__/|_|\__'_|\___|_|\_\_'__/ \__'_|_| |_|\__|\__'_|  ${TEXT_RESET}"
	echo -e "${TEXT_ERROR}                                                         ${TEXT_RESET}"
	echo -e "${TEXT_ERROR}                                      Blackbuntu v1.0.1  ${TEXT_RESET}"         
	echo
	echo -e "${TEXT_VALID} [i] [Package]: intrace${TEXT_RESET}"
	echo -e "${TEXT_VALID} [i] [Website]: https://blackbuntu.org${TEXT_RESET}"

  	echo
  	sleep 3s
}

## Check if provided username exist
## --------------------------------
function check_username
{
	if id "$1" >/dev/null 2>&1; then
	    sleep 1s
	else
		cd /tmp/
		echo
		echo -e " ${TEXT_ERROR}[!]${TEXT_RESET} The username $USERNAME has not been found in the system${TEXT_RESET}"
		echo -e " ${TEXT_ERROR}[!]${TEXT_RESET} Quitting ...${TEXT_RESET}"
		echo -e "\n"
		exit 1
	fi
}

## Check Internet status
## ---------------------
function check_internet
{
	for i in {1..10};
	do 
		ping -c 1 -W ${i} www.google.com &>/dev/null && break; 
	done
	
	if [[ "$?" -ne 0 ]]; 
	then
		cd /tmp/
		echo
		echo -e " ${TEXT_ERROR}[!]${TEXT_RESET} An unknown error occured ~ Possible DNS issues or no Internet connection${TEXT_RESET}"
		echo -e " ${TEXT_ERROR}[!]${TEXT_RESET} Quitting ..."
		echo -e "\n"
		exit 1
	fi
}

## ------------ ##
## Start Script ##
## ------------ ##

## Prompt for SUDO Password
## ------------------------
clear
sudo -v

## Display Header
## --------------
set_banner

## Prompt User for Confirmation
## ----------------------------
echo -e " Intrace is not yet compiled."
read -p " Do you want to compile it now [Y/n] ? " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]
then
	echo
	read -p " Please enter your username : " USERNAME
	check_username $USERNAME
	check_internet

	echo -e " Please wait while compiling Intrace ...${TEXT_RESET}"
	sleep 5s

	sudo rm -f /usr/bin/intrace
	cd /opt/blackbuntu/gathering/intrace/
	sudo make >/dev/null 2>&1
	sudo ln -s /opt/blackbuntu/gathering/intrace/intrace /usr/bin/intrace
	cd /tmp/

	echo
	echo -e " ${TEXT_VALID}[i]${TEXT_RESET} Intrace has been compiled successfully${TEXT_RESET}"
	echo -e " ${TEXT_VALID}[i]${TEXT_RESET} Close this terminal windows and re-open Intrace"
	echo -e "\n"
else
	echo
	echo -e " ${TEXT_ERROR}[!]${TEXT_RESET} Operation aborted by user${TEXT_RESET}"
	echo -e " ${TEXT_ERROR}[!]${TEXT_RESET} Quitting ..."
	echo -e "\n"
	exit 1
fi
