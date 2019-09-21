#!/bin/bash
rm -f release/release.md >/dev/null 2>&1
echo 'Distributor ID: BlackBuntu' | tee -a release/release.md >/dev/null 2>&1
echo 'Description: Blackbuntu Revive v1.0.1 Alpha' | tee -a release/release.md >/dev/null 2>&1
echo 'Release: 1.0.1' | tee -a release/release.md >/dev/null 2>&1
echo 'Codename: revive' | tee -a release/release.md >/dev/null 2>&1
echo 'Build: 20190922' | tee -a release/release.md >/dev/null 2>&1

TOOLS=( acccheck aircrack-ng airsnort androguard anonsurf apache2 apktool arachni ardt-ddos arduino armitage arp-scan atom automater autopsy backdoor-factory bed beef-project bing-ip2hosts binwalk blackeye blue-eye blueranger braa brutespray burpsuite cewl cherrytree chntpw cisco-exploiter cmospwd cmsmap coldwar commix cookie-cadger cowpatty crackle crackmapexec credcrack creddump credsniper crowbar crunch cryptcat cymothoa dc3dd ddrescue deblaze det-toolkit dex2jar dhcpig dirb dirbuster dmitry dnmap dns-inject dns-reverser dns2tcp dnschef dnsenum dnsftp dnsrecon dnstracer dnswalk doona dos2unix dotdotpwn dracnmap droopescan dsniff dumpzilla eapmd5pass edb-debugger empire enum4linux enumiax ettercap-graphical exe2hex extundelete fierce fimap finmyhash fluxion foremost funkload galleta getsploit ghost-eye gnmap golismero goofile gpp-decrypt grabber guymager hammer hashcat hashid hashtag hostapd hping3 httptunnel httrack hurl hydra i2p iaxflood inguma inspy intersect intrace ip-sorter ipcalc ipscan isc-dhcp-server ismtp iwebaudit java javasnoop jexboss john joomscan jsql-injection keepnote kismet knockpy lans-toolkit ldap-utils lfi-freak lft libenom linenum linux-xsuggest lnav load-balancing-detector lynis macchanger magictree maltego masscan mdk3 medusa metagoofil metasploit miranda mitm-dump mitm-framework mitm-proxy mitm-web morpheus msfpc nbtscan ncrack net-creds netcat netwox nfs-common nikto nishang nmap ntopng nullinux ohrwurm openconnect openssh-server openvpn ophcrack oscanner p0f patator pdf-parser pdfid pdgmail peepdf pipal pixiewps plecost pocsuite powersploit proxychains ptunnel pwnat pyrit radare2 rainbowcrack ratdecoders reaver recon-ng responder reverser ridenum rom-decoder routersploit rsmangler rtpflood sbd scalpel setoolkit sfuzz sharpmeter shellnoob shodan shodan-eye sidguesser sipcalc sipvicious skipfish slow-http-test smbspider smtp-user-enum sn1per sniffjoke socat sqlmap ssh-audit sslcaudit sslscan sslsplit sslyze subbrute sublist3r t50 tcpdump tcpick tcpreplay termineter thc-ipv6 thc-ssl-dos tilde-enum tnscmd10g torbrowser torphantom traceroute truecrack tshark twofi u3-pwn ua-tester udpflood unicorn unix-privesc-check valgrind vega vfeed volatility webscarab webshells websploit webtrace wfuzz whois wifi-honey wifijammer wifiphisher wifite wifresti windows-xsuggest wireshark wireshark-qt wol-e wps-breaker wpscan ws-attacker xspy yara yersinia zaproxy zenmap )
for TOOL in "${TOOLS[@]}"
do
	rm -f tools/$TOOL.md >/dev/null 2>&1
	echo 'Package: '$TOOL | tee -a tools/$TOOL.md >/dev/null 2>&1
	echo 'Distributor ID: BlackBuntu' | tee -a tools/$TOOL.md >/dev/null 2>&1
	echo 'Description: Blackbuntu Revive v1.0.1 Alpha' | tee -a tools/$TOOL.md >/dev/null 2>&1
	echo 'Release: 1.0.1' | tee -a tools/$TOOL.md >/dev/null 2>&1
	echo 'Codename: revive' | tee -a tools/$TOOL.md >/dev/null 2>&1
	echo 'Build: 20190922' | tee -a tools/$TOOL.md >/dev/null 2>&1
done
