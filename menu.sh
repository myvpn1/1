#!/bin/bash
# Menu For Script
# Edition : Stable Edition V1.0
# Auther  : 
# (C) Copyright 2021-2022
# =========================================
BIBlack='\033[1;90m'      # Black
BIRed='\033[1;91m'        # Red
BIGREEN='\033[1;92m'      # GREEN
BIYellow='\033[1;93m'     # Yellow
BIBlue='\033[1;94m'       # Blue
BIPurple='\033[1;95m'     # Purple
BICdyan='\033[1;96m'       # Cyan
BIWhite='\033[1;97m'      # White
UWhite='\033[4;37m'       # White
On_IPurple='\033[0;105m'  #
On_IRed='\033[0;101m'
IBlack='\033[0;90m'       # Black
IRed='\033[0;91m'         # Red
IGREEN='\033[0;92m'       # GREEN
IYellow='\033[0;93m'      # Yellow
IBlue='\033[0;94m'        # Blue
IPurple='\033[0;95m'      # Purple
ICyan='\033[0;96m'        # Cyan
IWhite='\033[0;97m'       # White
NC='\e[0m'

# // Export Color & Information
export RED='\033[0;31m'
export GREEN='\033[0;32m'
export YELLOW='\033[0;33m'
export BLUE='\033[0;34m'
export PURPLE='\033[0;35m'
export CYAN='\033[0;36m'
export LIGHT='\033[0;37m'
export NC='\033[0m'

# // Export Banner Status Information
export EROR="[${RED} EROR ${NC}]"
export INFO="[${YELLOW} INFO ${NC}]"
export OKEY="[${GREEN} OKEY ${NC}]"
export PENDING="[${YELLOW} PENDING ${NC}]"
export SEND="[${YELLOW} SEND ${NC}]"
export RECEIVE="[${YELLOW} RECEIVE ${NC}]"

# // Export Align
export BOLD="\e[1m"
export WARNING="${RED}\e[5m"
export UNDERLINE="\e[4m"

# // Root Checking
if [ "${EUID}" -ne 0 ]; then
		echo -e "${EROR} Please Run This Script As Root User !"
		exit 1
fi

# // Exporting IP Address
export IP=$( curl -s https://ipinfo.io/ip/ )

# // Exporting Network Interface
export NETWORK_IFACE="$(ip route show to default | awk '{print $5}')"

BURIQ () {
    curl -sS https://raw.githubusercontent.com/myvpn1/izin/main/tai > /root/tmp
    data=( `cat /root/tmp | grep -E "^### " | awk '{print $2}'` )
    for user in "${data[@]}"
    do
    exp=( `grep -E "^### $user" "/root/tmp" | awk '{print $3}'` )
    d1=(`date -d "$exp" +%s`)
    d2=(`date -d "$biji" +%s`)
    exp2=$(( (d1 - d2) / 86400 ))
    if [[ "$exp2" -le "0" ]]; then
    echo $user > /etc/.$user.ini
    else
    rm -f /etc/.$user.ini > /dev/null 2>&1
    fi
    done
    rm -f /root/tmp
}

MYIP=$(curl -sS ipv4.icanhazip.com)
Name=$(curl -sS https://raw.githubusercontent.com/myvpn1/izin/main/tai | grep $MYIP | awk '{print $2}')
echo $Name > /usr/local/etc/.$Name.ini
CekOne=$(cat /usr/local/etc/.$Name.ini)

Bloman () {
if [ -f "/etc/.$Name.ini" ]; then
CekTwo=$(cat /etc/.$Name.ini)
    if [ "$CekOne" = "$CekTwo" ]; then
        res="Expired"
    fi
else
res="Permission Accepted..."
fi
}

PERMISSION () {
    MYIP=$(curl -sS ipv4.icanhazip.com)
    IZIN=$(curl -sS https://raw.githubusercontent.com/myvpn1/izin/main/tai | awk '{print $4}' | grep $MYIP)
    if [ "$MYIP" = "$IZIN" ]; then
    Bloman
    else
    res="Permission Denied!"
    fi
    BURIQ
}
PERMISSION
if [ -f /home/needupdate ]; then
red "Your script need to update first !"
exit 0
elif [ "$res" = "Permission Accepted..." ]; then
echo -ne
else
red "Permission Denied!"
exit 0
fi
# // Clear
clear
clear && clear && clear
clear;clear;clear
cek=$(service ssh status | grep active | cut -d ' ' -f5)
if [ "$cek" = "active" ]; then
stat=-f5
else
stat=-f7
fi
ssh=$(service ssh status | grep active | cut -d ' ' $stat)
if [ "$ssh" = "active" ]; then
ressh="${GREEN}ON${NC}"
else
ressh="${red}OFF${NC}"
fi
sshstunel=$(service stunnel5 status | grep active | cut -d ' ' $stat)
if [ "$sshstunel" = "active" ]; then
resst="${GREEN}ON${NC}"
else
resst="${red}OFF${NC}"
fi
sshws=$(service ws-stunnel status | grep active | cut -d ' ' $stat)
if [ "$sshws" = "active" ]; then
ressshws="${GREEN}ON${NC}"
else
ressshws="${red}OFF${NC}"
fi
ngx=$(service nginx status | grep active | cut -d ' ' $stat)
if [ "$ngx" = "active" ]; then
resngx="${GREEN}ON${NC}"
else
resngx="${red}OFF${NC}"
fi
dbr=$(service dropbear status | grep active | cut -d ' ' $stat)
if [ "$dbr" = "active" ]; then
resdbr="${GREEN}ON${NC}"
else
resdbr="${red}OFF${NC}"
fi
v2r=$(service xray status | grep active | cut -d ' ' $stat)
if [ "$v2r" = "active" ]; then
resv2r="${GREEN}ON${NC}"
else
resv2r="${red}OFF${NC}"
fi
function addhost(){
clear
echo -e "\033[0;34m----------------------------------\033[0m"
echo ""
read -rp "Domain/Host: " -e host
echo ""
if [ -z $host ]; then
echo "????"
echo -e "\033[0;34m----------------------------------\033[0m"
read -n 1 -s -r -p "Press any key to back on menu"
setting-menu
else
rm -fr /etc/xray/domain
echo "IP=$host" > /var/lib/scrz-prem/ipvps.conf
echo $host > /etc/xray/domain
echo -e "\033[0;34m----------------------------------\033[0m"
echo "Dont forget to renew gen-ssl"
echo ""
read -n 1 -s -r -p "Press any key to back on menu"
menu
fi
}
function genssl(){
clear
systemctl stop nginx
systemctl stop xray
domain=$(cat /var/lib/scrz-prem/ipvps.conf | cut -d'=' -f2)
Cek=$(lsof -i:80 | cut -d' ' -f1 | awk 'NR==2 {print $1}')
if [[ ! -z "$Cek" ]]; then
sleep 1
echo -e "[ ${red}WARNING${NC} ] Detected port 80 used by $Cek " 
systemctl stop $Cek
sleep 2
echo -e "[ ${GREEN}INFO${NC} ] Processing to stop $Cek " 
sleep 1
fi
echo -e "[ ${GREEN}INFO${NC} ] Starting renew gen-ssl... " 
sleep 2
/root/.acme.sh/acme.sh --upgrade
/root/.acme.sh/acme.sh --upgrade --auto-upgrade
/root/.acme.sh/acme.sh --set-default-ca --server letsencrypt
/root/.acme.sh/acme.sh --issue -d $domain --standalone -k ec-256
~/.acme.sh/acme.sh --installcert -d $domain --fullchainpath /etc/xray/xray.crt --keypath /etc/xray/xray.key --ecc
echo -e "[ ${GREEN}INFO${NC} ] Renew gen-ssl done... " 
sleep 2
echo -e "[ ${GREEN}INFO${NC} ] Starting service $Cek " 
sleep 2
echo $domain > /etc/xray/domain
systemctl start nginx
systemctl start xray
echo -e "[ ${GREEN}INFO${NC} ] All finished... " 
sleep 0.5
echo ""
read -n 1 -s -r -p "Press any key to back on menu"
menu
}
IPVPS=$(curl -s ipinfo.io/ip )
ISPVPS=$( curl -s ipinfo.io/org )
clear
echo -e "\033[0;34m┌─────────────────────────────────────────────────────┐${NC}"
echo -e "\033[0;34m│                  ${BIWhite}${UWhite}Server Informations${NC}"
echo -e "\033[0;34m│"
echo -e "\033[0;34m│  ${BIGREEN}Use Core        :  ${BIPurple}XRAY-CORE${NC}"
echo -e "\033[0;34m│  ${BIGREEN}Current Domain  :  ${BIPurple}$(cat /etc/xray/domain)${NC}"
echo -e "\033[0;34m│  ${BIGREEN}IP-VPS          :  ${BIYellow}$IPVPS${NC}"
echo -e "\033[0;34m│  ${BIGREEN}ISP-VPS         :  ${BIYellow}$ISPVPS${NC}"
echo -e "\033[0;34m└─────────────────────────────────────────────────────┘${NC}"
echo -e "\033[0;34m┌─────────────────────────────────────────────────────┐${NC}"
echo -e "\033[0;34m│ $NC${BIWhite} SSH ${NC}: $ressh"" ${BIWhite} NGINX ${NC}: $resngx"" ${BIWhite}  XRAY ${NC}: $resv2r"" ${BIWhite} TROJAN ${NC}: $resv2r\E[0m\033[0;34m      │"
echo -e "\033[0;34m│ $NC${BIWhite}          DROPBEAR ${NC}: $resdbr" "${BIWhite} SSH-WS ${NC}: $ressshws \E[0m\033[0;34m               │"
echo -e "\033[0;34m└─────────────────────────────────────────────────────┘${NC}"
echo -e "\033[0;34m┌─────────────────────────────────────────────────────┐${NC}"
echo -e "\033[0;34m│ $NC${BIGREEN}[${BIWhite}01${BIGREEN}] ${NC}SSH MANAGER${BIGREEN}${BIYellow}${BIGREEN}${NC}             ${BIGREEN}[${BIWhite}13${BIGREEN}] ${NC}EDIT-BANNER ${BIGREEN}${BIYellow}${BIGREEN}${NC}" 
echo -e "\033[0;34m│ $NC${BIGREEN}[${BIWhite}02${BIGREEN}] ${NC}VMESS MANAGER ${BIGREEN}${BIYellow}${BIGREEN}${NC}          ${BIGREEN}[${BIWhite}14${BIGREEN}] ${NC}CEK-SERVICE ${BIGREEN}${BIYellow}${BIGREEN}${NC}" 
echo -e "\033[0;34m│ $NC${BIGREEN}[${BIWhite}03${BIGREEN}] ${NC}VLESS MANAGER ${BIGREEN}${BIYellow}${BIGREEN}${NC}          ${BIGREEN}[${BIWhite}15${BIGREEN}] ${NC}CEK-TRAFIK ${BIGREEN}${BIYellow}${BIGREEN}${NC}" 
echo -e "\033[0;34m│ $NC${BIGREEN}[${BIWhite}04${BIGREEN}] ${NC}TROJAN MANAGER ${BIGREEN}${BIYellow}${BIGREEN}${NC}         ${BIGREEN}[${BIWhite}16${BIGREEN}] ${NC}CEK-SPEED SERVER${BIGREEN}${BIYellow}${BIGREEN}${NC}"
echo -e "\033[0;34m│ $NC${BIGREEN}[${BIWhite}05${BIGREEN}] ${NC}SHADOWSOCKS MANAGER ${BIGREEN}${BIYellow}${BIGREEN}${NC}    ${BIGREEN}[${BIWhite}17${BIGREEN}] ${NC}CEK-BANDWIDTH ${BIGREEN}${BIYellow}${BIGREEN}${NC}"
echo -e "\033[0;34m│ $NC${BIGREEN}[${BIWhite}06${BIGREEN}] ${NC}TENDANG  USER${BIGREEN}${BIYellow}${BIGREEN}${NC}           ${BIGREEN}[${BIWhite}18${BIGREEN}] ${NC}LIMIT-SPEED ${BIGREEN}${BIYellow}${BIGREEN}${NC}"
echo -e "\033[0;34m│ $NC${BIGREEN}[${BIWhite}07${BIGREEN}] ${NC}AUTO-REBOOT SERVER${BIGREEN}${BIYellow}${BIGREEN}${NC}      ${BIGREEN}[${BIWhite}19${BIGREEN}] ${NC}WEBMIN ${BIGREEN}${BIYellow}${BIGREEN}${NC}"
echo -e "\033[0;34m│ $NC${BIGREEN}[${BIWhite}08${BIGREEN}] ${NC}REBOOT SERVER${BIGREEN}${BIYellow}${BIGREEN}${NC}           ${BIGREEN}[${BIWhite}20${BIGREEN}] ${NC}INFO-SCRIPT ${BIGREEN}${BIYellow}${BIGREEN}${NC}" 
echo -e "\033[0;34m│ $NC${BIGREEN}[${BIWhite}09${BIGREEN}] ${NC}RESTART SERVER${BIGREEN}${BIYellow}${BIGREEN}${NC}          ${BIGREEN}[${BIWhite}21${BIGREEN}] ${NC}CLEAR-LOG ${BIGREEN}${BIYellow}${BIGREEN}${NC}" 
echo -e "\033[0;34m│ $NC${BIGREEN}[${BIWhite}10${BIGREEN}] ${NC}BACKUP/RESTORE ${BIGREEN}${BIYellow}${BIGREEN}${NC}         ${BIGREEN}[${BIWhite}xx${BIGREEN}] ${NC} EXIT ${BIGREEN}${BIYellow}${BIGREEN}${NC}"  
echo -e "\033[0;34m│ $NC${BIGREEN}[${BIWhite}11${BIGREEN}] ${NC}ADD-HOST/DOMAIN ${BIGREEN}${BIYellow}${BIGREEN}${NC}" 
echo -e "\033[0;34m│ $NC${BIGREEN}[${BIWhite}12${BIGREEN}] ${NC}RENEW SSL CERTIFIKATE ${BIGREEN}${BIYellow}${BIGREEN}${NC}"
echo -e "\033[0;34m└─────────────────────────────────────────────────────┘${NC}"
echo -e "\033[0;34m┌─────────────────────────────────────────────────────┐${NC}"
echo -e "\033[0;34m│ $NC Version      ${NC} : $sem Last Update"
echo -e "\033[0;34m│ $NC User          :\033[1;36m $Nama_Issued_License \e[0m"
echo -e "\033[0;34m│ $NC Expiry script${NC} : ${BIYellow}$(cat /etc/${Auther}/license-remaining-active-days.db)${NC} Days"
echo -e "\033[0;34m└─────────────────────────────────────────────────────┘${NC}"
echo
read -p " Select menu : " opt
echo -e ""
case $opt in
1 | 01) clear ; menu-ssh ;;
2 | 02) clear ; menu-vmess ;;
3 | 03) clear ; menu-vless ;;
4 | 04) clear ; menu-trojan ;;
5 | 04) clear ; menu-ss ;;
6 | 06) clear ; tendang ;;
7 | 07) clear ; autoreboot ;;
8 | 08) clear ; reboot ;;
9 | 09) clear ; restart ;;
10) clear ; menu-bckp ;;
11) clear ; addhost ;;
12) clear ; genssl ;;
13) clear ; nano /etc/issue.net ;;
14) clear ; running ;;
15) clear ; cek-trafik ;;
16) clear ; cek-speed ;;
17) clear ; cek-bandwidth ;;
#18) clear ; cek-ram ;;
18) clear ; limit-speed ;;
19) clear ; wbm ;;
20) clear ; cat /root/log-install.txt ;;
21) clear ; clearlog ;;
#99) clear ; update ;;
0 | 00) clear ; menu ;;
x | xx) exit ;;
*) echo -e "" ; echo "Press any key to back exit" ; sleep 1 ; exit ;;
esac
