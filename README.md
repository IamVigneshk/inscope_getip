# inscope_getip
This Python Script allows and simplifies bug bounty hunter by scanning the in scope domains and get the ip address and root domain of the in scope domains that are in .txt file seperated by lines
Upload the file location in the input parameters
The run_nmap_scan function now uses the -Pn option to disable ping and -p- to perform a full port scan.
The script performs the Nmap scan correctly for each IP address obtained, whether from the URL's hostname or root domain.
Make sure Nmap is installed on your system to use this script. If not, install it via your package manager (e.g., sudo apt-get install nmap on Debian-based systems or brew install nmap on macOS).
