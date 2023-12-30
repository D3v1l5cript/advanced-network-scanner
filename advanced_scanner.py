import os
import nmap
from colorama import Fore, Style

RED = '\033[91m'
ENDC = '\033[0m'
HEADER = '\033[95m'
OKBLUE = '\033[94m'
OKCYAN = '\033[96m'
OKGREEN = '\033[92m'
WARNING = '\033[93m'
FAIL = '\033[91m'
ENDC = '\033[0m'
BOLD = '\033[1m'
UNDERLINE = '\033[4m'

def clear_console():
    # Clear console screen for a cleaner interface
    os.system('cls' if os.name == 'nt' else 'clear')

def nmap_port_scanner(target_ip, scan_option):
    nm = nmap.PortScanner()
    print(f"Scanning target: {OKBLUE}{target_ip}{ENDC}")

    try:
        scan_commands = {
            1: '-Pn -sS -sV -O -p 1-65535 -T4',
            2: '-Pn -sS -sV -p 1-1024 -T3',
            3: '-Pn -sU -sV -p 1-1024',
            4: '-Pn -sV --script http-csrf',
            5: '-Pn -p 554 -O --script-updatedb',
            6: '-Pn --script vuln',
            7: '-Pn -sS -sV -p 1-65535 -T5 -A',
            8: '-Pn -sS --script-updatedb'      
        }

        if scan_option not in scan_commands:
            print("Invalid scan option. Please choose 1, 2, 3, 4, 5, 6, or 7.")
            return

        nm.scan(hosts=target_ip, arguments=scan_commands[scan_option])

        print(f"{OKGREEN}Scan Results:{ENDC}")
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()
                for port in ports:
                    state = nm[host][proto][port]['state']
                    service = nm[host][proto][port]['name']
                    print(f"Port: {OKCYAN}{port}/{proto}{ENDC}\tState: {WARNING}{state}{ENDC}\tService: {OKGREEN}{service}{ENDC}")

                    if port == 8443 and service == 'http':
                        if 'http-csrf' in nm[host][proto][port]:
                            csrf_output = nm[host][proto][port]['http-csrf']
                            print(f"CSRF Vulnerabilities Detected on Port 8443:\n{csrf_output}")

                    elif 'script' in nm[host][proto][port]:
                        script_output = nm[host][proto][port]['script']
                        print(f"Vulnerability Information Detected on Port {port}:\n{script_output}")
    except nmap.PortScannerError as e:
        print(f"{FAIL}Nmap error: {e}{ENDC}")

if __name__ == "__main__":
    clear_console()
    print(HEADER + f"""
             __                                              
  ____ _____/ /   __   ______________ _____  ____  ___  _____
 / __ `/ __  / | / /  / ___/ ___/ __ `/ __ \/ __ \/ _ \/ ___/
/ /_/ / /_/ /| |/ /  (__  ) /__/ /_/ / / / / / / /  __/ /    
\__,_/\__,_/ |___/  /____/\___/\__,_/_/ /_/_/ /_/\___/_/     
                                                             
=================D3v1l5cript=====================""" + HEADER)
    print(Style.RESET_ALL)
    print("Please provide the target IP address or website and select a scan option.")

    target_ip = input(f"{OKGREEN}Enter the target IP address or website: {ENDC}")

    print("\nSelect scan option:")
    print(f"{WARNING}1. Normal scan ")
    print("2. Advanced scan ")
    print("3. UDP scan")
    print(RED + "4. Cross-Site Request Forgery (CSRF) scan")
    print(RED + "5. RTSP finder")
    print(FAIL + "6. Vuln finder")
    print("7. Advanced aggressive scan")
    print("8. only stealth scan")
    try:

        scan_choice = int(input(f"{OKGREEN}Enter your choice (1, 2, 3, 4, 5, 6, 7): {ENDC}"))
        nmap_port_scanner(target_ip, scan_choice)
    except ValueError as ve:
        print(f"{FAIL}Error: {ve}{ENDC}")
