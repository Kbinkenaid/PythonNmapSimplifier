#!/usr/bin/env python3
import nmap
import socket
import sys
import time

def get_local_ip():
    """Get the local IP address of the machine"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # doesn't need to be reachable
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

def print_menu():
    """Display the menu of scanning options"""
    print("\nAvailable Scan Types:")
    print("1. Ping Scan (Simple host discovery)")
    print("2. Stealth Scan (SYN scan - less detectable)")
    print("3. TCP Connect Scan (Full TCP handshake)")
    print("4. Service Version Detection (Identify running services)")
    print("5. OS Detection Scan (Determine target OS)")
    print("6. Change Target IP Address")
    print("7. Exit")

def print_scan_results(scanner, host):
    """Print detailed scan results for a host"""
    print(f"\nScan results for {host}:")
    print(f"State: {scanner[host].state()}")
    
    if 'osmatch' in scanner[host]:
        for osmatch in scanner[host]['osmatch']:
            print(f"OS Match: {osmatch['name']} - Accuracy: {osmatch['accuracy']}%")
    
    if 'tcp' in scanner[host]:
        print("\nOpen ports:")
        for port in scanner[host]['tcp']:
            port_info = scanner[host]['tcp'][port]
            service_info = f"Version: {port_info['version']}" if port_info['version'] else ""
            print(f"Port {port}/{port_info['name']}: {port_info['state']} {service_info}")

def main():
    # Display local IP
    local_ip = get_local_ip()
    print(f"Your IP address: {local_ip}")

    # Get target IP
    target_ip = input("\nEnter target IP address: ")

    # Initialize scanner
    scanner = nmap.PortScanner()

    while True:
        print_menu()
        choice = input("\nSelect scan type (1-7): ")

        try:
            if choice == '1':
                print("\nRunning Ping Scan...")
                scanner.scan(target_ip, arguments='-sn')
                for host in scanner.all_hosts():
                    print(f"\nHost {host} is {scanner[host].state()}")

            elif choice == '2':
                print("\nRunning Stealth Scan...")
                # Scan common ports with SYN scan
                scanner.scan(target_ip, '1-1024', arguments='-sS -v')
                for host in scanner.all_hosts():
                    print_scan_results(scanner, host)

            elif choice == '3':
                print("\nRunning TCP Connect Scan...")
                # Scan common ports with TCP connect scan
                scanner.scan(target_ip, '1-1024', arguments='-sT -v')
                for host in scanner.all_hosts():
                    print_scan_results(scanner, host)

            elif choice == '4':
                print("\nRunning Service Version Detection...")
                # Scan with version detection
                scanner.scan(target_ip, '1-1024', arguments='-sV -v')
                for host in scanner.all_hosts():
                    print_scan_results(scanner, host)

            elif choice == '5':
                print("\nRunning OS Detection Scan...")
                # Scan with OS detection and version detection
                scanner.scan(target_ip, '1-1024', arguments='-sV -O -v')
                for host in scanner.all_hosts():
                    print_scan_results(scanner, host)

            elif choice == '6':
                # Change target IP
                print(f"\nCurrent target IP: {target_ip}")
                new_ip = input("Enter new target IP address: ")
                target_ip = new_ip
                print(f"Target IP changed to: {target_ip}")

            elif choice == '7':
                print("Exiting...")
                sys.exit(0)
            else:
                print("Invalid option. Please select 1-7.")
                continue

            # Add a small delay to allow user to read results
            time.sleep(1)

        except nmap.PortScannerError as e:
            print(f"\nError: {str(e)}")
            print("Make sure you have nmap installed and are running with appropriate permissions.")
            print("On Windows, make sure nmap is in your PATH and you're running as Administrator.")
        except Exception as e:
            print(f"\nAn error occurred: {str(e)}")
            print("Make sure you have proper permissions and nmap is installed.")

if __name__ == "__main__":
    main()
