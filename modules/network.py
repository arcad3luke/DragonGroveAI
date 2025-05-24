import socket
import ipaddress
import psutil
import json
import asyncio
import os  # For accessing environment variables
import smtplib
from scapy.all import ARP, Ether, srp
import nmap
from rich.console import Console
from rich.table import Table

# Initialize Console for Stylish Output
console = Console()

### ACTIVE SUBNET DETECTION ###
def get_active_subnets():
    """
    Detect all active subnets, including IPv6, excluding loopback subnet.
    """
    active_subnets = []
    for interface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family in [socket.AF_INET, socket.AF_INET6]:  # IPv4 and IPv6
                try:
                    subnet = ipaddress.ip_network(f"{addr.address}/{addr.netmask}", strict=False)
                    # Exclude loopback subnets
                    if not subnet.overlaps(ipaddress.ip_network("127.0.0.0/8")):
                        active_subnets.append(str(subnet))
                except ValueError as e:
                    console.print(f"[red]Error processing subnet for {addr.address}: {e}[/red]")
    return active_subnets

### DEVICE DISCOVERY ###
def discover_devices():
    """
    Discover all devices on the network using ARP requests.
    """
    subnets = get_active_subnets()
    all_devices = []

    for subnet in subnets:
        console.print(f"[cyan]Scanning subnet: {subnet}[/cyan]")
        try:
            request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet)
            answered, _ = srp(request, timeout=2, verbose=False)
            for _, rcv in answered:
                ip = rcv.psrc
                mac = rcv.hwsrc
                hostname = resolve_hostname(ip)
                all_devices.append({"IP Address": ip, "MAC Address": mac, "Hostname": hostname})
        except Exception as e:
            console.print(f"[red]Error scanning subnet {subnet}: {e}[/red]")

    return all_devices

def resolve_hostname(ip):
    """
    Resolve the hostname for a given IP address.
    """
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except socket.herror:
        return "Unknown"

### PORT SCANNING ###
def flag_uncommon_ports(port_data):
    """
    Identify uncommon ports by comparing to the comprehensive list of top 1000 ports.
    """
    top_1000_ports = set(range(1, 1001))  # Comprehensive set of top ports
    uncommon_ports = [port for port in port_data if port["Port"] not in top_1000_ports]
    return uncommon_ports

def scan_ports(ip):
    """
    Scan the top 1000 ports on a given IP using nmap.
    """
    try:
        nm = nmap.PortScanner()
        console.print(f"[cyan]Scanning top 1000 ports on {ip}...[/cyan]")
        nm.scan(ip, arguments="--top-ports 1000 -sV")
        port_data = []
        for port, details in nm[ip]['tcp'].items():
            port_data.append({
                "Port": port,
                "State": details['state'],
                "Service": details['name'],
                "Version": details.get('version', "Unknown")
            })

        # Flag uncommon ports
        uncommon_ports = flag_uncommon_ports(port_data)
        if uncommon_ports:
            console.print(f"[red]Uncommon ports detected on {ip}: {uncommon_ports}[/red]")

        return port_data
    except Exception as e:
        console.print(f"[red]Error scanning ports on {ip}: {e}[/red]")
        return []

### LOGGING ###
def save_scan_results(devices, filename="network_scan_results.json"):
    """
    Save network scan results to a JSON file.
    """
    try:
        with open(filename, "w") as file:
            json.dump(devices, file, indent=4)
        console.print(f"[bold green]Scan results saved to {filename}[/bold green]")
    except Exception as e:
        console.print(f"[red]Failed to save scan results: {e}[/red]")

### ALERTS ###
def send_email_alert(subject, message):
    """
    Send an email alert using Gmail's SMTP server.
    """
    sender_email = "arcadeluke@gmail.com"
    receiver_email = "arcadeluke@gmail.com"  # Self-sent email
    password = os.getenv("EMAIL_PASSWORD")  # Fetch the password from environment variables

    if not password:
        console.print("[red]Email password not found in environment variables![/red]")
        return

    try:
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()  # Upgrade the connection to secure
            server.login(sender_email, password)
            server.sendmail(
                sender_email,
                receiver_email,
                f"Subject: {subject}\n\n{message}"
            )
        console.print("[bold green]Email alert sent successfully![/bold green]")
    except Exception as e:
        console.print(f"[red]Failed to send email alert: {e}[/red]")

### TABLE RENDERING ###
def render_device_table(devices):
    """
    Display the discovered devices in a Rich table.
    """
    table = Table(title="Discovered Devices")
    table.add_column("IP Address", justify="left", style="cyan")
    table.add_column("MAC Address", justify="left", style="green")
    table.add_column("Hostname", justify="left", style="magenta")

    for device in devices:
        table.add_row(device["IP Address"], device["MAC Address"], device["Hostname"])

    console.print(table)

def render_port_table(ip, ports):
    """
    Display the scanned port information in a Rich table.
    """
    table = Table(title=f"Port Scan Results for {ip}")
    table.add_column("Port", justify="center", style="cyan")
    table.add_column("State", justify="center", style="magenta")
    table.add_column("Service", justify="left", style="yellow")
    table.add_column("Version", justify="left", style="green")

    for port in ports:
        table.add_row(
            str(port["Port"]),
            port["State"],
            port["Service"],
            port["Version"]
        )

    console.print(table)

### MAIN DIAGNOSTIC FUNCTION ###
def run_network_diagnostics():
    """
    Perform network diagnostics, including device identification and port scanning.
    """
    console.print("[bold cyan]Running Network Diagnostics...[/bold cyan]")

    # Discover devices on the active subnets
    devices = discover_devices()
    if devices:
        console.print("[bold green]Discovered Devices:[/bold green]")
        render_device_table(devices)

        # Perform port scans on discovered devices
        for device in devices:
            ip = device["IP Address"]
            ports = scan_ports(ip)
            if ports:
                render_port_table(ip, ports)
    else:
        console.print("[yellow]No devices discovered on the active subnets.[/yellow]")

    # Save results to a log file
    save_scan_results(devices)

    console.print("[bold green]Network Diagnostics Complete![/bold green]")
