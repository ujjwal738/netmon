# from flask import Flask, render_template, request, jsonify
# import socket
# import concurrent.futures  # Import for ThreadPoolExecutor
# from scapy.all import srp, Ether, ARP

# app = Flask(__name__)

# def scan_network(ip_range):
#     print("Scanning network for devices...\n")
#     devices = []
#     try:
#         ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range), timeout=5, verbose=False)
#         devices = [(pkt[1].psrc, pkt[1].src) for pkt in ans]
#         devices_info = []

#         if devices:
#             print("Found active devices:")
#             for i, (ip, mac) in enumerate(devices, start=1):
#                 print(f"Device {i}:")
#                 print(f"  IP Address: {ip}")
#                 print(f"  MAC Address: {mac}")
#                 print("  Status: Online")
#                 open_ports = scan_ports(ip)
#                 print(f"  Open Ports: {open_ports}")
#                 print()
#                 devices_info.append({
#                     "ip": ip,
#                     "mac": mac,
#                     "ports": open_ports
#                 })
#         else:
#             print("No active devices found in the specified IP range.")
#     except Exception as e:
#         print(f"An error occurred during scanning: {str(e)}")

#     return devices_info


# def scan_ports(ip_address):
#     open_ports = []
#     print(f"Scanning ports for {ip_address}...")
#     with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
#         futures = []
#         for port in range(1, 1025):
#             futures.append(executor.submit(scan_port, ip_address, port))
#         for future in concurrent.futures.as_completed(futures):
#             result = future.result()
#             if result != -1:
#                 open_ports.append(result)
#     return open_ports

# def scan_port(ip_address, port):
#     with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
#         s.settimeout(1.0)  # Adjust timeout as necessary
#         result = s.connect_ex((ip_address, port))
#         if result == 0:
#             return port
#     return -1

# @app.route('/')
# def index():
#     return render_template('index.html')


# @app.route('/scan', methods=['POST'])
# def scan():
#     data = request.get_json()
#     ip_range = data.get('ip_range')
#     devices_info = scan_network(ip_range)
#     return jsonify(devices=devices_info)


# if __name__ == "__main__":
#     app.run(debug=True)



# from flask import Flask, render_template, request, jsonify
# import socket
# import concurrent.futures
# from scapy.all import srp, Ether, ARP, sniff, TCP, IP, Raw

# app = Flask(__name__)

# # Function to capture HTTP traffic and extract URLs
# def capture_http_traffic(ip):
#     browsing_history = []

#     def process_packet(packet):
#         if packet.haslayer(TCP) and packet.haslayer(Raw):
#             payload = packet[Raw].load.decode(errors='ignore')
#             if "HTTP" in payload:
#                 headers = payload.split('\r\n')
#                 for header in headers:
#                     if header.startswith("Host:") or header.startswith("GET") or header.startswith("POST"):
#                         browsing_history.append(header)
    
#     # Sniffing packets for a short duration to capture browsing history
#     sniff(filter=f"tcp and host {ip}", prn=process_packet, timeout=30)
    
#     return browsing_history

# def scan_network(ip_range):
#     print("Scanning network for devices...\n")
#     devices = []
#     try:
#         ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range), timeout=5, verbose=False)
#         devices = [(pkt[1].psrc, pkt[1].src) for pkt in ans]
#         devices_info = []

#         if devices:
#             print("Found active devices:")
#             for i, (ip, mac) in enumerate(devices, start=1):
#                 print(f"Device {i}:")
#                 print(f"  IP Address: {ip}")
#                 print(f"  MAC Address: {mac}")
#                 print("  Status: Online")
#                 open_ports = scan_ports(ip)
#                 print(f"  Open Ports: {open_ports}")
#                 browsing_history = capture_http_traffic(ip)
#                 print(f"  Browsing History: {browsing_history}")
#                 print()
#                 devices_info.append({
#                     "ip": ip,
#                     "mac": mac,
#                     "ports": open_ports,
#                     "browsing_history": browsing_history
#                 })
#         else:
#             print("No active devices found in the specified IP range.")
#     except Exception as e:
#         print(f"An error occurred during scanning: {str(e)}")

#     return devices_info

# def scan_ports(ip_address):
#     open_ports = []
#     print(f"Scanning ports for {ip_address}...")
#     with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
#         futures = []
#         for port in range(1, 1025):
#             futures.append(executor.submit(scan_port, ip_address, port))
#         for future in concurrent.futures.as_completed(futures):
#             result = future.result()
#             if result != -1:
#                 open_ports.append(result)
#     return open_ports

# def scan_port(ip_address, port):
#     with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
#         s.settimeout(1.0)
#         result = s.connect_ex((ip_address, port))
#         if result == 0:
#             return port
#     return -1

# @app.route('/')
# def index():
#     return render_template('index.html')

# @app.route('/scan', methods=['POST'])
# def scan():
#     data = request.get_json()
#     ip_range = data.get('ip_range')
#     devices_info = scan_network(ip_range)
#     return jsonify(devices=devices_info)

# if __name__ == "__main__":
#     app.run(debug=True)










# from flask import Flask, render_template, request, jsonify
# import socket
# import concurrent.futures
# from scapy.all import srp, Ether, ARP, sniff, TCP, IP, Raw

# app = Flask(__name__)

# # Function to capture HTTP traffic and extract URLs
# def capture_http_traffic(ip):
#     browsing_history = []

#     def process_packet(packet):
#         if packet.haslayer(TCP) and packet.haslayer(Raw) and packet.haslayer(IP):
#             if packet[IP].src == ip or packet[IP].dst == ip:
#                 payload = packet[Raw].load.decode(errors='ignore')
#                 if "HTTP" in payload:
#                     headers = payload.split('\r\n')
#                     for header in headers:
#                         if header.startswith("Host:") or header.startswith("GET") or header.startswith("POST"):
#                             browsing_history.append(header)

#     # Sniffing packets for a short duration to capture browsing history
#     sniff(filter=f"tcp and host {ip}", prn=process_packet, timeout=30)
    
#     return browsing_history

# def scan_network(ip_range):
#     print("Scanning network for devices...\n")
#     devices = []
#     try:
#         ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range), timeout=5, verbose=False)
#         devices = [(pkt[1].psrc, pkt[1].src) for pkt in ans]
#         devices_info = []

#         if devices:
#             print("Found active devices:")
#             for i, (ip, mac) in enumerate(devices, start=1):
#                 print(f"Device {i}:")
#                 print(f"  IP Address: {ip}")
#                 print(f"  MAC Address: {mac}")
#                 print("  Status: Online")
#                 open_ports = scan_ports(ip)
#                 print(f"  Open Ports: {open_ports}")
#                 browsing_history = capture_http_traffic(ip)
#                 print(f"  Browsing History: {browsing_history}")
#                 print()
#                 devices_info.append({
#                     "ip": ip,
#                     "mac": mac,
#                     "ports": open_ports,
#                     "browsing_history": browsing_history
#                 })
#         else:
#             print("No active devices found in the specified IP range.")
#     except Exception as e:
#         print(f"An error occurred during scanning: {str(e)}")

#     return devices_info

# def scan_ports(ip_address):
#     open_ports = []
#     print(f"Scanning ports for {ip_address}...")
#     with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
#         futures = []
#         for port in range(1, 1025):
#             futures.append(executor.submit(scan_port, ip_address, port))
#         for future in concurrent.futures.as_completed(futures):
#             result = future.result()
#             if result != -1:
#                 open_ports.append(result)
#     return open_ports

# def scan_port(ip_address, port):
#     with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
#         s.settimeout(1.0)
#         result = s.connect_ex((ip_address, port))
#         if result == 0:
#             return port
#     return -1

# @app.route('/')
# def index():
#     return render_template('index.html')

# @app.route('/scan', methods=['POST'])
# def scan():
#     data = request.get_json()
#     ip_range = data.get('ip_range')
#     devices_info = scan_network(ip_range)
#     return jsonify(devices=devices_info)

# if __name__ == "__main__":
#     app.run(debug=True)







# from flask import Flask, render_template, request, jsonify
# import socket
# import concurrent.futures
# from scapy.all import srp, Ether, ARP, sniff, TCP, IP, Raw, conf

# app = Flask(__name__)

# # Function to capture HTTP traffic and extract URLs
# def capture_http_traffic(ip):
#     browsing_history = []

#     def process_packet(packet):
#         if packet.haslayer(TCP) and packet.haslayer(Raw) and packet.haslayer(IP):
#             if packet[IP].src == ip or packet[IP].dst == ip:
#                 payload = packet[Raw].load.decode(errors='ignore')
#                 if "HTTP" in payload:
#                     headers = payload.split('\r\n')
#                     for header in headers:
#                         if header.startswith("Host:") or header.startswith("GET") or header.startswith("POST"):
#                             browsing_history.append(header)

#     # Sniffing packets for a short duration to capture browsing history
#     sniff(filter=f"tcp and host {ip}", prn=process_packet, timeout=30)
    
#     return browsing_history

# def scan_network(ip_range):
#     print("Scanning network for devices...\n")
#     devices = []
#     try:
#         # Debugging: Print the active network interface
#         print(f"Using network interface: {conf.iface}")
        
#         ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range), timeout=5, verbose=True)
#         devices = [(pkt[1].psrc, pkt[1].src) for pkt in ans]
#         devices_info = []

#         if devices:
#             print("Found active devices:")
#             for i, (ip, mac) in enumerate(devices, start=1):
#                 print(f"Device {i}:")
#                 print(f"  IP Address: {ip}")
#                 print(f"  MAC Address: {mac}")
#                 print("  Status: Online")
#                 open_ports = scan_ports(ip)
#                 print(f"  Open Ports: {open_ports}")
#                 browsing_history = capture_http_traffic(ip)
#                 print(f"  Browsing History: {browsing_history}")
#                 print()
#                 devices_info.append({
#                     "ip": ip,
#                     "mac": mac,
#                     "ports": open_ports,
#                     "browsing_history": browsing_history
#                 })
#         else:
#             print("No active devices found in the specified IP range.")
#     except Exception as e:
#         print(f"An error occurred during scanning: {str(e)}")

#     return devices_info

# def scan_ports(ip_address):
#     open_ports = []
#     print(f"Scanning ports for {ip_address}...")
#     with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
#         futures = []
#         for port in range(1, 1025):
#             futures.append(executor.submit(scan_port, ip_address, port))
#         for future in concurrent.futures.as_completed(futures):
#             result = future.result()
#             if result != -1:
#                 open_ports.append(result)
#     return open_ports

# def scan_port(ip_address, port):
#     with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
#         s.settimeout(1.0)
#         result = s.connect_ex((ip_address, port))
#         if result == 0:
#             return port
#     return -1

# @app.route('/')
# def index():
#     return render_template('index.html')

# @app.route('/scan', methods=['POST'])
# def scan():
#     data = request.get_json()
#     ip_range = data.get('ip_range')
#     devices_info = scan_network(ip_range)
#     return jsonify(devices=devices_info)

# if __name__ == "__main__":
#     # Ensuring the script runs with administrative/root privileges
#     import os
#     if os.name != 'nt' and os.geteuid() != 0:
#         raise PermissionError("Script must be run as root")
    
#     app.run(debug=True)



# from flask import Flask, render_template, request, jsonify
# import socket
# import concurrent.futures  # Import for ThreadPoolExecutor
# from scapy.all import srp, Ether, ARP, sniff
# import os

# app = Flask(__name__)

# def scan_network(ip_range):
#     print("Scanning network for devices...\n")
#     devices = []
#     try:
#         ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range), timeout=5, verbose=False)
#         devices = [(pkt[1].psrc, pkt[1].src) for pkt in ans]
#         devices_info = []

#         if devices:
#             print("Found active devices:")
#             for i, (ip, mac) in enumerate(devices, start=1):
#                 print(f"Device {i}:")
#                 print(f"  IP Address: {ip}")
#                 print(f"  MAC Address: {mac}")
#                 print("  Status: Online")
#                 open_ports = scan_ports(ip)
#                 print(f"  Open Ports: {open_ports}")
#                 print()
#                 devices_info.append({
#                     "ip": ip,
#                     "mac": mac,
#                     "ports": open_ports
#                 })
#         else:
#             print("No active devices found in the specified IP range.")
#     except Exception as e:
#         print(f"An error occurred during scanning: {str(e)}")

#     return devices_info


# def scan_ports(ip_address):
#     open_ports = []
#     print(f"Scanning ports for {ip_address}...")
#     with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
#         futures = []
#         for port in range(1, 1025):
#             futures.append(executor.submit(scan_port, ip_address, port))
#         for future in concurrent.futures.as_completed(futures):
#             result = future.result()
#             if result != -1:
#                 open_ports.append(result)
#     return open_ports

# def scan_port(ip_address, port):
#     with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
#         s.settimeout(1.0)  # Adjust timeout as necessary
#         result = s.connect_ex((ip_address, port))
#         if result == 0:
#             return port
#     return -1

# def packet_callback(packet):
#     # Customize this function to extract and print desired packet information
#     print(f"Packet: {packet.summary()}")

# def start_packet_capture(interface):
#     print(f"Starting packet capture on interface {interface}...")
#     try:
#         sniff(iface=interface, prn=packet_callback, store=0)
#     except OSError as e:
#         print(f"Error starting packet capture on interface {interface}: {e}")

# @app.route('/')
# def index():
#     return render_template('index.html')


# @app.route('/scan', methods=['POST'])
# def scan():
#     data = request.get_json()
#     ip_range = data.get('ip_range')
#     interface = data.get('interface', 'eth0')  # Default to 'eth0' if no interface is specified
#     if os.name == 'nt' and interface == 'eth0':  # Adjust default interface for Windows
#         interface = 'Ethernet'
#     devices_info = scan_network(ip_range)
#     start_packet_capture(interface)
#     return jsonify(devices=devices_info)


# if __name__ == "__main__":
#     app.run(debug=True)



from flask import Flask, render_template, request, jsonify
import socket
import concurrent.futures
import netifaces
from scapy.all import srp, Ether, ARP, sniff
import os

app = Flask(__name__)

def get_default_gateway():
    gateways = netifaces.gateways()
    default_gateway = gateways.get('default')
    if default_gateway:
        return default_gateway[netifaces.AF_INET][0]
    return None

def scan_network(ip_range):
    print("Scanning network for devices...\n")
    devices = []
    try:
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range), timeout=5, verbose=False)
        devices = [(pkt[1].psrc, pkt[1].src) for pkt in ans]
        devices_info = []

        if devices:
            print("Found active devices:")
            for i, (ip, mac) in enumerate(devices, start=1):
                print(f"Device {i}:")
                print(f"  IP Address: {ip}")
                print(f"  MAC Address: {mac}")
                print("  Status: Online")
                open_ports = scan_ports(ip)
                print(f"  Open Ports: {open_ports}")
                print()
                devices_info.append({
                    "ip": ip,
                    "mac": mac,
                    "ports": open_ports
                })
        else:
            print("No active devices found in the specified IP range.")
    except Exception as e:
        print(f"An error occurred during scanning: {str(e)}")

    return devices_info


def scan_ports(ip_address):
    open_ports = []
    print(f"Scanning ports for {ip_address}...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        futures = []
        for port in range(1, 1025):
            futures.append(executor.submit(scan_port, ip_address, port))
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result != -1:
                open_ports.append(result)
    return open_ports

def scan_port(ip_address, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1.0)  # Adjust timeout as necessary
        result = s.connect_ex((ip_address, port))
        if result == 0:
            return port
    return -1

def packet_callback(packet):
    # Customize this function to extract and print desired packet information
    print(f"Packet: {packet.summary()}")

def start_packet_capture(interface):
    print(f"Starting packet capture on interface {interface}...")
    try:
        sniff(iface=interface, prn=packet_callback, store=0)
    except OSError as e:
        print(f"Error starting packet capture on interface {interface}: {e}")

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/scan', methods=['POST'])
def scan():
    data = request.get_json()
    ip_range = data.get('ip_range')
    interface = data.get('interface', 'eth0')  # Default to 'eth0' if no interface is specified
    if os.name == 'nt' and interface == 'eth0':  # Adjust default interface for Windows
        interface = 'Ethernet'

    devices_info = scan_network(ip_range)

    # Get the default gateway
    default_gateway = get_default_gateway()
    if default_gateway:
        print(f"Default gateway: {default_gateway}")
        # Scan the default gateway's network as well
        gateway_devices_info = scan_network(f"{default_gateway}/24")
        devices_info.extend(gateway_devices_info)

    start_packet_capture(interface)
    return jsonify(devices=devices_info)


if __name__ == "__main__":
    app.run(debug=True)
