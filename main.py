from flask import Flask, jsonify
import nmap
import ipaddress  # Python standard library for IP address manipulation
import json

app = Flask(__name__)


def is_valid_ipv4(ip):
    try:
        ipaddress.IPv4Address(ip)
        return True
    except ipaddress.AddressValueError:
        return False


@app.route('/scan_network', methods=['POST'])
def scan_network():
    # Prompt the user for the target IP range
    user_input = input("Enter the target IP range (e.g., 192.168.1.1-254): ")

    # Validate the user input as a valid IPv4 address
    if not is_valid_ipv4(user_input):
        return jsonify({'error': 'Invalid IPv4 address'}), 400

    # Initialize the Nmap scanner
    nm = nmap.PortScanner()

    # Perform the scan to detect the OS of devices in the network
    nm.scan(hosts=user_input, arguments='-O')

    # Extract OS information from the scan results
    os_count = {}
    for host in nm.all_hosts():
        os_match = nm[host]['osmatch']
        if os_match:
            detected_os = os_match[0]['osclass'][0]['osfamily']
            os_count[detected_os] = os_count.get(detected_os, 0) + 1

    # Print the OS information
    print("OS Information:")
    for os, count in os_count.items():
        print(f"{os}: {count}")

    # Save the OS information to a local JSON file
    output_file = 'os_info.json'
    with open(output_file, 'w') as f:
        json.dump(os_count, f, indent=2)
    print(f"OS information saved to {output_file}")

    # Return the OS information as JSON
    return jsonify(os_count)


if __name__ == '__main__':
    app.run(debug=True)