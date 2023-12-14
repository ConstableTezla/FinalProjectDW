from flask import Flask, jsonify, request, render_template
from flask_sqlalchemy import SQLAlchemy
import nmap
import ipaddress
import json


app = Flask(__name__, template_folder='C:\\Users\\DaltonWright\\PycharmProjects\\FinalProjectDW\\templates')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///os_info.db'
db = SQLAlchemy(app)


def is_valid_ipv4(ip):
    try:
        ipaddress.IPv4Address(ip)
        return True
    except ipaddress.AddressValueError:
        return False


class OsInfo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    os_name = db.Column(db.String(50), nullable=False)
    count = db.Column(db.Integer, nullable=False)


@app.route('/scan_network', methods=['GET', 'POST'])
def scan_network():
    if request.method == 'POST':
        # Get the target IP range from the POST request data
        user_input = request.form.get('target_ip')
    else:
        user_input = None

    if user_input:
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

        # Save the OS information to the database
        with app.app_context():
            for os, count in os_count.items():
                os_info = OsInfo(os_name=os, count=count)
                db.session.add(os_info)
            db.session.commit()

        # Save the OS information to a local JSON file
        output_file = 'os_info.json'
        with open(output_file, 'w') as f:
            json.dump(os_count, f, indent=2)
        print(f"OS information saved to {output_file}")

        # Return the OS information as JSON
        return jsonify(os_count)

    return render_template('scan_form.html')


if __name__ == '__main__':
    with app.app_context():
        # Create the database tables
        db.create_all()
    app.run(debug=True)
