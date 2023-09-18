import argparse
import logging
from getpass import getpass

import pan.xapi
import xmltodict
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from config import db_uri

from models import Base, Panorama, Ngfw

# Set the SQLAlchemy engine's logging level to WARNING
logging.getLogger('sqlalchemy.engine').setLevel(logging.WARNING)

def __load_panorama(ip_address, username, password) -> None:
    """
    This method adds a panorama to the database
    """
    # Create the database engine
    try:
        engine = create_engine(db_uri)
        Session = sessionmaker(bind=engine)
        session = Session()
    except Exception as e:
        print(f"Issue connecting to the database.  Error: {e}")

    # Query the database for all panoramas
    try:
        pan_list = session.query(Panorama).all()
    except Exception as e:
        print(e)
        print(f"Issue querying the database.  Likley need to build the database first.")
        exit()  

    # If the panorama is already in the database, exit
    for p in pan_list:
        if p.ip_address == ip_address:
            print(f"Panorama {ip_address} already in database.  Exiting...")
            exit()

    try:
        xapi = pan.xapi.PanXapi(api_username=username, api_password=password, hostname=ip_address)

        # Show the system info
        xapi.op("<show><system><info></info></system></show>")
        system_info = xmltodict.parse('<root>' + xapi.xml_result() + '</root>')['root']

        if 'system-mode' not in system_info['system']:
            print(f"Device at {ip_address} is not a Panorama.  Exiting...")
            exit()

        # Show the HA info
        xapi.op("<show><high-availability><state></state></high-availability></show>")
        ha_info = xmltodict.parse('<root>' + xapi.xml_result() + '</root>')['root']

        if ha_info['enabled'] == 'yes':
            if 'active' in ha_info['local-info']['state']:
                active = True
            else:
                active = False
            alt_ip = ha_info['peer-info']['mgmt-ip']
        else:
            active = True
            alt_ip = None


    except pan.xapi.PanXapiError as e:
        print(f"Issue connecting to Panorama.  Error: {e}")
        exit()
    except Exception as e:
        print(f"Issue loading the Panorama to the database.  Error: {e}")
        exit()
    
    new_panorama = Panorama(hostname=system_info['system']['hostname'], ip_address=ip_address, alt_ip=alt_ip, active=active, api_key=xapi.api_key)

    session.add(new_panorama)

    session.commit()

    print(f"+ {system_info['system']['hostname']} added to database") 

    return system_info['system']['hostname']

def __load_ngfw(ip_address, username, password) -> None:
    """
    This method adds a ngfw to the database
    """
    # Create the database engine
    try:
        engine = create_engine(db_uri)
        Session = sessionmaker(bind=engine)
        session = Session()
    except Exception as e:
        print(f"Issue connecting to the database.  Error: {e}")

    # Create list of serial numbers in the database
    serial_numbers = []

    try:
        ngfw_list = session.query(Ngfw).all()
    except Exception as e:
        print(f"Issue querying the database.  Likley need to build the database first.")
        exit()

    for n in ngfw_list:
        serial_numbers.append(n.serial_number)
    
    try:
        xapi = pan.xapi.PanXapi(api_username=username, api_password=password, hostname=ip_address)
        
        # Show the system info
        xapi.op("<show><system><info></info></system></show>")
        device_info = xmltodict.parse('<root>' + xapi.xml_result() + '</root>')['root']
        
        # if PA- not in model, exit
        if 'PA-' not in device_info['system']['model']:
            print(f"Device at {ip_address} is not a NGFW.  Exiting...")
            exit()

        # Show the HA info
        xapi.op("<show><high-availability><state></state></high-availability></show>")
        ha_info = xmltodict.parse('<root>' + xapi.xml_result() + '</root>')['root']

        ngfw_info = {
            'hostname': device_info['system']['hostname'],
            'serial_number': device_info['system']['serial'],
            'ip_address': ip_address,
            'api_key': xapi.api_key,
            'panorama_id': None
        }

        # If serial number is not in serial_numbers, add to the database
        if ngfw_info['serial_number'] in serial_numbers:
            print(f"* {ngfw_info['hostname']} {ngfw_info['serial']} already in database.")
            exit()

        # Determine HA status
        if ha_info['enabled'] == 'yes':

            # If ha state is active, set active to true and alt_serial to peer serial number
            if ha_info['group']['local-info']['state'] == 'active':
                ngfw_info['active'] = True
            else:
                ngfw_info['active'] = False
            
            ngfw_info['alt_serial'] = device_info['serial'],
            ngfw_info['alt_ip'] = device_info['group']['peer-info']['mgmt-ip']

        else:
            ngfw_info['active'] = True
            ngfw_info['alt_serial'] = None
            ngfw_info['alt_ip'] = None
        
        new_ngfw = Ngfw(**ngfw_info)

        session.add(new_ngfw)

        print(f"+ {ngfw_info['hostname']} {new_ngfw.serial_number} added to database") 
            
        session.commit()

        return ngfw_info['hostname']

    except pan.xapi.PanXapiError as e:
        print(f"Issue connecting to Panorama.  Error: {e}")
        exit()

def build_database() -> None:
    """
    This method builds the database
    """
    try:
        # Create the database engine
        engine = create_engine(db_uri)

        # Create the tables in the database
        Base.metadata.create_all(engine)

        print("Empty database successfully created!")
    except Exception as e:
        print(f"Issue connecting to the database.  Error: {e}")
        exit()

def add_ngfw(username=None, password=None, ip_address=None):
    """
    This method adds a panorama to the database
    """
    # Get hostname, ip address, alt ip, and active from user input
    if ip_address is None:
        ip_address = input("Enter the IP address (can be fqdn): ")
    if username is None:
        username = input("Enter the username: ")
    if password is None:
        password = getpass("Enter password: ")

    # Add the panorama to the database
    hostname = __load_ngfw(ip_address=ip_address, username=username, password=password)
    print(f"!!WARINING!! API key is stored in plaintext in the database.  Set appropriate permissions on the database.")

def add_panorama(username=None, password=None, ip_address=None):
    """
    This method adds a panorama to the database
    """
    # Get hostname, ip address, alt ip, and active from user input
    if ip_address is None:
        ip_address = input("Enter the IP address (can be fqdn): ")
    if username is None:
        username = input("Enter the username: ")
    if password is None:
        password = getpass("Enter password: ")

    # Add the panorama to the database
    hostname = __load_panorama(ip_address=ip_address, username=username, password=password)
    print(f"!!WARINING!! API key is stored in plaintext in the database.  Set appropriate permissions on the database.")

if __name__ == "__main__":
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Companion tools to the mt-cli")
    parser.add_argument("-b", "--build-db", action="store_true", help="Create the empty database at uri specified in config")
    parser.add_argument("-p", "--add-panorama", action="store_true", help="Add a Panorama to the database via prompt")
    parser.add_argument("-n", "--add-ngfw", action="store_true", help="Add a non-managed firewall to the database via prompt")
    parser.add_argument("--ip-address", type=str, default=None, help="IP address (or fqdn) of Panorama or NGFW (prompt if not included)")
    parser.add_argument("--username", type=str, default=None, help="Username for Panorama or NGFW (prompt if not included)")
    parser.add_argument("--password", type=str, default=None, help="Password for Panorama or NGFW (prompt if not included)")

    args = parser.parse_args()

    # If build-db is specified, build the database
    if args.build_db:
        build_database()

    if args.add_panorama:
        add_panorama(username=args.username, password=args.password, ip_address=args.ip_address)

    if args.add_ngfw:
        add_ngfw(username=args.username, password=args.password, ip_address=args.ip_address)