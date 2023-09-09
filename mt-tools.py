import argparse
import logging
from getpass import getpass

import pan.xapi
import xmltodict
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from config import db_uri

from models import Base, Panorama

# Set the SQLAlchemy engine's logging level to WARNING
logging.getLogger('sqlalchemy.engine').setLevel(logging.WARNING)
def __load_panorama(hostname, ip_address, username, password) -> None:
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
        print(f"Issue querying the database.  Likley need to build the database first.")
        exit()  

    # If the panorama is already in the database, exit
    for p in pan_list:
        if p.ip_address == ip_address:
            print(f"Panorama {ip_address} already in database.  Exiting...")
            exit()

    try:
        xapi = pan.xapi.PanXapi(api_username=username, api_password=password, hostname=ip_address)

        xapi.op("<show><system><info></info></system></show>")
        system_info = xmltodict.parse('<root>' + xapi.xml_result() + '</root>')['root']

        if 'system-mode' not in system_info['system']:
            print(f"Device at {ip_address} This is not a Panorama.  Exiting...")
            exit()

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
    
    new_panorama = Panorama(hostname=hostname, ip_address=ip_address, alt_ip=alt_ip, active=active, api_key=xapi.api_key)
    session.add(new_panorama)
    session.commit()

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

def add_panorama():
    """
    This method adds a panorama to the database
    """
    # Get hostname, ip address, alt ip, and active from user input
    hostname = input("Enter the hostname (for display purposes): ")
    ip_address = input("Enter the IP address (can be fqdn): ")
    username = input("Enter the username: ")
    password = getpass("Enter password: ")

    # Add the panorama to the database
    __load_panorama(hostname=hostname, ip_address=ip_address, username=username, password=password)
    print(f"Panorama {hostname} successfully added to the database!")
    print(f"!!WARINING!! API key is stored in plaintext in the database.  Set appropriate permissions on the database.")

if __name__ == "__main__":
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Companion tools to the mt-cli")
    parser.add_argument("-b", "--build-db", action="store_true", help="Create the empty database at uri specified in config")
    parser.add_argument("-a", "--add-panorama", action="store_true", help="Add a Panorama to the database via prompt")

    args = parser.parse_args()

    # If build-db is specified, build the database
    if args.build_db:
        build_database()

    if args.add_panorama:
        add_panorama()