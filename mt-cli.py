# MIT License

# Copyright (c) 2023 josephberger

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import argparse
import ipaddress
from getpass import getpass

from config import db_uri, timeout
from mt_controller import MTController, MTControllerException, MTBuilder, MTBuilderException


def print_inventory(mt):
    """
    This method prints the inventory
    """

    inventory = mt.get_inventory()

    # Find the length of the longest key for consistent spacing
    max_key_length = max(len(key) for key in inventory.keys())

    # Iterate through the dictionary and print each item with consistent spacing
    for key, value in inventory.items():
        spacing = ' ' * (max_key_length - len(key))  # Calculate spacing based on key length
        print(f'{key}: {spacing}{value}')


def print_routes(mt,ngfw=None, virtual_router=None, destination=None, flags=None):
    """
    This method prints the routes
    """

    response = mt.get_routes(
        ngfw=ngfw,
        virtual_router=virtual_router,
        destination=destination,
        flags=flags
    )

    if response['results']:

        # Print Legend
        print("""\nflags: A:active, ?:loose, C:connect, H:host, S:static, ~:internal, R:rip, O:ospf, B:bgp,
        Oi:ospf intra-area, Oo:ospf inter-area, O1:ospf ext-type-1, O2:ospf ext-type-2, E:ecmp, M:multicast\n""")

        headers = {
            "NGFW": "ngfw",
            "Virtual Router": "virtual_router",
            "Destination": "destination",
            "Next Hop": "nexthop",
            "Metric": "metric",
            "Flags": "flags",
            "Interface": "interface",
            "Route Table": "route_table",
            "Age": "age",
            "Zone": "zone"
        }

        __print_results(headers, response['results'])

    if response['message']:
        print("\n".join(response['message']))

def print_interfaces(mt,ngfw=None, virtual_router=None, on_demand=False):
    """
    This method prints the interfaces
    """

    if on_demand:
        response = mt.show_interfaces(ngfw=ngfw, virtual_router=virtual_router)
    else:
        response = mt.get_interfaces(ngfw=ngfw,virtual_router=virtual_router)
        
    if response['results']:
    
        headers = {
            "NGFW": "ngfw",
            "Virtual Router": "virtual_router",
            "Name": "name",
            "Tag": "tag",
            "Address": "ip",
            "Zone": "zone"
        }

        __print_results(headers, response['results'])

    if response['message']:
        print("\n".join(response['message']))

def print_virtual_routers(mt,ngfw=None):
    """
    This method prints the virtual routers
    """

    response = mt.get_virtual_routers(ngfw=ngfw)

    if response['results']:
    
        headers = {
            "Hostname": "hostname",
            "Virtual Router": "virtual_router",
            "Route Count": "route_count",
            "Interface Count": "interface_count"
        }

        __print_results(headers, response['results'])

    if response['message']:
        print("\n".join(response['message']))

def print_ngfws(mt,panorama=None):
    """
    This method prints the ngfws
    """

    response = mt.get_ngfws(panorama=panorama)

    if response['results']:
        headers = {
            "Hostname": "hostname",
            "Serial Number": "serial_number",
            "IP Address": "ip_address",
            "Alt Serial": "alt_serial",
            "Active": "active",
            "Panorama": "panorama",
            "Last Refresh": "last_update"
        }

        __print_results(headers, response['results'])
    
    if response['message']:
        print("\n".join(response['message']))

def print_panorama(mt):
    """
    This method prints the panorama
    """

    # Query the database for the panorama
    response = mt.get_panoramas()

    if response['results']:
    
        headers = {
            "Hostname": "hostname",
            "Serial": "serial_number",
            "IP Address": "ip_address",
            "Alt IP": "alt_ip",
            "Active": "active",
            "NGFWs": "ngfws"
        }

        __print_results(headers, response['results'])

    if response['message']:
        print("\n".join(response['message']))

def test_fib_lookup(mt,ip_address, vr_query=None, ngfw_query=None, on_demand=False):
    """
    This method tests the fib lookup
    """

    # Verify the ip_address is a valid IPv4 address
    try:
        ip_address = ipaddress.IPv4Address(ip_address)
    except ValueError:
        print(f"'{ip_address}' is an invalid IPv4 address")
        return

    if on_demand:
        response = mt.test_fib_lookup(ip_address=ip_address, vr_query=vr_query, ngfw_query=ngfw_query)    
    else:
        response = mt.calculate_fib_lookup(ip_address=ip_address, vr_query=vr_query, ngfw_query=ngfw_query)

    if response['results']:

        headers = {
            "NGFW": "ngfw",
            "Virtual Router": "virtual_router",
            "Interface": "interface",
            "Next Hop": "nexthop",
            "Zone": "zone"
        }

        __print_results(headers, response['results'])

    if response['message']:
        print("\n".join(response['message']))

def print_neighbors(mt,ngfw=None, on_demand=False):
    """
    This method shows the lldp neighbors
    """

    if on_demand:
        response = mt.show_neighbors(ngfw=ngfw)
    else:
        response = mt.get_neighbors(ngfw=ngfw)

    if response['results']:
    
        headers = {
            "NGFW": "ngfw",
            "Local Interface": "local_interface",
            "Remote Interface ID": "remote_interface_id",
            "Remote Interface Description": "remote_interface_description",
            "Remote Hostname": "remote_hostname"
        }

        __print_results(headers, response['results'])

    if response['message']:
        print("\n".join(response['message']))

def print_bgp_peers(mt,ngfw=None, virtual_router=None, on_demand=False):
    """
    This method shows the bgp peers
    """


    if on_demand:
        response = mt.show_bgp_peers(ngfw=ngfw, virtual_router=virtual_router)
    else:
        response = mt.get_bgp_peers(ngfw=ngfw, virtual_router=virtual_router)

    if response['results']:

        headers = {
            "NGFW": "ngfw",
            "Virtual Router": "virtual_router",
            "Peer Name": "peer_name",
            "Peer Group": "peer_group",
            "Peer Router ID": "peer_router_id",
            "Remote AS": "remote_as",
            "Status": "status",
            "Duration": "status_duration",
            "Peer Address": "peer_address",
            "Local Address": "local_address"
        }

        __print_results(headers, response['results'])

    if response['message']:
        print("\n".join(response['message']))

def refresh_ngfws(mt,ngfw=None):

    if not ngfw:
        ngfw_count = int(mt.get_inventory()['NGFWs'])

        if ngfw_count > 1:

            choice = input(f"Are you sure you want to refresh all {ngfw_count} NGFWs for a total of {4*ngfw_count} API calls? (y/n): ")

            if choice.lower().strip() == 'y':
                print(f"Refreshing {ngfw_count} NGFWs.  This may take some time...")
            else:
                exit()

    message = mt.refresh_ngfws(ngfw=ngfw)

    print("\n".join(message))

def add_panorama(mb, username=None, password=None, ip_address=None):
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
    try:
        response = mb.add_panorama(ip_address=ip_address, username=username, password=password)
        print(response)
        print(f"!!WARINING!! API key is stored in plaintext in the database.  Set appropriate permissions on the database.")
    except MTBuilderException as e:
        print(e)
        exit()

def add_ngfw(mb, username=None, password=None, ip_address=None):
    """
    This method adds a ngfw to the database
    """
    # Get hostname, ip address, alt ip, and active from user input
    if ip_address is None:
        ip_address = input("Enter the IP address (can be fqdn): ")
    if username is None:
        username = input("Enter the username: ")
    if password is None:
        password = getpass("Enter password: ")

    # Add the panorama to the database
    try:
        response = mb.add_ngfw(ip_address=ip_address, username=username, password=password)
        print(response)
        print(f"!!WARINING!! API key is stored in plaintext in the database.  Set appropriate permissions on the database.")
    except MTBuilderException as e:
        print(e)
        exit()

def delete_panorama(mb, serial_number=None):
    """
    This method deletes a panorama from the database
    """
    # Get serial number from user input
    if serial_number is None:
        serial_number = input("Enter the serial number: ")

    # Delete the panorama from the database
    try:
        response = mb.delete_panorama(serial_number=serial_number)
        print(response)
    except MTBuilderException as e:
        print(e)
        exit()

def delete_ngfw(mb, serial_number=None):
    """
    This method deletes a ngfw from the database
    """
    # Get serial number from user input
    if serial_number is None:
        serial_number = input("Enter the serial number: ")

    # Delete the ngfw from the database
    try:
        response = mb.delete_ngfw(serial_number=serial_number)
        print(response)
    except MTBuilderException as e:
        print(e)
        exit()



def __print_results(headers, results):

    if not results:
        return

    def calculate_max_widths():
        max_widths = {}
        for header, key in headers.items():
            header_width = len(str(header))
            value_width = max(len(str(r[key])) for r in results)
            max_widths[header] = max(header_width, value_width)
        return max_widths

    def create_format_string(max_widths):
        spacing = 2
        return " ".join(f"{{:<{width+spacing}}}" for width in max_widths.values())

    def print_header(format_string):
        header_str = format_string.format(*headers.keys())
        print(header_str)

    def print_data(format_string):
        for r in results:
            result_values = [r[key] for key in headers.values()]
            result_str = format_string.format(*result_values)
            print(result_str)

    max_widths = calculate_max_widths()
    format_string = create_format_string(max_widths)

    print_header(format_string)
    print_data(format_string)
    print()

if __name__ == '__main__':
    
    parser = argparse.ArgumentParser(description="Retrieve and print NGFW routes, interfaces and virtual routers.  Perform on demand fib lookups")
    
    # Subcommands
    subparsers = parser.add_subparsers(title="Commands", metavar="", dest="command")

    try:
        # try to create the MT Controller object to verify the database is available
        mt = MTController(db_uri=db_uri, timeout=timeout)
        mt.get_inventory()
    except:
        mt = None

    if mt:
        # Subcommand 'add'
        parser_add = subparsers.add_parser("add", help="Add Panorama or NGFW to the database")
        parser_add.add_argument("devicetype", help="Panorama or NGFW")
        parser_add.add_argument("-H", "--host", type=str, default=None, help="IP address (or fqdn) of Panorama or NGFW (prompt if not included)")
        parser_add.add_argument("-u", "--username", type=str, default=None, help="Username for Panorama or NGFW (prompt if not included)")
        parser_add.add_argument("-p", "--password", type=str, default=None, help="Password for Panorama or NGFW (prompt if not included)")

        # Subcommand 'delete'
        parser_delete = subparsers.add_parser("delete", help="Delete Panorama or NGFW from the database")
        parser_delete.add_argument("devicetype", help="Panorama or NGFW")
        parser_delete.add_argument("-s", "--serial", type=str, default=None, help="Serial of device (prompt if not included)")

        # Subcommand 'import'
        parser_import = subparsers.add_parser("import", help="Import Panorama NGFWs (run before anything else if using Panorama)")
        parser_import.add_argument("--pan", type=str, default=None, help="Which Panorama to import")

        # Subcommand 'refresh'
        parser_refresh = subparsers.add_parser("refresh", help="Refresh NGFW (no filter will refresh all NGFWs)")
        parser_refresh.add_argument("--ngfw", type=str, default=None, help="Which NGFW to refresh")

        # Subcommand 'show'
        parser_show = subparsers.add_parser("show", help="Show: routes, vrs, interfaces, ngfws, pan, lldp, bgp-peers, inventory")
        parser_show.add_argument("option", help="routes, vrs, interfaces, ngfws, pan, lldp, bgp-peers, inventory")
        parser_show.add_argument("--pan", type=str, default=None, help="Filter Panorama (ngfws)")
        parser_show.add_argument("--ngfw", type=str, default=None, help="Filter NGFW")
        parser_show.add_argument("--vr", type=str, default=None, help="Filter virtual router")
        parser_show.add_argument("--dst", type=str, default=None, help="Filter destination (routes)")
        parser_show.add_argument("--flag", type=str, default=None, help="Filter comma separated flags (routes)")
        parser_show.add_argument("--on-demand", action="store_true", help="On demand API call vs querying the database")

        # Subcommand 'fib'
        parser_fib = subparsers.add_parser("fib", help="Perform FIB Lookup")
        parser_fib.add_argument("address", help="IPv4 address for FIB lookup.")
        parser_fib.add_argument("--ngfw", type=str, default=None, help="Filter NGFW")
        parser_fib.add_argument("--vr", type=str, default=None, help="Filter virtual router")
        parser_fib.add_argument("--on-demand", action="store_true", help="On demand API call vs routing calculation")

        # Subcommand 'update-ha'
        parser_updateha = subparsers.add_parser("update-ha", help="Update HA Status")
        parser_updateha.add_argument("--pan", type=str, default=None, help="Filter Panorama")
        parser_updateha.add_argument("--ngfw", type=str, default=None, help="Filter NGFW")
    else:
        # Subcommand 'build-db'
        parser_build = subparsers.add_parser("build-db", help="Build the database (must be run before anything else)")

    args = parser.parse_args()
    
    mb = MTBuilder(db_uri=db_uri)

    if args.command == "build-db":
        message = mb.build_database()
        print(message)

    elif args.command == "add":
        if args.devicetype is None:
            print("device-type is required.")
        elif args.devicetype.lower() == "panorama":
            add_panorama(mb, username=args.username, password=args.password, ip_address=args.host)
        elif args.devicetype.lower() == "ngfw":
            add_ngfw(mb, username=args.username, password=args.password, ip_address=args.host)

    elif args.command == "delete":
        if args.devicetype is None:
            print("device-type is required (Panorama or NGFW).")
        elif args.devicetype.lower() == "ngfw":
            delete_ngfw(mb, serial_number=args.serial)
        elif args.devicetype.lower() == "panorama":
            delete_panorama(mb, serial_number=args.serial)
        else:
            print("Invalid devicetype.  Valid devicetypes are Panorama or NGFW.")

    elif args.command == "import":
        print("Importing Panorama connected NGFWs.")
        messages = mt.import_panorama_devices(pan_filter=args.pan)
        print("\n".join(messages))

    elif args.command == "refresh":
        refresh_ngfws(mt, ngfw=args.ngfw)

    elif args.command == "show":
        if args.option is None:
            print("show option is required.")
        if args.option == 'routes':
            print_routes(mt,virtual_router=args.vr, ngfw=args.ngfw, destination=args.dst, flags=args.flag)
        elif args.option == 'interfaces':
            print_interfaces(mt,virtual_router=args.vr, ngfw=args.ngfw, on_demand=args.on_demand)
        elif args.option == 'vrs':
            print_virtual_routers(mt,ngfw=args.ngfw)
        elif args.option == 'ngfws':
            print_ngfws(mt,panorama=args.pan)
        elif args.option == 'pan':
            print_panorama(mt)
        elif args.option == 'lldp':
            print_neighbors(mt,ngfw=args.ngfw, on_demand=args.on_demand)
        elif args.option == 'bgp-peers':
            print_bgp_peers(mt,ngfw=args.ngfw, virtual_router=args.vr, on_demand=args.on_demand)
        elif args.option == 'inventory':
            print_inventory(mt)
        else:
            print ("Invalid show option.  Valid options are 'routes', 'vrs', 'interfaces', 'ngfws', 'pan', 'lldp', 'bgp-peers', 'ivnentory'")

    elif args.command == "fib":
        test_fib_lookup(mt,ip_address=args.address, vr_query=args.vr, ngfw_query=args.ngfw, on_demand=args.on_demand)

    elif args.command == "update-ha":
        message = mt.update_ha_status()
        if message:
            print("\n".join(message))
        else:
            print("No HA NGFWs configured.")