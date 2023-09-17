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

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from config import db_uri
from mt_controller import MTController, MTControllerException

# Create the database engine
engine = create_engine(db_uri)

# Create a session to interact with the database
Session = sessionmaker(bind=engine)
session = Session()
# Create an instance of the MtController class with db_uri, username, password, panorama_id

# TODO: Determine appropriate location for this code
try:
    mt = MTController(db_uri=db_uri)
except MTControllerException as e:
    print(e)
    exit()

def print_inventory():
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


def print_routes(ngfw=None, virtual_router=None, destination=None, flags=None):
    """
    This method prints the routes
    """

    routes = mt.get_routes(
        ngfw=ngfw,
        virtual_router=virtual_router,
        destination=destination,
        flags=flags
    )

    if not routes:
        print(f"No routes found.")
        return

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

    __print_results(headers, routes)

def print_interfaces(ngfw=None, virtual_router=None, on_demand=False):
    """
    This method prints the interfaces
    """

    if on_demand:
        interfaces, message = mt.show_interfaces(ngfw=ngfw, virtual_router=virtual_router)
    else:
        interfaces, message = mt.get_interfaces(
            ngfw=ngfw,
            virtual_router=virtual_router
        )
        
    if not interfaces:
        print(f"No interfaces found.")
        return None, None
    
    headers = {
        "NGFW": "ngfw",
        "Virtual Router": "virtual_router",
        "Name": "name",
        "Tag": "tag",
        "Address": "ip",
        "Zone": "zone"
    }

    __print_results(headers, interfaces)

    if not message:
        pass
    else:
        print()
        print("\n".join(message))

def print_virtual_routers(ngfw=None):
    """
    This method prints the virtual routers
    """

    virtual_routers = mt.get_virtual_routers(ngfw=ngfw)

    if not virtual_routers:
        print(f"No virtual-routers found.")
        return
    
    headers = {
        "Hostname": "hostname",
        "Virtual Router": "virtual_router",
        "Route Count": "route_count",
        "Interface Count": "interface_count"
    }

    __print_results(headers, virtual_routers)

def print_ngfws(panorama=None):
    """
    This method prints the ngfws
    """

    ngfws_list = mt.get_ngfws(panorama=panorama)

    if not ngfws_list:
        print(f"No ngfws found.")
        return
    
    headers = {
        "Hostname": "hostname",
        "Serial Number": "serial_number",
        "IP Address": "ip_address",
        "Alt Serial": "alt_serial",
        "Active": "active",
        "Panorama": "panorama"
    }

    __print_results(headers, ngfws_list)

def print_panorama():
    """
    This method prints the panorama
    """

    # Query the database for the panorama
    panorama = mt.get_panoramas()

    if not panorama:
        print(f"No panorama found.")
        return
    
    headers = {
        "Hostname": "hostname",
        "IP Address": "ip_address",
        "Alt IP": "alt_ip",
        "Active": "active"
    }

    __print_results(headers, panorama)

def test_fib_lookup(ip_address, vr_query=None, ngfw_query=None, on_demand=False):
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
        results, message = mt.test_fib_lookup(ip_address=ip_address, vr_query=vr_query, ngfw_query=ngfw_query)    
    else:
        results, message = mt.calculate_fib_lookup(ip_address=ip_address, vr_query=vr_query, ngfw_query=ngfw_query)

    if not results:
        print(f"No fib-test results returned.")
        return

    headers = {
        "NGFW": "ngfw",
        "Virtual Router": "virtual_router",
        "Interface": "interface",
        "Next Hop": "nexthop",
        "Zone": "zone"
    }

    __print_results(headers, results)

    if not message:
        pass
    else:
        print()
        print("\n".join(message))

def show_lldp_neighbors(ngfw=None, on_demand=False):
    """
    This method shows the lldp neighbors
    """

    if on_demand:
        lldp_neighbors, message = mt.show_lldp_neighbors(ngfw=ngfw)
    else:
        lldp_neighbors, message = mt.get_neighbors(ngfw=ngfw)

    if not lldp_neighbors:
        print(f"No lldp neighbors found.")
        return
    
    headers = {
        "NGFW": "ngfw",
        "Local Interface": "local_interface",
        "Remote Interface ID": "remote_interface_id",
        "Remote Interface Description": "remote_interface_description",
        "Remote Hostname": "remote_hostname"
    }

    __print_results(headers, lldp_neighbors)

    if not message:
        pass
    else:
        print()
        print("\n".join(message))

def show_bgp_peers(ngfw=None, virtual_router=None, on_demand=False):
    """
    This method shows the bgp peers
    """

    if on_demand:
        bgp_peers, message = mt.show_bgp_peers(ngfw=ngfw, virtual_router=virtual_router)
    else:
        bgp_peers, message  = mt.get_bgp_peers(ngfw=ngfw, virtual_router=virtual_router)

    if not bgp_peers:
        print(f"No bgp peers found.")
        return
    
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

    __print_results(headers, bgp_peers)

    if not message:
        pass
    else:
        print()
        print("\n".join(message))

def refresh_ngfws(ngfw=None):

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

if __name__ == '__main__':
    
    parser = argparse.ArgumentParser(description="Retrieve and print NGFW routes, interfaces and virtual routers.  Perform on demand fib lookups")
    parser.add_argument("-i", "--import-ngfws", action="store_true", help="Import Panorama NGFWs (run before anything else)")
    parser.add_argument("-r", "--refresh", action="store_true", help="Refresh NGFW (no filter will refresh all NGFWs)")
    parser.add_argument("-s", "--show", type=str, default=None, help="Choose what show: 'routes', 'vrs', 'interfaces', or 'ngfws', 'pan','lldp', 'bgp-peers', 'inventory'")
    parser.add_argument("-f", "--fib-lookup", type=str, help="Perform FIB Lookup")
    parser.add_argument("--ha-status", action="store_true", help="Update HA Status")
    parser.add_argument("--vr", type=str, default=None, help="Virtual Router filter for various commands")
    parser.add_argument("--pan", type=str, default=None, help="Panorama for various commands")
    parser.add_argument("--ngfw", type=str, default=None, help="NGFW filter for various commands")
    parser.add_argument("--dst", type=str, default=None, help="Destination filter for routes")
    parser.add_argument("--flag", type=str, default=None, help="Comma separated flags for routes")
    parser.add_argument("--on-demand", action="store_true", help="On demand API call vs querying the database.")
    parser.add_argument("--logging", action="store_true", help="Trun logging to the terminal on")
    
    args = parser.parse_args()

    try:
        # If refresh-ngfws is selected, refresh the ngfws
        if args.refresh:
            refresh_ngfws(ngfw=args.ngfw)

        # If import is selected, import the panorama ngfws
        if args.import_ngfws:
            messages = mt.import_panorama_devices()
            print("\n".join(messages))

        # If ha-status is selected, update the ha status
        if args.ha_status:
            message = mt.update_ha_status()
            if message:
                print("\n".join(message))
            else:
                print("No HA NGFWs configured.")

        # Fib Lookup is selected, perform the fib lookup
        if args.fib_lookup:
            test_fib_lookup(ip_address=args.fib_lookup, vr_query=args.vr, ngfw_query=args.ngfw, on_demand=args.on_demand)

        # Show is selected
        if args.show:
            if args.show == 'routes':
                print_routes(virtual_router=args.vr, ngfw=args.ngfw, destination=args.dst, flags=args.flag)
            elif args.show == 'interfaces':
                print_interfaces(virtual_router=args.vr, ngfw=args.ngfw, on_demand=args.on_demand)
            elif args.show == 'vrs':
                print_virtual_routers(ngfw=args.ngfw)
            elif args.show == 'ngfws':
                print_ngfws(panorama=args.pan)
            elif args.show == 'pan':
                print_panorama()
            elif args.show == 'lldp':
                show_lldp_neighbors(ngfw=args.ngfw, on_demand=args.on_demand)
            elif args.show == 'bgp-peers':
                show_bgp_peers(ngfw=args.ngfw, virtual_router=args.vr, on_demand=args.on_demand)
            elif args.show == 'inventory':
                print_inventory()
            else:
                print ("Invalid show option.  Valid options are 'routes', 'vrs', 'interfaces', 'ngfws', 'pan', 'lldp', 'bgp-peers'")

    except MTControllerException as e:
        print(e)
        exit()