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

    # Print Header
    print("{:<20} {:<15} {:<20} {:<20} {:<10} {:<10} {:<15} {:<15} {:<5} {:<15}".format("NGFW", "Virtual Router", "Destination", "Next Hop", "Metric", "Flags", "Interface", "Route Table", "Age", "Zone"))

    for r in routes:
        print("{:<20} {:<15} {:<20} {:<20} {:<10} {:<10} {:<15} {:<15} {:<5} {:<15}".format(
            r['ngfw'],
            r['virtual_router'],
            r['destination'],
            r['nexthop'],
            r['metric'],
            r['flags'],
            r['interface'],
            r['route_table'],
            r['age'],
            r['zone']
        ))

def print_interfaces(ngfw=None, virtual_router=None):
    """
    This method prints the interfaces
    """

    interfaces = mt.get_interfaces(
        ngfw=ngfw,
        virtual_router=virtual_router
    )
        
    if not interfaces:
        print(f"No interfaces found.")
        return
        
    # Print Header for interfaces
    print("{:<20} {:<15} {:<20} {:<10} {:<20} {:<10}".format("NGFW", "Virtual Router", "Name", "Tag", "Address", "Zone"))
    
    # Print each interface, interfaces are in formatted dictionary
    for i in interfaces:
        print("{:<20} {:<15} {:<20} {:<10} {:<20} {:<10}".format(
            i['ngfw'],
            i['virtual_router'],
            i['name'],
            i['tag'],
            i['ip'] or "None",
            i['zone']
        ))

def print_virtual_routers(ngfw=None):
    """
    This method prints the virtual routers
    """

    virtual_routers = mt.get_virtual_routers(ngfw=ngfw)

    if not virtual_routers:
        print(f"No virtual-routers found.")
        return
    
    # Print Header for virtual routers
    print("{:<20} {:<15} {:<15} {:<15}".format("NGFW", "Virtual Router", "Route Count", "Interface Count"))

    # For each virtual-router print the hostname, virtual router, route count, and interface count
    for vr in virtual_routers:
        print("{:<20} {:<15} {:<15} {:<15}".format(
            vr['hostname'],
            vr['virtual_router'],
            vr['route_count'],
            vr['interface_count']
        ))

def print_ngfws(panorama=None):
    """
    This method prints the ngfws
    """

    ngfws_list = mt.get_ngfws(panorama=panorama)

    if not ngfws_list:
        print(f"No ngfws found.")
        return
    
    # Print Header for ngfws
    print("{:<20} {:<15} {:<15} {:<15} {:<15} {:<15}".format("Hostname", "Serial Number", "IP Address", "Alt Serial", "Active", "Panorama"))

    # For each ngfw get the hostname, serial number, ip address, alt serial, active, and panorama
    for n in ngfws_list:
        print("{:<20} {:<15} {:<15} {:<15} {:<15} {:<15}".format(
            n['hostname'],
            n['serial_number'],
            n['ip_address'],
            n['alt_serial'] or 'None',
            'yes' if n['active'] == 1 else 'no',  # Convert 1 to 'yes' and 0 to 'no'
            n['panorama']
        ))

def print_panorama():
    """
    This method prints the panorama
    """

    # Query the database for the panorama
    panorama = mt.get_panoramas()

    if not panorama:
        print(f"No panorama found.")
        return
    
    # Print Header for panorama
    print("{:<20} {:<15} {:<15} {:<15}".format("Hostname", "IP Address", "Alt IP", "Active"))

    # Loop through panorama list and print each panorama's data
    for p in panorama:
        print("{:<20} {:<15} {:<15} {:<15}".format(
            p['hostname'],
            p['ip_address'],
            p['alt_ip'] or 'None',
            'yes' if p['active'] == 1 else 'no',  # Convert 1 to 'yes' and 0 to 'no'
        ))

def test_fib_lookup(ip_address, vr_query=None, ngfw_query=None):
    """
    This method tests the fib lookup
    """

    # Verify the ip_address is a valid IPv4 address
    try:
        ip_address = ipaddress.IPv4Address(ip_address)
    except ValueError:
        print("Invalid IP address")
        return
    
    results = mt.test_fib_lookup(ip_address=ip_address, vr_query=vr_query, ngfw_query=ngfw_query)

    if not results:
        print(f"No fib-tet results returned.")
        return

    # Print a header
    print("{:<20} {:<15} {:<20} {:<20} {:<20}".format("NGFW", "Virtual Router", "Interface", "Next Hop", "Zone"))

    # For each result print
    for r in results:
        print("{:<20} {:<15} {:<20} {:<20} {:<20}".format(
            r['hostname'],
            r['virtual_router'],
            r['interface'],
            r['nexthop'],
            r['zone']
        ))

def show_lldp_neighbors(ngfw=None):
    """
    This method shows the lldp neighbors
    """

    lldp_neighbors = mt.show_lldp_neighbors()

    if not lldp_neighbors:
        print(f"No lldp neighbors found.")
        return
    
    # Print headers
    print("{:<20} {:<15} {:<15} {:<25} {:<25}".format("NGFW", "Interface","Remote Int ID", "Remote Int Description", "Remote Hostname"))

    # For each lldp neighbor print
    for lldp_n in lldp_neighbors:
        print("{:<20} {:<15} {:<15} {:<25} {:<25}".format(
            lldp_n['ngfw'],
            lldp_n['local_interface'],
            lldp_n['remote_interface_id'] or "None",
            lldp_n['remote_interface_description'] or "None",
            lldp_n['remote_hostname'] or "None"
        ))

def show_bgp_peers(ngfw=None, virtual_router=None):
    """
    This method shows the bgp peers
    """

    bgp_peers = mt.show_bgp_peers(ngfw=ngfw, virtual_router=virtual_router)

    if not bgp_peers:
        print(f"No bgp peers found.")
        return
    
    # Print headers
    print("{:<16} {:<15} {:<20} {:<15} {:<20} {:<15} {:<15} {:<10} {:<15} {:<15}".format("NGFW", "Virtual Router", "Peer Name", "Peer Group", "Peer Router ID", "Remote AS", "Status", "Duration", "Peer Address", "Local Address"))

    # For each bgp peer print
    for bgp_p in bgp_peers:
        print("{:<16} {:<15} {:<20} {:<15} {:<20} {:<15} {:<15} {:<10} {:<15} {:<15}".format(
            bgp_p['ngfw'],
            bgp_p['virtual_router'],
            bgp_p['peer_name'],
            bgp_p['peer_group'] or "None",
            bgp_p['peer_router_id'] or "None",
            bgp_p['remote_as'] or "None",
            bgp_p['status'] or "None",
            bgp_p['status_duration'] or "None",
            bgp_p['peer_address'] or "None",
            bgp_p['local_address'] or "None"
        ))

if __name__ == '__main__':
    
    parser = argparse.ArgumentParser(description="Retrieve and print NGFW routes, interfaces and virtual routers.  Perform on demand fib lookups")
    parser.add_argument("-i", "--import-ngfws", action="store_true", help="Import Panorama NGFWs (run before anything else)")
    parser.add_argument("-r", "--refresh", type=str, default=None, help="Refresh DB: routes (filter ngfw and vr), interfaces (filter ngfw), ngfws (filter ngfw), all")
    parser.add_argument("-p", "--print", type=str, default=None, help="Choose what to print: 'routes', 'vrs', 'interfaces', or 'ngfws', 'pan'")
    parser.add_argument("-s", "--show", type=str, default=None, help="Choose what to 'show' on demand: 'lldp'")
    parser.add_argument("-f", "--fib-lookup", type=str, help="Perform FIB Lookup")
    parser.add_argument("--ha-status", action="store_true", help="Update HA Status")
    parser.add_argument("--vr", type=str, default=None, help="Virtual Router filter for various commands")
    parser.add_argument("--pan", type=str, default=None, help="Panorama for various commands")
    parser.add_argument("--ngfw", type=str, default=None, help="NGFW filter for various commands")
    parser.add_argument("--dst", type=str, default=None, help="Destination filter for routes")
    parser.add_argument("--flag", type=str, default=None, help="Comma separated flags for routes")
    
    args = parser.parse_args()

    # If refresh-ngfws is selected, refresh the ngfws
    if args.refresh:
        if args.refresh == 'routes':
            mt.refresh_routes(ngfw=args.ngfw, virtual_router=args.vr)
        elif args.refresh == 'interfaces':
            mt.refresh_interfaces(ngfw=args.ngfw)
        elif args.refresh == 'ngfws':
            mt.refresh_ngfws(ngfw=args.ngfw)
        elif args.refresh == 'all':
            mt.refresh_ngfws()
        else:
            print ("Invalid refresh option.  Valid options are 'routes', 'interfaces', 'ngfws', and 'all'")

    # If lldp is selected, show lldp neighbors
    if args.show:
        if args.show == 'lldp':
            show_lldp_neighbors(ngfw=args.ngfw)
        elif args.show == 'bgp-peers':
            show_bgp_peers(ngfw=args.ngfw, virtual_router=args.vr)
        else:
            print("Invalid show option.  Valid options are 'lldp'")

    # If import is selected, import the panorama ngfws
    if args.import_ngfws:
        messages = mt.import_panorama_devices()
        print("\n".join(messages))

    # If ha-status is selected, update the ha status
    if args.ha_status:
        messages = mt.update_ha_status()
        if messages:
            print("\n".join(messages))
        else:
            print("No HA NGFWs configured.")

    # Fib Lookup is selected, perform the fib lookup
    if args.fib_lookup:
        fib_value = args.fib_lookup
        # If --vr argument is present, pass it to the test_fib_lookup function
        if args.vr and args.ngfw:
            virtual_router = args.vr
            ngfw = args.ngfw
            test_fib_lookup(ip_address=fib_value, vr_query=virtual_router, ngfw_query=ngfw)
        elif args.ngfw:
            ngfw = args.ngfw
            test_fib_lookup(ip_address=fib_value, ngfw_query=ngfw)
        elif args.vr and not args.ngfw:
            virtual_router = args.vr
            test_fib_lookup(ip_address=fib_value, vr_query=virtual_router)
        else:
            test_fib_lookup(ip_address=fib_value)

    # Print is selected, print the routes
    if args.print:
        if args.print == 'routes':
            print_routes(virtual_router=args.vr, ngfw=args.ngfw, destination=args.dst, flags=args.flag)
        elif args.print == 'interfaces':
            print_interfaces(virtual_router=args.vr, ngfw=args.ngfw)
        elif args.print == 'vrs':
            print_virtual_routers(ngfw=args.ngfw)
        elif args.print == 'ngfws':
            print_ngfws(panorama=args.pan)
        elif args.print == 'pan':
            print_panorama()
        else:
            print ("Invalid print option.  Valid options are 'routes', 'interfaces', 'vrs', 'ngfws', and 'pan'")