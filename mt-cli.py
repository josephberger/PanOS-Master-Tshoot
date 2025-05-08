import argparse
import ipaddress
from getpass import getpass
import os
import sys
import logging
import sqlalchemy.exc

# Configuration and backend imports
from config import db_uri, timeout
from mastertshoot.mt_controller import MTController, MTControllerException, MTDatabaseSchemaError
from mastertshoot.mt_builder import MTBuilder, MTBuilderException

# Basic logging setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        #logging.StreamHandler(sys.stdout),  # Output to console
        logging.FileHandler('mt-cli.log')  # Log to file
    ]
)

# ==============================================================================
# Constants
# ==============================================================================
# Command options / Platform types
CMD_ROUTES = 'routes'
CMD_FIBS = 'fibs'
CMD_ARPS = 'arps'
CMD_BGP_PEERS = 'bgp-peers'
CMD_INTERFACES = 'interfaces'
CMD_INTERFACESV6 = 'interfacesv6'
CMD_VRS = 'vrs'
CMD_NGFWS = 'ngfws'
CMD_PAN = 'pan'
CMD_LLDP = 'lldp'
PLATFORM_PANORAMA = 'panorama'
PLATFORM_NGFW = 'ngfw'

# Common Header Keys / Data Keys (adjust keys based on actual controller return values)
HDR_NGFW = "NGFW"
HDR_VR = "Virtual Router"
HDR_DEST = "Destination"
HDR_NEXTHOP = "Next Hop"
HDR_METRIC = "Metric"
HDR_FLAGS = "Flags"
HDR_INTERFACE = "Interface"
HDR_ROUTE_TABLE = "Route Table"
HDR_AGE = "Age"
HDR_ZONE = "Zone"
HDR_NH_TYPE = "Type"
HDR_MTU = "MTU"
HDR_PEER_NAME = "Peer Name"
HDR_PEER_GROUP = "Peer Group"
HDR_PEER_ROUTER_ID = "Peer Router ID"
HDR_REMOTE_AS = "Remote AS"
HDR_STATUS = "Status"
HDR_DURATION = "Duration"
HDR_PEER_ADDRESS = "Peer Address"
HDR_LOCAL_ADDRESS = "Local Address"
HDR_NAME = "Name"
HDR_TAG = "Tag"
HDR_ADDRESS = "Address"
HDR_IP = "IP Address"
HDR_MAC = "MAC Address"
HDR_PORT = "Port"
HDR_TTL = "TTL"
HDR_LOCAL_IF = "Local Interface"
HDR_REMOTE_IF_ID = "Remote Interface ID"
HDR_REMOTE_IF_DESC = "Remote Interface Description"
HDR_REMOTE_HOSTNAME = "Remote Hostname"
HDR_ROUTE_COUNT = "Route Count"
HDR_FIB_COUNT = "Fib Count"
HDR_IF_COUNT = "Interface Count"
HDR_HOSTNAME = "Hostname"
HDR_SERIAL = "Serial Number"
HDR_MODEL = "Model"
HDR_ALT_SERIAL = "Alt Serial"
HDR_ACTIVE = "Active"
HDR_PANORAMA = "Panorama"
HDR_LAST_REFRESH = "Last Refresh"
HDR_ALT_IP = "Alt IP"
HDR_NGFW_COUNT = "NGFWs"
HDR_IPV6_PRESENT = "IPv6"
HDR_IPV6_ADDRESSES = "IPv6 Addresses"

KEY_NGFW = "ngfw"
KEY_VR = "virtual_router"
KEY_DEST = "destination"
KEY_NEXTHOP = "nexthop"
KEY_METRIC = "metric"
KEY_FLAGS = "flags"
KEY_INTERFACE = "interface"
KEY_ROUTE_TABLE = "route_table"
KEY_AGE = "age"
KEY_ZONE = "zone"
KEY_NH_TYPE = "nh_type"
KEY_MTU = "mtu"
KEY_PEER_NAME = "peer_name"
KEY_PEER_GROUP = "peer_group"
KEY_PEER_ROUTER_ID = "peer_router_id"
KEY_REMOTE_AS = "remote_as"
KEY_STATUS = "status"
KEY_DURATION = "status_duration"
KEY_PEER_ADDRESS = "peer_address"
KEY_LOCAL_ADDRESS = "local_address"
KEY_NAME = "name"
KEY_TAG = "tag"
KEY_ADDRESS_IP = "ip"
KEY_LOCAL_IF = "local_interface"
KEY_REMOTE_IF_ID = "remote_interface_id"
KEY_REMOTE_IF_DESC = "remote_interface_description"
KEY_REMOTE_HOSTNAME = "remote_hostname"
KEY_MAC = "mac"
KEY_PORT = "port"
KEY_TTL = "ttl"
KEY_ROUTE_COUNT = "route_count"
KEY_FIB_COUNT = "fib_count"
KEY_IF_COUNT = "interface_count"
KEY_HOSTNAME = "hostname"
KEY_SERIAL = "serial_number"
KEY_IP_ADDRESS = "ip_address"
KEY_MODEL = "model"
KEY_ALT_SERIAL = "alt_serial"
KEY_ACTIVE = "active"
KEY_PANORAMA = "panorama"
KEY_LAST_UPDATE = "last_update"
KEY_ALT_IP = "alt_ip"
KEY_NGFW_COUNT = "ngfws"
KEY_IPV6_PRESENT = "ipv6_present"
KEY_IPV6_ADDRESS_LIST = 'ipv6_address_list'


# ==============================================================================
# Helper Functions (Data Formatting and Printing)
# ==============================================================================

def _print_results(headers, results=None, message=None):
    """
    Formats and prints results in a tabular format.

    Args:
        headers (dict): Dictionary mapping display header names (str) to data keys (str).
                        Example: {"NGFW": "ngfw", "Virtual Router": "virtual_router"}
        results (list[dict], optional): List of dictionaries, where each dictionary is a row
                                         containing data keyed by the values in `headers`. Defaults to None.
        message (list[str], optional): List of strings to print after the table. Defaults to None.
    """
    # --- Check if results is None or empty ---
    if not results:
        if message:
             print() # Add a newline before messages
             print("\n".join(message))
        else:
             print("No results found.") # Inform user if no results and no message
        print() # Add a final newline for spacing
        return # Exit the function early

    # --- Calculate Column Widths ---
    def calculate_max_widths():
        max_widths = {}
        for header, key in headers.items():
            header_width = len(str(header))
            # Ensure key exists in results before accessing, provide default length 0 if not
            # Also handle potential None values in results
            value_width = max((len(str(r.get(key, ''))) for r in results if r is not None), default=0)
            max_widths[header] = max(header_width, value_width)
        return max_widths

    # --- Format Strings ---
    def create_format_string(max_widths):
        spacing = 2
        return " ".join(f"{{:<{width+spacing}}}" for width in max_widths.values())

    # --- Print Header ---
    def print_header(format_string):
        header_str = format_string.format(*headers.keys())
        print(header_str)

    # --- Print Data Rows ---
    def print_data(format_string):
        for r in results:
            if r is None: # Skip if a result row is None
                continue
            # Ensure all keys from headers are present in the result dictionary 'r'
            # Provide a default value (e.g., 'N/A' or '') if a key is missing
            result_values = [r.get(key, 'N/A') for key in headers.values()]
            result_str = format_string.format(*result_values)
            print(result_str)

    # --- Execution ---
    max_widths = calculate_max_widths()
    format_string = create_format_string(max_widths)

    print_header(format_string)
    print_data(format_string)

    # --- Print Optional Messages ---
    if message:
        print() # Add a newline before messages
        print("\n".join(message))

    print() # Add a final newline for spacing

def _print_interfaces_v6(results, message):
    """
    Handles the custom multi-line printing for IPv6 enabled interfaces.

    Args:
        results (list[dict]): List of dictionaries, each representing an interface
                              and containing 'ipv6_address_list'.
        message (list[str]): List of messages from the controller to print afterwards.
    """
    if not results:
        print() # Newline for spacing
        if message:
            print("\n".join(message))
        else:
            # Provide specific message if controller didn't
            print("No IPv6 enabled interfaces found matching criteria.")
        print() # Final newline
        return

    # --- Custom Printing Logic (Moved from handle_show) ---
    hdr_ngfw = HDR_NGFW # "NGFW"
    hdr_vr = HDR_VR     # "Virtual Router"
    hdr_name = HDR_NAME   # "Name"
    hdr_tag = HDR_TAG    # "Tag"
    hdr_zone = HDR_ZONE  # "Zone"
    hdr_ipv6 = HDR_IPV6_ADDRESSES # "IPv6 Addresses"

    # Calculate widths for fixed columns
    col_padding = 2 # Spaces between columns
    max_ngfw_width = max(len(hdr_ngfw), max((len(r.get(KEY_NGFW, '')) for r in results), default=0))
    max_vr_width = max(len(hdr_vr), max((len(r.get(KEY_VR, '')) for r in results), default=0))
    max_name_width = max(len(hdr_name), max((len(r.get(KEY_NAME, '')) for r in results), default=0))
    max_tag_width = max(len(hdr_tag), max((len(str(r.get(KEY_TAG, ''))) for r in results), default=0))
    max_zone_width = max(len(hdr_zone), max((len(r.get(KEY_ZONE, '')) for r in results), default=0))

    # Print Header Row
    header_format = (
        f"{{:<{max_ngfw_width + col_padding}}}"
        f"{{:<{max_vr_width + col_padding}}}"
        f"{{:<{max_name_width + col_padding}}}"
        f"{{:<{max_tag_width + col_padding}}}"
        f"{{:<{max_zone_width + col_padding}}}"
        f"{{}}"
    )
    print(header_format.format(hdr_ngfw, hdr_vr, hdr_name, hdr_tag, hdr_zone, hdr_ipv6))

    separator_length = (max_ngfw_width + col_padding +
                        max_vr_width + col_padding +
                        max_name_width + col_padding +
                        max_tag_width + col_padding +
                        max_zone_width + col_padding +
                        len(hdr_ipv6))

    # Print Data Rows
    base_row_format = (
        f"{{:<{max_ngfw_width + col_padding}}}"
        f"{{:<{max_vr_width + col_padding}}}"
        f"{{:<{max_name_width + col_padding}}}"
        f"{{:<{max_tag_width + col_padding}}}"
        f"{{:<{max_zone_width + col_padding}}}"
    )

    indent_length = (max_ngfw_width + col_padding +
                     max_vr_width + col_padding +
                     max_name_width + col_padding +
                     max_tag_width + col_padding +
                     max_zone_width + col_padding)
    indent = " " * indent_length

    for r in results:
        ngfw = r.get(KEY_NGFW, 'N/A')
        vr = r.get(KEY_VR, 'N/A')
        name = r.get(KEY_NAME, 'N/A')
        tag = str(r.get(KEY_TAG, 'N/A'))
        zone = r.get(KEY_ZONE, 'N/A')
        ipv6_list = r.get(KEY_IPV6_ADDRESS_LIST, []) # Use constant KEY

        first_line = True
        if ipv6_list:
            for ipv6_addr in ipv6_list:
                if first_line:
                    print(base_row_format.format(ngfw, vr, name, tag, zone) + f"{ipv6_addr}")
                    first_line = False
                else:
                    print(f"{indent}{ipv6_addr}")
        else:
            print(base_row_format.format(ngfw, vr, name, tag, zone) + "(No IPv6 Addresses Found)")

    # Print any controller messages after the table
    if message:
        print("\n")
        print("\n".join(message))

    print() # Final newline for spacing

def _confirm_on_demand_scope(ngfw_query, controller, multiplier=1, yes=False):
    """
    Checks if an on-demand operation targets multiple NGFWs and prompts for confirmation.

    Args:
        ngfw_query (str | None): The user's filter for NGFWs (can be None).
        controller (MTController): The controller instance to query inventory.
        multiplier (int): Factor to multiply the NGFW count by for API call estimation.
        yes (bool): If True, bypass the confirmation prompt.

    Returns:
        bool: True if the operation should proceed, False otherwise (exits script).

    Raises:
        MTControllerException: If getting inventory fails.
        ValueError: If inventory count is not an integer.
        TypeError: If inventory structure is unexpected.
    """
    # Only prompt if the query is not specific to one NGFW
    if not ngfw_query:
        try:
            inventory = controller.get_inventory() # This call might raise MTControllerException
            # Use .get with default 0, handle potential non-integer value
            ngfw_count = int(inventory.get('NGFWs', 0)) # This might raise ValueError/TypeError

            if ngfw_count > 1 and not yes:
                api_calls_estimate = ngfw_count * multiplier
                prompt_msg = (f"{ngfw_count} NGFWs selected. This may result in approximately "
                              f"{api_calls_estimate} API calls. Proceed? (y/n): ")
                choice = input(prompt_msg)
                if choice.lower().strip() != 'y':
                    print("Operation cancelled by user.")
                    sys.exit(0) # Graceful exit if user cancels
        except (MTControllerException, ValueError, TypeError) as e:
            # Log specific error but exit consistently
            print(f"Warning: Could not determine NGFW count for confirmation: {e}", file=sys.stderr)
            print("Cannot confirm scope, cancelling operation.", file=sys.stderr)
            sys.exit(1) # Exit cautiously

    # Proceed if specific NGFW, count <= 1, yes=True, or user confirmed
    return True

# ==============================================================================
# Command Handler Functions
# ==============================================================================

def handle_build_db(args, builder):
    """
    Handles the 'build-db' command. Initializes the database schema.

    Args:
        args (argparse.Namespace): Parsed command-line arguments (not used in this handler).
        builder (MTBuilder): The database builder instance.

    Raises:
        MTBuilderException: If building the database fails in the backend.
    """
    print("Building database...")
    try:
        # Wrap the backend call in try/except
        message = builder.build_database()
        print(message)
        try:
            # Attempt to create a clean, absolute path from the db_uri
            if db_uri.startswith('sqlite:///'):
                db_path_rel = db_uri.replace('sqlite:///', '', 1)
                db_path = os.path.abspath(db_path_rel)
                print(f"Database located at {db_path}")
            else:
                # Print URI if not a standard file path
                print(f"Database URI: {db_uri}")
        except Exception:
            # Fallback
            print(f"Database URI: {db_uri}")
    except MTBuilderException as e:
        raise e # Re-raise for the main loop to handle


def handle_inventory(args, controller):
    """
    Handles the 'inventory' command. Displays counts of items in the database.

    Args:
        args (argparse.Namespace): Parsed command-line arguments (not used in this handler).
        controller (MTController): The data controller instance.

    Raises:
        MTControllerException: If getting inventory fails in the backend.
    """
    try:
        # Wrap the backend call in try/except
        inventory = controller.get_inventory()
        # Handle case where inventory is empty or None
        if not inventory:
            print("Database inventory is empty or could not be retrieved.")
            return

        # find the length of the longest key for consistent spacing
        max_key_length = max((len(key) for key in inventory.keys()), default=0)
        # iterate through the dictionary and print each item with consistent spacing
        print("\n--- Database Inventory ---")
        for key, value in inventory.items():
            # Calculate spacing based on key length
            spacing = ' ' * (max_key_length - len(key))
            print(f'{key}: {spacing}{value}')
        print("------------------------\n")
    except MTControllerException as e:
        raise e # Re-raise for the main loop to handle


def handle_add(args, builder):
    """
    Handles the 'add' command. Adds a Panorama or NGFW device to the database.

    Args:
        args (argparse.Namespace): Parsed arguments, expects 'platform', 'host',
                                   'username', 'password'.
        builder (MTBuilder): The database builder instance.

    Raises:
        MTBuilderException: If adding the device fails in the backend.
    """
    # Platform already validated by argparse choices
    platform = args.platform
    ip_address = args.host or input(f"Enter the IP address (or FQDN) for {platform}: ")
    username = args.username or input(f"Enter the username for {platform}: ")
    # Use getpass directly here for better security if password not provided
    password = args.password or getpass(f"Enter password for {platform}: ")

    print(f"Attempting to add {platform} at {ip_address}...")
    try:
        # Backend calls are already wrapped in the original code's try/except
        if platform == PLATFORM_PANORAMA:
            response = builder.add_panorama(ip_address=ip_address, username=username, password=password)
        else: # platform == PLATFORM_NGFW
            response = builder.add_ngfw(ip_address=ip_address, username=username, password=password)
        print(response)
        print(f"\n!! WARNING !! API key for {ip_address} may be stored in plaintext in the database.")
        print("Ensure appropriate file permissions are set on the database file.")
    except MTBuilderException as e:
        # Let the main loop handle printing the error and setting exit code
        # Re-raise the exception
        raise e


def handle_delete(args, builder):
    """
    Handles the 'delete' command. Removes a Panorama or NGFW from the database.

    Args:
        args (argparse.Namespace): Parsed arguments, expects 'platform', 'serial'.
        builder (MTBuilder): The database builder instance.

    Raises:
        MTBuilderException: If deleting the device fails in the backend.
    """
    # Platform validated by choices
    platform = args.platform
    serial_number = args.serial or input(f"Enter the serial number of the {platform} to delete: ")

    # Add a confirmation step
    confirm_msg = (f"Are you sure you want to delete {platform} with serial "
                   f"'{serial_number}' from the database? (y/n): ")
    confirm = input(confirm_msg)
    if confirm.lower().strip() != 'y':
        print("Deletion cancelled.")
        # Don't raise error, just return normally
        return

    print(f"Attempting to delete {platform} {serial_number}...")
    try:
        # Backend calls are already wrapped in the original code's try/except
        if platform == PLATFORM_PANORAMA:
            response = builder.delete_panorama(serial_number=serial_number)
        else: # platform == PLATFORM_NGFW
            response = builder.delete_ngfw(serial_number=serial_number)
        # Assuming response is a list of messages or a single string
        if isinstance(response, list):
             print("\n".join(response))
        elif response: # Print if not None or empty
             print(response)
        else:
             # Confirmation message
             print(f"{platform} {serial_number} deleted successfully (or was not found).")
    except MTBuilderException as e:
        # Let the main loop handle printing the error and setting exit code
        # Re-raise the exception
        raise e

def handle_import(args, controller):
    """
    Handles the 'import' command. Imports NGFW details from associated Panoramas.

    Args:
        args (argparse.Namespace): Parsed arguments, expects optional 'pan' filter.
        controller (MTController): The data controller instance.

    Raises:
        MTControllerException: If importing fails in the backend.
    """
    pan_filter = args.pan
    if pan_filter:
        print(f"Importing NGFWs managed by Panorama: {pan_filter}...")
    else:
        print("Importing NGFWs managed by ALL Panoramas...")

    try:
        # Wrap the backend call in try/except
        messages = controller.import_panorama_devices(pan_filter=pan_filter)
        if messages:
            print("\n".join(messages))
        else:
            print("No messages returned from import process.")
    except MTControllerException as e:
        raise e # Re-raise for main loop


def handle_refresh(args, controller):
    """
    Handles the 'refresh' command. Updates data for NGFWs by querying them via API.

    Args:
        args (argparse.Namespace): Parsed arguments, expects optional 'ngfw' filter and 'yes' flag.
        controller (MTController): The data controller instance.

    Raises:
        MTControllerException: If refreshing fails in the backend.
    """
    ngfw_filter = args.ngfw
    # Check for multiple NGFWs if no specific filter is applied
    # Estimate 3 API calls per NGFW (can be adjusted if needed)
    # Note: _confirm_on_demand_scope handles its own exceptions or exits
    if not _confirm_on_demand_scope(ngfw_query=ngfw_filter, controller=controller, multiplier=3, yes=args.yes):
        return # Exit if user cancelled or scope check failed

    if ngfw_filter:
         print(f"Refreshing NGFW data for: {ngfw_filter}...")
    else:
         print("Refreshing data for ALL NGFWs. This may take some time...")

    try:
        # Wrap the backend call in try/except
        message = controller.refresh_ngfws(ngfw_filter=ngfw_filter)
        if message:
            print("\n".join(message))
        else:
            print("Refresh process completed with no specific messages.")
    except MTControllerException as e:
        raise e # Re-raise for main loop


def handle_update(args, controller):
    """
    Handles the 'update' command. Updates specific data sets (routes, arps, etc.) for NGFWs via API.

    Args:
        args (argparse.Namespace): Parsed arguments, expects 'option', optional 'ngfw', 'vr', 'int', 'yes'.
        controller (MTController): The data controller instance.

    Raises:
        MTControllerException: If the update operation fails in the backend.
    """
    # Option validated by choices
    option = args.option
    ngfw_filter = args.ngfw
    vr_filter = args.vr
    int_filter = args.int

    # Estimate API calls based on option
    api_multiplier = 2 if option == CMD_ROUTES else 1

    # Check confirmation for potentially multiple NGFWs
    # Note: _confirm_on_demand_scope handles its own exceptions or exits
    if not _confirm_on_demand_scope(ngfw_query=ngfw_filter, controller=controller, multiplier=api_multiplier, yes=args.yes):
        return # Exit if user cancelled or scope check failed

    print(f"Attempting to update '{option}' data...")
    # Provide context on filters being applied
    target_info = []
    if ngfw_filter: target_info.append(f"NGFW: {ngfw_filter}")
    if vr_filter and option in [CMD_ROUTES, CMD_BGP_PEERS]: target_info.append(f"VR: {vr_filter}")
    if int_filter and option == CMD_ARPS: target_info.append(f"Interface: {int_filter}")
    if target_info: print(f"  Filters: {', '.join(target_info)}")
    elif not ngfw_filter: print("  Target: All applicable NGFWs")


    message = []
    try:
        # Backend calls are already wrapped in the original code's try/except
        if option == CMD_ROUTES:
            message = controller.update_routes(ngfw=ngfw_filter, virtual_router=vr_filter)
        elif option == CMD_LLDP:
            message = controller.update_neighbors(ngfw=ngfw_filter)
        elif option == CMD_BGP_PEERS:
            # Pass vr_filter only if it's provided, controller method should handle None
            message = controller.update_bgp_peers(ngfw=ngfw_filter, virtual_router=vr_filter)
        elif option == CMD_ARPS:
            # Pass int_filter only if it's provided
            message = controller.update_arps(ngfw=ngfw_filter, interface=int_filter)
        # Note: 'all' option was commented out in original, not implemented here yet.

        if message:
            print("\n".join(message))
        else:
            print(f"Update process for '{option}' completed with no specific messages.")
    except MTControllerException as e:
        raise e # Re-raise for main loop


# Within mt-cli.py

def handle_show(args, controller):
    """
    Handles the 'show' command. Displays various information from the database or via on-demand API calls.
    Includes custom handling for 'interfacesv6'.
    """
    # Option validated by choices
    option = args.option
    on_demand = args.on_demand
    ngfw_filter = args.ngfw
    vr_filter = args.vr
    afi_filter = args.afi if hasattr(args, 'afi') else 'ipv4'

    # --- On-Demand Confirmation (Applies generally) ---
    if on_demand and option != CMD_INTERFACESV6: # Defer confirmation for interfacesv6 if needed
        # ... (existing confirmation logic using _confirm_on_demand_scope) ...
        # (Keep this as is for other commands)
        print(f"Fetching '{option}' data on-demand...")

    # --- Filter Context (Applies generally) ---
    filter_info = []
    # ... (existing filter context logic) ...
    if filter_info: print(f"  Filters: {', '.join(filter_info)}")


    # --- Define headers and call the appropriate controller method ---
    response = {'results': None, 'message': None}
    headers = {} # Standard headers for _print_results
    legend = None

    try:
        # Standard processing for most commands using _print_results
        if option == CMD_ROUTES:
            response = controller.get_routes(
                ngfw=ngfw_filter, virtual_router=vr_filter, destination=args.dst,
                flags=args.flag, on_demand=on_demand, afi=afi_filter # Pass AFI value
            )
            headers = {HDR_NGFW: KEY_NGFW, HDR_VR: KEY_VR, HDR_DEST: KEY_DEST,
                       HDR_NEXTHOP: KEY_NEXTHOP, HDR_METRIC: KEY_METRIC, HDR_FLAGS: KEY_FLAGS,
                       HDR_INTERFACE: KEY_INTERFACE, HDR_ROUTE_TABLE: KEY_ROUTE_TABLE, HDR_AGE: KEY_AGE, HDR_ZONE: KEY_ZONE}
            legend = """flags: A:active, ?:loose, C:connect, H:host, S:static, ~:internal, R:rip, O:ospf, B:bgp,
            Oi:ospf intra-area, Oo:ospf inter-area, O1:ospf ext-type-1, O2:ospf ext-type-2, E:ecmp, M:multicast"""

        elif option == CMD_FIBS:
            # <<< Pass args.afi to controller method >>>
            response = controller.get_fibs(
                ngfw=ngfw_filter, virtual_router=vr_filter, destination=args.dst,
                flags=args.flag, on_demand=on_demand, afi=afi_filter # Pass AFI value
            )
            headers = {HDR_NGFW: KEY_NGFW, HDR_VR: KEY_VR, HDR_DEST: KEY_DEST,
                       HDR_NEXTHOP: KEY_NEXTHOP, HDR_NH_TYPE: KEY_NH_TYPE, HDR_FLAGS: KEY_FLAGS,
                       HDR_INTERFACE: KEY_INTERFACE, HDR_MTU: KEY_MTU, HDR_ZONE: KEY_ZONE}
            legend = "flags: u - up, h - host, g - gateway, e - ecmp, * - preferred path"

        elif option == CMD_BGP_PEERS:
            response = controller.get_bgp_peers(ngfw=ngfw_filter, virtual_router=vr_filter, on_demand=on_demand)
            headers = {HDR_NGFW: KEY_NGFW, HDR_VR: KEY_VR, HDR_PEER_NAME: KEY_PEER_NAME, HDR_PEER_GROUP: KEY_PEER_GROUP, HDR_PEER_ROUTER_ID: KEY_PEER_ROUTER_ID, HDR_REMOTE_AS: KEY_REMOTE_AS, HDR_STATUS: KEY_STATUS, HDR_DURATION: KEY_DURATION, HDR_PEER_ADDRESS: KEY_PEER_ADDRESS, HDR_LOCAL_ADDRESS: KEY_LOCAL_ADDRESS}

        elif option == CMD_INTERFACES: # Standard interfaces command
            response = controller.get_interfaces(ngfw=ngfw_filter, virtual_router=vr_filter, on_demand=on_demand, ipv6_enabled_only=False)
            headers = {HDR_NGFW: KEY_NGFW, HDR_VR: KEY_VR, HDR_NAME: KEY_NAME, HDR_TAG: KEY_TAG, HDR_ADDRESS: KEY_ADDRESS_IP, HDR_IPV6_PRESENT: KEY_IPV6_PRESENT, HDR_ZONE: KEY_ZONE}

        elif option == CMD_INTERFACESV6:

            if on_demand:
                 if not _confirm_on_demand_scope(ngfw_query=ngfw_filter, controller=controller, multiplier=1, yes=args.yes):
                      return # Exit if user cancelled
                 else:
                    print(f"Fetching IPv6 interface data{' (on-demand)' if on_demand else ''}...")

            # Call controller to get filtered data
            response = controller.get_interfaces(
                ngfw=ngfw_filter,
                virtual_router=vr_filter,
                ipv6_enabled_only=True, # Filter flag
                on_demand=on_demand
            )
            results = response.get('results')
            message = response.get('message')

            # Call the dedicated print helper
            _print_interfaces_v6(results, message)

            return # Exit handler, do not proceed to generic _print_results
        
        elif option == CMD_LLDP:
            response = controller.get_neighbors(ngfw=ngfw_filter, on_demand=on_demand)
            headers = {HDR_NGFW: KEY_NGFW, HDR_LOCAL_IF: KEY_LOCAL_IF, HDR_REMOTE_IF_ID: KEY_REMOTE_IF_ID, HDR_REMOTE_IF_DESC: KEY_REMOTE_IF_DESC, HDR_REMOTE_HOSTNAME: KEY_REMOTE_HOSTNAME}

        elif option == CMD_ARPS:
            response = controller.get_arps(ngfw=ngfw_filter, interface=args.int, on_demand=on_demand)
            headers = {HDR_NGFW: KEY_NGFW, HDR_INTERFACE: KEY_INTERFACE, HDR_IP: KEY_ADDRESS_IP, HDR_MAC: KEY_MAC, HDR_PORT: KEY_PORT, HDR_STATUS: KEY_STATUS, HDR_TTL: KEY_TTL, HDR_ZONE: KEY_ZONE}

        elif option == CMD_VRS:
            response = controller.get_virtual_routers(ngfw=ngfw_filter, virtual_router=vr_filter)
            headers = {HDR_NGFW: KEY_NGFW, HDR_VR: KEY_VR, HDR_ROUTE_COUNT: KEY_ROUTE_COUNT, HDR_FIB_COUNT: KEY_FIB_COUNT, HDR_IF_COUNT: KEY_IF_COUNT}

        elif option == CMD_NGFWS:
            pan_arg = args.pan if hasattr(args, 'pan') else None
            response = controller.get_ngfws(panorama=pan_arg)
            headers = {HDR_HOSTNAME: KEY_HOSTNAME, HDR_SERIAL: KEY_SERIAL, HDR_IP: KEY_IP_ADDRESS, HDR_MODEL: KEY_MODEL, HDR_ALT_SERIAL: KEY_ALT_SERIAL, HDR_ACTIVE: KEY_ACTIVE, HDR_PANORAMA: KEY_PANORAMA, HDR_LAST_REFRESH: KEY_LAST_UPDATE}

        elif option == CMD_PAN:
            response = controller.get_panoramas()
            headers = {HDR_HOSTNAME: KEY_HOSTNAME, HDR_SERIAL: KEY_SERIAL, HDR_IP: KEY_IP_ADDRESS, HDR_ALT_IP: KEY_ALT_IP, HDR_ACTIVE: KEY_ACTIVE, HDR_NGFW_COUNT: KEY_NGFW_COUNT}

        # --- Print Legend and Results (for standard commands) ---
        # This part is skipped if option == CMD_INTERFACESV6 due to the 'return' above
        if legend and response.get('results'):
             print(f"\n{legend}\n")

        # Generic print function for standard table outputs
        _print_results(headers, response.get('results'), response.get('message'))

    except MTControllerException as e:
         # Let the main loop handle printing the error and setting exit code
         raise e

def handle_fib_lookup(args, controller):
    """
    Handles the 'fib-lookup' command. Performs FIB lookup calculation or on-demand test.

    Args:
        args (argparse.Namespace): Parsed arguments, expects 'address', optional 'ngfw',
                                   'vr', 'on_demand', 'yes'.
        controller (MTController): The data controller instance.

    Raises:
        ValueError: If the provided address is not a valid IPv4 address.
        MTControllerException: If the lookup/test fails in the backend.
    """
    ip_address_str = args.address
    ngfw_filter = args.ngfw
    vr_filter = args.vr
    on_demand = args.on_demand
    yes = args.yes

    # Validate IP address
    try:
        ip_address = ipaddress.ip_address(ip_address_str) # Use ip_address for validation
    except ValueError:
        # Raise specific error for main loop to catch
        raise ValueError(f"Invalid IP address provided: '{ip_address_str}'")

    headers = {HDR_NGFW: KEY_NGFW, HDR_VR: KEY_VR,
               HDR_INTERFACE: KEY_INTERFACE, HDR_NEXTHOP: KEY_NEXTHOP, HDR_ZONE: KEY_ZONE}
    response = {'results': None, 'message': None}

    try:
        # Wrap the backend calls in try/except
        if on_demand:
            # Keep this message for on-demand
            print(f"Performing on-demand FIB lookup for {ip_address}...")
            # Check how many VRs/NGFWs this might hit
            # Get potential target VRs based on filters to estimate API calls
            # Note: _confirm_on_demand_scope handles its own exceptions or exits
            vr_list = controller.get_virtual_routers(ngfw=ngfw_filter, virtual_router=vr_filter).get('results', [])
            vr_count = len(vr_list)

            if vr_count == 0:
                 print("Warning: No matching virtual routers found for the specified filters.", file=sys.stderr)
                 # Allow attempt, controller method should handle no VRs found
            elif vr_count > 1 and not yes:
                 confirm_msg = (f"{vr_count} virtual-routers match the query. This will perform "
                                f"{vr_count} API calls for the FIB test. Proceed? (y/n): ")
                 choice = input(confirm_msg)
                 if choice.lower().strip() != 'y':
                     print("Operation cancelled.")
                     # Don't proceed
                     return

            if vr_count > 0:
                 print(f"Testing FIB on {vr_count} virtual-router(s). This may take some time...\n")

            # Call the on-demand test method - pass the validated ip_address object
            response = controller.test_fib_lookup(ip_address=ip_address, vr_query=vr_filter, ngfw_query=ngfw_filter)

        else:
            # Call the calculation method (no message needed here) - pass the original string
            response = controller.calculate_fib_lookup(ip_address_str=ip_address_str, vr_query=vr_filter, ngfw_query=ngfw_filter)

        _print_results(headers, response.get('results'), response.get('message'))

    except MTControllerException as e:
         # Let the main loop handle printing the error and setting exit code
         # Re-raise the exception
         raise e


def handle_update_ha(args, controller):
    """
    Handles the 'update-ha' command. Updates HA status for devices via API calls.

    Args:
        args (argparse.Namespace): Parsed arguments, expects optional 'pan', 'ngfw' filters.
        controller (MTController): The data controller instance.

    Raises:
        MTControllerException: If updating HA status fails in the backend.
    """
    print("Updating HA status for relevant devices...")
    try:
        # Wrap the backend call in try/except
        message = controller.update_ha_status(pan_filter=args.pan, ngfw_filter=args.ngfw)
        if message:
            print("\n".join(message))
        else:
            print("No HA status updates performed or no HA devices found.")
    except MTControllerException as e:
        raise e # Re-raise for main loop


# ==============================================================================
# Main Execution Block
# ==============================================================================

def main():
    """
    Main function to parse arguments and dispatch commands.
    Initializes backend components (Builder, Controller) and sets up argparse.
    Performs a check for database readiness before defining most commands.
    """
    # --- Setup Argument Parser ---
    parser = argparse.ArgumentParser(
        description="Master Troubleshooter CLI: Manage and query Palo Alto Networks device info.",
        epilog="Use '<command> --help' for more information on a specific command."
    )
    subparsers = parser.add_subparsers(
        title="Available Commands",
        metavar="COMMAND",
        dest="command", # Store the command name
        help="The action to perform",
        required=True # Ensure a command is always given
    )

    # --- Initialize Database Builder ---
    # Builder is needed for 'add', 'delete', and 'build-db' commands.
    builder = None # Initialize to None
    try:
        # Attempt to create an instance of the database builder
        builder = MTBuilder(db_uri=db_uri)
    except Exception as e: # Catch potential errors during builder initialization
         print(f"Fatal Error: Could not initialize Database Builder: {e}", file=sys.stderr)
         print("Please ensure database configuration is correct and dependencies are installed.", file=sys.stderr)
         sys.exit(1) # Exit if builder cannot be initialized

    # --- Command: build-db ---
    # This command should always be available, regardless of DB state.
    parser_build = subparsers.add_parser(
        "build-db",
        help="Build the database schema (run first if DB doesn't exist)"
    )
    # Associate the handler function, passing the builder instance via lambda
    parser_build.set_defaults(func=lambda args: handle_build_db(args, builder))

    # --- Initialize Controller and Check DB Status ---
    # Controller is needed for most other commands. Check DB readiness here.
    controller = None # Initialize to None
    inventory = None  # To store inventory counts if DB is ready
    db_ready = False  # Flag to track if the DB schema exists and controller is usable
    try:
        # Attempt to initialize the controller. MTController.__init__ now performs the schema check.
        controller = MTController(db_uri=db_uri, timeout=timeout)

        # If controller initialization succeeds, try to get inventory.
        # This serves as a secondary check and provides data for conditional command setup.
        inventory = controller.get_inventory()
        # If inventory is successfully retrieved (even if empty), assume DB is ready.
        if isinstance(inventory, dict):
             db_ready = True
        else:
             # This case might indicate an issue beyond just schema missing (e.g., DB corruption after creation)
             logging.error("Controller initialized, but inventory retrieval failed.")

    # --- MODIFICATION START: Reordered Exception Handling ---
    except MTDatabaseSchemaError as schema_err:
        # Catch the specific schema error raised by MTController.__init__ FIRST
        logging.error("Database schema not found. Please run 'build-db' first.")
        db_ready = False

    except sqlalchemy.exc.OperationalError as db_err:
        # Catch *other* OperationalErrors (e.g., permissions, file corruption)
        # that might occur during engine creation or the inventory check.
        logging.error("Database connection failed. Check permissions and file integrity.")
        db_ready = False

    except MTControllerException as e: # Catch other specific controller init errors NEXT
        # This will now catch general MTControllerExceptions but NOT MTDatabaseSchemaError
        logging.error(f"Controller initialization failed: {e}")
        db_ready = False

    except Exception as e: # Catch any other unexpected init errors LAST
        logging.error(f"Unexpected error during controller initialization: {e}")
        db_ready = False
    # --- MODIFICATION END: Reordered Exception Handling ---


    # --- Define Commands Requiring a Ready Database ---
    # Only add these subparsers if the controller initialized successfully and DB schema is present.
    if db_ready:
        # --- Command: inventory ---
        parser_inv = subparsers.add_parser(
            "inventory",
            help="Display database inventory metrics"
        )
        # Associate handler, passing the controller instance
        parser_inv.set_defaults(func=lambda args: handle_inventory(args, controller))

        # --- Command: add ---
        parser_add = subparsers.add_parser(
            "add",
            help="Add a Panorama or NGFW device to the database"
        )
        parser_add.add_argument("platform", choices=[PLATFORM_PANORAMA, PLATFORM_NGFW], help=f"Specify '{PLATFORM_PANORAMA}' or '{PLATFORM_NGFW}'")
        parser_add.add_argument("-H", "--host", type=str, help="IP address or FQDN (will prompt if omitted)")
        parser_add.add_argument("-u", "--username", type=str, help="Device username (will prompt if omitted)")
        parser_add.add_argument("-p", "--password", type=str, help="Device password (will prompt securely if omitted)")
        # Associate handler, passing the builder instance
        parser_add.set_defaults(func=lambda args: handle_add(args, builder))

        # --- Commands requiring Panorama in DB ---
        # Check inventory dictionary safely using .get() before defining these commands
        show_pan_filter_enabled = False # Flag to enable --pan filter in 'show ngfws' later
        if inventory and inventory.get('Panoramas', 0) > 0:
            # --- Command: import ---
            parser_import = subparsers.add_parser(
                "import",
                help="Import NGFWs managed by Panorama(s) into the database"
            )
            parser_import.add_argument("--pan", type=str, help="Filter by specific Panorama hostname or IP")
            # Associate handler, passing the controller instance
            parser_import.set_defaults(func=lambda args: handle_import(args, controller))
            show_pan_filter_enabled = True # Enable the filter option for show command


        # --- Commands requiring NGFWs or Panoramas in DB ---
        # Check if there's anything to delete or update HA status for
        if inventory and (inventory.get('NGFWs', 0) > 0 or inventory.get('Panoramas', 0) > 0):
             # --- Command: delete ---
             parser_delete = subparsers.add_parser(
                 "delete",
                 help="Delete a Panorama or NGFW device from the database"
             )
             parser_delete.add_argument("platform", choices=[PLATFORM_PANORAMA, PLATFORM_NGFW], help=f"Specify '{PLATFORM_PANORAMA}' or '{PLATFORM_NGFW}'")
             parser_delete.add_argument("-s", "--serial", type=str, help="Serial number of the device (will prompt if omitted)")
             # Associate handler, passing the builder instance
             parser_delete.set_defaults(func=lambda args: handle_delete(args, builder))

             # --- Command: update-ha ---
             parser_updateha = subparsers.add_parser(
                 "update-ha",
                 help="Update HA status for devices in the database"
             )
             # Add optional filters if the handler/controller supports them
             parser_updateha.add_argument("--pan", type=str, help="Filter by specific Panorama hostname or IP")
             parser_updateha.add_argument("--ngfw", type=str, help="Filter by specific NGFW hostname, IP, or serial")
             # Associate handler, passing the controller instance
             parser_updateha.set_defaults(func=lambda args: handle_update_ha(args, controller))


        # --- Commands requiring NGFWs in DB ---
        # Check inventory for NGFWs before defining these commands
        if inventory and inventory.get('NGFWs', 0) > 0:
            # --- Command: refresh ---
            parser_refresh = subparsers.add_parser(
                "refresh",
                help="Refresh data for NGFW(s) via API calls (updates DB)"
            )
            parser_refresh.add_argument("--ngfw", type=str, help="Filter by specific NGFW hostname, IP, or serial (refreshes all if omitted)")
            parser_refresh.add_argument("--yes", "-y", action="store_true", help="Bypass confirmation prompt when refreshing multiple NGFWs")
            # Associate handler, passing the controller instance
            parser_refresh.set_defaults(func=lambda args: handle_refresh(args, controller))

            # --- Command: update ---
            parser_update = subparsers.add_parser(
                "update",
                help="Update specific attributes for NGFW(s) via API calls (updates DB)"
            )
            update_options = [CMD_ROUTES, CMD_ARPS, CMD_LLDP, CMD_BGP_PEERS] # Add 'all' back if implemented
            parser_update.add_argument(
                "option",
                choices=update_options,
                help="The specific attribute set to update"
            )
            parser_update.add_argument("--ngfw", type=str, help="Filter by specific NGFW hostname, IP, or serial (updates all matching if omitted)")
            parser_update.add_argument("--vr", type=str, help="Filter by virtual router name (for routes, bgp-peers)")
            parser_update.add_argument("--int", type=str, help="Filter by interface name (for arps)")
            parser_update.add_argument("--yes", "-y", action="store_true", help="Bypass confirmation prompt for multiple NGFWs")
            # Associate handler, passing the controller instance
            parser_update.set_defaults(func=lambda args: handle_update(args, controller))

            # --- Command: fib-lookup ---
            parser_fib = subparsers.add_parser(
                "fib-lookup",
                help="Perform a FIB lookup for an IPv4 address"
            )
            parser_fib.add_argument("address", help="IPv4 address for the FIB lookup")
            parser_fib.add_argument("--ngfw", type=str, help="Filter by specific NGFW hostname, IP, or serial")
            parser_fib.add_argument("--vr", type=str, help="Filter by virtual router name")
            parser_fib.add_argument("--on-demand", action="store_true", help="Perform live API test on device(s) instead of DB calculation")
            parser_fib.add_argument("--yes", "-y", action="store_true", help="Bypass confirmation prompt for on-demand tests on multiple VRs/NGFWs")
            # Associate handler, passing the controller instance
            parser_fib.set_defaults(func=lambda args: handle_fib_lookup(args, controller))


        # --- Command: show ---
        # Requires either Panoramas or NGFWs to show something meaningful generally
        if inventory and (inventory.get('Panoramas', 0) > 0 or inventory.get('NGFWs', 0) > 0):
            parser_show = subparsers.add_parser(
                "show",
                help="Show information from the database or via on-demand API calls"
            )
            show_options = [CMD_ROUTES, CMD_FIBS, CMD_ARPS, CMD_BGP_PEERS,
                            CMD_INTERFACES, CMD_INTERFACESV6,
                            CMD_VRS, CMD_NGFWS, CMD_PAN, CMD_LLDP]
            parser_show.add_argument(
                "option",
                choices=show_options,
                help="The type of information to show"
            )
            # Add filters - some apply only to certain options, handled within the handler
            # Conditionally add the --pan filter only if Panoramas exist
            if show_pan_filter_enabled:
                 parser_show.add_argument("--pan", type=str, help="Filter by Panorama (used for 'show ngfws')")
            parser_show.add_argument("--ngfw", type=str, help="Filter by NGFW (hostname, IP, or serial)")
            parser_show.add_argument("--vr", type=str, help="Filter by virtual router name")
            parser_show.add_argument("--dst", type=str, help="Filter by destination prefix (for routes, fibs)")
            parser_show.add_argument("--flag", type=str, help="Filter by route/FIB flags (comma-separated)")
            parser_show.add_argument("--int", type=str, help="Filter by interface name (for arps)")
            parser_show.add_argument("--afi", "-a", type=str, choices=["ipv4", "ipv6"], default="ipv4",help="Address family for routes and fibs (default: ipv4)")
            parser_show.add_argument("--on-demand", action="store_true", help="Fetch data directly from device(s) via API instead of DB")
            parser_show.add_argument("--yes", "-y", action="store_true", help="Bypass confirmation prompt for on-demand queries on multiple NGFWs")
            # Associate handler, passing the controller instance
            parser_show.set_defaults(func=lambda args: handle_show(args, controller))
        # No 'else' needed; if DB is ready but empty, 'show' command is simply not added


    # --- Parse Arguments ---
    # This is placed after command definitions so --help works correctly,
    # showing only available commands based on db_ready state.
    try:
        args = parser.parse_args()
    except SystemExit as e:
         # Catch SystemExit from argparse (e.g., for --help or invalid choice) and exit cleanly
         sys.exit(e.code)


    # --- Execute Selected Command's Function ---
    exit_code = 0 # Default exit code for success
    try:
        # Check if the selected command's function exists (set by set_defaults)
        # This check is crucial because if db_ready was False, args.func might not exist for commands other than 'build-db'.
        if hasattr(args, 'func'):
            # Call the chosen handler function, passing the args object.
            # The lambda functions used in set_defaults handle passing 'controller' or 'builder'.
            args.func(args)
        else:
            # This case should ideally not be reached if subparsers are required=True
            # and parsing happens after defining commands based on db_ready state.
            # However, it's a safeguard.
            print("\nError: Command not available or invalid.", file=sys.stderr)
            exit_code = 1

    # --- General Exception Handling for Command Execution ---
    except (MTControllerException, MTBuilderException) as e:
         # Catch custom exceptions from controller or builder operations
         print(f"\nExecution Error: {e}", file=sys.stderr)
         exit_code = 1 # Indicate failure
    except ValueError as e: # Catch specific errors like invalid IP in fib-lookup handler
         print(f"\nInput Error: {e}", file=sys.stderr)
         exit_code = 1
    except KeyboardInterrupt:
         # Handle Ctrl+C gracefully
         print("\nOperation interrupted by user.", file=sys.stderr)
         exit_code = 1
    except Exception as e: # Catch any other unexpected errors during command execution
        print(f"\nAn unexpected error occurred: {e}", file=sys.stderr)
        # Optional: Add traceback for debugging non-handled errors during development
        # import traceback
        # traceback.print_exc()
        exit_code = 1

    # Exit the script with the determined exit code
    sys.exit(exit_code)


if __name__ == '__main__':
    main()