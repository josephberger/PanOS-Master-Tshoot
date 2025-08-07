import argparse
import ipaddress
from getpass import getpass
import os
import sys
import logging
# Removed csv import as it's now handled by MTCLIOutput

# Configuration and backend imports
from config import db_uri, timeout, log_level, log_file, log_to_terminal
from mastertshoot.mt_controller import MTController, MTControllerException, MTDatabaseSchemaError
from mastertshoot.mt_builder import MTBuilder, MTBuilderException
from mastertshoot.mt_database_manager import MTDatabaseManager, MTDatabaseManagerException 

# NEW: Import constants and MTCLIOutput
from mastertshoot.mt_constants import *
from mastertshoot.mt_cli_output import MTCLIOutput


# Basic logging setup
log_handlers = [logging.FileHandler(log_file)]

# Conditionally add StreamHandler for terminal output
if log_to_terminal:
    log_handlers.append(logging.StreamHandler(sys.stdout))

logging.basicConfig(
    level=getattr(logging, log_level.upper(), logging.INFO),
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=log_handlers
)

# ==============================================================================
# Initialize CLI Output Handler
# ==============================================================================
cli_output = MTCLIOutput()


# ==============================================================================
# Helper Functions (CLI-specific, not output formatting)
# ==============================================================================

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
# Command Handler Functions (Delegating to MTController and MTCLIOutput)
# ==============================================================================

def handle_build_db(args, builder):
    """
    Handles the 'build-db' command. Initializes the database schema.
    """
    print("Building database...")
    try:
        message = builder.build_database()
        print(message)
        try:
            if db_uri.startswith('sqlite:///'):
                db_path_rel = db_uri.replace('sqlite:///', '', 1)
                db_path = os.path.abspath(db_path_rel)
                print(f"Database located at {db_path}")
            else:
                print(f"Database URI: {db_uri}")
        except Exception:
            print(f"Database URI: {db_uri}")
    except MTBuilderException as e:
        raise e

def handle_inventory(args, controller):
    """
    Handles the 'inventory' command. Displays counts of items in the database.
    """
    try:
        inventory = controller.get_inventory()
        if not inventory:
            print("Database inventory is empty or could not be retrieved.")
            return

        max_key_length = max((len(key) for key in inventory.keys()), default=0)
        print("\n--- Database Inventory ---")
        for key, value in inventory.items():
            spacing = ' ' * (max_key_length - len(key))
            print(f'{key}: {spacing}{value}')
        print("------------------------\n")
    except MTControllerException as e:
        raise e

def handle_add(args, builder):
    """
    Handles the 'add' command. Adds a Panorama or NGFW device to the database.
    """
    platform = args.platform
    ip_address = args.host or input(f"Enter the IP address (or FQDN) for {platform}: ")
    username = args.username or input(f"Enter the username for {platform}: ")
    password = args.password or getpass(f"Enter password for {platform}: ")

    print(f"Attempting to add {platform} at {ip_address}...")
    try:
        if platform == PLATFORM_PANORAMA:
            response = builder.add_panorama(ip_address=ip_address, username=username, password=password)
        else: # platform == PLATFORM_NGFW
            response = builder.add_ngfw(ip_address=ip_address, username=username, password=password)
        print(response)
        print(f"\n!! WARNING !! API key for {ip_address} may be stored in plaintext in the database.")
        print("Ensure appropriate file permissions are set on the database file.")
    except MTBuilderException as e:
        raise e

def handle_delete(args, builder):
    """
    Handles the 'delete' command. Removes a Panorama or NGFW from the database.
    """
    platform = args.platform
    serial_number = args.serial or input(f"Enter the serial number of the {platform} to delete: ")

    confirm_msg = (f"Are you sure you want to delete {platform} with serial "
                   f"'{serial_number}' from the database? (y/n): ")
    confirm = input(confirm_msg)
    if confirm.lower().strip() != 'y':
        print("Deletion cancelled.")
        return

    print(f"Attempting to delete {platform} {serial_number}...")
    try:
        if platform == PLATFORM_PANORAMA:
            response = builder.delete_panorama(serial_number=serial_number)
        else: # platform == PLATFORM_NGFW
            response = builder.delete_ngfw(serial_number=serial_number)
        if isinstance(response, list):
             print("\n".join(response))
        elif response:
             print(response)
        else:
             print(f"{platform} {serial_number} deleted successfully (or was not found).")
    except MTBuilderException as e:
        raise e

def handle_import(args, controller):
    """
    Handles the 'import' command. Imports NGFW details from associated Panoramas.
    """
    pan_filter = args.pan
    if pan_filter:
        print(f"Importing NGFWs managed by Panorama: {pan_filter}...")
    else:
        print("Importing NGFWs managed by ALL Panoramas...")

    try:
        messages = controller.import_panorama_devices(pan_filter=pan_filter)
        if messages:
            print("\n".join(messages))
        else:
            print("No messages returned from import process.")
    except MTControllerException as e:
        raise e

def handle_refresh(args, controller):
    """
    Handles the 'refresh' command. Updates data for NGFWs by querying them via API.
    """
    ngfw_filter = args.ngfw
    if not _confirm_on_demand_scope(ngfw_query=ngfw_filter, controller=controller, multiplier=3, yes=args.yes):
        return

    if ngfw_filter:
         print(f"Refreshing NGFW data for: {ngfw_filter}...")
    else:
         print("Refreshing data for ALL NGFWs. This may take some time...")

    try:
        message = controller.refresh_ngfws(ngfw_filter=ngfw_filter)
        if message:
            print("\n".join(message))
        else:
            print("Refresh process completed with no specific messages.")
    except MTControllerException as e:
        raise e

def handle_update(args, controller):
    """
    Handles the 'update' command. Updates specific data sets (routes, arps, etc.) for NGFWs via API.
    """
    option = args.option
    ngfw_filter = args.ngfw
    vr_filter = args.vr
    int_filter = args.int

    api_multiplier = 2 if option in [CMD_ROUTES, CMD_FIBS] else 1

    if not _confirm_on_demand_scope(ngfw_query=ngfw_filter, controller=controller, multiplier=api_multiplier, yes=args.yes):
        return

    print(f"Attempting to update '{option}' data...")
    target_info = []
    if ngfw_filter: target_info.append(f"NGFW: {ngfw_filter}")
    if vr_filter and option in [CMD_ROUTES, CMD_BGP_PEERS]: target_info.append(f"VR: {vr_filter}")
    if int_filter and option == CMD_ARPS: target_info.append(f"Interface: {int_filter}")
    if target_info: print(f"  Filters: {', '.join(target_info)}")
    elif not ngfw_filter: print("  Target: All applicable NGFWs")

    message = []
    try:
        if option == CMD_ROUTES:
            message = controller.update_routes(ngfw=ngfw_filter, virtual_router=vr_filter)
        elif option == CMD_LLDP:
            message = controller.update_neighbors(ngfw=ngfw_filter)
        elif option == CMD_BGP_PEERS:
            message = controller.update_bgp_peers(ngfw=ngfw_filter, virtual_router=vr_filter)
        elif option == CMD_ARPS:
            message = controller.update_arps(ngfw=ngfw_filter, interface=int_filter)

        if message:
            print("\n".join(message))
        else:
            print(f"Update process for '{option}' completed with no specific messages.")
    except MTControllerException as e:
        raise e

def handle_show(args, controller):
    """
    Handles the 'show' command. Displays various information from the database
    or via on-demand API calls. Includes logic for CSV output.
    """
    option = args.option
    on_demand = args.on_demand
    ngfw_filter = args.ngfw
    vr_filter = args.vr
    show_detail = args.detail if hasattr(args, 'detail') else False
    afi_filter = args.afi if hasattr(args, 'afi') else 'ipv4'

    csv_output_file = None
    if args.csv:
        if isinstance(args.csv, str):
            csv_output_file = args.csv
        else:
            csv_output_file = f"{option.replace('-', '_')}.csv"

    if on_demand and option != CMD_INTERFACESV6:
        api_multiplier = 1 
        if option in [CMD_ROUTES, CMD_FIBS]:
            api_multiplier = 2
        
        if not _confirm_on_demand_scope(ngfw_query=ngfw_filter, controller=controller, multiplier=api_multiplier, yes=args.yes):
            return
        else:
             print(f"Fetching '{option}' data on-demand...")

    filter_info = []
    if ngfw_filter: filter_info.append(f"NGFW: {ngfw_filter}")
    if vr_filter: filter_info.append(f"VR: {vr_filter}")
    if hasattr(args, 'dst') and args.dst: filter_info.append(f"Destination: {args.dst}")
    if hasattr(args, 'flag') and args.flag: filter_info.append(f"Flags: {args.flag}")
    if hasattr(args, 'int') and args.int: filter_info.append(f"Interface: {args.int}")
    if hasattr(args, 'pan') and args.pan: filter_info.append(f"Panorama: {args.pan}")
    if hasattr(args, 'afi') and args.afi != 'ipv4': filter_info.append(f"AFI: {args.afi}")
    if filter_info: print(f"  Filters: {', '.join(filter_info)}")

    response = {'results': None, 'message': None}
    headers = {}
    legend = None

    attributes_for_ngfw_detail_csv = []
    attributes_for_pan_detail_csv = []

    try:
        if option == CMD_ROUTES:
            response = controller.get_routes(
                ngfw=ngfw_filter, virtual_router=vr_filter, destination=args.dst,
                flags=args.flag, on_demand=on_demand, afi=afi_filter
            )
            headers = {HDR_NGFW: KEY_NGFW, HDR_VR: KEY_VR, HDR_DEST: KEY_DEST,
                       HDR_NEXTHOP: KEY_NEXTHOP, HDR_METRIC: KEY_METRIC, HDR_FLAGS: KEY_FLAGS,
                       HDR_INTERFACE: KEY_INTERFACE, HDR_ROUTE_TABLE: KEY_ROUTE_TABLE, HDR_AGE: KEY_AGE, HDR_ZONE: KEY_ZONE}
            legend = """flags: A:active, ?:loose, C:connect, H:host, S:static, ~:internal, R:rip, O:ospf, B:bgp,
            Oi:ospf intra-area, Oo:ospf inter-area, O1:ospf ext-type-1, O2:ospf ext-type-2, E:ecmp, M:multicast"""

        elif option == CMD_FIBS:
            response = controller.get_fibs(
                ngfw=ngfw_filter, virtual_router=vr_filter, destination=args.dst,
                flags=args.flag, on_demand=on_demand, afi=afi_filter
            )
            headers = {HDR_NGFW: KEY_NGFW, HDR_VR: KEY_VR, HDR_DEST: KEY_DEST,
                       HDR_NEXTHOP: KEY_NEXTHOP, HDR_NH_TYPE: KEY_NH_TYPE, HDR_FLAGS: KEY_FLAGS,
                       HDR_INTERFACE: KEY_INTERFACE, HDR_MTU: KEY_MTU, HDR_ZONE: KEY_ZONE}
            legend = "flags: u - up, h - host, g - gateway, e - ecmp, * - preferred path"

        elif option == CMD_BGP_PEERS:
            response = controller.get_bgp_peers(ngfw=ngfw_filter, virtual_router=vr_filter, on_demand=on_demand)
            headers = {HDR_NGFW: KEY_NGFW, HDR_VR: KEY_VR, HDR_PEER_NAME: KEY_PEER_NAME, HDR_PEER_GROUP: KEY_PEER_GROUP, HDR_PEER_ROUTER_ID: KEY_PEER_ROUTER_ID, HDR_REMOTE_AS: KEY_REMOTE_AS, HDR_STATUS: KEY_STATUS, HDR_DURATION: KEY_DURATION, HDR_PEER_ADDRESS: KEY_PEER_ADDRESS, HDR_LOCAL_ADDRESS: KEY_LOCAL_ADDRESS}

        elif option == CMD_INTERFACES:
            response = controller.get_interfaces(ngfw=ngfw_filter, virtual_router=vr_filter, on_demand=on_demand, ipv6_enabled_only=False)
            headers = {HDR_NGFW: KEY_NGFW, HDR_VR: KEY_VR, HDR_NAME: KEY_NAME, HDR_TAG: KEY_TAG, HDR_ADDRESS: KEY_ADDRESS_IP, HDR_IPV6_PRESENT: KEY_IPV6_PRESENT, HDR_ZONE: KEY_ZONE}

        elif option == CMD_INTERFACESV6:
            if on_demand:
                if not _confirm_on_demand_scope(ngfw_query=ngfw_filter, controller=controller, multiplier=1, yes=args.yes):
                    return
                else:
                    print(f"Fetching IPv6 interface data{' (on-demand)' if on_demand else ''}...")

            response = controller.get_interfaces(
                ngfw=ngfw_filter,
                virtual_router=vr_filter,
                ipv6_enabled_only=True,
                on_demand=on_demand
            )

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
            if show_detail:
                attributes_for_ngfw_detail_csv = [
                    (LBL_HOSTNAME, KEY_HOSTNAME), (LBL_SERIAL, KEY_SERIAL),
                    (LBL_IP_ADDRESS, KEY_IP_ADDRESS), (LBL_IPV6_ADDRESS, KEY_IPV6_ADDRESS_DETAIL),
                    (LBL_MAC_ADDRESS, KEY_MAC), (LBL_MODEL, KEY_MODEL),
                    (LBL_SW_VERSION, KEY_SW_VERSION_DETAIL), (LBL_UPTIME, KEY_UPTIME_DETAIL),
                    (LBL_PANORAMA, KEY_PANORAMA), (LBL_ACTIVE, KEY_ACTIVE),
                    (LBL_ALT_SERIAL, KEY_ALT_SERIAL), (LBL_ALT_IP, KEY_ALT_IP), (LBL_ARE, KEY_ARE),
                    (LBL_APP_VERSION, KEY_APP_VERSION_DETAIL), (LBL_THREAT_VERSION, KEY_THREAT_VERSION_DETAIL),
                    (LBL_AV_VERSION, KEY_AV_VERSION_DETAIL), (LBL_WILDFIRE_VERSION, KEY_WILDFIRE_VERSION_DETAIL),
                    (LBL_URL_FILTERING_VERSION, KEY_URL_FILTERING_VERSION_DETAIL),
                    (LBL_DEVICE_CERT_PRESENT, KEY_DEVICE_CERT_PRESENT_DETAIL), (LBL_DEVICE_CERT_EXPIRY, KEY_DEVICE_CERT_EXPIRY_DETAIL),
                    (LBL_LAST_REFRESH, KEY_LAST_UPDATE)
                ]
            else:
                headers = {HDR_HOSTNAME: KEY_HOSTNAME, HDR_SERIAL: KEY_SERIAL, HDR_IP: KEY_IP_ADDRESS,
                           HDR_MODEL: KEY_MODEL, HDR_ALT_SERIAL: KEY_ALT_SERIAL, HDR_ACTIVE: KEY_ACTIVE,
                           HDR_PANORAMA: KEY_PANORAMA, HDR_ARE: KEY_ARE, HDR_LAST_REFRESH: KEY_LAST_UPDATE}

        elif option == CMD_PAN:
            response = controller.get_panoramas()
            if show_detail:
                attributes_for_pan_detail_csv = [
                    (LBL_PAN_HOSTNAME, KEY_PAN_HOSTNAME), (LBL_PAN_SERIAL, KEY_PAN_SERIAL),
                    (LBL_PAN_IP_ADDRESS, KEY_PAN_IP_ADDRESS), (LBL_PAN_IPV6_ADDRESS, KEY_PAN_IPV6_ADDRESS),
                    (LBL_PAN_MAC_ADDRESS, KEY_PAN_MAC_ADDRESS), (LBL_PAN_MODEL, KEY_PAN_MODEL),
                    (LBL_PAN_SYSTEM_MODE, KEY_PAN_SYSTEM_MODE), (LBL_PAN_SW_VERSION, KEY_PAN_SW_VERSION),
                    (LBL_PAN_UPTIME, KEY_PAN_UPTIME), (LBL_PAN_ACTIVE, KEY_PAN_ACTIVE),
                    (LBL_PAN_ALT_IP, KEY_PAN_ALT_IP), (LBL_PAN_NGFW_COUNT, KEY_PAN_NGFW_COUNT),
                    (LBL_PAN_LIC_DEV_CAP, KEY_PAN_LIC_DEV_CAP), (LBL_PAN_APP_VERSION, KEY_PAN_APP_VERSION),
                    (LBL_PAN_AV_VERSION, KEY_PAN_AV_VERSION), (LBL_PAN_WILDFIRE_VERSION, KEY_PAN_WILDFIRE_VERSION),
                    (LBL_PAN_LOGDB_VERSION, KEY_PAN_LOGDB_VERSION), (LBL_PAN_DEV_CERT_STATUS, KEY_PAN_DEV_CERT_STATUS),
                    (LBL_PAN_LAST_SYS_REFRESH, KEY_PAN_LAST_SYS_REFRESH)
                ]
            else:
                headers = {HDR_HOSTNAME: KEY_HOSTNAME, HDR_SERIAL: KEY_SERIAL, HDR_IP: KEY_IP_ADDRESS,
                           HDR_ALT_IP: KEY_ALT_IP, HDR_ACTIVE: KEY_ACTIVE, HDR_NGFW_COUNT: KEY_NGFW_COUNT}

    except MTControllerException as e:
        raise e

    if csv_output_file:
        data_results = response.get('results')
        csv_generation_message = ""
        success_writing_csv = False

        if not data_results:
            if response.get('message'):
                print(f"Info: {' '.join(response.get('message', [])).strip()}. CSV file '{csv_output_file}' not generated.")
            else:
                print(f"Info: No data found to write to CSV for '{option}'. File '{csv_output_file}' not generated.")
            return

        if option == CMD_INTERFACESV6:
            success_writing_csv, csv_generation_message = cli_output.write_interfaces_v6_to_csv(csv_output_file, data_results)
        elif show_detail and option == CMD_NGFWS and attributes_for_ngfw_detail_csv:
            success_writing_csv, csv_generation_message = cli_output.write_detail_to_csv_generic(csv_output_file, attributes_for_ngfw_detail_csv, data_results)
        elif show_detail and option == CMD_PAN and attributes_for_pan_detail_csv:
            success_writing_csv, csv_generation_message = cli_output.write_detail_to_csv_generic(csv_output_file, attributes_for_pan_detail_csv, data_results)
        elif headers:
            success_writing_csv, csv_generation_message = cli_output.write_results_to_csv(csv_output_file, headers, data_results)
        else:
            csv_generation_message = f"Error: CSV output scenario for '{option}' (detail={show_detail}) is not properly configured. File '{csv_output_file}' not generated."
            success_writing_csv = False

        print(csv_generation_message)

    else:
        if option == CMD_INTERFACESV6:
            cli_output.print_interfaces_v6(response.get('results'), response.get('message'))
        elif show_detail and option == CMD_NGFWS:
            cli_output.print_ngfw_detail_results(results=response.get('results'), message=response.get('message'))
        elif show_detail and option == CMD_PAN:
            cli_output.print_panorama_detail_results(results=response.get('results'), message=response.get('message'))
        else:
            if legend and response.get('results'):
                print(f"\n{legend}\n")
            if not headers and response.get('results'):
                 print(f"Warning: Output headers missing for command '{option}'. Raw data might be incomplete or unformatted.")
            cli_output.print_results(headers, response.get('results'), response.get('message'))

def handle_fib_lookup(args, controller):
    """
    Handles the 'fib-lookup' command. Performs FIB lookup calculation or on-demand test.
    """
    ip_address_str = args.address
    ngfw_filter = args.ngfw
    vr_filter = args.vr
    on_demand = args.on_demand
    yes = args.yes

    try:
        ipaddress.ip_address(ip_address_str)
    except ValueError:
        raise ValueError(f"Invalid IP address provided: '{ip_address_str}'")

    headers = {HDR_NGFW: KEY_NGFW, HDR_VR: KEY_VR,
               HDR_INTERFACE: KEY_INTERFACE, HDR_NEXTHOP: KEY_NEXTHOP, HDR_ZONE: KEY_ZONE}
    response = {'results': None, 'message': None}

    try:
        if on_demand:
            print(f"Performing on-demand FIB lookup for {ip_address_str}...")
            vr_list = controller.get_virtual_routers(ngfw=ngfw_filter, virtual_router=vr_filter).get('results', [])
            vr_count = len(vr_list)

            if vr_count == 0:
                 print("Warning: No matching virtual routers found for the specified filters.", file=sys.stderr)
            elif vr_count > 1 and not yes:
                 confirm_msg = (f"{vr_count} virtual-routers match the query. This will perform "
                                f"{vr_count} API calls for the FIB test. Proceed? (y/n): ")
                 choice = input(confirm_msg)
                 if choice.lower().strip() != 'y':
                     print("Operation cancelled.")
                     return

            if vr_count > 0:
                 print(f"Testing FIB on {vr_count} virtual-router(s). This may take some time...\n")

            response = controller.test_fib_lookup(ip_address_str, vr_query=vr_filter, ngfw_query=ngfw_filter)

        else:
            response = controller.calculate_fib_lookup(ip_address_str=ip_address_str, vr_query=vr_filter, ngfw_query=ngfw_filter)

        cli_output.print_results(headers, response.get('results'), response.get('message'))

    except MTControllerException as e:
        raise e

def handle_update_ha(args, controller):
    """
    Handles the 'update-ha' command. Updates HA status for devices via API calls.
    """
    print("Updating HA status for relevant devices...")
    try:
        message = controller.update_ha_status(pan_filter=args.pan, ngfw_filter=args.ngfw)
        if message:
            print("\n".join(message))
        else:
            print("No HA status updates performed or no HA devices found.")
    except MTControllerException as e:
        raise e

# ==============================================================================
# Main Execution Block
# ==============================================================================

def main():
    """
    Main function to parse arguments and dispatch commands.
    Initializes backend components (Builder, Controller) and sets up argparse.
    Performs a check for database readiness before defining most commands.
    """
    parser = argparse.ArgumentParser(
        description="Master Troubleshooter CLI: Manage and query Palo Alto Networks device info.",
        epilog="Use '<command> --help' for more information on a specific command."
    )
    subparsers = parser.add_subparsers(
        title="Available Commands",
        metavar="COMMAND",
        dest="command",
        help="The action to perform",
        required=True
    )

    builder = None
    try:
        builder = MTBuilder(db_uri=db_uri)
    except Exception as e:
         print(f"Fatal Error: Could not initialize Database Builder: {e}", file=sys.stderr)
         print("Please ensure database configuration is correct and dependencies are installed.", file=sys.stderr)
         sys.exit(1)

    parser_build = subparsers.add_parser(
        "build-db",
        help="Build the database schema (run first if DB doesn't exist)"
    )
    parser_build.set_defaults(func=lambda args: handle_build_db(args, builder))

    controller = None
    inventory = None
    db_ready = False
    try:
        controller = MTController(db_uri=db_uri, timeout=timeout)
        inventory = controller.get_inventory()
        if isinstance(inventory, dict):
             db_ready = True
        else:
             logging.error("Controller initialized, but inventory retrieval failed.")

    except MTDatabaseSchemaError as schema_err:
        logging.error("Database schema not found. Please run 'build-db' first.")
        db_ready = False
    except sqlalchemy_exc.OperationalError as db_err:
        logging.error(f"Database connection failed: {db_err}. Check permissions and file integrity.")
        db_ready = False
    except MTDatabaseManagerException as e:
        logging.error(f"Database Manager error during controller initialization: {e}")
        db_ready = False
    except MTControllerException as e:
        logging.error(f"Controller initialization failed: {e}")
        db_ready = False
    except Exception as e:
        logging.error(f"Unexpected error during controller initialization: {e}")
        db_ready = False

    if db_ready:
        parser_inv = subparsers.add_parser(
            "inventory",
            help="Display database inventory metrics"
        )
        parser_inv.set_defaults(func=lambda args: handle_inventory(args, controller))

        parser_add = subparsers.add_parser(
            "add",
            help="Add a Panorama or NGFW device to the database"
        )
        parser_add.add_argument("platform", choices=[PLATFORM_PANORAMA, PLATFORM_NGFW], help=f"Specify '{PLATFORM_PANORAMA}' or '{PLATFORM_NGFW}'")
        parser_add.add_argument("-H", "--host", type=str, help="IP address or FQDN (will prompt if omitted)")
        parser_add.add_argument("-u", "--username", type=str, help="Device username (will prompt if omitted)")
        parser_add.add_argument("-p", "--password", type=str, help="Device password (will prompt securely if omitted)")
        parser_add.set_defaults(func=lambda args: handle_add(args, builder))

        show_pan_filter_enabled = False
        if inventory and inventory.get('Panoramas', 0) > 0:
            parser_import = subparsers.add_parser(
                "import",
                help="Import NGFWs managed by Panorama(s) into the database"
            )
            parser_import.add_argument("--pan", type=str, help="Filter by specific Panorama hostname or IP")
            parser_import.set_defaults(func=lambda args: handle_import(args, controller))
            show_pan_filter_enabled = True

        if inventory and (inventory.get('NGFWs', 0) > 0 or inventory.get('Panoramas', 0) > 0):
             parser_delete = subparsers.add_parser(
                 "delete",
                 help="Delete a Panorama or NGFW device from the database"
             )
             parser_delete.add_argument("platform", choices=[PLATFORM_PANORAMA, PLATFORM_NGFW], help=f"Specify '{PLATFORM_PANORAMA}' or '{PLATFORM_NGFW}'")
             parser_delete.add_argument("-s", "--serial", type=str, help="Serial number of the device (will prompt if omitted)")
             parser_delete.set_defaults(func=lambda args: handle_delete(args, builder))

             parser_updateha = subparsers.add_parser(
                 "update-ha",
                 help="Update HA status for devices in the database"
             )
             parser_updateha.add_argument("--pan", type=str, help="Filter by specific Panorama hostname or IP")
             parser_updateha.add_argument("--ngfw", type=str, help="Filter by specific NGFW hostname, IP, or serial")
             parser_updateha.set_defaults(func=lambda args: handle_update_ha(args, controller))

        if inventory and inventory.get('NGFWs', 0) > 0:
            parser_refresh = subparsers.add_parser(
                "refresh",
                help="Refresh data for NGFW(s) via API calls (updates DB)"
            )
            parser_refresh.add_argument("--ngfw", type=str, help="Filter by specific NGFW hostname, IP, or serial (refreshes all if omitted)")
            parser_refresh.add_argument("--yes", "-y", action="store_true", help="Bypass confirmation prompt when refreshing multiple NGFWs")
            parser_refresh.set_defaults(func=lambda args: handle_refresh(args, controller))

            parser_update = subparsers.add_parser(
                "update",
                help="Update specific attributes for NGFW(s) via API calls (updates DB)"
            )
            update_options = [CMD_ROUTES, CMD_ARPS, CMD_LLDP, CMD_BGP_PEERS]
            parser_update.add_argument(
                "option",
                choices=update_options,
                help="The specific attribute set to update"
            )
            parser_update.add_argument("--ngfw", type=str, help="Filter by specific NGFW hostname, IP, or serial (updates all matching if omitted)")
            parser_update.add_argument("--vr", type=str, help="Filter by virtual router name (for routes, bgp-peers)")
            parser_update.add_argument("--int", type=str, help="Filter by interface name (for arps)")
            parser_update.add_argument("--yes", "-y", action="store_true", help="Bypass confirmation prompt for multiple NGFWs")
            parser_update.set_defaults(func=lambda args: handle_update(args, controller))

            parser_fib = subparsers.add_parser(
                "fib-lookup",
                help="Perform a FIB lookup for an IPv4 address"
            )
            parser_fib.add_argument("address", help="IPv4 address for the FIB lookup")
            parser_fib.add_argument("--ngfw", type=str, help="Filter by specific NGFW hostname, IP, or serial")
            parser_fib.add_argument("--vr", type=str, help="Filter by virtual router name")
            parser_fib.add_argument("--on-demand", action="store_true", help="Perform live API test on device(s) instead of DB calculation")
            parser_fib.add_argument("--yes", "-y", action="store_true", help="Bypass confirmation prompt for on-demand tests on multiple VRs/NGFWs")
            parser_fib.set_defaults(func=lambda args: handle_fib_lookup(args, controller))

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
            
            parser_show.add_argument(
                "--detail",
                action="store_true",
                help="Show detailed information (currently applies to 'show ngfws')"
            )

            parser_show.add_argument(
                "--csv",
                nargs='?',
                const=True,
                metavar="FILENAME.CSV",
                help="Output the results to a CSV file. Optionally specify a filename. Defaults to <command_option>.csv."
            )

            parser_show.set_defaults(func=lambda args: handle_show(args, controller))

    try:
        args = parser.parse_args()
    except SystemExit as e:
         sys.exit(e.code)

    exit_code = 0
    try:
        if hasattr(args, 'func'):
            args.func(args)
        else:
            print("\nError: Command not available or invalid.", file=sys.stderr)
            exit_code = 1
    except (MTControllerException, MTBuilderException, MTDatabaseManagerException) as e:
         print(f"\nExecution Error: {e}", file=sys.stderr)
         exit_code = 1
    except ValueError as e:
         print(f"\nInput Error: {e}", file=sys.stderr)
         exit_code = 1
    except KeyboardInterrupt:
         print("\nOperation interrupted by user.", file=sys.stderr)
         exit_code = 1
    except Exception as e:
        print(f"\nAn unexpected error occurred: {e}", file=sys.stderr)
        exit_code = 1

    sys.exit(exit_code)


if __name__ == '__main__':
    main()
