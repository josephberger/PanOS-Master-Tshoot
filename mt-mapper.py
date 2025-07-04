import json
import argparse
import logging
import sys
from collections import defaultdict
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, joinedload, subqueryload

try:
    from models import Base, Ngfw, VirtualRouter, Interface, Fib
    from config import db_uri
except ImportError:
    print("Could not import database models or config. Make sure this script is run from the correct directory.")
    sys.exit(1)


class MapperException(Exception):
    """Custom exception for mt-mapper errors."""
    pass

def setup_logging():
    """Sets up basic logging."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[logging.StreamHandler(sys.stdout)]
    )

def format_vr_map(vr_obj):
    """
    Formats the data for a single virtual router into the required dict structure.
    """
    map_data = {
        "ngfw": {
            "name": vr_obj.ngfw.hostname,
            "children": [
                {
                    "name": vr_obj.name,
                    "type": "virtual-router",
                    "children": []
                }
            ]
        }
    }
    vr_children = []
    
    # --- NEW: More efficient and robust FIB processing logic ---

    # 1. Get all VR names on the same NGFW for validation
    all_vr_names_on_ngfw = {vr.name for vr in vr_obj.ngfw.virtual_routers}

    # 2. Partition all FIBs in a single pass
    fibs_by_interface_id = defaultdict(list)
    next_vr_groups = defaultdict(list)
    drop_fibs = []

    for fib in vr_obj.fib:
        if not fib.destination:
            continue

        # If fib has an interface_id, it belongs to a regular interface
        if fib.interface_id:
            fibs_by_interface_id[fib.interface_id].append(fib.destination)
            continue

        # If no interface_id, check for special types (next-vr or drop)
        is_next_vr = False
        if fib.interface and '/' in fib.interface:
            dest_vr_candidate = fib.interface.split('/')[0]
            if dest_vr_candidate in all_vr_names_on_ngfw:
                next_vr_groups[dest_vr_candidate].append(fib.destination)
                is_next_vr = True
        
        if not is_next_vr and fib.nexthop == 'drop':
            drop_fibs.append(fib.destination)

    # 3. Process regular interfaces using the partitioned FIBs
    for iface in vr_obj.interfaces:
        fib_destinations = fibs_by_interface_id.get(iface.id, [])
        if not fib_destinations:
            continue

        vr_children.append({
            "name": iface.name,
            "zone": iface.zone,
            "ip": iface.ip,
            "vsys": iface.vsys,
            "tag": iface.tag,
            "ipv6_enabled": iface.ipv6_enabled,
            "ipv6_addresses": [addr.address for addr in iface.ipv6_addresses],
            "type": "interface",
            "children": [{"name": "FIBs", "type": "fib-container", "fibs": fib_destinations}]
        })

    # 4. Create synthetic "drop" node
    if drop_fibs:
        vr_children.append({
            "name": "drop", "type": "drop", "children": [{"name": "FIBs", "type": "fib-container", "fibs": drop_fibs}]
        })

    # 5. Create synthetic "next-vr" nodes
    for dest_vr, fibs in next_vr_groups.items():
        vr_children.append({
            "name": f"To: {dest_vr}", "type": "next-vr", "children": [{"name": "FIBs", "type": "fib-container", "fibs": fibs}]
        })
    
    map_data["ngfw"]["children"][0]["children"] = vr_children
    return map_data

def get_single_vr_data(session, ngfw_name, vr_name):
    logging.info(f"Querying database for NGFW '{ngfw_name}' and VR '{vr_name}'...")
    vr_obj = session.query(VirtualRouter).join(Ngfw).options(
        subqueryload(VirtualRouter.interfaces).subqueryload(Interface.ipv6_addresses),
        subqueryload(VirtualRouter.fib),
        joinedload(VirtualRouter.ngfw)
    ).filter(
        Ngfw.hostname == ngfw_name,
        VirtualRouter.name == vr_name
    ).first()
    if not vr_obj: raise MapperException(f"Could not find Virtual Router '{vr_name}' on NGFW '{ngfw_name}' in the database.")
    logging.info("Found Virtual Router. Formatting data...")
    return format_vr_map(vr_obj)

def get_all_vr_data(session):
    logging.info("Querying database for all NGFWs and Virtual Routers...")
    all_ngfws = session.query(Ngfw).options(
        subqueryload(Ngfw.virtual_routers).subqueryload(VirtualRouter.interfaces).subqueryload(Interface.ipv6_addresses),
        subqueryload(Ngfw.virtual_routers).subqueryload(VirtualRouter.fib)
    ).all()
    if not all_ngfws: raise MapperException("No NGFWs found in the database.")
    logging.info(f"Found {len(all_ngfws)} NGFW(s). Formatting map data for all VRs...")
    all_maps = {}
    for ngfw in all_ngfws:
        for vr in ngfw.virtual_routers:
            key = f"{ngfw.hostname} - {vr.name}"
            map_data = format_vr_map(vr)
            all_maps[key] = map_data
            logging.info(f"  - Formatted map for '{key}'")
    return all_maps

def main():
    setup_logging()
    parser = argparse.ArgumentParser(description="MT-Mapper: Generate visualization data for a PanOS virtual router.")
    parser.add_argument("--ngfw", help="The hostname of the NGFW to target. (Required for single mode).")
    parser.add_argument("--vr", help="The name of the virtual-router to map. (Required for single mode).")
    parser.add_argument("-o", "--output", default="map_data.json", help="The output filename for the JSON data.")
    args = parser.parse_args()
    if args.ngfw and args.vr: mode = "single"
    elif not args.ngfw and not args.vr: mode = "batch"
    else: parser.error("Invalid argument combination. You must specify BOTH --ngfw and --vr, or NEITHER for batch mode.")
    try:
        engine = create_engine(db_uri)
        Session = sessionmaker(bind=engine)
        session = Session()
        if mode == "single": map_data = get_single_vr_data(session, args.ngfw, args.vr)
        else: map_data = get_all_vr_data(session)
        logging.info(f"Writing map data to '{args.output}'...")
        with open(args.output, 'w') as f: json.dump(map_data, f, indent=4)
        logging.info(f"Successfully created map data file: {args.output}")
    except MapperException as e: logging.error(f"Error: {e}")
    except Exception as e: logging.error(f"An unexpected error occurred: {e}", exc_info=True)
    finally:
        if 'session' in locals(): session.close()

if __name__ == "__main__":
    main()