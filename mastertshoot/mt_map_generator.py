# mastertshoot/mt_map_generator.py

import logging
from collections import defaultdict # Needed for LLDP map grouping

# Import models
from models import (
    Ngfw, VirtualRouter, Fib, Interface, InterfaceIPv6Address, Neighbor
)

# Import dependencies
from mastertshoot.mt_database_manager import MTDatabaseManager
from mastertshoot.mt_data_formatter import MTDataFormatter

# SQLAlchemy imports for type hinting and queries
from sqlalchemy.orm import Session, joinedload
from sqlalchemy import exc as sqlalchemy_exc

class MTMapGeneratorException(Exception):
    """Custom exception for MTMapGenerator errors."""
    pass

class MTMapGenerator:
    """
    Handles all data generation and structuring specifically for D3.js compatible
    network topology and LLDP maps.
    """

    def __init__(self, db_manager: MTDatabaseManager, data_formatter: MTDataFormatter):
        """
        Initializes the MTMapGenerator.

        Args:
            db_manager (MTDatabaseManager): An instance of MTDatabaseManager for database interactions.
            data_formatter (MTDataFormatter): An instance of MTDataFormatter for data presentation.
        """
        self.db_manager = db_manager
        self.data_formatter = data_formatter
        logging.debug("MTMapGenerator initialized.")

    def get_all_map_keys(self) -> list:
        """
        Retrieves a sorted list of all possible map keys (e.g., "NGFW-1 - vr:default").
        Used to populate the UI dropdown menu for logical maps.
        """
        logging.debug("Fetching all logical map keys for UI.")
        map_keys = []
        try:
            with self.db_manager.get_session() as session:
                all_vrs = session.query(VirtualRouter).options(joinedload(VirtualRouter.ngfw)).all()
                
                for vr_obj in all_vrs:
                    if vr_obj.ngfw:
                        map_keys.append(f"{vr_obj.ngfw.hostname} - {vr_obj.name}")
            return sorted(map_keys)
        except sqlalchemy_exc.SQLAlchemyError as e:
            raise MTMapGeneratorException(f"Database error fetching map keys: {e}")
        except Exception as e:
            raise MTMapGeneratorException(f"An unexpected error occurred getting all map keys: {e}")

    def get_map_by_key(self, map_key: str) -> dict:
        """
        Gets the data for a single logical map, identified by its key (e.g., "FW-NAME - VR-NAME").
        """
        logging.info(f"Generating logical map data for key: '{map_key}'")
        try:
            parts = map_key.split(' - ', 1)
            if len(parts) != 2:
                logging.warning(f"Invalid map key format: '{map_key}'")
                return None

            ngfw_hostname, vr_name = parts[0].strip(), parts[1].strip()
            logging.info(f"Searching for NGFW hostname: '{ngfw_hostname}' and VR name: '{vr_name}'")

            with self.db_manager.get_session() as session:
                vr_obj = session.query(VirtualRouter).join(Ngfw).filter(
                    Ngfw.hostname == ngfw_hostname,
                    VirtualRouter.name == vr_name
                ).options(
                    joinedload(VirtualRouter.ngfw).subqueryload(Ngfw.virtual_routers),
                    joinedload(VirtualRouter.interfaces).joinedload(Interface.ipv6_addresses),
                    joinedload(VirtualRouter.interfaces).subqueryload(Interface.fib_entries)
                ).first()

                if not vr_obj:
                    logging.warning(f"No match found in database for NGFW '{ngfw_hostname}' and VR '{vr_name}'.")
                    return None

                logging.info(f"Found match for {map_key}. Generating map data.")
                map_data = self._generate_logical_map_for_vr(vr_obj, session, vr_obj.ngfw)
                return map_data

        except sqlalchemy_exc.SQLAlchemyError as e:
            logging.error(f"Database error generating map for key {map_key}: {e}", exc_info=True)
            raise MTMapGeneratorException(f"Database error generating map for key {map_key}: {e}")
        except Exception as e:
            logging.error(f"An unexpected error occurred in get_map_by_key for key {map_key}: {e}", exc_info=True)
            raise MTMapGeneratorException(f"An unexpected error occurred for key {map_key}: {e}")

    def get_all_maps_for_ui(self) -> dict:
        """
        Generates the data for all logical maps in the format required by the D3.js frontend.
        """
        logging.debug("Generating data for all logical maps for UI.")
        maps_data = {}
        try:
            with self.db_manager.get_session() as session:
                all_ngfws = session.query(Ngfw).options(
                    joinedload(Ngfw.virtual_routers).joinedload(VirtualRouter.interfaces).joinedload(Interface.ipv6_addresses),
                    joinedload(Ngfw.virtual_routers).joinedload(VirtualRouter.interfaces).subqueryload(Interface.fib_entries)
                ).all()

                for ngfw in all_ngfws:
                    for vr_obj in ngfw.virtual_routers:
                        map_key = f"{ngfw.hostname} - {vr_obj.name}"
                        map_data = self._generate_logical_map_for_vr(vr_obj, session, ngfw)
                        maps_data[map_key] = map_data
            return maps_data
        except sqlalchemy_exc.SQLAlchemyError as e:
            raise MTMapGeneratorException(f"Database error generating all logical map data: {e}")
        except Exception as e:
            raise MTMapGeneratorException(f"An unexpected error occurred getting all logical maps for UI: {e}")

    def _generate_logical_map_for_vr(self, vr_obj: VirtualRouter, session: Session, parent_ngfw=None) -> dict:
        """
        Helper function to generate the D3.js JSON structure for a single VR object (logical map).
        Added parent_ngfw to allow passing NGFW details like model.
        """
        vr_children = []
        zones = {}
        processed_fib_ids = set()

        if parent_ngfw is None and vr_obj.ngfw:
            parent_ngfw = vr_obj.ngfw

        for iface_obj in vr_obj.interfaces:
            zone_name = iface_obj.zone or "unzoned"
            if zone_name not in zones:
                zones[zone_name] = {"name": zone_name, "type": "zone", "interfaces": []}
            
            fib_destinations = [fib.destination for fib in iface_obj.fib_entries if fib.destination]
            for fib in iface_obj.fib_entries:
                processed_fib_ids.add(fib.id)

            zones[zone_name]["interfaces"].append({
                "name": iface_obj.name, "ip": iface_obj.ip, "tag": iface_obj.tag,
                "ipv6_enabled": iface_obj.ipv6_enabled,
                "ipv6_addresses": [ipv6.address for ipv6 in iface_obj.ipv6_addresses],
                "fibs": fib_destinations
            })
        
        vr_children.extend(list(zones.values()))

        drop_fibs = []
        next_vr_groups = {}
        
        all_vr_names_on_ngfw = {vr.name for vr in parent_ngfw.virtual_routers}

        # Query all FIBs for this VR once
        all_vr_fibs = session.query(Fib).filter(Fib.virtual_router_id == vr_obj.id).all()

        for fib_obj in all_vr_fibs:
            if fib_obj.id in processed_fib_ids:
                continue

            if fib_obj.nexthop == 'drop':
                drop_fibs.append(fib_obj.destination)
                continue

            if fib_obj.interface and '/' in fib_obj.interface:
                dest_vr_candidate = fib_obj.nexthop
                if dest_vr_candidate in all_vr_names_on_ngfw:
                    if dest_vr_candidate not in next_vr_groups:
                        next_vr_groups[dest_vr_candidate] = []
                    next_vr_groups[dest_vr_candidate].append(fib_obj.destination)

        if drop_fibs:
            vr_children.append({"name": "drop", "type": "drop", "fibs": sorted(list(set(drop_fibs)))})

        for dest_vr, fibs in sorted(next_vr_groups.items()):
            vr_children.append({"name": dest_vr, "type": "next-vr", "fibs": sorted(list(set(fibs)))})

        return {
            "ngfw": {
                "name": parent_ngfw.hostname,
                "model": parent_ngfw.model,
                "children": [{"name": vr_obj.name, "children": vr_children}]
            }
        }

    def _generate_single_lldp_map_data(self, ngfw_obj: Ngfw, session: Session) -> dict:
        """
        Helper function to generate the D3.js JSON structure for a single NGFW's
        LLDP neighbors, grouped by remote_hostname.
        """
        logging.debug(f"Generating LLDP map data for NGFW: {ngfw_obj.hostname}")

        lldp_entries = self.db_manager.get_lldp_entries_for_ngfw(session, ngfw_obj.id)

        temp_grouped = defaultdict(list)
        for entry in lldp_entries:
            temp_grouped[entry.remote_hostname].append({
                'local_interface': entry.local_interface,
                'remote_interface_id': entry.remote_interface_id,
                'remote_interface_description': entry.remote_interface_description,
                'ngfw_hostname': ngfw_obj.hostname,
                'connected_device_name': entry.remote_hostname,
                'connected_device_type': 'remote_device'
            })

        unique_neighbor_nodes = []
        for hostname, connections in temp_grouped.items():
            unique_neighbor_nodes.append({
                'remote_hostname': hostname,
                'connections': connections
            })

        unique_neighbor_nodes.sort(key=lambda x: x['remote_hostname'])

        return {
            "ngfw_hostname": ngfw_obj.hostname,
            "ngfw_serial": ngfw_obj.serial_number,
            "ngfw_model": ngfw_obj.model,
            "unique_neighbors": unique_neighbor_nodes,
        }

    def get_lldp_map_for_ui(self, ngfw_hostname: str) -> dict | None:
            """
            Retrieves the grouped LLDP neighbor data for a specific NGFW,
            formatted for UI visualization.
            """
            logging.info(f"API call to get_lldp_map_for_ui for NGFW: '{ngfw_hostname}'")
            try:
                with self.db_manager.get_session() as session:
                    ngfw_obj_list = self.db_manager.get_ngfws_by_filter(session, ngfw_hostname)
                    ngfw_obj = ngfw_obj_list[0] if ngfw_obj_list else None
                    
                    if not ngfw_obj:
                        logging.warning(f"NGFW '{ngfw_hostname}' not found for LLDP map generation.")
                        return None
                    
                    return self._generate_single_lldp_map_data(ngfw_obj, session)

            except sqlalchemy_exc.SQLAlchemyError as e:
                logging.error(f"Database error fetching LLDP map for NGFW '{ngfw_hostname}': {e}", exc_info=True)
                raise MTMapGeneratorException(f"Database error fetching LLDP map for NGFW '{ngfw_hostname}': {e}")
            except Exception as e:
                logging.error(f"An unexpected error occurred in get_lldp_map_for_ui for NGFW '{ngfw_hostname}': {e}", exc_info=True)
                raise MTMapGeneratorException(f"An unexpected error occurred for NGFW '{ngfw_hostname}': {e}")

    def _generate_all_lldp_graph_data(self, session: Session) -> dict:
        """
        Generates a consolidated graph data structure (nodes and links)
        for all NGFWs and their unique LLDP neighbors, suitable for
        a force-directed layout.
        
        Excludes NGFWs that do not have any LLDP neighbors.
        Adds a 'label' field for truncated display names on remote devices,
        truncating to MAX_DISPLAY_LABEL_LENGTH with '..'.
        """
        logging.debug("Generating global LLDP graph data for UI.")
        
        nodes = {}
        links = []

        ngfw_nodes_added = set()
        remote_hostname_to_node_id = {}
        next_node_id = 0

        MAX_DISPLAY_LABEL_LENGTH = 12

        lldp_entries = self.db_manager.get_all_lldp_entries(session)

        if not lldp_entries:
            logging.info("No LLDP neighbor entries found in database for global map.")
            return {"nodes": [], "links": []}

        for entry in lldp_entries:
            ngfw_obj = entry.ngfw
            if not ngfw_obj:
                logging.warning(f"Skipping LLDP entry (ID: {entry.id}) due to missing associated NGFW.")
                continue

            if ngfw_obj.hostname not in ngfw_nodes_added:
                node_id = f"ngfw-{ngfw_obj.serial_number}"
                nodes[node_id] = {
                    "id": node_id,
                    "name": ngfw_obj.hostname,
                    "label": ngfw_obj.hostname,
                    "serial_number": ngfw_obj.serial_number,
                    "type": "ngfw",
                    "locked": False,
                     "model": ngfw_obj.model
                }
                ngfw_nodes_added.add(ngfw_obj.hostname)

            ngfw_source_id = nodes[f"ngfw-{ngfw_obj.serial_number}"]["id"]

            remote_hostname = entry.remote_hostname
            remote_node_id = remote_hostname_to_node_id.get(remote_hostname)

            if not remote_node_id:
                remote_node_id = f"remote-{next_node_id}"
                remote_hostname_to_node_id[remote_hostname] = remote_node_id
                
                if len(remote_hostname) > MAX_DISPLAY_LABEL_LENGTH:
                    display_label = remote_hostname[:MAX_DISPLAY_LABEL_LENGTH - 2] + ".."
                else:
                    display_label = remote_hostname
                
                nodes[remote_node_id] = {
                    "id": remote_node_id,
                    "name": remote_hostname,
                    "label": display_label,
                    "type": "remote_device",
                }
                next_node_id += 1
            
            links.append({
                "source": ngfw_source_id,
                "target": remote_node_id,
                "local_interface": entry.local_interface,
                "remote_interface_id": entry.remote_interface_id,
                "remote_interface_description": entry.remote_interface_description,
                "ngfw_hostname": ngfw_obj.hostname,
            })

        final_nodes_list = list(nodes.values())
        
        return {
            "nodes": final_nodes_list,
            "links": links
        }

    def get_global_lldp_map_for_ui(self) -> dict:
        """
        Retrieves consolidated LLDP neighbor data from all NGFWs,
        formatted as a graph (nodes and links) for a global map visualization.
        """
        logging.info("API call to get_global_lldp_map_for_ui (all NGFWs).")
        try:
            with self.db_manager.get_session() as session:
                return self._generate_all_lldp_graph_data(session)
        except sqlalchemy_exc.SQLAlchemyError as e:
            logging.error(f"Database error fetching global LLDP map data: {e}", exc_info=True)
            raise MTMapGeneratorException(f"Database error fetching global LLDP map data: {e}")
        except Exception as e:
            logging.error(f"An unexpected error occurred in get_global_lldp_map_for_ui: {e}", exc_info=True)
            raise MTMapGeneratorException(f"An unexpected error occurred in get_global_lldp_map_for_ui: {e}")
