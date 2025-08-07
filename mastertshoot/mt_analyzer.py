# mastertshoot/mt_analyzer.py

import ipaddress
import logging
import copy
from collections import defaultdict

# --- SQLAlchemy Imports ---
from sqlalchemy.orm import Session, joinedload
from sqlalchemy import select, exc as sqlalchemy_exc

# Import models
from models import Ngfw, VirtualRouter, Fib, Interface, InterfaceIPv6Address, Route, BGPPeer, Neighbor, Arp

# Import dependencies (these should now be passed in __init__)
from mastertshoot.mt_database_manager import MTDatabaseManager
from mastertshoot.mt_api_service import MTAPIService
from mastertshoot.mt_data_formatter import MTDataFormatter

# Import custom exceptions from the centralized file
from mastertshoot.mt_exceptions import MTControllerException, MTAPIServiceException


class MTAnalyzer:
    """
    Provides core network analysis functionalities, including FIB lookup calculations,
    path tracing, zone enrichment, and other data processing logic.
    It operates on data fetched from the database via MTDatabaseManager
    and can trigger live API lookups via MTAPIService.
    """

    def __init__(self, db_manager: MTDatabaseManager, api_service: MTAPIService, data_formatter: MTDataFormatter):
        """
        Initializes the MTAnalyzer.

        Args:
            db_manager (MTDatabaseManager): An instance of MTDatabaseManager for database interactions.
            api_service (MTAPIService): An instance of MTAPIService for live API calls.
            data_formatter (MTDataFormatter): An instance of MTDataFormatter for data presentation.
        """
        self.db_manager = db_manager
        self.api_service = api_service
        self.data_formatter = data_formatter
        logging.debug("MTAnalyzer initialized.")

    def trace_path_on_map(self, src_ip_str: str, dst_ip_str: str, map_key: str = None,
                          get_map_by_key_func=None, get_all_maps_for_ui_func=None) -> dict:
        """
        Performs two calculated FIB lookups for a source and destination IP,
        and returns a filtered map structure containing only the ingress and egress
        trace nodes, including special handling for DROP routes.

        Args:
            src_ip_str (str): The source IP address for the trace.
            dst_ip_str (str): The destination IP address for the trace.
            map_key (str, optional): A specific map key (e.g., "NGFW-1 - vr:default")
                                     to limit the trace to a single map. Defaults to None (all maps).
            get_map_by_key_func (callable): Function reference from MTController to get a single map.
            get_all_maps_for_ui_func (callable): Function reference from MTController to get all maps.

        Returns:
            dict: A dictionary representing the traced map data.
                  Returns None if no paths could be traced.
        """
        logging.info(f"Tracing path on map. Source: {src_ip_str}, Destination: {dst_ip_str}, Map Key: {map_key or 'All'}")

        vr_filter = None
        ngfw_filter = None
        if map_key:
            ngfw_filter, vr_filter = [part.strip() for part in map_key.split(' - ', 1)]

        # Calls self.calculate_fib_lookup which is now part of MTAnalyzer
        src_lookup_data = self.calculate_fib_lookup(src_ip_str, vr_query=vr_filter, ngfw_query=ngfw_filter)
        dst_lookup_data = self.calculate_fib_lookup(dst_ip_str, vr_query=vr_filter, ngfw_query=ngfw_filter)

        src_results = src_lookup_data.get('results')
        dst_results = dst_lookup_data.get('results')

        if not src_results or not dst_results:
            return None

        ingress_map = {f"{res['ngfw']} - {res['virtual_router']}": res for res in src_results}
        egress_map = {f"{res['ngfw']} - {res['virtual_router']}": res for res in dst_results}

        # These functions will be passed from MTController (the orchestrator)
        if get_map_by_key_func is None or get_all_maps_for_ui_func is None:
            logging.error("MTAnalyzer: Map retrieval functions not provided for trace_path_on_map.")
            return None

        if map_key:
            full_map_data = {map_key: get_map_by_key_func(map_key)}
        else:
            full_map_data = get_all_maps_for_ui_func()

        traced_maps = {}

        for key, map_data in full_map_data.items():
            if not map_data: continue

            ingress_result = ingress_map.get(key)
            egress_result = egress_map.get(key)

            if not ingress_result or not egress_result:
                continue

            new_map_data = copy.deepcopy(map_data)
            trace_nodes = []

            if ingress_result:
                if ingress_result.get('nexthop') == 'drop':
                    trace_nodes.append({"name": "DROP!!", "type": "drop", "trace_type": "ingress"})
                elif ingress_result.get('interface'):
                    trace_nodes.append({
                        "name": ingress_result['zone'],
                        "interface_name": ingress_result['interface'],
                        "type": "zone",
                        "trace_type": "ingress"
                    })

            if egress_result:
                is_ingress_drop = ingress_result and ingress_result.get('nexthop') == 'drop'
                is_egress_drop = egress_result.get('nexthop') == 'drop'
                is_same_interface = ingress_result and ingress_result.get('interface') and ingress_result.get('interface') == egress_result.get('interface')

                if is_ingress_drop and is_egress_drop:
                    for node in trace_nodes:
                        if node.get('trace_type') == 'ingress':
                            node['trace_type'] = 'ingress-egress'
                            break
                elif is_same_interface:
                     for node in trace_nodes:
                        if node.get('trace_type') == 'ingress':
                            node['trace_type'] = 'ingress-egress'
                            break
                elif is_egress_drop:
                    trace_nodes.append({"name": "DROP!!", "type": "drop", "trace_type": "egress"})
                elif egress_result.get('interface'):
                    trace_nodes.append({
                        "name": egress_result['zone'],
                        "interface_name": egress_result['interface'],
                        "type": "zone",
                        "trace_type": "egress"
                    })

            if trace_nodes:
                new_map_data['ngfw']['children'][0]['children'] = trace_nodes
                traced_maps[key] = new_map_data

        return traced_maps if not map_key else traced_maps.get(map_key)

    def calculate_fib_lookup_for_map(self, ip_address_str: str, map_key: str = None,
                                      get_map_by_key_func=None, get_all_maps_for_ui_func=None) -> dict:
        """
        Performs a calculated FIB lookup and returns a filtered map structure
        containing only the egress path for the given IP.

        Args:
            ip_address_str (str): The IP address for the FIB lookup.
            map_key (str, optional): A specific map key (e.g., "NGFW-1 - vr:default")
                                     to limit the lookup to a single map. Defaults to None (all maps).
            get_map_by_key_func (callable): Function reference from MTController to get a single map.
            get_all_maps_for_ui_func (callable): Function reference from MTController to get all maps.

        Returns:
            dict: A dictionary representing the filtered map data.
                  Returns None if no matching route is found.
        """
        logging.info(f"Calculating map-based FIB lookup for IP: {ip_address_str}, Map Key: {map_key or 'All'}")

        vr_filter = None
        ngfw_filter = None
        if map_key:
            ngfw_filter, vr_filter = [part.strip() for part in map_key.split(' - ', 1)]
        
        # Calls self.calculate_fib_lookup which is now part of MTAnalyzer
        lookup_results_data = self.calculate_fib_lookup(ip_address_str, vr_query=vr_filter, ngfw_query=ngfw_filter)
        lookup_results = lookup_results_data.get('results')

        if not lookup_results:
            return None

        egress_map = {f"{res['ngfw']} - {res['virtual_router']}": res['interface'] for res in lookup_results}

        # These functions will be passed from MTController (the orchestrator)
        if get_map_by_key_func is None or get_all_maps_for_ui_func is None:
            logging.error("MTAnalyzer: Map retrieval functions not provided for calculate_fib_lookup_for_map.")
            return None

        if map_key:
            full_map_data = {map_key: get_map_by_key_func(map_key)}
        else:
            full_map_data = get_all_maps_for_ui_func()

        filtered_maps = {}

        for key, map_data in full_map_data.items():
            if not map_data: continue

            egress_interface = egress_map.get(key)
            if not egress_interface:
                continue

            new_map_data = copy.deepcopy(map_data)
            
            vr_children = new_map_data['ngfw']['children'][0]['children']
            
            final_node = None
            if egress_interface == 'drop' or egress_interface.split('/')[0] in {vr['name'] for vr in vr_children if vr['type'] == 'next-vr'}:
                node_name = egress_interface.split('/')[0]
                final_node = next((node for node in vr_children if node['name'] == node_name), None)
            else:
                for zone in vr_children:
                    if zone.get('type') == 'zone' and zone.get('interfaces'):
                        if any(iface['name'] == egress_interface for iface in zone['interfaces']):
                            final_node = zone
                            break
            
            if final_node:
                new_map_data['ngfw']['children'][0]['children'] = [final_node]
                filtered_maps[key] = new_map_data

        return filtered_maps if not map_key else filtered_maps.get(map_key)

    def test_fib_lookup(self, ip_address, vr_query=None, ngfw_query=None) -> dict:
        """
        Performs an on-demand FIB lookup test directly on device(s) via API.

        Args:
            ip_address (str): The IP address to test.
            vr_query (str, optional): Filter by virtual router name.
            ngfw_query (str, optional): Filter by NGFW hostname, IP, or serial.

        Returns:
            dict: A dictionary containing 'message' (list of strings) and 'results' (list of formatted dicts).
        """
        logging.info(f"Performing on-demand FIB lookup test. IP: {ip_address}, NGFW: '{ngfw_query}', VR: '{vr_query}'")
        response = {'message': [], 'results': None}
        temp_results = []

        try:
            with self.db_manager.get_session() as session:
                # Use db_manager to get VRs based on filters
                vr_list_db = self.db_manager.get_vrs_by_ngfw_and_filter(session, None, vr_query)
                if ngfw_query:
                    ngfw_objs = self.db_manager.get_ngfws_by_filter(session, ngfw_query)
                    if not ngfw_objs:
                        response['message'].append("No NGFWs found matching criteria.")
                        return response
                    ngfw_ids = {n.id for n in ngfw_objs}
                    vr_list_db = [vr for vr in vr_list_db if vr.ngfw_id in ngfw_ids]
                
                if not vr_list_db:
                    response['message'].append("No VRs found matching criteria.")
                    return response

                # Get all unique NGFW IDs to pass to zone enrichment
                all_ngfw_ids = list({vr.ngfw.id for vr in vr_list_db if vr.ngfw})

                for vr in vr_list_db:
                    if not vr.ngfw: # Ensure NGFW object is loaded
                        logging.warning(f"Skipping VR {vr.name} due to missing NGFW association.")
                        continue

                    response['message'].append(f"--- Testing FIB Lookup (On-Demand) for {ip_address} on {vr.ngfw.hostname}/{vr.name} ---")
                    # Use api_service to fetch live FIB lookup test
                    result_api = self.api_service.fetch_fib_lookup_test(vr.ngfw, ip_address, vr.name)

                    result_dict = {'ngfw': vr.ngfw.hostname, 'virtual_router': vr.name}

                    if result_api is None:
                        response['message'].append(f"  API Error or connection failure.")
                        result_dict.update({'interface': 'API Error', 'nexthop': 'API Error', 'zone': 'API Error'})
                    elif 'interface' not in result_api:
                        response['message'].append(f"  No route found via API test.")
                        result_dict.update({'interface': 'None', 'nexthop': 'None', 'zone': 'None'})
                    else:
                        result_dict['interface'] = result_api.get('interface')
                        nh_key = result_api.get('nh')
                        next_hop = result_api.get(nh_key, 'self') if nh_key else 'self'
                        result_dict['nexthop'] = next_hop
                        response['message'].append(f"  Lookup successful (raw): Interface='{result_dict['interface']}', Nexthop='{result_dict['nexthop']}'.")
                    temp_results.append(result_dict)

                if temp_results:
                    # Call the now existing _enrich_results_with_zone on self
                    self._enrich_results_with_zone(session, all_ngfw_ids, temp_results)
                    # The data_formatter.format_fib_lookup_result will handle 'None' to '' conversion
                    formatted_results = [self.data_formatter.format_fib_lookup_result(res) for res in temp_results]

            if formatted_results:
                response['results'] = formatted_results
            return response
        except sqlalchemy_exc.SQLAlchemyError as e:
            raise MTControllerException(f"Database error in test_fib_lookup: {e}")
        except MTAPIServiceException as e:
            raise MTControllerException(f"API service error in test_fib_lookup: {e}")
        except Exception as e:
            logging.error(f"Error in test_fib_lookup: {e}", exc_info=True)
            raise MTControllerException(f"An unexpected error occurred: {e}")


    def calculate_fib_lookup(self, ip_address_str: str, vr_query: str = None, ngfw_query: str = None) -> dict:
        """
        Calculates the best matching FIB entry for a given IP address across specified virtual routers.

        Args:
            ip_address_str (str): The IP address (IPv4 or IPv6) to perform the FIB lookup on.
            vr_query (str, optional): The virtual router name to filter the lookup. Defaults to None (all VRs).
            ngfw_query (str, optional): The NGFW hostname, IP, or serial to filter the lookup. Defaults to None (all NGFWs).

        Returns:
            dict: A dictionary containing:
                - 'message' (list): Status messages during processing.
                - 'results' (list | None): A list of dictionaries, each representing the best FIB match
                                           found for the IP in a specific virtual router. Returns None if no results.
                                           Each result dictionary is formatted by data_formatter.format_fib_lookup_result.

        Raises:
            MTControllerException: If the provided IP address string is invalid or a database error occurs.
        """
        response = {'message': [], 'results': None}
        formatted_results = []

        try:
            target_ip = ipaddress.ip_address(ip_address_str)
        except ValueError:
            raise MTControllerException(f"Invalid IP Address provided: {ip_address_str}")

        try:
            with self.db_manager.get_session() as session:
                ngfw_ids = None
                if ngfw_query:
                    ngfw_objs = self.db_manager.get_ngfws_by_filter(session, ngfw_query)
                    if not ngfw_objs:
                        response['message'].append(f"No NGFWs found matching filter: {ngfw_query}")
                        return response
                    ngfw_ids = {n.id for n in ngfw_objs}

                query = session.query(VirtualRouter).options(
                    joinedload(VirtualRouter.ngfw),
                    joinedload(VirtualRouter.fib)
                )
                if ngfw_ids:
                    query = query.filter(VirtualRouter.ngfw_id.in_(ngfw_ids))
                if vr_query:
                    query = query.filter(VirtualRouter.name == vr_query)

                virtual_router_list = query.all()

                if not virtual_router_list:
                    response['message'].append("No virtual routers found matching the specified criteria.")
                    return response

                response['message'].append(f"Found {len(virtual_router_list)} virtual router(s) to check.")

                for vr in virtual_router_list:
                    best_match_fib = None
                    longest_prefix = -1

                    for fib_entry in vr.fib:
                        if "u" not in fib_entry.flags.lower():
                            continue

                        try:
                            network = ipaddress.ip_network(fib_entry.destination, strict=False)
                            if target_ip in network:
                                if network.prefixlen > longest_prefix:
                                    longest_prefix = network.prefixlen
                                    best_match_fib = fib_entry
                        except ValueError:
                            response['message'].append(f"Warning: Skipping invalid FIB destination '{fib_entry.destination}' in VR '{vr.name}' on NGFW '{vr.ngfw.hostname}'.")
                            continue

                    if best_match_fib: # Only append if a match was found for this VR
                        lookup_data = {
                            'ngfw': vr.ngfw.hostname,
                            'virtual_router': vr.name,
                            'destination': best_match_fib.destination,
                            'nexthop': best_match_fib.nexthop,
                            'flags': best_match_fib.flags,
                            'interface': best_match_fib.interface,
                            'zone': best_match_fib.zone
                        }
                        # The data_formatter.format_fib_lookup_result will handle 'None' to '' conversion
                        formatted_results.append(self.data_formatter.format_fib_lookup_result(lookup_data))
                        response['message'].append(f"Match found in {vr.ngfw.hostname}/{vr.name}: {best_match_fib.destination}")
                    else:
                        no_match_data = {
                            'ngfw': vr.ngfw.hostname,
                            'virtual_router': vr.name,
                            'destination': "None",
                            'nexthop': "None",
                            'flags': "None",
                            'interface': "None",
                            'zone': None # Set to None for formatter to handle
                        }
                        # The data_formatter.format_fib_lookup_result will handle 'None' to '' conversion
                        formatted_results.append(self.data_formatter.format_fib_lookup_result(no_match_data))
                        response['message'].append(f"No matching route found for {ip_address_str} in {vr.ngfw.hostname}/{vr.name}")

                if formatted_results:
                    response['results'] = formatted_results

            return response
        except sqlalchemy_exc.SQLAlchemyError as db_err:
            raise MTControllerException(f"Database error during FIB lookup calculation: {db_err}")
        except Exception as e:
            raise MTControllerException(f"Unexpected error during FIB lookup calculation: {e}")

    def _enrich_results_with_zone(self, session: Session, ngfw_ids: list, results_list: list):
        """
        Helper method to enrich a list of results (from API calls) with zone information
        by querying the database. Modifies the results_list in place.

        Args:
            session (Session): The SQLAlchemy session to use for database queries.
            ngfw_ids (list): A list of NGFW IDs to limit the interface query.
            results_list (list): A list of dictionaries, each expected to have 'ngfw' (hostname)
                                 and 'interface' fields, and will be updated with a 'zone' field.
        """
        logging.debug(f"Enriching {len(results_list)} results with zone information for NGFW IDs: {ngfw_ids}")
        interface_zone_map = {} # {(ngfw_id, interface_name): zone_name}

        if not ngfw_ids:
            logging.warning("No NGFW IDs provided for zone enrichment. Skipping enrichment.")
            return

        # Fetch all relevant interfaces for the given NGFW IDs in one go
        interfaces = session.query(Interface).join(VirtualRouter).join(Ngfw).filter(
            Ngfw.id.in_(ngfw_ids)
        ).options(
            joinedload(Interface.virtual_router).joinedload(VirtualRouter.ngfw)
        ).all()

        for iface in interfaces:
            if iface.virtual_router and iface.virtual_router.ngfw:
                interface_zone_map[(iface.virtual_router.ngfw.hostname, iface.name)] = iface.zone

        for result in results_list:
            ngfw_hostname = result.get('ngfw')
            interface_name = result.get('interface')
            
            if ngfw_hostname and interface_name:
                # Set to None if not found, so formatter can turn it into ''
                zone = interface_zone_map.get((ngfw_hostname, interface_name), None) 
                result['zone'] = zone
            else:
                result['zone'] = None # Set to None for formatter to handle
        logging.debug("Zone enrichment complete.")

    def _detect_address_family(self, address_string: str) -> str | None:
        """Detects if an IP address or prefix string is IPv4 or IPv6."""
        if not address_string:
            return None
        try:
            addr = ipaddress.ip_address(address_string)
            return 'ipv6' if isinstance(addr, ipaddress.IPv6Address) else 'ipv4'
        except ValueError:
            try:
                net = ipaddress.ip_network(address_string, strict=False)
                return 'ipv6' if isinstance(net, ipaddress.IPv6Network) else 'ipv4'
            except ValueError:
                if address_string == 'default': return 'ipv4'
                logging.warning("Warning: Could not determine AFI for destination: %s", address_string)
                return None
