# mastertshoot/mt_controller.py

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

import logging

from sqlalchemy import exc as sqlalchemy_exc
from sqlalchemy.orm import Session, joinedload # Session and joinedload still needed for direct DB queries in some get methods

from models import (
    Ngfw, Route, VirtualRouter, Interface, Panorama,
    Neighbor, BGPPeer, Fib, Arp, InterfaceIPv6Address
)

# Import dependencies (all service classes)
from mastertshoot.mt_database_manager import MTDatabaseManager, MTDatabaseManagerException
from mastertshoot.mt_api_service import MTAPIService, MTAPIServiceException
from mastertshoot.mt_data_formatter import MTDataFormatter
from mastertshoot.mt_analyzer import MTAnalyzer
from mastertshoot.mt_update_manager import MTUpdateManager
from mastertshoot.mt_map_generator import MTMapGenerator

# Importing the config module for database URI and timeout settings
try:
    from config import db_uri, timeout
except ImportError:
    logging.warning("Warning: Could not import db_uri and timeout from config. Using defaults or potentially failing.")
    db_uri = 'sqlite:///mtdb.db'
    timeout = 5


class MTControllerException(Exception):
    """Custom exception for MTController errors."""
    pass

class MTDatabaseSchemaError(MTControllerException):
    """Custom exception for missing or incompatible database schema."""
    pass

class MTController:
    """
    Acts as the orchestrator for the Master Troubleshooter application.
    It initializes and coordinates calls between various specialized service layers:
    MTDatabaseManager, MTAPIService, MTDataFormatter, MTAnalyzer, MTUpdateManager, and MTMapGenerator.
    It provides a high-level API for the CLI/UI to interact with the application's core logic.
    """

    def __init__(self, db_uri=db_uri, timeout=timeout) -> None:
        """
        Initializes an instance of the MTController class, setting up all service dependencies.

        Performs an initial check to ensure the database schema exists and is accessible.

        Args:
            db_uri (str): The URI of the database (e.g., 'sqlite:///mydatabase.db').
            timeout (int): The timeout value in seconds for API calls to devices.

        Raises:
            MTControllerException: If db_uri is missing or timeout is invalid.
            MTDatabaseSchemaError: If the database schema (required tables) is not found or incomplete.
            MTControllerException: If database connection/engine creation fails during initialization,
                                   or if a database error occurs during the schema check.
        """
        if not db_uri:
            raise MTControllerException("No 'db_uri' provided")
        self.db_uri = db_uri

        try:
            self.timeout = int(timeout)
        except (ValueError, TypeError):
            raise MTControllerException(f"'timeout' must be an integer, received: {timeout}")

        try:
            # Initialize core services
            self.db_manager = MTDatabaseManager(db_uri=self.db_uri)
            self.api_service = MTAPIService(timeout=self.timeout)
            self.data_formatter = MTDataFormatter(db_manager=self.db_manager)

            # Initialize higher-level services, injecting dependencies
            self.analyzer = MTAnalyzer(db_manager=self.db_manager, api_service=self.api_service, data_formatter=self.data_formatter)
            self.update_manager = MTUpdateManager(db_manager=self.db_manager, api_service=self.api_service, data_formatter=self.data_formatter, analyzer=self.analyzer)
            self.map_generator = MTMapGenerator(db_manager=self.db_manager, data_formatter=self.data_formatter)

            # Perform initial schema check
            if not self.db_manager.check_schema_exists():
                raise MTDatabaseSchemaError("Database schema not found or is incomplete.")

        except MTDatabaseManagerException as e:
            if "schema not found" in str(e).lower() or "no such table" in str(e).lower():
                raise MTDatabaseSchemaError("Database schema not found or is incomplete.") from e
            else:
                raise MTControllerException(f"Database communication issue during initialization: {e}") from e
        except Exception as e:
             raise MTControllerException(f"Unexpected error during MTController initialization: {e}")

    # ===========================================================================
    # Public API Methods (Delegating to Services)
    # These methods act as the main entry points for CLI/UI requests.
    # ===========================================================================

    def get_inventory(self) -> dict:
        """
        Returns counts of various object types currently stored in the database.
        Delegates to MTDatabaseManager.
        """
        logging.debug("Retrieving inventory counts from the database.")
        try:
            with self.db_manager.get_session() as session:
                inventory = {
                    'Panoramas': self.db_manager.count_table_entries(session, Panorama),
                    'NGFWs': self.db_manager.count_table_entries(session, Ngfw),
                    'Virtual Routers': self.db_manager.count_table_entries(session, VirtualRouter),
                    'Interfaces': self.db_manager.count_table_entries(session, Interface),
                    'Routes': self.db_manager.count_table_entries(session, Route),
                    'FIBs': self.db_manager.count_table_entries(session, Fib),
                    'ARPs': self.db_manager.count_table_entries(session, Arp),
                    'BGP Peers': self.db_manager.count_table_entries(session, BGPPeer),
                    'Neighbors': self.db_manager.count_table_entries(session, Neighbor)
                }
                return inventory
        except sqlalchemy_exc.SQLAlchemyError as db_err:
            raise MTControllerException(f"Database error while retrieving inventory: {db_err}")
        except Exception as e:
             raise MTControllerException(f"Unexpected error during get_inventory: {e}")

    def import_panorama_devices(self, pan_filter=None):
        """
        Imports NGFW details from Panoramas. This is a GENERATOR that yields
        status messages during its execution. Delegates to MTUpdateManager.
        """
        return self.update_manager.import_panorama_devices(pan_filter=pan_filter)

    def refresh_ngfws(self, ngfw_filter=None):
        """
        Refreshes NGFW data. This is a GENERATOR that yields status messages.
        Delegates to MTUpdateManager.
        """
        return self.update_manager.refresh_ngfws(ngfw_filter=ngfw_filter)

    def update_routes(self, ngfw=None, virtual_router=None) -> list:
        """
        Updates routes and FIBs (IPv4 & IPv6) in the database using API data.
        Delegates to MTUpdateManager.
        """
        return self.update_manager.update_routes(ngfw=ngfw, virtual_router=virtual_router)

    def update_arps(self, ngfw=None, interface=None) -> list:
        """
        Updates ARP entries in the database using API data.
        Delegates to MTUpdateManager.
        """
        return self.update_manager.update_arps(ngfw=ngfw, interface=interface)

    def update_neighbors(self, ngfw=None) -> list:
        """
        Updates LLDP neighbors in the database using API data.
        Delegates to MTUpdateManager.
        """
        return self.update_manager.update_neighbors(ngfw=ngfw)

    def update_bgp_peers(self, ngfw=None, virtual_router=None) -> list:
        """
        Updates BGP peers in the database using API data.
        Delegates to MTUpdateManager.
        """
        return self.update_manager.update_bgp_peers(ngfw=ngfw, virtual_router=virtual_router)

    def update_ha_status(self, ngfw_filter=None, pan_filter=None) -> list:
        """
        Updates HA status in the database using API data.
        Delegates to MTUpdateManager.
        """
        return self.update_manager.update_ha_status(ngfw_filter=ngfw_filter, pan_filter=pan_filter)

    def test_fib_lookup(self, ip_address, vr_query=None, ngfw_query=None) -> dict:
        """
        Performs an on-demand FIB lookup test via API.
        Delegates to MTAnalyzer.
        """
        return self.analyzer.test_fib_lookup(ip_address, vr_query, ngfw_query)

    def calculate_fib_lookup(self, ip_address_str: str, vr_query: str = None, ngfw_query: str = None) -> dict:
        """
        Calculates the best matching FIB entry for a given IP address across specified virtual routers.
        Delegates to MTAnalyzer.
        """
        return self.analyzer.calculate_fib_lookup(ip_address_str, vr_query, ngfw_query)

    def trace_path_on_map(self, src_ip_str: str, dst_ip_str: str, map_key: str = None) -> dict:
        """
        Performs two calculated FIB lookups for a source and destination IP,
        and returns a filtered map structure containing only the ingress and egress
        trace nodes, including special handling for DROP routes.
        Delegates to MTAnalyzer, passing map generation methods from MTMapGenerator.
        """
        return self.analyzer.trace_path_on_map(
            src_ip_str=src_ip_str,
            dst_ip_str=dst_ip_str,
            map_key=map_key,
            get_map_by_key_func=self.map_generator.get_map_by_key,
            get_all_maps_for_ui_func=self.map_generator.get_all_maps_for_ui
        )

    def calculate_fib_lookup_for_map(self, ip_address_str: str, map_key: str = None) -> dict:
        """
        Performs a calculated FIB lookup and returns a filtered map structure
        containing only the egress path for the given IP.
        Delegates to MTAnalyzer, passing map generation methods from MTMapGenerator.
        """
        return self.analyzer.calculate_fib_lookup_for_map(
            ip_address_str=ip_address_str,
            map_key=map_key,
            get_map_by_key_func=self.map_generator.get_map_by_key,
            get_all_maps_for_ui_func=self.map_generator.get_all_maps_for_ui
        )

    def get_all_map_keys(self) -> list:
        """
        Retrieves a sorted list of all possible logical map keys (e.g., "NGFW-1 - vr:default").
        Delegates to MTMapGenerator.
        """
        return self.map_generator.get_all_map_keys()

    def get_map_by_key(self, map_key: str) -> dict:
        """
        Gets the data for a single logical map, identified by its key (e.g., "FW-NAME - VR-NAME").
        Delegates to MTMapGenerator.
        """
        return self.map_generator.get_map_by_key(map_key)

    def get_all_maps_for_ui(self) -> dict:
        """
        Generates the data for all logical maps in the format required by the D3.js frontend.
        Delegates to MTMapGenerator.
        """
        return self.map_generator.get_all_maps_for_ui()

    def get_lldp_map_for_ui(self, ngfw_hostname: str) -> dict | None:
        """
        Retrieves the grouped LLDP neighbor data for a specific NGFW,
        formatted for UI visualization. Delegates to MTMapGenerator.
        """
        return self.map_generator.get_lldp_map_for_ui(ngfw_hostname)

    def get_global_lldp_map_for_ui(self) -> dict:
        """
        Retrieves consolidated LLDP neighbor data from all NGFWs,
        formatted as a graph (nodes and links) for a global map visualization.
        Delegates to MTMapGenerator.
        """
        return self.map_generator.get_global_lldp_map_for_ui()

    def add_manual_lldp_neighbor(self, ngfw_hostname: str, local_interface: str,
                                 remote_hostname: str, remote_interface_id: str,
                                 remote_interface_description: str) -> str:
        """
        Adds a new manual LLDP neighbor entry to the database.
        Coordinates database interaction.
        """
        if not all([ngfw_hostname, local_interface, remote_hostname, remote_interface_id, remote_interface_description]):
            raise MTControllerException("All fields are required to add a manual LLDP neighbor.")

        with self.db_manager.get_session() as session:
            ngfw_obj_list = self.db_manager.get_ngfws_by_filter(session, ngfw_hostname)
            if not ngfw_obj_list:
                raise MTControllerException(f"NGFW '{ngfw_hostname}' not found in the database. Please add it first.")
            ngfw_obj = ngfw_obj_list[0]

            existing_neighbor = session.query(Neighbor).filter(
                Neighbor.ngfw_id == ngfw_obj.id,
                Neighbor.local_interface == local_interface
            ).first()

            if existing_neighbor:
                raise MTControllerException(f"Local interface '{local_interface}' on NGFW '{ngfw_hostname}' is already associated with an LLDP neighbor ('{existing_neighbor.remote_hostname}').")

            new_neighbor = Neighbor(
                ngfw_id=ngfw_obj.id,
                local_interface=local_interface,
                remote_hostname=remote_hostname,
                remote_interface_id=remote_interface_id,
                remote_interface_description=remote_interface_description
            )
            self.db_manager.add_object(session, new_neighbor)
            session.commit()

            return f"Manual LLDP neighbor '{remote_hostname}' on '{ngfw_hostname}' ({local_interface}) added successfully."

    def get_all_devices_for_ui(self):
        """
        Retrieves a combined list of all Panoramas and NGFWs for display.
        Coordinates database retrieval and data formatting.
        """
        logging.debug("Fetching all devices for UI inventory.")
        devices = {'panoramas': [], 'ngfws': []}
        try:
            with self.db_manager.get_session() as session:
                panoramas = self.db_manager.get_all_panoramas(session)
                for pan in panoramas:
                    devices['panoramas'].append(self.data_formatter.format_panorama_result(pan))
                    
                ngfws = self.db_manager.get_all_ngfws(session, load_panorama=True)
                for ngfw_obj in ngfws:
                    devices['ngfws'].append(self.data_formatter.format_ngfw_result(ngfw_obj))
            return devices
        except sqlalchemy_exc.SQLAlchemyError as e:
            raise MTControllerException(f"Database error fetching device list: {e}")

    def get_routes(self, ngfw=None, virtual_router=None, destination=None, flags=None, on_demand=False, afi='ipv4') -> dict:
        """
        Retrieves routing table information, filtered by Address Family Indicator (AFI).
        Coordinates API fetch/DB query, analysis (zone enrichment), and data formatting.
        """
        logging.info(f"Fetching routes. NGFW: '{ngfw}', VR: '{virtual_router}', Dest: '{destination}', Flags: '{flags}', On-demand: {on_demand}, AFI: {afi}")
        response = {'message': [], 'results': None}
        formatted_results = []
        try:
            if on_demand:
                with self.db_manager.get_session() as session:
                    ngfw_list = self.db_manager.get_ngfws_by_filter(session, ngfw)
                    if not ngfw_list:
                        response['message'].append(f"No NGFWs found matching '{ngfw or 'Any'}'.")
                        return response

                    all_api_routes = []
                    for ngfw_obj in ngfw_list:
                        routes_api = self.api_service.fetch_routes(ngfw_obj, virtual_router, destination, flags)

                        if routes_api is None: response['message'].append(f"  Failed to fetch routes via API for {ngfw_obj.hostname}."); continue
                        if not routes_api: response['message'].append(f"  No routes found matching basic filters via API for {ngfw_obj.hostname}."); continue

                        response['message'].append(f"  Received {len(routes_api)} route(s) from API for {ngfw_obj.hostname}.")
                        for r in routes_api: r['ngfw'] = ngfw_obj.hostname
                        self.analyzer._enrich_results_with_zone(session, [ngfw_obj.id], routes_api)
                        all_api_routes.extend(routes_api)

                formatted_results_all = [self.data_formatter.format_route_result(route_dict=r) for r in all_api_routes]

                filtered_results = []
                for res in formatted_results_all:
                    detected_afi = self.analyzer._detect_address_family(res.get('destination', ''))
                    if afi == 'all' or detected_afi == afi:
                        filtered_results.append(res)

                formatted_results = filtered_results
                if not formatted_results and all_api_routes:
                    response['message'].append(f"No AFI='{afi}' routes found matching criteria (on-demand).")

            else:
                with self.db_manager.get_session() as session:
                    routes_db = self.db_manager.get_routes_for_query(session, ngfw, virtual_router, destination, flags, afi)
                    if not routes_db:
                        response['message'].append(f"No AFI='{afi if afi in ['ipv4','ipv6'] else 'any'}' routes found in database matching criteria.")
                    else:
                        formatted_results = [self.data_formatter.format_route_result(route_obj=r) for r in routes_db]

            if formatted_results: response['results'] = formatted_results
            elif not response['message']: response['message'].append(f"No AFI='{afi if afi in ['ipv4','ipv6'] else 'any'}' routes found matching criteria.")

        except sqlalchemy_exc.SQLAlchemyError as db_err: raise MTControllerException(f"DB error getting routes: {db_err}")
        except Exception as e: raise MTControllerException(f"Unexpected error getting routes: {e}")
        return response

    def get_fibs(self, ngfw=None, virtual_router=None, destination=None, flags=None, on_demand=False, afi='ipv4') -> dict:
        """
        Retrieves FIB entries, filtered by Address Family Indicator (AFI).
        Coordinates API fetch/DB query, analysis (zone enrichment), and data formatting.
        """
        response = {'message': [], 'results': None}
        formatted_results = []
        try:
            if on_demand:
                with self.db_manager.get_session() as session:
                    ngfw_list = self.db_manager.get_ngfws_by_filter(session, ngfw)
                    if not ngfw_list:
                        response['message'].append(f"No NGFWs found matching '{ngfw or 'Any'}'.")
                        return response

                    all_api_fibs = []
                    for ngfw_obj in ngfw_list:
                        fibs_api = self.api_service.fetch_fibs(ngfw_obj, virtual_router, destination, flags)
                        if fibs_api is None: response['message'].append(f"  Failed to fetch FIBs via API for {ngfw_obj.hostname}."); continue
                        if not fibs_api: response['message'].append(f"  No FIB entries found matching basic filters via API for {ngfw_obj.hostname}."); continue

                        response['message'].append(f"  Received {len(fibs_api)} FIB entry(s) from API for {ngfw_obj.hostname}.")
                        for f in fibs_api: f['ngfw'] = ngfw_obj.hostname
                        self.analyzer._enrich_results_with_zone(session, [ngfw_obj.id], fibs_api)
                        all_api_fibs.extend(fibs_api)

                formatted_results_all = [self.data_formatter.format_fib_result(fib_dict=f) for f in all_api_fibs]

                filtered_results = []
                for res in formatted_results_all:
                    detected_afi = self.analyzer._detect_address_family(res.get('destination', ''))
                    if afi == 'all' or detected_afi == afi:
                         filtered_results.append(res)

                formatted_results = filtered_results
                if not formatted_results and all_api_fibs:
                    response['message'].append(f"No AFI='{afi}' FIB entries found matching criteria (on-demand).")

            else:
                with self.db_manager.get_session() as session:
                    fibs_db = self.db_manager.get_fibs_for_query(session, ngfw, virtual_router, destination, flags, afi)
                    if not fibs_db:
                        response['message'].append(f"No AFI='{afi if afi in ['ipv4','ipv6'] else 'any'}' FIB entries found in database matching criteria.")
                    else:
                        formatted_results = [self.data_formatter.format_fib_result(fib_obj=f) for f in fibs_db]

            if formatted_results: response['results'] = formatted_results
            elif not response['message']: response['message'].append(f"No AFI='{afi if afi in ['ipv4','ipv6'] else 'any'}' FIB entries found matching criteria.")

        except sqlalchemy_exc.SQLAlchemyError as db_err: raise MTControllerException(f"DB error getting FIBs: {db_err}")
        except Exception as e: raise MTControllerException(f"Unexpected error getting FIBs: {e}")
        return response

    def get_interfaces(self, ngfw=None, virtual_router=None, on_demand=False, ipv6_enabled_only=False) -> dict:
        """
        Retrieves interface information, including IPv6 presence indicator and addresses.
        Coordinates API fetch/DB query and data formatting.
        """
        response = {'message': [], 'results': None}
        formatted_results = []
        try:
            with self.db_manager.get_session() as session:
                if on_demand:
                    ngfw_list = self.db_manager.get_ngfws_by_filter(session, ngfw)
                    if not ngfw_list:
                         response['message'].append(f"No NGFWs found matching '{ngfw or 'Any'}'.")
                         return response
                    all_api_interfaces = []
                    for ngfw_obj in ngfw_list:
                         response['message'].append(f"--- Querying Interfaces (On-Demand) for: {ngfw_obj.hostname} ---")
                         interfaces_api = self.api_service.fetch_interfaces(ngfw_obj, virtual_router)
                         if interfaces_api is None: response['message'].append(f"  Failed to fetch interfaces via API."); continue
                         if not interfaces_api: response['message'].append(f"  No interfaces found matching filters via API."); continue

                         response['message'].append(f"  Received {len(interfaces_api)} interface(s) from API.")
                         for if_data in interfaces_api:
                              if 'ngfw' not in if_data: if_data['ngfw'] = ngfw_obj.hostname
                              all_api_interfaces.append(if_data)

                    formatted_results_all = [self.data_formatter.format_interface_result(if_dict=if_data) for if_data in all_api_interfaces]

                    if ipv6_enabled_only:
                        formatted_results = [res for res in formatted_results_all if res.get('ipv6_present') == '*']
                        if not formatted_results:
                             response['message'].append("No IPv6 enabled interfaces found matching criteria (on-demand).")
                    else:
                        formatted_results = formatted_results_all

                else:
                    interfaces_db = self.db_manager.get_interfaces_for_query(session, ngfw, virtual_router, ipv6_enabled_only)
                    if not interfaces_db:
                        msg = "No interfaces found in database matching criteria."
                        if ipv6_enabled_only:
                            msg = "No IPv6 enabled interfaces found in database matching criteria."
                        response['message'].append(msg)
                    else:
                        formatted_results = [self.data_formatter.format_interface_result(if_obj=i) for i in interfaces_db]

            if formatted_results:
                response['results'] = formatted_results
            elif not response['message']:
                 msg = "No interfaces found matching criteria."
                 if ipv6_enabled_only:
                     msg = "No IPv6 enabled interfaces found matching criteria."
                 response['message'].append(msg)

        except sqlalchemy_exc.SQLAlchemyError as db_err:
            raise MTControllerException(f"DB error getting interfaces: {db_err}")
        except Exception as e:
             raise MTControllerException(f"Unexpected error getting interfaces: {e}")
        return response
    
    def get_bgp_peers(self, ngfw=None, virtual_router=None, on_demand=False) -> dict:
        """
        Retrieves BGP peer information.
        Coordinates API fetch/DB query and data formatting.
        """
        response = {'message': [], 'results': None}
        formatted_results = []
        try:
            with self.db_manager.get_session() as session:
                if on_demand:
                    ngfw_list = self.db_manager.get_ngfws_by_filter(session, ngfw)
                    if not ngfw_list: response['message'].append(f"No NGFWs found matching '{ngfw or 'Any'}'."); return response
                    for ngfw_obj in ngfw_list:
                        response['message'].append(f"--- Querying BGP Peers (On-Demand) for: {ngfw_obj.hostname} ---")
                        bgp_peers_api = self.api_service.fetch_bgp_peers(ngfw_obj, virtual_router)
                        if bgp_peers_api is None: response['message'].append(f"  Failed to fetch BGP peers via API."); continue
                        if not bgp_peers_api: response['message'].append(f"  No BGP peers found matching filters via API."); continue
                        response['message'].append(f"  Received {len(bgp_peers_api)} BGP peer(s) from API.")
                        for peer_data in bgp_peers_api:
                             peer_data['ngfw'] = ngfw_obj.hostname
                             formatted_results.append(self.data_formatter.format_bgp_peer_result(peer_dict=peer_data))
                else:
                    bgp_peers_db = self.db_manager.get_bgp_peers_for_query(session, ngfw, virtual_router)
                    if not bgp_peers_db: response['message'].append("No BGP peers found in database matching criteria.")
                    else: formatted_results = [self.data_formatter.format_bgp_peer_result(peer_obj=p) for p in bgp_peers_db]

            if formatted_results: response['results'] = formatted_results
            elif not response['message']: response['message'].append("No BGP peers found matching criteria.")
        except sqlalchemy_exc.SQLAlchemyError as db_err: raise MTControllerException(f"DB error getting BGP peers: {db_err}")
        except Exception as e: raise MTControllerException(f"Unexpected error getting BGP peers: {e}")
        return response

    def get_arps(self, ngfw=None, interface=None, on_demand=False) -> dict:
        """
        Retrieves ARP table entries.
        Coordinates API fetch/DB query, analysis (zone enrichment), and data formatting.
        """
        response = {'message': [], 'results': None}
        formatted_results = []
        try:
            with self.db_manager.get_session() as session:
                if on_demand:
                    ngfw_list = self.db_manager.get_ngfws_by_filter(session, ngfw)
                    if not ngfw_list: response['message'].append(f"No NGFWs found matching '{ngfw or 'Any'}'."); return response
                    for ngfw_obj in ngfw_list:
                        response['message'].append(f"--- Querying ARPs (On-Demand) for: {ngfw_obj.hostname} ---")
                        arps_api = self.api_service.fetch_arps(ngfw_obj, interface)
                        if arps_api is None: response['message'].append(f"  Failed to fetch ARPs via API."); continue
                        if not arps_api: response['message'].append(f"  No ARP entries found matching filters via API."); continue

                        response['message'].append(f"  Received {len(arps_api)} ARP entry(s) from API.")
                        for a in arps_api: a['ngfw'] = ngfw_obj.hostname
                        self.analyzer._enrich_results_with_zone(session, [ngfw_obj.id], arps_api)
                        formatted_results.extend([self.data_formatter.format_arp_result(arp_dict=a) for a in arps_api])
                else:
                    arps_db = self.db_manager.get_arps_for_query(session, ngfw, interface)
                    if not arps_db: response['message'].append("No ARP entries found in database matching criteria.")
                    else: formatted_results = [self.data_formatter.format_arp_result(arp_obj=a) for a in arps_db]

            if formatted_results: response['results'] = formatted_results
            elif not response['message']: response['message'].append("No ARP entries found matching criteria.")
        except sqlalchemy_exc.SQLAlchemyError as db_err: raise MTControllerException(f"DB error getting ARPs: {db_err}")
        except Exception as e: raise MTControllerException(f"Unexpected error getting ARPs: {e}")
        return response

    def get_virtual_routers(self, ngfw=None, virtual_router=None, extra_info=True) -> dict:
        """
        Retrieves virtual router information from the database.
        Coordinates database retrieval and data formatting.
        """
        response = {'message': [], 'results': None}
        formatted_results = []
        try:
            with self.db_manager.get_session() as session:
                vr_list_db = self.db_manager.get_vrs_by_ngfw_and_filter(session, None, virtual_router)
                if ngfw:
                    ngfw_ids = {n.id for n in self.db_manager.get_ngfws_by_filter(session, ngfw)}
                    vr_list_db = [vr for vr in vr_list_db if vr.ngfw_id in ngfw_ids]
                if not vr_list_db: response['message'].append("No virtual routers found matching criteria."); return response
                formatted_results = [self.data_formatter.format_vr_result(vr_obj=vr, include_counts=extra_info) for vr in vr_list_db]
            if formatted_results: response['results'] = formatted_results
        except sqlalchemy_exc.SQLAlchemyError as db_err: raise MTControllerException(f"DB error getting VRs: {db_err}")
        except Exception as e: raise MTControllerException(f"Unexpected error getting VRs: {e}")
        return response

    def get_ngfws(self, panorama=None) -> dict:
        """
        Retrieves NGFW information from the database.
        Coordinates database retrieval and data formatting.
        """
        response = {'message': [], 'results': None}
        formatted_results = []
        try:
            with self.db_manager.get_session() as session:
                query = session.query(Ngfw).options(joinedload(Ngfw.panorama))
                if panorama:
                    query = query.join(Ngfw.panorama).filter((Panorama.hostname == panorama) | (Panorama.ip_address == panorama))
                ngfws_db = query.all()
                
                if not ngfws_db: response['message'].append(f"No NGFWs found {'managed by Panorama ' + panorama if panorama else 'in database'}."); return response
                formatted_results = [self.data_formatter.format_ngfw_result(ngfw_obj=n) for n in ngfws_db]
            if formatted_results: response['results'] = formatted_results
        except sqlalchemy_exc.SQLAlchemyError as db_err: raise MTControllerException(f"DB error getting NGFWs: {db_err}")
        except Exception as e: raise MTControllerException(f"Unexpected error getting NGFWs: {e}")
        return response

    def get_ngfw_details(self, serial: str) -> dict | None:
        """
        Retrieves the full, formatted details for a single NGFW by its serial number.
        Coordinates database retrieval and data formatting.
        """
        logging.debug(f"Fetching details for NGFW with serial: {serial}")
        try:
            with self.db_manager.get_session() as session:
                ngfw_obj = self.db_manager.get_ngfw_by_serial(session, serial)
                if not ngfw_obj:
                    logging.warning(f"No NGFW found in database with serial: {serial}")
                    return None
                return self.data_formatter.format_ngfw_result(ngfw_obj)
        except sqlalchemy_exc.SQLAlchemyError as e:
            logging.error(f"Database error fetching details for NGFW {serial}: {e}", exc_info=True)
            raise MTControllerException(f"Database error fetching details for NGFW {serial}: {e}")

    def get_panorama_details(self, serial: str) -> dict | None:
        """
        Retrieves the full, formatted details for a single Panorama by its serial number.
        Coordinates database retrieval and data formatting.
        """
        logging.debug(f"Fetching details for Panorama with serial: {serial}")
        try:
            with self.db_manager.get_session() as session:
                pan_obj = self.db_manager.get_panorama_by_serial(session, serial)
                if not pan_obj:
                    logging.warning(f"No Panorama found in database with serial: {serial}")
                    return None
                return self.data_formatter.format_panorama_result(pan_obj)
        except sqlalchemy_exc.SQLAlchemyError as e:
            logging.error(f"Database error fetching details for Panorama {serial}: {e}", exc_info=True)
            raise MTControllerException(f"Database error fetching details for Panorama {serial}: {e}")

    def get_neighbors(self, ngfw=None, on_demand=False) -> dict:
        """
        Retrieves LLDP neighbor information.
        Coordinates API fetch/DB query, analysis (zone enrichment), and data formatting.
        """
        response = {'message': [], 'results': None}
        formatted_results = []
        try:
            with self.db_manager.get_session() as session:
                if on_demand:
                    ngfw_list = self.db_manager.get_ngfws_by_filter(session, ngfw)
                    if not ngfw_list: response['message'].append(f"No NGFWs found matching '{ngfw or 'Any'}'."); return response
                    for ngfw_obj in ngfw_list:
                        response['message'].append(f"--- Querying LLDP Neighbors (On-Demand) for: {ngfw_obj.hostname} ---")
                        neighbors_api = self.api_service.fetch_neighbors(ngfw_obj)
                        if neighbors_api is None: response['message'].append(f"  Failed to fetch neighbors via API."); continue
                        if not neighbors_api: response['message'].append(f"  No LLDP neighbors found via API."); continue
                        response['message'].append(f"  Received {len(neighbors_api)} neighbor(s) from API.")
                        for neighbor_data in neighbors_api:
                             neighbor_data['ngfw'] = ngfw_obj.hostname
                             self.analyzer._enrich_results_with_zone(session, [ngfw_obj.id], [neighbor_data]) # Apply zone enrichment to single neighbor_data dict
                             formatted_results.append(self.data_formatter.format_neighbor_result(neighbor_dict=neighbor_data))
                else:
                    neighbors_db = self.db_manager.get_neighbors_for_query(session, ngfw)
                    if not neighbors_db: response['message'].append("No LLDP neighbors found in database matching criteria.")
                    else: formatted_results = [self.data_formatter.format_neighbor_result(neighbor_obj=n) for n in neighbors_db]

            if formatted_results: response['results'] = formatted_results
            elif not response['message']: response['message'].append("No LLDP neighbors found matching criteria.")
        except sqlalchemy_exc.SQLAlchemyError as db_err: raise MTControllerException(f"DB error getting neighbors: {db_err}")
        except Exception as e: raise MTControllerException(f"Unexpected error getting neighbors: {e}")
        return response

    def get_panoramas(self) -> dict:
        """
        Retrieves Panorama information from the database.
        Coordinates database retrieval and data formatting.
        """
        response = {'message': [], 'results': None}
        formatted_results = []
        try:
            with self.db_manager.get_session() as session:
                panoramas_db = self.db_manager.get_all_panoramas(session, load_ngfws=True)
                if not panoramas_db:
                    response['message'].append("No Panoramas found in database.")
                    return response
                formatted_results = [self.data_formatter.format_panorama_result(p) for p in panoramas_db]
            
            if formatted_results:
                response['results'] = formatted_results
        except sqlalchemy_exc.SQLAlchemyError as db_err:
            raise MTControllerException(f"DB error getting Panoramas: {db_err}")
        except Exception as e:
            raise MTControllerException(f"Unexpected error getting Panoramas: {e}")
        return response
