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

import ipaddress
import datetime
import time
import logging

from sqlalchemy import create_engine, select, exc as sqlalchemy_exc
from sqlalchemy.orm import sessionmaker, joinedload, Session
from sqlalchemy import create_engine, select, inspect as sqlalchemy_inspect, exc as sqlalchemy_exc
# Assuming models.py defines the Base and specific table classes correctly
# and includes cascade delete configurations.
from models import (
    Base, Ngfw, Route, VirtualRouter, Interface, Panorama,
    Neighbor, BGPPeer, Fib, Arp, InterfaceIPv6Address # <<< Ensure InterfaceIPv6Address is imported
)

# Importing the MTpanorama and MTngfw classes from mt_devices.py
try:
    # Attempt relative import first (for package structure)
    from .mt_devices import MTpanorama, MTngfw, MTpanoramaException, MTngfwException
except ImportError:
    # Fallback if run as a script directly
    from mt_devices import MTpanorama, MTngfw, MTpanoramaException, MTngfwException

# Importing the config module for database URI and timeout settings
try:
    from config import db_uri, timeout
except ImportError:
    # Provide default fallbacks or raise a more specific error if config is mandatory
    logging.warining("Warning: Could not import db_uri and timeout from config. Using defaults or potentially failing.")
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
    Handles retrieving, updating, and processing data related to network devices
    stored in the database or fetched on-demand via API. Assumes the underlying
    database models (in models.py/db.py) may define cascade delete rules.
    Separates direct API interaction and data formatting into internal helper methods.
    """

    def __init__(self, db_uri=db_uri, timeout=timeout) -> None:
        """
        Initializes an instance of the MTController class.

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
        # Validate db_uri presence
        if not db_uri:
            raise MTControllerException("No 'db_uri' provided")
        self.db_uri = db_uri

        # Validate timeout value
        try:
            self.timeout = int(timeout)
        except (ValueError, TypeError): # Catch specific errors if timeout is not convertible to int
            raise MTControllerException(f"'timeout' must be an integer, received: {timeout}")

        try:
            # Create SQLAlchemy engine and session factory once during initialization
            self._engine = create_engine(self.db_uri, echo=False)
            # Store the session factory (class) itself, not an instance, for creating sessions later
            self._Session = sessionmaker(bind=self._engine)

            # --- Add Schema Check Here ---
            # This block attempts to verify that the necessary database structure exists.
            try:
                # Use SQLAlchemy's inspect feature to reflect on the database
                inspector = sqlalchemy_inspect(self._engine)

                # Check for the existence of one or more essential tables.
                # If this table doesn't exist, it's assumed the schema is missing or incomplete.
                if not inspector.has_table("ngfw"):
                     # Raise the specific, user-friendly error if the table is missing
                     raise MTDatabaseSchemaError("Database schema not found or is incomplete.")

            except sqlalchemy_exc.SQLAlchemyError as db_err:
                 # If the inspection process itself fails due to a database error (e.g., connection refused, permissions),
                 if "no such table" in str(db_err).lower(): # Fallback check
                     raise MTDatabaseSchemaError("Database schema not found or is incomplete.") from db_err
                 else:
                     # Raise a general controller exception for other DB connection/operational errors during the check
                     raise MTControllerException(f"Database connection error during schema check: {db_err}") from db_err
            # --- End Schema Check ---

        except sqlalchemy_exc.SQLAlchemyError as e:
            # Catch errors specifically during engine or sessionmaker creation
            raise MTControllerException(f"Database communication issue during initialization: {e}")
        except Exception as e:
             # Catch any other unexpected errors during the initialization process
             raise MTControllerException(f"Unexpected error during MTController initialization: {e}")

    # ==========================================================================
    # Internal API Fetch Helper Methods
    # ==========================================================================

    def _fetch_api_panorama_devices(self, panorama_obj) -> list | None:
        """
        Fetches connected device list from a Panorama via API.

        Args:
            panorama_obj (Panorama): The Panorama database object.

        Returns:
            list | None: List of device dictionaries from API, or None on error.
        """
        try:
            mtp = MTpanorama(panorama=panorama_obj, timeout=self.timeout)
            devices_api = mtp.show_devices()
            return devices_api if devices_api else []
        except MTpanoramaException as e:
            logging.error(f"Warning: API error fetching devices from Panorama {panorama_obj.hostname}: {e}")
            return None

    def _fetch_api_system_info(self, ngfw_obj) -> dict | None:
        """
        Fetches system info from an NGFW via API.

        Args:
            ngfw_obj (Ngfw): The NGFW database object.

        Returns:
            dict | None: System info dictionary ('system' key) from API, or None on error.
        """
        try:
            mtd = MTngfw(ngfw=ngfw_obj, timeout=self.timeout)
            system_info = mtd.show_system_info()
            return system_info if system_info else None
        except MTngfwException as e:
            logging.error(f"Warning: API error fetching system info from {ngfw_obj.hostname}: {e}")
            return None

    def _fetch_api_virtual_routes(self, ngfw_obj) -> list | None:
        """
        Fetches virtual router names from an NGFW via API.

        Args:
            ngfw_obj (Ngfw): The NGFW database object.

        Returns:
            list | None: List of virtual router name strings, or None on error.
        """
        try:
            mtd = MTngfw(ngfw=ngfw_obj, timeout=self.timeout)
            vr_names_api = mtd.show_virtual_routes()
            return vr_names_api if vr_names_api else []
        except MTngfwException as e:
            logging.error(f"Warning: API error fetching virtual routes from {ngfw_obj.hostname}: {e}")
            return None

    def _fetch_api_interfaces(self, ngfw_obj, virtual_router=None) -> list | None:
        """
        Fetches interface details from an NGFW via API.

        Args:
            ngfw_obj (Ngfw): The NGFW database object.
            virtual_router (str, optional): Filter by virtual router name.

        Returns:
            list | None: List of interface dictionaries from API, or None on error.
        """
        try:
            mtd = MTngfw(ngfw=ngfw_obj, timeout=self.timeout)
            interfaces_api = mtd.show_interfaces(virtual_router=virtual_router)
            return interfaces_api if interfaces_api else []
        except MTngfwException as e:
            logging.error(f"Warning: API error fetching interfaces from {ngfw_obj.hostname}: {e}")
            return None

    def _fetch_api_routes(self, ngfw_obj, virtual_router=None, destination=None, flags=None) -> list | None:
        """
        Fetches route data from an NGFW via API.

        Args:
            ngfw_obj (Ngfw): The NGFW database object.
            virtual_router (str, optional): Filter by virtual router name.
            destination (str, optional): Filter by destination prefix.
            flags (str, optional): Filter by route flags.

        Returns:
            list | None: List of route dictionaries from API, or None on error.
        """
        try:
            mtd = MTngfw(ngfw=ngfw_obj, timeout=self.timeout)
            routes_api = mtd.show_routes(virtual_router=virtual_router, dst=destination, flags=flags)
            return routes_api if routes_api else []
        except MTngfwException as e:
            logging.error(f"Warning: API error fetching routes from {ngfw_obj.hostname}: {e}")
            return None

    def _fetch_api_fibs(self, ngfw_obj, virtual_router=None, destination=None, flags=None) -> list | None:
        """
        Fetches FIB data from an NGFW via API.

        Args:
            ngfw_obj (Ngfw): The NGFW database object.
            virtual_router (str, optional): Filter by virtual router name.
            destination (str, optional): Filter by destination prefix.
            flags (str, optional): Filter by FIB flags.

        Returns:
            list | None: List of FIB dictionaries from API, or None on error.
        """
        try:
            mtd = MTngfw(ngfw=ngfw_obj, timeout=self.timeout)
            fibs_api = mtd.show_fibs(virtual_router=virtual_router, dst=destination, flags=flags)
            return fibs_api if fibs_api else []
        except MTngfwException as e:
            logging.error(f"Warning: API error fetching FIBs from {ngfw_obj.hostname}: {e}")
            return None

    def _fetch_api_bgp_peers(self, ngfw_obj, virtual_router=None) -> list | None:
        """
        Fetches BGP peer data from an NGFW via API.

        Args:
            ngfw_obj (Ngfw): The NGFW database object.
            virtual_router (str, optional): Filter by virtual router name.

        Returns:
            list | None: List of BGP peer dictionaries from API, or None on error.
        """
        try:
            mtd = MTngfw(ngfw=ngfw_obj, timeout=self.timeout)
            bgp_peers_api = mtd.show_bgp_peers(virtual_router=virtual_router)
            return bgp_peers_api if bgp_peers_api else []
        except MTngfwException as e:
            logging.error(f"Warning: API error fetching BGP peers from {ngfw_obj.hostname}: {e}")
            return None

    def _fetch_api_arps(self, ngfw_obj, interface=None) -> list | None:
        """
        Fetches ARP data from an NGFW via API.

        Args:
            ngfw_obj (Ngfw): The NGFW database object.
            interface (str, optional): Filter by interface name.

        Returns:
            list | None: List of ARP dictionaries from API, or None on error.
        """
        try:
            mtd = MTngfw(ngfw=ngfw_obj, timeout=self.timeout)
            arps_api = mtd.show_arps(interface=interface)
            return arps_api if arps_api else []
        except MTngfwException as e:
            logging.error(f"Warning: API error fetching ARPs from {ngfw_obj.hostname}: {e}")
            return None

    def _fetch_api_neighbors(self, ngfw_obj) -> list | None:
        """
        Fetches LLDP neighbor data from an NGFW via API.

        Args:
            ngfw_obj (Ngfw): The NGFW database object.

        Returns:
            list | None: List of neighbor dictionaries from API, or None on error.
        """
        try:
            mtd = MTngfw(ngfw=ngfw_obj, timeout=self.timeout)
            neighbors_api = mtd.show_neighbors()
            return neighbors_api if neighbors_api else []
        except MTngfwException as e:
            logging.error(f"Warning: API error fetching LLDP neighbors from {ngfw_obj.hostname}: {e}")
            return None

    def _fetch_api_fib_lookup_test(self, ngfw_obj, ip_address, vr_name) -> dict | None:
        """
        Performs a live FIB lookup test on an NGFW via API by calling the MTngfw method.

        Args:
            ngfw_obj (Ngfw): The NGFW database object.
            ip_address (ipaddress.IPv4Address): The IP address object to test.
            vr_name (str): The name of the virtual router for the test.

        Returns:
            dict | None: Parsed result dictionary from the API test, or None on error.
        """
        try:
            # Instantiate the device handler
            mtd = MTngfw(ngfw=ngfw_obj, timeout=self.timeout)

            # Call the specific method on the MTngfw object
            # Pass ip_address as string, as expected by the new method
            result_dict = mtd.test_fib_lookup(ip_address=str(ip_address), virtual_router=vr_name)

            # The MTngfw method now handles parsing and basic API errors.
            # We just return the dictionary it provides.
            return result_dict

        except MTngfwException as e:
            # Catch exceptions raised by the MTngfw method (API errors, critical parse errors)
            logging.error(f"Warning: API error during FIB lookup test on {ngfw_obj.hostname}/{vr_name}: {e}")
            return None
        except Exception as e:
            # Catch any other unexpected Python errors during instantiation etc.
            logging.error(f"Warning: Unexpected error preparing for FIB lookup test on {ngfw_obj.hostname}/{vr_name}: {e}")
            return None

    def _fetch_api_panorama_ha_state(self, panorama_obj) -> dict | None:
        """
        Fetches HA state from a Panorama via API.

        Args:
            panorama_obj (Panorama): The Panorama database object.

        Returns:
            dict | None: HA state dictionary from API, or None on error.
        """
        try:
            mtp = MTpanorama(panorama=panorama_obj, timeout=self.timeout)
            ha_info = mtp.show_ha_state()
            return ha_info
        except MTpanoramaException as e:
            logging.error(f"Warning: API error fetching HA state from Panorama {panorama_obj.hostname}: {e}")
            return None

    def _fetch_api_ngfw_ha_status(self, ngfw_obj) -> dict | None:
        """
        Fetches HA status from an NGFW via API.

        Args:
            ngfw_obj (Ngfw): The NGFW database object.

        Returns:
            dict | None: HA status dictionary from API, or None on error.
        """
        try:
            mtd = MTngfw(ngfw=ngfw_obj, timeout=self.timeout)
            ha_info = mtd.show_ha_status()
            return ha_info
        except MTngfwException as e:
            logging.error(f"Warning: API error fetching HA status from NGFW {ngfw_obj.hostname}: {e}")
            return None

    # ==========================================================================
    # Internal Data Formatting Helper Methods
    # ==========================================================================

    def _format_route_result(self, route_obj=None, route_dict=None) -> dict:
        """
        Formats a Route DB object or an API route dict into the standard result structure.

        Args:
            route_obj (Route, optional): A Route SQLAlchemy object.
            route_dict (dict, optional): A dictionary representing a route.

        Returns:
            dict: A dictionary with standardized keys and formatted values.
        """
        if route_obj: # Format from DB object
            ngfw_name = route_obj.virtual_router.ngfw.hostname if route_obj.virtual_router and route_obj.virtual_router.ngfw else 'Unknown'
            vr_name = route_obj.virtual_router.name if route_obj.virtual_router else 'Unknown'
            return {
                'ngfw': ngfw_name, 'virtual_router': vr_name,
                'destination': route_obj.destination or '', 'nexthop': route_obj.nexthop or '',
                'metric': str(route_obj.metric) if route_obj.metric is not None else '',
                'flags': route_obj.flags or '', 'interface': route_obj.interface or '',
                'route_table': route_obj.route_table or '',
                'age': str(route_obj.age) if route_obj.age is not None else '',
                'zone': route_obj.zone or ''
            }
        elif route_dict: # Format from API dictionary
            checked_dict = self._null_value_check(route_dict.copy())
            return {
                'ngfw': checked_dict.get('ngfw', ''), 'virtual_router': checked_dict.get('virtual_router', ''),
                'destination': checked_dict.get('destination', ''), 'nexthop': checked_dict.get('nexthop', ''),
                'metric': str(checked_dict.get('metric', '')), 'flags': checked_dict.get('flags', ''),
                'interface': checked_dict.get('interface', ''), 'route_table': checked_dict.get('route_table', ''),
                'age': str(checked_dict.get('age', '')), 'zone': checked_dict.get('zone', '')
            }
        return {}

    def _format_fib_result(self, fib_obj=None, fib_dict=None) -> dict:
        """
        Formats a Fib DB object or an API FIB dict into the standard result structure.

        Args:
            fib_obj (Fib, optional): A Fib SQLAlchemy object.
            fib_dict (dict, optional): A dictionary representing a FIB entry.

        Returns:
            dict: A dictionary with standardized keys and formatted values.
        """
        if fib_obj: # Format from DB object
            ngfw_name = fib_obj.virtual_router.ngfw.hostname if fib_obj.virtual_router and fib_obj.virtual_router.ngfw else 'Unknown'
            vr_name = fib_obj.virtual_router.name if fib_obj.virtual_router else 'Unknown'
            return {
                'ngfw': ngfw_name, 'virtual_router': vr_name,
                'fib_id': str(fib_obj.fib_id) if fib_obj.fib_id is not None else '',
                'destination': fib_obj.destination or '', 'interface': fib_obj.interface or '',
                'nh_type': fib_obj.nh_type or '', 'flags': fib_obj.flags or '',
                'nexthop': fib_obj.nexthop or '',
                'mtu': str(fib_obj.mtu) if fib_obj.mtu is not None else '',
                'zone': fib_obj.zone or ''
            }
        elif fib_dict: # Format from API dictionary
            checked_dict = self._null_value_check(fib_dict.copy())
            return {
                'ngfw': checked_dict.get('ngfw', ''), 'virtual_router': checked_dict.get('virtual_router', ''),
                'fib_id': str(checked_dict.get('fib_id', '')),
                'destination': checked_dict.get('destination', ''), 'interface': checked_dict.get('interface', ''),
                'nh_type': checked_dict.get('nh_type', ''), 'flags': checked_dict.get('flags', ''),
                'nexthop': checked_dict.get('nexthop', ''), 'mtu': str(checked_dict.get('mtu', '')),
                'zone': checked_dict.get('zone', '')
            }
        return {}

    def _format_interface_result(self, if_obj=None, if_dict=None) -> dict:
        """
        Formats an Interface DB object or an API interface dict.
        Includes an indicator ('*') if IPv6 is enabled.
        Also includes 'ipv6_address_list' containing a list of IPv6 address strings.
        """
        ipv6_present_indicator = ""
        ipv6_address_list = []

        if if_obj: # Format from DB object
            ngfw_name = if_obj.virtual_router.ngfw.hostname if if_obj.virtual_router and if_obj.virtual_router.ngfw else 'Unknown'
            vr_name = if_obj.virtual_router.name if if_obj.virtual_router else 'Unknown'

            # Use the boolean flag for the indicator
            if if_obj.ipv6_enabled:
                 ipv6_present_indicator = "*"

            # <<< Populate the list from the relationship >>>
            if hasattr(if_obj, 'ipv6_addresses') and if_obj.ipv6_addresses:
                 # Extract the 'address' attribute from each related object
                 ipv6_address_list = [ipv6.address for ipv6 in if_obj.ipv6_addresses]

            result = {
                'ngfw': ngfw_name, 'virtual_router': vr_name,
                'name': if_obj.name or '', 'tag': if_obj.tag or '',
                'vsys': if_obj.vsys or '', 'ip': if_obj.ip or '',
                'zone': if_obj.zone or '',
                'ipv6_present': ipv6_present_indicator, # Indicator flag ('*' or '')
                'ipv6_address_list': ipv6_address_list # <<< ADDED KEY: List of IPv6 strings
            }
            return result

        elif if_dict: # Format from API dictionary (on-demand case)
            checked_dict = self._null_value_check(if_dict.copy())
            # Get the list directly from the API dict results
            ipv6_address_list = checked_dict.get('ipv6_addresses', []) # Already a list of strings here

            # Set indicator based on presence of list in API data
            if isinstance(ipv6_address_list, list) and ipv6_address_list:
                 ipv6_present_indicator = "*"

            result = {
                'ngfw': checked_dict.get('ngfw', ''), 'virtual_router': checked_dict.get('virtual_router', ''),
                'name': checked_dict.get('name', ''), 'tag': checked_dict.get('tag', ''),
                'vsys': checked_dict.get('vsys', ''), 'ip': checked_dict.get('ip', ''), # IPv4 address
                'zone': checked_dict.get('zone', ''),
                'ipv6_present': ipv6_present_indicator, # Indicator flag ('*' or '')
                'ipv6_address_list': ipv6_address_list
            }
            return result
        return {}

    def _format_bgp_peer_result(self, peer_obj=None, peer_dict=None) -> dict:
        """
        Formats a BGPPeer DB object or an API peer dict into the standard result structure.

        Args:
            peer_obj (BGPPeer, optional): A BGPPeer SQLAlchemy object.
            peer_dict (dict, optional): A dictionary representing a BGP peer.

        Returns:
            dict: A dictionary with standardized keys and formatted values.
        """
        if peer_obj: # Format from DB object
            ngfw_name = peer_obj.ngfw.hostname if peer_obj.ngfw else 'Unknown'
            vr_name = peer_obj.virtual_router.name if peer_obj.virtual_router else 'Unknown'
            return {
                'ngfw': ngfw_name, 'virtual_router': vr_name,
                'peer_name': peer_obj.peer_name or '', 'peer_group': peer_obj.peer_group or '',
                'peer_router_id': peer_obj.peer_router_id or '', 'remote_as': peer_obj.remote_as or '',
                'status': peer_obj.status or '', 'status_duration': peer_obj.status_duration or '',
                'peer_address': peer_obj.peer_address or '', 'local_address': peer_obj.local_address or ''
            }
        elif peer_dict: # Format from API dictionary
            checked_dict = self._null_value_check(peer_dict.copy())
            return {
                'ngfw': checked_dict.get('ngfw', ''), 'virtual_router': checked_dict.get('virtual_router', ''),
                'peer_name': checked_dict.get('peer_name', ''), 'peer_group': checked_dict.get('peer_group', ''),
                'peer_router_id': checked_dict.get('peer_router_id', ''), 'remote_as': checked_dict.get('remote_as', ''),
                'status': checked_dict.get('status', ''), 'status_duration': checked_dict.get('status_duration', ''),
                'peer_address': checked_dict.get('peer_address', ''), 'local_address': checked_dict.get('local_address', '')
            }
        return {}

    def _format_arp_result(self, arp_obj=None, arp_dict=None) -> dict:
        """
        Formats an Arp DB object or an API ARP dict into the standard result structure.

        Args:
            arp_obj (Arp, optional): An Arp SQLAlchemy object.
            arp_dict (dict, optional): A dictionary representing an ARP entry.

        Returns:
            dict: A dictionary with standardized keys and formatted values.
        """
        if arp_obj: # Format from DB object
            ngfw_name = arp_obj.interface.virtual_router.ngfw.hostname if arp_obj.interface and arp_obj.interface.virtual_router and arp_obj.interface.virtual_router.ngfw else 'Unknown'
            if_name = arp_obj.interface.name if arp_obj.interface else 'Unknown'
            return {
                'ngfw': ngfw_name, 'interface': if_name,
                'ip': arp_obj.ip or '', 'mac': arp_obj.mac or '',
                'port': arp_obj.port or '',
                'ttl': str(arp_obj.ttl) if arp_obj.ttl is not None else '',
                'status': arp_obj.status or '', 'zone': arp_obj.zone or ''
            }
        elif arp_dict: # Format from API dictionary
            checked_dict = self._null_value_check(arp_dict.copy())
            return {
                'ngfw': checked_dict.get('ngfw', ''), 'interface': checked_dict.get('interface', ''),
                'ip': checked_dict.get('ip', ''), 'mac': checked_dict.get('mac', ''),
                'port': checked_dict.get('port', ''), 'ttl': str(checked_dict.get('ttl', '')),
                'status': checked_dict.get('status', ''), 'zone': checked_dict.get('zone', '')
            }
        return {}

    def _format_neighbor_result(self, neighbor_obj=None, neighbor_dict=None) -> dict:
        """
        Formats a Neighbor DB object or an API neighbor dict into the standard result structure.

        Args:
            neighbor_obj (Neighbor, optional): A Neighbor SQLAlchemy object.
            neighbor_dict (dict, optional): A dictionary representing an LLDP neighbor.

        Returns:
            dict: A dictionary with standardized keys and formatted values.
        """
        if neighbor_obj: # Format from DB object
            ngfw_name = neighbor_obj.ngfw.hostname if neighbor_obj.ngfw else 'Unknown'
            return {
                'ngfw': ngfw_name, 'local_interface': neighbor_obj.local_interface or '',
                'remote_interface_id': neighbor_obj.remote_interface_id or '',
                'remote_interface_description': neighbor_obj.remote_interface_description or '',
                'remote_hostname': neighbor_obj.remote_hostname or ''
            }
        elif neighbor_dict: # Format from API dictionary
            checked_dict = self._null_value_check(neighbor_dict.copy())
            return {
                'ngfw': checked_dict.get('ngfw', ''), 'local_interface': checked_dict.get('local_interface', ''),
                'remote_interface_id': checked_dict.get('remote_interface_id', ''),
                'remote_interface_description': checked_dict.get('remote_interface_description', ''),
                'remote_hostname': checked_dict.get('remote_hostname', '')
            }
        return {}

    def _format_ngfw_result(self, ngfw_obj) -> dict:
        """
        Formats an Ngfw DB object into the standard result structure.

        Args:
            ngfw_obj (Ngfw): An Ngfw SQLAlchemy object.

        Returns:
            dict: A dictionary with standardized keys and formatted values.
        """
        if not ngfw_obj: return {}
        return {
            'hostname': ngfw_obj.hostname, 'serial_number': ngfw_obj.serial_number,
            'ip_address': ngfw_obj.ip_address or '', 'model': ngfw_obj.model or '',
            'alt_serial': ngfw_obj.alt_serial or '', 'alt_ip': ngfw_obj.alt_ip or '',
            'active': 'yes' if ngfw_obj.active else 'no',
            'panorama': ngfw_obj.panorama.hostname if ngfw_obj.panorama else 'Standalone',
            'last_update': ngfw_obj.last_update or 'Never',
        }

    def _format_panorama_result(self, pan_obj) -> dict:
        """
        Formats a Panorama DB object into the standard result structure.

        Args:
            pan_obj (Panorama): A Panorama SQLAlchemy object.

        Returns:
            dict: A dictionary with standardized keys and formatted values.
        """
        if not pan_obj: return {}
        # Assumes ngfws relationship was eagerly loaded for count
        ngfw_count = len(pan_obj.ngfws) if hasattr(pan_obj, 'ngfws') else \
                     self._Session().query(Ngfw).filter(Ngfw.panorama_id == pan_obj.id).count() # Fallback count query
        return {
            'hostname': pan_obj.hostname, 'serial_number': pan_obj.serial_number,
            'ip_address': pan_obj.ip_address, 'alt_ip': pan_obj.alt_ip or "",
            'active': 'yes' if pan_obj.active else 'no', 'ngfws': ngfw_count
        }

    def _format_vr_result(self, vr_obj, include_counts=True, session=None) -> dict:
        """
        Formats a VirtualRouter DB object into the standard result structure.

        Args:
            vr_obj (VirtualRouter): A VirtualRouter SQLAlchemy object.
            include_counts (bool): Whether to include counts of related items.
            session (Session, optional): An active session to use for count queries.

        Returns:
            dict: A dictionary with standardized keys and formatted values.
        """
        if not vr_obj: return {}
        vr_dict = {
            'ngfw': vr_obj.ngfw.hostname if vr_obj.ngfw else 'Unknown',
            'virtual_router': vr_obj.name,
        }
        if include_counts:
            current_session = session or self._Session() # Use provided or create temporary
            try:
                vr_dict['route_count'] = current_session.query(Route).filter(Route.virtual_router_id == vr_obj.id).count()
                vr_dict['fib_count'] = current_session.query(Fib).filter(Fib.virtual_router_id == vr_obj.id).count()
                vr_dict['interface_count'] = current_session.query(Interface).filter(Interface.virtual_router_id == vr_obj.id).count()
            finally:
                if not session: # Close temporary session if created
                    current_session.close()
        return vr_dict

    def _format_fib_lookup_result(self, lookup_dict) -> dict:
         """
         Formats a FIB lookup result dictionary (from API or calculation).

         Args:
            lookup_dict (dict): Dictionary containing lookup result details.

         Returns:
            dict: A dictionary with standardized keys and formatted values.
         """
         checked_dict = self._null_value_check(lookup_dict.copy())
         next_hop = checked_dict.get('nexthop', 'None')
         if next_hop == "0.0.0.0": next_hop = "self" # Standardize self representation

         return {
            'ngfw': checked_dict.get('ngfw', 'Unknown'),
            'virtual_router': checked_dict.get('virtual_router', 'Unknown'),
            'destination': checked_dict.get('destination', 'None'),
            'nexthop': next_hop,
            'flags': checked_dict.get('flags', 'None'),
            'interface': checked_dict.get('interface', 'None'),
            'zone': checked_dict.get('zone', 'None')
         }

    # ==========================================================================
    # Internal Utility Helper Methods
    # ==========================================================================

    def _null_value_check(self, result_dict) -> dict:
        """
        Iterates through a dictionary and replaces None values with empty strings.
        Modifies the dictionary in-place and returns it.

        Args:
            result_dict (dict): The dictionary to check.

        Returns:
            dict: The modified dictionary with None values replaced by ''.
        """
        if not isinstance(result_dict, dict):
             return result_dict # Return unchanged if not a dict

        for key, value in result_dict.items():
            if value is None:
                result_dict[key] = ''
        return result_dict

    def _enrich_results_with_zone(self, session, ngfw_ids: list, results_list: list):
        """
        Enriches a list of result dictionaries (from API) with 'zone' information
        looked up from the database based on interface name, FIB entry, or inferred for self routes (IPv4/IPv6).

        Modifies the dictionaries in results_list in-place.

        Args:
            session (Session): The active SQLAlchemy session.
            ngfw_ids (list[int]): List of NGFW database IDs relevant to the results.
            results_list (list[dict]): List of dictionaries to enrich (e.g., from API).
                                       Each dict must have 'ngfw' (hostname) and potentially
                                       'interface', 'destination', 'nexthop' keys.
        """
        if not results_list or not ngfw_ids:
            return

        try:
            # --- Pre-fetch data ---
            # Fetch Interfaces (includes IPv4 IP and zone)
            all_interfaces_db = session.query(Interface).join(VirtualRouter)\
                .options(joinedload(Interface.virtual_router).joinedload(VirtualRouter.ngfw))\
                .filter(VirtualRouter.ngfw_id.in_(ngfw_ids)).all()

            # Map for direct interface name lookup (Interface Name -> Zone)
            interface_zone_map = {(iface.virtual_router.ngfw_id, iface.name): iface.zone
                                  for iface in all_interfaces_db if iface.name}

            # Map for inference lookup (NGFW ID -> list of Interface objects)
            ngfw_interfaces_map = {}
            for iface in all_interfaces_db:
                ngfw_id = iface.virtual_router.ngfw_id
                if ngfw_id not in ngfw_interfaces_map:
                    ngfw_interfaces_map[ngfw_id] = []
                ngfw_interfaces_map[ngfw_id].append(iface)

            # Query InterfaceIPv6Address, joining Interface to get the zone
            all_ipv6_addrs_db = session.query(InterfaceIPv6Address).join(Interface)\
                .options(joinedload(InterfaceIPv6Address.interface)).filter(Interface.virtual_router_id.in_( # Filter via Interface's VR
                    session.query(VirtualRouter.id).filter(VirtualRouter.ngfw_id.in_(ngfw_ids))
                )).all()

            # Map for IPv6 inference lookup (NGFW ID -> list of (ipv6_addr_str, zone) tuples)
            ngfw_ipv6_interfaces_map = {}
            for ipv6_addr_obj in all_ipv6_addrs_db:
                iface_parent = ipv6_addr_obj.interface
                if not iface_parent or not iface_parent.virtual_router: continue # Skip if relationships missing
                ngfw_id = iface_parent.virtual_router.ngfw_id
                if ngfw_id not in ngfw_ipv6_interfaces_map:
                    ngfw_ipv6_interfaces_map[ngfw_id] = []
                # Store tuple of (address string, zone string)
                ngfw_ipv6_interfaces_map[ngfw_id].append(
                    (ipv6_addr_obj.address, iface_parent.zone or '')
                )

            # Pre-fetch FIBs if needed (assuming FIB table now has mixed v4/v6)
            needs_fib_lookup = 'destination' in results_list[0] # Heuristic check
            fib_zone_map = {}
            if needs_fib_lookup:
                # This query now fetches both IPv4 and IPv6 FIB entries
                all_fibs_db = session.query(Fib).join(VirtualRouter)\
                    .options(joinedload(Fib.virtual_router).joinedload(VirtualRouter.ngfw))\
                    .filter(VirtualRouter.ngfw_id.in_(ngfw_ids)).all()
                # Key needs to include AFI if the same destination prefix can exist for v4/v6 in same VR
                # For now, assuming destination prefix is unique within VR regardless of AFI for zone mapping
                fib_zone_map = {(fib.virtual_router.ngfw_id, fib.virtual_router.name, fib.destination): fib.zone
                                for fib in all_fibs_db}

            # Pre-fetch NGFW hostnames
            ngfw_hostname_to_id = {n.hostname: n.id for n in session.query(Ngfw).filter(Ngfw.id.in_(ngfw_ids)).all()}

            # --- Iterate and enrich ---
            for result_item in results_list:
                zone = None # Reset zone for each item
                ngfw_hostname = result_item.get('ngfw')
                iface_name = result_item.get('interface') # Interface name from the route/fib entry itself
                ngfw_id = ngfw_hostname_to_id.get(ngfw_hostname)

                if not ngfw_id:
                    result_item['zone'] = result_item.get('zone', '')
                    continue # Skip if missing ngfw ID

                # 1. Primary lookup: Interface name map (if route/fib lists an interface)
                if iface_name:
                    zone = interface_zone_map.get((ngfw_id, iface_name))

                # 2. Secondary lookup: FIB map (if primary failed and applicable)
                if (zone is None or zone == '') and needs_fib_lookup and fib_zone_map:
                    vr_name = result_item.get('virtual_router')
                    dest = result_item.get('destination')
                    if vr_name and dest:
                        zone = fib_zone_map.get((ngfw_id, vr_name, dest))

                # 3. Tertiary lookup: Inference for self/host routes (if zone still unknown)
                if zone is None or zone == '':
                    is_route_or_fib = 'destination' in result_item
                    nexthop = result_item.get('nexthop')
                    destination = result_item.get('destination', '')
                    # Check for null next hops (IPv4, IPv6, empty) and presence of prefix slash
                    is_likely_self_route = (nexthop in ['0.0.0.0', '::', '']) and '/' in destination

                    if is_route_or_fib and is_likely_self_route:
                        dest_str = destination
                        try:
                            # Extract IP part from destination string (e.g., "10.0.0.1/32" -> "10.0.0.1")
                            dest_ip_str = dest_str.split('/')[0]
                            dest_ip = ipaddress.ip_address(dest_ip_str) # Can be IPv4Address or IPv6Address

                            # Check against configured IPv4 interface IPs
                            interfaces_to_check_v4 = ngfw_interfaces_map.get(ngfw_id, [])
                            for iface in interfaces_to_check_v4:
                                if not iface.ip: continue # Skip if no IPv4 configured
                                try:
                                    iface_interface_v4 = ipaddress.ip_interface(iface.ip)
                                    if dest_ip == iface_interface_v4.ip:
                                        zone = iface.zone # Found match on IPv4
                                        logging.debug(f"Inferred zone '{zone}' for {dest_ip} from IPv4 interface {iface.name} ({iface.ip})")
                                        break # Exit inner loop once match found
                                except ValueError:
                                    continue # Skip invalid IPv4 interface formats

                            # If no IPv4 match found, check against configured IPv6 interface IPs
                            if zone is None or zone == '':
                                interfaces_to_check_v6 = ngfw_ipv6_interfaces_map.get(ngfw_id, [])
                                for ipv6_addr_str, iface_zone in interfaces_to_check_v6:
                                    if not ipv6_addr_str: continue
                                    try:
                                        iface_interface_v6 = ipaddress.ip_interface(ipv6_addr_str)
                                        if dest_ip == iface_interface_v6.ip:
                                            zone = iface_zone # Found match on IPv6
                                            logging.debug(f"Inferred zone '{zone}' for {dest_ip} from IPv6 interface address {ipv6_addr_str}")
                                            break # Exit inner loop once match found
                                    except ValueError:
                                        continue # Skip invalid IPv6 interface formats

                        except ValueError:
                             logging.debug(f"Skipping zone inference: Invalid destination IP format '{dest_str}'")
                             pass # Continue (zone remains None or '')

                # Update the result dictionary with the final zone found (or default to empty string)
                result_item['zone'] = zone if zone is not None else ''

        except sqlalchemy_exc.SQLAlchemyError as db_err:
            logging.error(f"Database error during zone enrichment: {db_err}")
            for item in results_list: item['zone'] = item.get('zone', '') # Preserve existing if possible, else default ''
        except Exception as e:
            logging.error(f"Unexpected error during zone enrichment: {e}")
            for item in results_list: item['zone'] = item.get('zone', '')

    # ==========================================================================
    # Public Controller Methods
    # ==========================================================================

    def get_inventory(self) -> dict:
        """ Returns counts of various object types currently stored in the database. """
        inventory = {}
        try:
            with self._Session() as session:
                inventory = {
                    'Panoramas': session.query(Panorama).count(), 'NGFWs': session.query(Ngfw).count(),
                    'Virtual Routers': session.query(VirtualRouter).count(), 'Interfaces': session.query(Interface).count(),
                    'Routes': session.query(Route).count(), 'FIBs': session.query(Fib).count(),
                    'ARPs': session.query(Arp).count(), 'BGP Peers': session.query(BGPPeer).count(),
                    'Neighbors': session.query(Neighbor).count()
                }
                return inventory
        except sqlalchemy_exc.SQLAlchemyError as db_err:
            raise MTControllerException(f"Database error while retrieving inventory: {db_err}")
        except Exception as e:
             raise MTControllerException(f"Unexpected error during get_inventory: {e}")

    def import_panorama_devices(self, pan_filter=None) -> list:
        """ Imports NGFW details from associated Panoramas into the database. """
        messages = []
        try:
            with self._Session() as session:
                pan_query = session.query(Panorama)
                if pan_filter:
                    pan_query = pan_query.filter((Panorama.hostname == pan_filter) | (Panorama.ip_address == pan_filter))
                panorama_list = pan_query.all()

                if not panorama_list:
                    messages.append(f"Panorama '{pan_filter or 'Any'}' not found in database.")
                    return messages

                existing_serials = {s for s, in session.query(Ngfw.serial_number).all()} | \
                                   {s for s, in session.query(Ngfw.alt_serial).filter(Ngfw.alt_serial.isnot(None)).all()}

                for panorama_obj in panorama_list:
                    messages.append(f"--- Processing Panorama: {panorama_obj.hostname} ({panorama_obj.ip_address}) ---")
                    devices_api = self._fetch_api_panorama_devices(panorama_obj)

                    if devices_api is None:
                        messages.append(f"  Failed to fetch devices via API. Skipping.")
                        continue
                    if not devices_api:
                         messages.append(f"  No connected devices reported by API.")
                         continue

                    added_count, skipped_count, error_count = 0, 0, 0
                    for device_data in devices_api:
                        try:
                            serial = device_data.get('serial')
                            hostname = device_data.get('hostname', f"Unnamed-{serial[:4]}" if serial else "Unknown")
                            if not serial or serial in existing_serials or device_data.get('connected') != 'yes':
                                skipped_count += 1; continue # Skip missing serial, existing, or disconnected

                            active, alt_serial = True, None
                            ha_info = device_data.get('ha', {})
                            if ha_info and 'active' not in ha_info.get('state', 'active').lower():
                                skipped_count += 1; continue # Skip non-active HA peers reported by Panorama
                            if ha_info: alt_serial = ha_info.get('peer', {}).get('serial') or None

                            ngfw_data = { 'hostname': hostname, 'serial_number': serial, 'ip_address': device_data.get('ip-address'),
                                          'model': device_data.get('model'), 'panorama_id': panorama_obj.id, 'active': active,
                                          'alt_serial': alt_serial, 'alt_ip': None, 'api_key': None, 'last_update': None }
                            new_ngfw = Ngfw(**ngfw_data)
                            session.add(new_ngfw)
                            existing_serials.add(serial)
                            if alt_serial: existing_serials.add(alt_serial)
                            added_count += 1
                            messages.append(f"  NGFW '{hostname}' ({serial}) successfully added.")
                        except Exception as processing_err:
                            error_count += 1; messages.append(f"  Error processing device data (Serial: {serial or 'Unknown'}): {processing_err}"); session.rollback()
                    messages.append(f"  Import complete: Added {added_count}, Skipped {skipped_count}, Errors {error_count}.")
                    session.commit()
        except sqlalchemy_exc.SQLAlchemyError as db_err:
            session.rollback(); raise MTControllerException(f"Database error during import: {db_err}")
        except Exception as e:
             session.rollback(); raise MTControllerException(f"Unexpected error during import: {e}")
        return messages

    def refresh_ngfws(self, ngfw_filter=None) -> list:
        """ Refreshes basic info (VRs, Interfaces including IPv6 flag and addresses) for specified NGFWs via API. """
        messages = []
        try:
            with self._Session() as session:
                ngfw_list = self._get_ngfws_by_filter(session, ngfw_filter)
                if not ngfw_list:
                    messages.append(f"NGFW '{ngfw_filter or 'Any'}' not found in database.")
                    return messages

                for ngfw_obj in ngfw_list:
                    messages.append(f"--- Refreshing NGFW: {ngfw_obj.hostname} ({ngfw_obj.serial_number}) ---")
                    refresh_time = datetime.datetime.now().isoformat(timespec='seconds')
                    commit_needed = False
                    system_info = self._fetch_api_system_info(ngfw_obj)
                    if system_info is None:
                        messages.append(f"  {ngfw_obj.hostname} not connecting - skipping refresh.")
                        continue
                    messages.append(f"  Successfully connected.")

                    messages.append("  Processing Virtual Routers and Interfaces...")
                    try:
                        # Delete existing VRs
                        existing_vr_ids = {vr_id[0] for vr_id in session.query(VirtualRouter.id).filter(VirtualRouter.ngfw_id == ngfw_obj.id).all()} # Corrected tuple access
                        if existing_vr_ids:
                             deleted_vr_count = session.query(VirtualRouter).filter(VirtualRouter.id.in_(existing_vr_ids)).delete(synchronize_session=False)
                             messages.append(f"  Deleted {deleted_vr_count} existing VR(s) and associated data (Interfaces, IPv6 Addr, etc. via cascade).")
                             session.flush()
                             commit_needed = deleted_vr_count > 0
                        else:
                             messages.append("  No existing VRs found for this NGFW.")

                        # Add new VRs
                        vr_map = {} # Maps vr_name -> vr_object
                        vr_names_api = self._fetch_api_virtual_routes(ngfw_obj)
                        if vr_names_api is None: messages.append(f"  Failed to fetch VRs via API. Aborting interface processing.")
                        elif not vr_names_api: messages.append(f"  No VRs reported by API.")
                        else:
                            messages.append(f"  Found {len(vr_names_api)} VRs via API. Adding them...")
                            for vr_name in vr_names_api:
                                new_vr = VirtualRouter(name=vr_name, ngfw_id=ngfw_obj.id)
                                session.add(new_vr)
                                vr_map[vr_name] = new_vr # Store object before flush
                            session.flush() # Assign IDs
                            messages.append(f"  Added {len(vr_map)} new VR(s).")
                            commit_needed = True

                            # Add new Interfaces and their IPv6 addresses
                            interfaces_api = self._fetch_api_interfaces(ngfw_obj)
                            if interfaces_api is None: messages.append("  Failed to fetch Interfaces via API.")
                            elif not interfaces_api: messages.append(f"  No interfaces reported by API.")
                            else:
                                messages.append(f"  Found {len(interfaces_api)} Interfaces via API. Processing...")
                                added_if_count, skipped_if_count, added_ipv6_count = 0, 0, 0
                                # Temporary lists to hold objects before adding to session
                                new_interfaces_to_add = []
                                ipv6_addresses_to_add = []

                                for if_data in interfaces_api:
                                    vr_name = if_data.get('virtual_router')
                                    if vr_name in vr_map:
                                        vr_obj = vr_map[vr_name] # Get VR object (now has ID)

                                        # Determine IPv6 status AND get the list from API data
                                        ipv6_list = if_data.get('ipv6_addresses', [])
                                        has_ipv6 = bool(ipv6_list) # True if list exists and is not empty

                                        # Create Interface object, setting the flag
                                        new_if = Interface(
                                            name=if_data.get('name', ''),
                                            tag=if_data.get('tag', ''),
                                            vsys=if_data.get('vsys', ''),
                                            zone=if_data.get('zone', ''),
                                            ip=if_data.get('ip', ''),
                                            virtual_router_id=vr_obj.id, # Use VR ID
                                            ipv6_enabled=has_ipv6 # <<< SET BOOLEAN FLAG HERE >>>
                                        )
                                        new_interfaces_to_add.append(new_if)
                                        added_if_count += 1

                                        # Create InterfaceIPv6Address objects for storage
                                        for ipv6_addr in ipv6_list:
                                            new_ipv6 = InterfaceIPv6Address(
                                                address=ipv6_addr,
                                                interface=new_if # Link to parent Interface object
                                            )
                                            ipv6_addresses_to_add.append(new_ipv6)
                                            added_ipv6_count += 1
                                    else:
                                        skipped_if_count += 1

                                # Add all new interfaces and their associated IPv6 addresses to the session
                                if new_interfaces_to_add:
                                    session.add_all(new_interfaces_to_add)
                                    session.add_all(ipv6_addresses_to_add)
                                    commit_needed = True # Mark changes were made

                                messages.append(f"  Processed {added_if_count} Interface(s) and {added_ipv6_count} IPv6 Address(es). Skipped {skipped_if_count}.")

                    # Exception handling for VR/Interface processing
                    except sqlalchemy_exc.SQLAlchemyError as db_op_err:
                         messages.append(f"  DB error during VR/Interface processing: {db_op_err}. Rolling back changes for this NGFW.")
                         session.rollback(); commit_needed = False; continue
                    except Exception as proc_err:
                         messages.append(f"  Unexpected error during VR/Interface processing: {proc_err}. Rolling back.")
                         session.rollback(); commit_needed = False; continue

                    # Update timestamp and commit logic
                    ngfw_obj.last_update = refresh_time
                    if commit_needed:
                         try: session.commit(); messages.append(f"  Refresh commit successful.")
                         except sqlalchemy_exc.SQLAlchemyError as commit_err: messages.append(f"  DB commit error: {commit_err}. Rolled back."); session.rollback()
                    else: # Only update timestamp if no other changes were committed
                         try: session.merge(ngfw_obj); session.commit(); messages.append(f"  Refresh timestamp updated (no other data changes committed).")
                         except sqlalchemy_exc.SQLAlchemyError as commit_err: messages.append(f"  DB commit error updating timestamp: {commit_err}."); session.rollback()

        except sqlalchemy_exc.SQLAlchemyError as db_err:
            # Catch errors during initial NGFW query or session handling
            raise MTControllerException(f"Database error during refresh_ngfws setup: {db_err}")
        except Exception as e:
             # Catch other unexpected errors like initialization issues
             raise MTControllerException(f"Unexpected error during refresh_ngfws: {e}")
        return messages

    # --- Helpers for creating DB objects (Internal) ---
    def _create_route_object(self, vr_id, afi, data):
        """ Creates a Route object from a dictionary, handling type conversions and AFI.
            Adapts to standard XML output and ARE JSON output formats processed by mt_devices.py.
        """
        # Metric: Try converting, default 0
        try: metric = int(data.get('metric')) if data.get('metric') is not None and str(data.get('metric')).strip() != '' else 0
        except (ValueError, TypeError): metric = 0

        # Age: Try converting standard age, default None. ARE provides 'uptime' string, set age=None for it.
        age_raw = data.get('age')
        age = None
        if age_raw is not None and str(age_raw).strip() != '':
             try:
                 age = int(age_raw)
             except (ValueError, TypeError):
                 # If it's not an integer (like ARE uptime string), store None in DB age column
                 age = None

        # Flags: Store the string provided by mt_devices (could be standard flags or ARE 'A protocol')
        flags = data.get('flags','')

        # Create object
        return Route(virtual_router_id=vr_id, afi=afi, destination=data.get('destination',''),
                     nexthop=data.get('nexthop',''), metric=metric, flags=flags,
                     age=age, interface=data.get('interface',''),
                     route_table=data.get('route_table',''), zone=data.get('zone',''))

    def _create_fib_object(self, vr_id, afi, data):
        """ Creates a Fib object from a dictionary, handling type conversions and AFI.
            Adapts to standard XML output and ARE XML output formats processed by mt_devices.py.
        """
        # MTU: Try converting, default 0
        try: mtu = int(data.get('mtu')) if data.get('mtu') is not None and str(data.get('mtu')).strip() != '' else 0
        except (ValueError, TypeError): mtu = 0

        # FIB ID: Try converting, default None
        try: fib_id = int(data.get('fib_id')) if data.get('fib_id') is not None and str(data.get('fib_id')).strip() != '' else None
        except (ValueError, TypeError): fib_id = None

        # NH Type: Store the string provided by mt_devices (could be standard string or ARE numeric string)
        nh_type = data.get('nh_type','')

        # Flags: Store the string provided
        flags = data.get('flags','')

        # Create object
        return Fib(virtual_router_id=vr_id, afi=afi, fib_id=fib_id,
                   destination=data.get('destination',''), interface=data.get('interface',''),
                   nh_type=nh_type, flags=flags,
                   nexthop=data.get('nexthop',''), mtu=mtu, zone=data.get('zone',''))

    def _create_arp_object(self, interface_id, zone, data):
         """ Creates an Arp object from a dictionary, handling type conversions. """
         try: ttl = int(data.get('ttl')) if data.get('ttl') is not None and str(data.get('ttl')).strip() != '' else None
         except (ValueError, TypeError): ttl = None
         return Arp(interface_id=interface_id, ip=data.get('ip'), mac=data.get('mac'), port=data.get('port'),
                    ttl=ttl, status=data.get('status'), zone=zone)

    def _create_neighbor_object(self, ngfw_id, data):
         """ Creates a Neighbor object from a dictionary. """
         return Neighbor(ngfw_id=ngfw_id, local_interface=data.get('local_interface'), remote_interface_id=data.get('remote_interface_id'),
                         remote_interface_description=data.get('remote_interface_description'), remote_hostname=data.get('remote_hostname'))

    def _create_bgp_peer_object(self, ngfw_id, vr_id, data):
         """ Creates a BGPPeer object from a dictionary. """
         return BGPPeer(ngfw_id=ngfw_id, virtual_router_id=vr_id, peer_name=data.get('peer_name'), peer_group=data.get('peer_group'),
                        peer_router_id=data.get('peer_router_id'), remote_as=data.get('remote_as'), status=data.get('status'),
                        status_duration=data.get('status_duration'), peer_address=data.get('peer_address'), local_address=data.get('local_address'))

    # --- Generic Query Helpers (Internal) ---
    def _get_ngfws_by_filter(self, session, ngfw_filter=None):
        """ Queries NGFW objects by filter (hostname, IP, serial). """
        query = session.query(Ngfw).options(joinedload(Ngfw.panorama))
        if ngfw_filter: query = query.filter((Ngfw.hostname == ngfw_filter) | (Ngfw.ip_address == ngfw_filter) | (Ngfw.serial_number == ngfw_filter) | (Ngfw.alt_ip == ngfw_filter) | (Ngfw.alt_serial == ngfw_filter))
        return query.all()

    def _get_vrs_by_ngfw_and_filter(self, session, ngfw_id=None, vr_filter=None):
        """ Queries VirtualRouter objects by NGFW ID and/or VR name. """
        query = session.query(VirtualRouter)
        if ngfw_id is not None: query = query.filter(VirtualRouter.ngfw_id == ngfw_id)
        elif vr_filter: query = query.join(VirtualRouter.ngfw)
        if vr_filter: query = query.filter(VirtualRouter.name == vr_filter)
        query = query.options(joinedload(VirtualRouter.ngfw))
        return query.all()

    def _get_interfaces_by_ngfw_and_filter(self, session, ngfw_id, interface_filter=None):
         """ Queries Interface objects by NGFW ID and/or interface name. """
         query = session.query(Interface).join(VirtualRouter).filter(VirtualRouter.ngfw_id == ngfw_id)
         if interface_filter: query = query.filter(Interface.name == interface_filter)
         query = query.options(joinedload(Interface.virtual_router).joinedload(VirtualRouter.ngfw))
         return query.all()
    
    def _detect_address_family(self, address_string: str) -> str | None:
        """Detects if an IP address or prefix string is IPv4 or IPv6."""
        if not address_string:
            return None
        try:
            # Try parsing as address first
            addr = ipaddress.ip_address(address_string)
            return 'ipv6' if isinstance(addr, ipaddress.IPv6Address) else 'ipv4'
        except ValueError:
            try:
                # If not an address, try parsing as network prefix
                net = ipaddress.ip_network(address_string, strict=False)
                return 'ipv6' if isinstance(net, ipaddress.IPv6Network) else 'ipv4'
            except ValueError:
                # Cannot determine AFI if it's not a valid address or network
                # Handle special cases like 'default' if necessary, otherwise return None
                if address_string == 'default': return 'ipv4' # Default route typically v4, adjust if needed
                # Add other special case handling here if required
                logging.warning(f"Warning: Could not determine AFI for destination: {address_string}")
                return None # Indicate failure to determine

    # ==========================================================================
    # Public Get Methods (Using Formatters)
    # ==========================================================================

    def get_routes(self, ngfw=None, virtual_router=None, destination=None, flags=None, on_demand=False, afi='ipv4') -> dict:
        """ Retrieves routing table information, filtered by Address Family Indicator (AFI). """
        response = {'message': [], 'results': None}
        formatted_results = []
        try:
            # --- On-Demand Handling ---
            if on_demand:
                with self._Session() as session: # Create session for DB lookups needed in on-demand path
                    ngfw_list = self._get_ngfws_by_filter(session, ngfw)
                    if not ngfw_list:
                        response['message'].append(f"No NGFWs found matching '{ngfw or 'Any'}'.")
                        return response

                    all_api_routes = []
                    # Loop through NGFWs to fetch API data
                    for ngfw_obj in ngfw_list:
                        # Assuming _fetch_api_routes gets all AFIs
                        routes_api = self._fetch_api_routes(ngfw_obj, virtual_router, destination, flags)

                        if routes_api is None: response['message'].append(f"  Failed to fetch routes via API for {ngfw_obj.hostname}."); continue
                        if not routes_api: response['message'].append(f"  No routes found matching basic filters via API for {ngfw_obj.hostname}."); continue

                        response['message'].append(f"  Received {len(routes_api)} route(s) from API for {ngfw_obj.hostname}.")
                        # Add ngfw hostname before enrichment
                        for r in routes_api: r['ngfw'] = ngfw_obj.hostname
                        # Enrich results *using the already opened session*
                        self._enrich_results_with_zone(session, [ngfw_obj.id], routes_api) # Pass existing session
                        all_api_routes.extend(routes_api)

                # --- Formatting and Filtering (Outside session block) ---
                # Format all collected routes
                formatted_results_all = [self._format_route_result(route_dict=r) for r in all_api_routes]

                # Filter formatted results by detected AFI
                filtered_results = []
                for res in formatted_results_all:
                    detected_afi = self._detect_address_family(res.get('destination', ''))
                    # Check if requested afi is 'all' or matches detected
                    if afi == 'all' or detected_afi == afi:
                        filtered_results.append(res)

                formatted_results = filtered_results # Assign filtered list
                if not formatted_results and all_api_routes: # Add message only if filtering removed everything
                    response['message'].append(f"No AFI='{afi}' routes found matching criteria (on-demand).")

            # --- Database Query Logic ---
            else:
                with self._Session() as session:
                    query = session.query(Route).join(Route.virtual_router).join(VirtualRouter.ngfw)
                    # Apply standard filters
                    if ngfw: query = query.filter((Ngfw.hostname == ngfw) | (Ngfw.ip_address == ngfw) | (Ngfw.serial_number == ngfw) | (Ngfw.alt_ip == ngfw) | (Ngfw.alt_serial == ngfw))
                    if virtual_router: query = query.filter(VirtualRouter.name == virtual_router)
                    if destination: query = query.filter(Route.destination.like(f"{destination}%"))
                    if flags:
                        for f in [fl.strip().upper() for fl in flags.split(',')]: query = query.filter(Route.flags.contains(f))

                    # Filter by AFI from DB column
                    if afi and afi.lower() in ['ipv4', 'ipv6']:
                         query = query.filter(Route.afi == afi.lower())
                    # If afi is 'all' or invalid/None, no AFI filter is applied to the DB query

                    routes_db = query.options(joinedload(Route.virtual_router).joinedload(VirtualRouter.ngfw)).all()
                    if not routes_db:
                        response['message'].append(f"No AFI='{afi if afi in ['ipv4','ipv6'] else 'any'}' routes found in database matching criteria.")
                    else:
                        formatted_results = [self._format_route_result(route_obj=r) for r in routes_db]

            # --- Result Handling ---
            if formatted_results: response['results'] = formatted_results
            elif not response['message']: response['message'].append(f"No AFI='{afi if afi in ['ipv4','ipv6'] else 'any'}' routes found matching criteria.")

        except sqlalchemy_exc.SQLAlchemyError as db_err: raise MTControllerException(f"DB error getting routes: {db_err}")
        except Exception as e: raise MTControllerException(f"Unexpected error getting routes: {e}")
        return response

    def get_fibs(self, ngfw=None, virtual_router=None, destination=None, flags=None, on_demand=False, afi='ipv4') -> dict:
        """ Retrieves FIB entries, filtered by Address Family Indicator (AFI). """
        response = {'message': [], 'results': None}
        formatted_results = []
        try:
            # --- On-Demand Handling ---
            if on_demand:
                with self._Session() as session: # Create session for DB lookups needed
                    ngfw_list = self._get_ngfws_by_filter(session, ngfw) # <<< Now session exists
                    if not ngfw_list:
                        response['message'].append(f"No NGFWs found matching '{ngfw or 'Any'}'.")
                        return response

                    all_api_fibs = []
                    # Loop through NGFWs to fetch API data and enrich
                    for ngfw_obj in ngfw_list:
                        # Assuming _fetch_api_fibs now gets all AFIs if device method changed
                        fibs_api = self._fetch_api_fibs(ngfw_obj, virtual_router, destination, flags)
                        if fibs_api is None: response['message'].append(f"  Failed to fetch FIBs via API for {ngfw_obj.hostname}."); continue
                        if not fibs_api: response['message'].append(f"  No FIB entries found matching basic filters via API for {ngfw_obj.hostname}."); continue

                        response['message'].append(f"  Received {len(fibs_api)} FIB entry(s) from API for {ngfw_obj.hostname}.")
                        # Add ngfw hostname and enrich *using the current session*
                        for f in fibs_api: f['ngfw'] = ngfw_obj.hostname
                        self._enrich_results_with_zone(session, [ngfw_obj.id], fibs_api) # Pass existing session
                        all_api_fibs.extend(fibs_api)

                # --- Formatting and Filtering (Outside session block) ---
                # Format all collected FIBs
                formatted_results_all = [self._format_fib_result(fib_dict=f) for f in all_api_fibs]

                # Filter formatted results by detected AFI
                filtered_results = []
                for res in formatted_results_all:
                    detected_afi = self._detect_address_family(res.get('destination', ''))
                    # Check if requested afi is 'all' or matches detected
                    if afi == 'all' or detected_afi == afi:
                         filtered_results.append(res)

                formatted_results = filtered_results
                if not formatted_results and all_api_fibs: # Add message only if filtering removed everything
                    response['message'].append(f"No AFI='{afi}' FIB entries found matching criteria (on-demand).")

            # --- Database Query Logic ---
            else:
                with self._Session() as session:
                    query = session.query(Fib).join(Fib.virtual_router).join(VirtualRouter.ngfw)
                    # Apply standard filters
                    if ngfw: query = query.filter((Ngfw.hostname == ngfw) | (Ngfw.ip_address == ngfw) | (Ngfw.serial_number == ngfw) | (Ngfw.alt_ip == ngfw) | (Ngfw.alt_serial == ngfw))
                    if virtual_router: query = query.filter(VirtualRouter.name == virtual_router)
                    if destination: query = query.filter(Fib.destination.like(f"{destination}%"))
                    if flags:
                         for f in [fl.strip().upper() for fl in flags.split(',')]: query = query.filter(Fib.flags.contains(f))

                    # Filter by AFI from DB column
                    if afi and afi.lower() in ['ipv4', 'ipv6']:
                         query = query.filter(Fib.afi == afi.lower())
                    # If afi is 'all' or invalid/None, no AFI filter is applied

                    fibs_db = query.options(joinedload(Fib.virtual_router).joinedload(VirtualRouter.ngfw)).all()
                    if not fibs_db:
                        response['message'].append(f"No AFI='{afi if afi in ['ipv4','ipv6'] else 'any'}' FIB entries found in database matching criteria.")
                    else:
                        formatted_results = [self._format_fib_result(fib_obj=f) for f in fibs_db]

            # --- Result Handling ---
            if formatted_results: response['results'] = formatted_results
            elif not response['message']: response['message'].append(f"No AFI='{afi if afi in ['ipv4','ipv6'] else 'any'}' FIB entries found matching criteria.")

        except sqlalchemy_exc.SQLAlchemyError as db_err: raise MTControllerException(f"DB error getting FIBs: {db_err}")
        except Exception as e: raise MTControllerException(f"Unexpected error getting FIBs: {e}")
        return response

    def get_interfaces(self, ngfw=None, virtual_router=None, on_demand=False, ipv6_enabled_only=False) -> dict:
        """ Retrieves interface information, including IPv6 presence indicator and addresses.
            Can optionally filter for only IPv6 enabled interfaces.
        """
        response = {'message': [], 'results': None}
        formatted_results = []
        try:
            with self._Session() as session:
                if on_demand:
                    # On-demand logic: Fetch all interfaces matching basic filters first.
                    # Filtering by ipv6_enabled status happens *after* formatting.
                    ngfw_list = self._get_ngfws_by_filter(session, ngfw)
                    if not ngfw_list:
                         response['message'].append(f"No NGFWs found matching '{ngfw or 'Any'}'.")
                         return response
                    all_api_interfaces = []
                    for ngfw_obj in ngfw_list:
                         response['message'].append(f"--- Querying Interfaces (On-Demand) for: {ngfw_obj.hostname} ---")
                         interfaces_api = self._fetch_api_interfaces(ngfw_obj, virtual_router)
                         if interfaces_api is None: response['message'].append(f"  Failed to fetch interfaces via API."); continue # Skip NGFW on error
                         if not interfaces_api: response['message'].append(f"  No interfaces found matching filters via API."); continue # Skip NGFW if none found

                         response['message'].append(f"  Received {len(interfaces_api)} interface(s) from API.")
                         # Add ngfw hostname before formatting/filtering
                         for if_data in interfaces_api:
                              if 'ngfw' not in if_data: if_data['ngfw'] = ngfw_obj.hostname
                              all_api_interfaces.append(if_data)

                    # Format all fetched interfaces
                    formatted_results_all = [self._format_interface_result(if_dict=if_data) for if_data in all_api_interfaces]

                    # Apply ipv6_enabled_only filter *after* formatting if requested
                    if ipv6_enabled_only:
                        # Filter based on the 'ipv6_present' key which indicates if IPv6 was found
                        formatted_results = [res for res in formatted_results_all if res.get('ipv6_present') == '*']
                        if not formatted_results:
                             response['message'].append("No IPv6 enabled interfaces found matching criteria (on-demand).")
                    else:
                        formatted_results = formatted_results_all

                else:
                    # DB Query Logic
                    query = session.query(Interface).join(Interface.virtual_router).join(VirtualRouter.ngfw)
                    if ngfw:
                        query = query.filter((Ngfw.hostname == ngfw) | (Ngfw.ip_address == ngfw) | (Ngfw.serial_number == ngfw) | (Ngfw.alt_ip == ngfw) | (Ngfw.alt_serial == ngfw))
                    if virtual_router:
                        query = query.filter(VirtualRouter.name == virtual_router)

                    if ipv6_enabled_only:
                        query = query.filter(Interface.ipv6_enabled == True)

                    # Eager load relationships needed by the formatter
                    query = query.options(
                        joinedload(Interface.virtual_router).joinedload(VirtualRouter.ngfw),
                        joinedload(Interface.ipv6_addresses) # Need this for the address list
                    )

                    interfaces_db = query.all()
                    if not interfaces_db:
                        # Adjust message based on filter
                        msg = "No interfaces found in database matching criteria."
                        if ipv6_enabled_only:
                            msg = "No IPv6 enabled interfaces found in database matching criteria."
                        response['message'].append(msg)
                    else:
                        formatted_results = [self._format_interface_result(if_obj=i) for i in interfaces_db]

            # Result handling...
            if formatted_results:
                response['results'] = formatted_results
            elif not response['message']: # Add default message if none exists yet
                 # Adjust message based on filter
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
        """ Retrieves BGP peer information. """
        response = {'message': [], 'results': None}
        formatted_results = []
        try:
            with self._Session() as session:
                if on_demand:
                    ngfw_list = self._get_ngfws_by_filter(session, ngfw)
                    if not ngfw_list: response['message'].append(f"No NGFWs found matching '{ngfw or 'Any'}'."); return response
                    for ngfw_obj in ngfw_list:
                        response['message'].append(f"--- Querying BGP Peers (On-Demand) for: {ngfw_obj.hostname} ---")
                        bgp_peers_api = self._fetch_api_bgp_peers(ngfw_obj, virtual_router)
                        if bgp_peers_api is None: response['message'].append(f"  Failed to fetch BGP peers via API."); continue
                        if not bgp_peers_api: response['message'].append(f"  No BGP peers found matching filters via API."); continue
                        response['message'].append(f"  Received {len(bgp_peers_api)} BGP peer(s) from API.")
                        for peer_data in bgp_peers_api:
                             peer_data['ngfw'] = ngfw_obj.hostname
                             formatted_results.append(self._format_bgp_peer_result(peer_dict=peer_data))
                else:
                    # DB Query Logic
                    query = session.query(BGPPeer).join(BGPPeer.virtual_router).join(VirtualRouter.ngfw)
                    if ngfw: query = query.filter((Ngfw.hostname == ngfw) | (Ngfw.ip_address == ngfw) | (Ngfw.serial_number == ngfw) | (Ngfw.alt_ip == ngfw) | (Ngfw.alt_serial == ngfw))
                    if virtual_router: query = query.filter(VirtualRouter.name == virtual_router)
                    bgp_peers_db = query.options(joinedload(BGPPeer.virtual_router).joinedload(VirtualRouter.ngfw), joinedload(BGPPeer.ngfw)).all()
                    if not bgp_peers_db: response['message'].append("No BGP peers found in database matching criteria.")
                    else: formatted_results = [self._format_bgp_peer_result(peer_obj=p) for p in bgp_peers_db]

            if formatted_results: response['results'] = formatted_results
            elif not response['message']: response['message'].append("No BGP peers found matching criteria.")
        except sqlalchemy_exc.SQLAlchemyError as db_err: raise MTControllerException(f"DB error getting BGP peers: {db_err}")
        except Exception as e: raise MTControllerException(f"Unexpected error getting BGP peers: {e}")
        return response

    def get_arps(self, ngfw=None, interface=None, on_demand=False) -> dict:
        """ Retrieves ARP table entries. """
        response = {'message': [], 'results': None}
        formatted_results = []
        try:
            with self._Session() as session:
                if on_demand:
                    ngfw_list = self._get_ngfws_by_filter(session, ngfw)
                    if not ngfw_list: response['message'].append(f"No NGFWs found matching '{ngfw or 'Any'}'."); return response
                    all_ngfw_ids = [n.id for n in ngfw_list]

                    for ngfw_obj in ngfw_list:
                        response['message'].append(f"--- Querying ARPs (On-Demand) for: {ngfw_obj.hostname} ---")
                        arps_api = self._fetch_api_arps(ngfw_obj, interface)
                        if arps_api is None: response['message'].append(f"  Failed to fetch ARPs via API."); continue
                        if not arps_api: response['message'].append(f"  No ARP entries found matching filters via API."); continue

                        response['message'].append(f"  Received {len(arps_api)} ARP entry(s) from API.")
                        # Add ngfw hostname before enrichment/formatting
                        for a in arps_api: a['ngfw'] = ngfw_obj.hostname
                        # Enrich with zone information
                        self._enrich_results_with_zone(session, [ngfw_obj.id], arps_api)
                        # Format results
                        formatted_results.extend([self._format_arp_result(arp_dict=a) for a in arps_api])
                else:
                    # DB Query Logic
                    query = session.query(Arp).join(Arp.interface).join(Interface.virtual_router).join(VirtualRouter.ngfw)
                    if ngfw: query = query.filter((Ngfw.hostname == ngfw) | (Ngfw.ip_address == ngfw) | (Ngfw.serial_number == ngfw) | (Ngfw.alt_ip == ngfw) | (Ngfw.alt_serial == ngfw))
                    if interface: query = query.filter(Interface.name == interface)
                    arps_db = query.options(joinedload(Arp.interface).joinedload(Interface.virtual_router).joinedload(VirtualRouter.ngfw)).all()
                    if not arps_db: response['message'].append("No ARP entries found in database matching criteria.")
                    else: formatted_results = [self._format_arp_result(arp_obj=a) for a in arps_db]

            if formatted_results: response['results'] = formatted_results
            elif not response['message']: response['message'].append("No ARP entries found matching criteria.")
        except sqlalchemy_exc.SQLAlchemyError as db_err: raise MTControllerException(f"DB error getting ARPs: {db_err}")
        except Exception as e: raise MTControllerException(f"Unexpected error getting ARPs: {e}")
        return response

    def get_virtual_routers(self, ngfw=None, virtual_router=None, extra_info=True) -> dict:
        """ Retrieves virtual router information from the database. """
        response = {'message': [], 'results': None}
        formatted_results = []
        try:
            with self._Session() as session:
                vr_list_db = self._get_vrs_by_ngfw_and_filter(session, None, virtual_router)
                if ngfw:
                    ngfw_ids = {n.id for n in self._get_ngfws_by_filter(session, ngfw)}
                    vr_list_db = [vr for vr in vr_list_db if vr.ngfw_id in ngfw_ids]
                if not vr_list_db: response['message'].append("No virtual routers found matching criteria."); return response
                formatted_results = [self._format_vr_result(vr_obj=vr, include_counts=extra_info, session=session) for vr in vr_list_db]
            if formatted_results: response['results'] = formatted_results
        except sqlalchemy_exc.SQLAlchemyError as db_err: raise MTControllerException(f"DB error getting VRs: {db_err}")
        except Exception as e: raise MTControllerException(f"Unexpected error getting VRs: {e}")
        return response

    def get_ngfws(self, panorama=None) -> dict:
        """ Retrieves NGFW information from the database. """
        response = {'message': [], 'results': None}
        formatted_results = []
        try:
            with self._Session() as session:
                query = session.query(Ngfw).options(joinedload(Ngfw.panorama))
                if panorama: query = query.join(Ngfw.panorama).filter((Panorama.hostname == panorama) | (Panorama.ip_address == panorama))
                ngfws_db = query.all()
                if not ngfws_db: response['message'].append(f"No NGFWs found {'managed by Panorama ' + panorama if panorama else 'in database'}."); return response
                formatted_results = [self._format_ngfw_result(ngfw_obj=n) for n in ngfws_db]
            if formatted_results: response['results'] = formatted_results
        except sqlalchemy_exc.SQLAlchemyError as db_err: raise MTControllerException(f"DB error getting NGFWs: {db_err}")
        except Exception as e: raise MTControllerException(f"Unexpected error getting NGFWs: {e}")
        return response

    def get_neighbors(self, ngfw=None, on_demand=False) -> dict:
        """ Retrieves LLDP neighbor information. """
        response = {'message': [], 'results': None}
        formatted_results = []
        try:
            with self._Session() as session:
                if on_demand:
                    ngfw_list = self._get_ngfws_by_filter(session, ngfw)
                    if not ngfw_list: response['message'].append(f"No NGFWs found matching '{ngfw or 'Any'}'."); return response
                    for ngfw_obj in ngfw_list:
                        response['message'].append(f"--- Querying LLDP Neighbors (On-Demand) for: {ngfw_obj.hostname} ---")
                        neighbors_api = self._fetch_api_neighbors(ngfw_obj)
                        if neighbors_api is None: response['message'].append(f"  Failed to fetch neighbors via API."); continue
                        if not neighbors_api: response['message'].append(f"  No LLDP neighbors found via API."); continue
                        response['message'].append(f"  Received {len(neighbors_api)} neighbor(s) from API.")
                        for neighbor_data in neighbors_api:
                             neighbor_data['ngfw'] = ngfw_obj.hostname
                             formatted_results.append(self._format_neighbor_result(neighbor_dict=neighbor_data))
                else:
                    # DB Query Logic
                    query = session.query(Neighbor).join(Neighbor.ngfw)
                    if ngfw: query = query.filter((Ngfw.hostname == ngfw) | (Ngfw.ip_address == ngfw) | (Ngfw.serial_number == ngfw) | (Ngfw.alt_ip == ngfw) | (Ngfw.alt_serial == ngfw))
                    neighbors_db = query.options(joinedload(Neighbor.ngfw)).all()
                    if not neighbors_db: response['message'].append("No LLDP neighbors found in database matching criteria.")
                    else: formatted_results = [self._format_neighbor_result(neighbor_obj=n) for n in neighbors_db]

            if formatted_results: response['results'] = formatted_results
            elif not response['message']: response['message'].append("No LLDP neighbors found matching criteria.")
        except sqlalchemy_exc.SQLAlchemyError as db_err: raise MTControllerException(f"DB error getting neighbors: {db_err}")
        except Exception as e: raise MTControllerException(f"Unexpected error getting neighbors: {e}")
        return response

    def get_panoramas(self) -> dict:
        """ Retrieves Panorama information from the database. """
        response = {'message': [], 'results': None}
        formatted_results = []
        try:
            with self._Session() as session:
                panoramas_db = session.query(Panorama).options(joinedload(Panorama.ngfws)).all() # Eager load for count
                if not panoramas_db: response['message'].append("No Panoramas found in database."); return response
                formatted_results = [self._format_panorama_result(p) for p in panoramas_db]
            if formatted_results: response['results'] = formatted_results
        except sqlalchemy_exc.SQLAlchemyError as db_err: raise MTControllerException(f"DB error getting Panoramas: {db_err}")
        except Exception as e: raise MTControllerException(f"Unexpected error getting Panoramas: {e}")
        return response

    # ==========================================================================
    # Update Methods (Using API Helpers and DB Object Creation Helpers)
    # ==========================================================================

    def update_routes(self, ngfw=None, virtual_router=None) -> list:
            """
            Updates routes and FIBs (IPv4 & IPv6) in the database using API data,
            including zone enrichment before saving.
            """
            messages = []
            try:
                # Start a database session that covers the entire update process for an NGFW
                # Using self._Session() assumes it's defined in __init__ as sessionmaker(bind=self._engine)
                with self._Session() as session:
                    # 1. Find Target NGFW(s)
                    ngfw_list = self._get_ngfws_by_filter(session, ngfw)
                    if not ngfw_list:
                        return [f"No NGFWs found matching '{ngfw or 'Any'}'."]

                    # 2. Process Each NGFW
                    for ngfw_obj in ngfw_list:
                        messages.append(f"--- Updating Routes/FIBs (v4/v6) for NGFW: {ngfw_obj.hostname} ---")

                        # 3. Find Target Virtual Routers for this NGFW
                        vr_list_db = self._get_vrs_by_ngfw_and_filter(session, ngfw_obj.id, virtual_router)
                        target_vr_ids = [vr.id for vr in vr_list_db] # Get IDs for deletion query
                        vr_map = {vr.name: vr.id for vr in vr_list_db} # Map VR name to ID for adding new entries
                        if not vr_map:
                            messages.append(f"  No VRs matching '{virtual_router or 'Any'}' found on this NGFW. Skipping.")
                            continue # Skip to the next NGFW

                        # 4. Delete Existing Route/FIB Data for Target VRs
                        commit_needed = False # Flag to track if actual DB changes occur
                        try:
                            if target_vr_ids:
                                messages.append(f"  Deleting existing Routes/FIBs for VR ID(s): {target_vr_ids}...")
                                deleted_fib_count = session.query(Fib).filter(Fib.virtual_router_id.in_(target_vr_ids)).delete(synchronize_session=False)
                                deleted_route_count = session.query(Route).filter(Route.virtual_router_id.in_(target_vr_ids)).delete(synchronize_session=False)
                                messages.append(f"  Deleted {deleted_fib_count} FIB(s) and {deleted_route_count} Route(s).")
                                commit_needed = commit_needed or deleted_fib_count > 0 or deleted_route_count > 0
                                session.flush() # Process deletes in the transaction buffer before adds
                        except sqlalchemy_exc.SQLAlchemyError as db_del_err:
                             messages.append(f"  DB error deleting existing entries: {db_del_err}. Aborting update for this NGFW.")
                             session.rollback() # Rollback changes for this NGFW within the session
                             continue # Skip processing this NGFW

                        # 5. Fetch, Enrich, and Prepare New Data
                        fib_count, route_count = 0, 0 # Counters for newly added items
                        db_fibs_to_add = [] # List to hold new Fib objects
                        db_routes_to_add = [] # List to hold new Route objects

                        try:
                            # --- Process FIBs ---
                            messages.append(f"  Fetching FIBs for VR(s): {', '.join(vr_map.keys())}...")
                            fibs_api = self._fetch_api_fibs(ngfw_obj, virtual_router=virtual_router)

                            if fibs_api is None:
                                messages.append("  Warning: Failed to fetch FIBs via API. Skipping FIB update.")
                            elif fibs_api:
                                messages.append(f"  Enriching {len(fibs_api)} FIB entries with zone information...")
                                for f_data in fibs_api: f_data['ngfw'] = ngfw_obj.hostname # Add context needed by enricher
                                self._enrich_results_with_zone(session, [ngfw_obj.id], fibs_api) # Enrich IN PLACE

                                # Process the API data
                                messages.append(f"  Processing {len(fibs_api)} enriched FIB entries...")
                                for f_data in fibs_api: # Iterate through enriched data
                                    dest = f_data.get('destination', '')
                                    afi = self._detect_address_family(dest) # Detect AFI
                                    vr_name = f_data.get('virtual_router')
                                    if afi and vr_name in vr_map: # Check AFI and VR filter
                                        vr_id = vr_map[vr_name]
                                        # Create DB object using enriched data
                                        db_fibs_to_add.append(self._create_fib_object(vr_id, afi, f_data))
                                    elif not afi:
                                         messages.append(f"  Skipping FIB entry with unidentifiable AFI: {dest}")

                            # --- Process Routes ---
                            messages.append(f"  Fetching Routes for VR(s): {', '.join(vr_map.keys())}...")
                            routes_api = self._fetch_api_routes(ngfw_obj, virtual_router=virtual_router)

                            if routes_api is None:
                                messages.append("  Warning: Failed to fetch Routes via API. Skipping Route update.")
                            elif routes_api:
                                messages.append(f"  Enriching {len(routes_api)} Route entries with zone information...")
                                for r_data in routes_api: r_data['ngfw'] = ngfw_obj.hostname # Add context
                                self._enrich_results_with_zone(session, [ngfw_obj.id], routes_api) # Enrich IN PLACE

                                # Process the (now potentially enriched) API data
                                messages.append(f"  Processing {len(routes_api)} enriched Route entries...")
                                for r_data in routes_api: # Iterate through enriched data
                                    dest = r_data.get('destination', '')
                                    afi = self._detect_address_family(dest) # Detect AFI
                                    vr_name = r_data.get('virtual_router')
                                    if afi and vr_name in vr_map: # Check AFI and VR filter
                                        vr_id = vr_map[vr_name]
                                        # Create DB object using enriched data
                                        db_routes_to_add.append(self._create_route_object(vr_id, afi, r_data))
                                    elif not afi:
                                         messages.append(f"  Skipping Route entry with unidentifiable AFI: {dest}")

                            # 6. Add Prepared Objects to Session
                            if db_fibs_to_add:
                                session.add_all(db_fibs_to_add)
                                fib_count = len(db_fibs_to_add)
                                messages.append(f"  Prepared {fib_count} new FIB(s).")
                                commit_needed = True
                            else:
                                messages.append("  No new valid FIBs found/processed.")

                            if db_routes_to_add:
                                session.add_all(db_routes_to_add)
                                route_count = len(db_routes_to_add)
                                messages.append(f"  Prepared {route_count} new Route(s).")
                                commit_needed = True
                            else:
                                messages.append("  No new valid Routes found/processed.")

                        # Handle exceptions during the fetch/enrich/prepare phase
                        except MTngfwException as api_err:
                             messages.append(f"  API error during fetch/process: {api_err}. Aborting update for this NGFW.")
                             session.rollback(); commit_needed = False; continue
                        except Exception as update_err:
                             logging.error(f"Error during update processing for {ngfw_obj.hostname}: {update_err}", exc_info=True)
                             messages.append(f"  Error during update processing: {update_err}. Rolling back.")
                             session.rollback(); commit_needed = False; continue

                        # 7. Commit Phase (only if changes were prepared and no errors occurred)
                        if commit_needed:
                            try:
                                session.commit() # Commit changes for this NGFW
                                messages.append(f"  Successfully updated {route_count} route(s) and {fib_count} FIB(s).")
                            except sqlalchemy_exc.SQLAlchemyError as commit_err:
                                messages.append(f"  DB commit error: {commit_err}. Rolled back.")
                                session.rollback() # Rollback failed commit
                        else:
                            messages.append(f"  No database changes were committed for routes/FIBs.")

                        messages.append(f"--- Update complete for {ngfw_obj.hostname} ---")
                # End of loop for single NGFW

            # Outer exception handling
            except sqlalchemy_exc.SQLAlchemyError as db_err:
                 raise MTControllerException(f"DB error during update_routes setup: {db_err}")
            except Exception as e:
                 logging.error(f"Unexpected error during update_routes: {e}", exc_info=True)
                 raise MTControllerException(f"Unexpected error during update_routes: {e}")

            return messages # Return accumulated messages


    def update_arps(self, ngfw=None, interface=None) -> list:
        """ Updates ARP entries in the database using API data. """
        messages = []
        try:
            with self._Session() as session:
                ngfw_list = self._get_ngfws_by_filter(session, ngfw)
                if not ngfw_list: return [f"No NGFWs found matching '{ngfw or 'Any'}'."]

                for ngfw_obj in ngfw_list:
                    messages.append(f"--- Updating ARPs for NGFW: {ngfw_obj.hostname} ---")
                    interfaces_db = self._get_interfaces_by_ngfw_and_filter(session, ngfw_obj.id, interface)
                    target_interface_ids = [i.id for i in interfaces_db]
                    interface_map = {i.name: {'id': i.id, 'zone': i.zone} for i in interfaces_db}
                    if not interface_map: messages.append(f"  No Interfaces matching '{interface or 'Any'}'. Skipping."); continue

                    arp_count = 0
                    commit_needed = False
                    try:
                        messages.append(f"  Fetching ARPs for interface(s): {interface or 'All'}...")
                        arps_api = self._fetch_api_arps(ngfw_obj, interface=interface)
                        if arps_api is None: messages.append("  Failed to fetch ARPs via API."); raise MTControllerException("API Fetch Failed")
                        if target_interface_ids:
                            deleted_arp_count = session.query(Arp).filter(Arp.interface_id.in_(target_interface_ids)).delete(synchronize_session=False)
                            messages.append(f"  Deleted {deleted_arp_count} existing ARP(s)."); commit_needed = commit_needed or deleted_arp_count > 0
                        db_arps = [self._create_arp_object(interface_map[a_data['interface']]['id'], interface_map[a_data['interface']]['zone'], a_data)
                                   for a_data in arps_api if a_data.get('interface') in interface_map]
                        if db_arps: session.add_all(db_arps); arp_count = len(db_arps); messages.append(f"  Added {arp_count} new ARP(s)."); commit_needed = True
                        else: messages.append("  No new ARPs to add.")
                    except Exception as update_err: messages.append(f"  Error during update: {update_err}. Rolling back."); session.rollback(); commit_needed = False
                    finally:
                         if commit_needed:
                              try: session.commit(); messages.append(f"  Successfully updated {arp_count} ARP(s).")
                              except sqlalchemy_exc.SQLAlchemyError as commit_err: messages.append(f"  DB commit error: {commit_err}. Rolled back."); session.rollback()
                         else: messages.append(f"  No database changes to commit.")
                         messages.append(f"--- ARP Update complete for {ngfw_obj.hostname} ---")
        except sqlalchemy_exc.SQLAlchemyError as db_err: raise MTControllerException(f"DB error during update_arps setup: {db_err}")
        except Exception as e: raise MTControllerException(f"Unexpected error during update_arps: {e}")
        return messages

    def update_neighbors(self, ngfw=None) -> list:
        """ Updates LLDP neighbors in the database using API data. """
        messages = []
        try:
            with self._Session() as session:
                ngfw_list = self._get_ngfws_by_filter(session, ngfw)
                if not ngfw_list: return [f"No NGFWs found matching '{ngfw or 'Any'}'."]

                for ngfw_obj in ngfw_list:
                    messages.append(f"--- Updating LLDP Neighbors for NGFW: {ngfw_obj.hostname} ---")
                    neighbor_count = 0
                    commit_needed = False
                    try:
                        messages.append(f"  Fetching LLDP neighbors from API...")
                        neighbors_api = self._fetch_api_neighbors(ngfw_obj)
                        if neighbors_api is None: messages.append("  Failed to fetch neighbors via API."); raise MTControllerException("API Fetch Failed")
                        deleted_neighbor_count = session.query(Neighbor).filter(Neighbor.ngfw_id == ngfw_obj.id).delete(synchronize_session=False)
                        messages.append(f"  Deleted {deleted_neighbor_count} existing Neighbor(s)."); commit_needed = commit_needed or deleted_neighbor_count > 0
                        db_neighbors = [self._create_neighbor_object(ngfw_obj.id, ne_data) for ne_data in neighbors_api]
                        if db_neighbors: session.add_all(db_neighbors); neighbor_count = len(db_neighbors); messages.append(f"  Added {neighbor_count} new Neighbor(s)."); commit_needed = True
                        else: messages.append("  No new LLDP neighbors to add.")
                    except Exception as update_err: messages.append(f"  Error during update: {update_err}. Rolling back."); session.rollback(); commit_needed = False
                    finally:
                         if commit_needed:
                              try: session.commit(); messages.append(f"  Successfully updated {neighbor_count} LLDP neighbor(s).")
                              except sqlalchemy_exc.SQLAlchemyError as commit_err: messages.append(f"  DB commit error: {commit_err}. Rolled back."); session.rollback()
                         else: messages.append(f"  No database changes to commit.")
                         messages.append(f"--- Neighbor Update complete for {ngfw_obj.hostname} ---")
        except sqlalchemy_exc.SQLAlchemyError as db_err: raise MTControllerException(f"DB error during update_neighbors setup: {db_err}")
        except Exception as e: raise MTControllerException(f"Unexpected error during update_neighbors: {e}")
        return messages

    def update_bgp_peers(self, ngfw=None, virtual_router=None) -> list:
        """ Updates BGP peers in the database using API data. """
        messages = []
        try:
            with self._Session() as session:
                ngfw_list = self._get_ngfws_by_filter(session, ngfw)
                if not ngfw_list: return [f"No NGFWs found matching '{ngfw or 'Any'}'."]

                for ngfw_obj in ngfw_list:
                    messages.append(f"--- Updating BGP Peers for NGFW: {ngfw_obj.hostname} ---")
                    vr_list_db = self._get_vrs_by_ngfw_and_filter(session, ngfw_obj.id, virtual_router)
                    target_vr_ids = [vr.id for vr in vr_list_db]
                    vr_map = {vr.name: vr.id for vr in vr_list_db}
                    if not vr_map: messages.append(f"  No VRs matching '{virtual_router or 'Any'}'. Skipping."); continue

                    bgp_peer_count = 0
                    commit_needed = False
                    try:
                        messages.append(f"  Fetching BGP peers for VR(s): {', '.join(vr_map.keys())}...")
                        bgp_peers_api = self._fetch_api_bgp_peers(ngfw_obj, virtual_router=virtual_router)
                        if bgp_peers_api is None: messages.append("  Failed to fetch BGP peers via API."); raise MTControllerException("API Fetch Failed")
                        if target_vr_ids:
                            deleted_bgp_count = session.query(BGPPeer).filter(BGPPeer.ngfw_id == ngfw_obj.id, BGPPeer.virtual_router_id.in_(target_vr_ids)).delete(synchronize_session=False)
                            messages.append(f"  Deleted {deleted_bgp_count} existing BGP Peer(s)."); commit_needed = commit_needed or deleted_bgp_count > 0
                        db_bgp_peers = [self._create_bgp_peer_object(ngfw_obj.id, vr_map[p_data['virtual_router']], p_data)
                                        for p_data in bgp_peers_api if p_data.get('virtual_router') in vr_map]
                        if db_bgp_peers: session.add_all(db_bgp_peers); bgp_peer_count = len(db_bgp_peers); messages.append(f"  Added {bgp_peer_count} new BGP Peer(s)."); commit_needed = True
                        else: messages.append("  No new BGP peers to add.")
                    except Exception as update_err: messages.append(f"  Error during update: {update_err}. Rolling back."); session.rollback(); commit_needed = False
                    finally:
                         if commit_needed:
                              try: session.commit(); messages.append(f"  Successfully updated {bgp_peer_count} BGP peer(s).")
                              except sqlalchemy_exc.SQLAlchemyError as commit_err: messages.append(f"  DB commit error: {commit_err}. Rolled back."); session.rollback()
                         else: messages.append(f"  No database changes to commit.")
                         messages.append(f"--- BGP Peer Update complete for {ngfw_obj.hostname} ---")
        except sqlalchemy_exc.SQLAlchemyError as db_err: raise MTControllerException(f"DB error during update_bgp_peers setup: {db_err}")
        except Exception as e: raise MTControllerException(f"Unexpected error during update_bgp_peers: {e}")
        return messages

    def test_fib_lookup(self, ip_address, vr_query=None, ngfw_query=None) -> dict:
        """ Performs an on-demand FIB lookup test via API. """
        response = {'message': [], 'results': None}
        formatted_results = []

        # if not isinstance(ip_address, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
        #     # Raise error if it's not one of the expected IP address object types
        #     raise TypeError(f"Invalid IP Address object type provided: {type(ip_address)}")

        try:
            with self._Session() as session:
                vr_list_db = self._get_vrs_by_ngfw_and_filter(session, None, vr_query)
                if ngfw_query:
                    ngfw_ids = {n.id for n in self._get_ngfws_by_filter(session, ngfw_query)}
                    vr_list_db = [vr for vr in vr_list_db if vr.ngfw_id in ngfw_ids]
                if not vr_list_db: response['message'].append("No VRs found matching criteria."); return response

                # Get all NGFW IDs involved for zone enrichment
                all_ngfw_ids = list({vr.ngfw_id for vr in vr_list_db})

                # Store results temporarily before enrichment
                temp_results = []

                for vr in vr_list_db:
                    response['message'].append(f"--- Testing FIB Lookup (On-Demand) for {ip_address} on {vr.ngfw.hostname}/{vr.name} ---")
                    result_api = self._fetch_api_fib_lookup_test(vr.ngfw, ip_address, vr.name)

                    # Prepare result dictionary, even for errors, adding context
                    result_dict = {'ngfw': vr.ngfw.hostname, 'virtual_router': vr.name}

                    if result_api is None:
                        response['message'].append(f"  API Error or connection failure.")
                        result_dict.update({'interface': 'API Error', 'nexthop': 'API Error', 'zone': 'API Error'})
                    elif 'interface' not in result_api:
                        response['message'].append(f"  No route found via API test.")
                        result_dict.update({'interface': 'None', 'nexthop': 'None', 'zone': 'None'})
                    else:
                        # Extract raw data needed for formatting and enrichment
                        result_dict['interface'] = result_api.get('interface')
                        nh_key = result_api.get('nh')
                        next_hop = result_api.get(nh_key, 'self') if nh_key else 'self'
                        result_dict['nexthop'] = next_hop # Store raw nexthop for formatter
                        # Zone will be added by enrichment helper
                        response['message'].append(f"  Lookup successful (raw): Interface='{result_dict['interface']}', Nexthop='{result_dict['nexthop']}'.")
                    temp_results.append(result_dict)

                # Enrich all collected results with zone info
                if temp_results:
                    self._enrich_results_with_zone(session, all_ngfw_ids, temp_results)

                # Format the enriched results
                formatted_results = [self._format_fib_lookup_result(res) for res in temp_results]

            if formatted_results: response['results'] = formatted_results
        except sqlalchemy_exc.SQLAlchemyError as db_err: raise MTControllerException(f"DB error during test_fib_lookup setup: {db_err}")
        except Exception as e: raise MTControllerException(f"Unexpected error during test_fib_lookup: {e}")
        return response

    def calculate_fib_lookup(self, ip_address_str: str, vr_query: str = None, ngfw_query: str = None) -> dict:
            """
            Calculates the best matching FIB entry for a given IP address across specified virtual routers.

            This method queries the database for FIB entries within the filtered virtual routers
            and performs a longest prefix match calculation against the provided IP address.

            Args:
                ip_address_str (str): The IP address (IPv4 or IPv6) to perform the FIB lookup on.
                vr_query (str, optional): The virtual router name to filter the lookup. Defaults to None (all VRs).
                ngfw_query (str, optional): The NGFW hostname, IP, or serial to filter the lookup. Defaults to None (all NGFWs).

            Returns:
                dict: A dictionary containing:
                    - 'message' (list): Status messages during processing.
                    - 'results' (list | None): A list of dictionaries, each representing the best FIB match
                                            found for the IP in a specific virtual router. Returns None if no results.
                                            Each result dictionary is formatted by _format_fib_lookup_result.

            Raises:
                MTControllerException: If the provided IP address string is invalid or a database error occurs.
            """
            response = {'message': [], 'results': None}
            formatted_results = []

            # Validate IP address early
            try:
                target_ip = ipaddress.ip_address(ip_address_str)
            except ValueError:
                raise MTControllerException(f"Invalid IP Address provided: {ip_address_str}")

            try:
                with self._Session() as session:
                    # Get NGFW IDs based on the filter
                    ngfw_ids = None
                    if ngfw_query:
                        ngfw_objs = self._get_ngfws_by_filter(session, ngfw_query)
                        if not ngfw_objs:
                            response['message'].append(f"No NGFWs found matching filter: {ngfw_query}")
                            return response
                        ngfw_ids = {n.id for n in ngfw_objs}

                    # Get relevant VirtualRouter objects using the helper
                    # Filter by NGFW IDs if provided
                    query = session.query(VirtualRouter).options(
                        joinedload(VirtualRouter.ngfw),
                        joinedload(VirtualRouter.fib) # Eager load FIBs for these VRs
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

                    # Process each virtual router
                    for vr in virtual_router_list:
                        best_match_fib = None
                        longest_prefix = -1 # Use -1 to handle default routes (prefix 0)

                        # Iterate through the pre-loaded FIB entries for this VR
                        for fib_entry in vr.fib:
                            # Skip routes that are not usable ('u' flag)
                            if "u" not in fib_entry.flags.lower():
                                continue

                            try:
                                network = ipaddress.ip_network(fib_entry.destination, strict=False)
                                # Check if the target IP is within this FIB destination network
                                if target_ip in network:
                                    # Check if this is a more specific match (longer prefix)
                                    if network.prefixlen > longest_prefix:
                                        longest_prefix = network.prefixlen
                                        best_match_fib = fib_entry
                            except ValueError:
                                # Ignore invalid destinations in the DB? Or log?
                                response['message'].append(f"Warning: Skipping invalid FIB destination '{fib_entry.destination}' in VR '{vr.name}' on NGFW '{vr.ngfw.hostname}'.")
                                continue # Skip this invalid FIB entry

                        # Format the result for this VR
                        if best_match_fib:
                            # Create a dictionary similar to what _format_fib_lookup_result expects
                            lookup_data = {
                                'ngfw': vr.ngfw.hostname,
                                'virtual_router': vr.name,
                                'destination': best_match_fib.destination,
                                'nexthop': best_match_fib.nexthop,
                                'flags': best_match_fib.flags,
                                'interface': best_match_fib.interface,
                                'zone': best_match_fib.zone
                            }
                            formatted_results.append(self._format_fib_lookup_result(lookup_data))
                            response['message'].append(f"Match found in {vr.ngfw.hostname}/{vr.name}: {best_match_fib.destination}")
                        else:
                            # No matching route found in this VR, append a 'None' entry
                            no_match_data = {
                                'ngfw': vr.ngfw.hostname,
                                'virtual_router': vr.name,
                                'destination': "None",
                                'nexthop': "None",
                                'flags': "None",
                                'interface': "None",
                                'zone': 'None'
                            }
                            formatted_results.append(self._format_fib_lookup_result(no_match_data))
                            response['message'].append(f"No matching route found for {ip_address_str} in {vr.ngfw.hostname}/{vr.name}")

                if formatted_results:
                    response['results'] = formatted_results

            except sqlalchemy_exc.SQLAlchemyError as db_err:
                # Log the specific DB error if needed
                raise MTControllerException(f"Database error during FIB lookup calculation: {db_err}")
            except Exception as e:
                # Catch any other unexpected errors
                raise MTControllerException(f"Unexpected error during FIB lookup calculation: {e}")

            return response

    def update_ha_status(self, ngfw_filter=None, pan_filter=None) -> list:
        """ Updates HA status in the database using API data. """
        # (Implementation remains the same - uses API helpers)
        messages = []
        updated_devices = []
        try:
            with self._Session() as session:
                # Check Panoramas
                pan_query = session.query(Panorama);
                if pan_filter: pan_query = pan_query.filter((Panorama.hostname == pan_filter) | (Panorama.ip_address == pan_filter))
                messages.append(f"--- Checking HA Status for {pan_query.count()} Panorama(s) ---")
                for p in pan_query.all():
                    if p.alt_ip:
                        messages.append(f"  Checking Panorama: {p.hostname}...")
                        ha_info = self._fetch_api_panorama_ha_state(p)
                        if ha_info is None: messages.append(f"    Failed to fetch HA state via API."); continue
                        is_active_api = ha_info.get('enabled') == 'yes' and 'local-info' in ha_info and 'active' in ha_info['local-info'].get('state', '').lower()
                        if p.active != is_active_api: messages.append(f"    Status Change: Now {'ACTIVE' if is_active_api else 'PASSIVE'}. Updating DB."); p.active = is_active_api; updated_devices.append(p)
                        else: messages.append(f"    Status Verified: {'ACTIVE' if p.active else 'PASSIVE'}. No change.")
                    else: messages.append(f"  Skipping Panorama {p.hostname}: Not HA configured.")
                # Check NGFWs
                ngfw_list = self._get_ngfws_by_filter(session, ngfw_filter)
                messages.append(f"--- Checking HA Status for {len(ngfw_list)} NGFW(s) ---")
                for n in ngfw_list:
                    if n.alt_serial:
                        messages.append(f"  Checking NGFW: {n.hostname}...")
                        ha_info = self._fetch_api_ngfw_ha_status(n)
                        if ha_info is None: messages.append(f"    Failed to fetch HA status via API."); continue
                        is_active_api = 'active' in ha_info.get('state', 'unknown').lower()
                        if n.active != is_active_api: messages.append(f"    Status Change: Now {'ACTIVE' if is_active_api else 'PASSIVE'}. Updating DB."); n.active = is_active_api; updated_devices.append(n)
                        else: messages.append(f"    Status Verified: {'ACTIVE' if n.active else 'PASSIVE'}. No change.")
                    else: messages.append(f"  Skipping NGFW {n.hostname}: Not HA configured.")
                # Commit changes
                if updated_devices:
                    messages.append(f"--- Committing {len(updated_devices)} HA status update(s) ---")
                    try: session.commit(); messages.append("--- DB commit successful ---")
                    except sqlalchemy_exc.SQLAlchemyError as commit_err: messages.append(f"--- DB commit FAILED: {commit_err}. Rolled back. ---"); session.rollback()
                else: messages.append("--- No HA status changes detected ---")
        except sqlalchemy_exc.SQLAlchemyError as db_err: raise MTControllerException(f"DB error during update_ha_status: {db_err}")
        except Exception as e: raise MTControllerException(f"Unexpected error during update_ha_status: {e}")
        return messages

    # --- Internal helper to safely check/clean API dictionary results ---
    def _null_value_check(self, result_dict) -> dict:
        """
        Iterates through a dictionary and replaces None values with empty strings.
        Modifies the dictionary in-place and returns it.

        Args:
            result_dict (dict): The dictionary to check.

        Returns:
            dict: The modified dictionary with None values replaced by ''.
        """
        if not isinstance(result_dict, dict):
             return result_dict # Return unchanged if not a dict

        for key, value in result_dict.items():
            if value is None:
                result_dict[key] = ''
        return result_dict

