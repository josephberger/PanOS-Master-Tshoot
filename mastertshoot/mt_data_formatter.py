# mastertshoot/mt_data_formatter.py

import logging
# ipaddress is not directly used by formatter methods for IP validation/detection,
# so it can be removed from here. It will be used by MTAnalyzer.
# import ipaddress 
from collections import defaultdict # Only needed if formatters perform complex grouping, generally not. Can remove if not used.

# Import models for type hinting and for formatting methods that access model attributes
from models import (
    Ngfw, Route, VirtualRouter, Interface, Panorama,
    Neighbor, BGPPeer, Fib, Arp, InterfaceIPv6Address
)

# Import dependencies
# MTDatabaseManager is needed if formatters query the DB (e.g., for counts)
from mastertshoot.mt_database_manager import MTDatabaseManager
from sqlalchemy.orm import Session # For type hinting if methods accept a session directly (e.g., if passing to db_manager)

# No custom exception defined in this file itself, as per discussion to centralize
# or keep granular exceptions where they are primarily raised.


class MTDataFormatter:
    """
    Handles all data transformation and formatting for various data types
    (e.g., routes, interfaces, devices) into a standardized dictionary structure
    suitable for UI display or other consumption.
    """
    def __init__(self, db_manager: MTDatabaseManager = None):
        """
        Initializes the MTDataFormatter.

        Args:
            db_manager (MTDatabaseManager, optional): An instance of MTDatabaseManager.
                                                      Needed if any formatting methods
                                                      require querying the database for
                                                      additional data (e.g., counts).
        """
        self.db_manager = db_manager
        logging.debug("MTDataFormatter initialized.")

    def null_value_check(self, value):
        """
        Replaces None values with empty strings.
        This method was previously _null_value_check in MTController.
        """
        if value is None:
            return ''
        if isinstance(value, dict):
            # Recursively apply to dictionaries
            for key, val in value.items():
                value[key] = self.null_value_check(val)
        elif isinstance(value, list):
            # Apply to elements in a list
            value = [self.null_value_check(item) for item in value]
        return value

    def format_route_result(self, route_obj=None, route_dict=None) -> dict:
        """
        Formats a Route DB object or an API route dict into the standard result structure.
        This method was previously _format_route_result in MTController.
        """
        if route_obj:
            ngfw_name = route_obj.virtual_router.ngfw.hostname if route_obj.virtual_router and route_obj.virtual_router.ngfw else 'Unknown'
            vr_name = route_obj.virtual_router.name if route_obj.virtual_router else 'Unknown'
            return self.null_value_check({
                'ngfw': ngfw_name, 'virtual_router': vr_name,
                'destination': route_obj.destination, 'nexthop': route_obj.nexthop,
                'metric': str(route_obj.metric) if route_obj.metric is not None else None,
                'flags': route_obj.flags, 'interface': route_obj.interface,
                'route_table': route_obj.route_table,
                'age': str(route_obj.age) if route_obj.age is not None else None,
                'zone': route_obj.zone
            })
        elif route_dict:
            # Apply null_value_check to the whole dictionary after copying
            return self.null_value_check({
                'ngfw': route_dict.get('ngfw', None), 'virtual_router': route_dict.get('virtual_router', None),
                'destination': route_dict.get('destination', None), 'nexthop': route_dict.get('nexthop', None),
                'metric': str(route_dict.get('metric', '')) if route_dict.get('metric') is not None else None, # Convert to string then null check
                'flags': route_dict.get('flags', None),
                'interface': route_dict.get('interface', None), 'route_table': route_dict.get('route_table', None),
                'age': str(route_dict.get('age', '')) if route_dict.get('age') is not None else None, # Convert to string then null check
                'zone': route_dict.get('zone', None)
            })
        return {}

    def format_fib_result(self, fib_obj=None, fib_dict=None) -> dict:
        """
        Formats a Fib DB object or an API FIB dict into the standard result structure.
        This method was previously _format_fib_result in MTController.
        """
        if fib_obj:
            ngfw_name = fib_obj.virtual_router.ngfw.hostname if fib_obj.virtual_router and fib_obj.virtual_router.ngfw else 'Unknown'
            vr_name = fib_obj.virtual_router.name if fib_obj.virtual_router else 'Unknown'
            return self.null_value_check({
                'ngfw': ngfw_name, 'virtual_router': vr_name,
                'fib_id': str(fib_obj.fib_id) if fib_obj.fib_id is not None else None,
                'destination': fib_obj.destination, 'interface': fib_obj.interface,
                'nh_type': fib_obj.nh_type, 'flags': fib_obj.flags,
                'nexthop': fib_obj.nexthop,
                'mtu': str(fib_obj.mtu) if fib_obj.mtu is not None else None,
                'zone': fib_obj.zone
            })
        elif fib_dict:
            return self.null_value_check({
                'ngfw': fib_dict.get('ngfw', None), 'virtual_router': fib_dict.get('virtual_router', None),
                'fib_id': str(fib_dict.get('fib_id', '')) if fib_dict.get('fib_id') is not None else None,
                'destination': fib_dict.get('destination', None), 'interface': fib_dict.get('interface', None),
                'nh_type': fib_dict.get('nh_type', None), 'flags': fib_dict.get('flags', None),
                'nexthop': fib_dict.get('nexthop', None), 'mtu': str(fib_dict.get('mtu', '')) if fib_dict.get('mtu') is not None else None,
                'zone': fib_dict.get('zone', None)
            })
        return {}

    def format_interface_result(self, if_obj=None, if_dict=None) -> dict:
        """
        Formats an Interface DB object or an API interface dict.
        Includes an indicator ('*') if IPv6 is enabled.
        Also includes 'ipv6_address_list' containing a list of IPv6 address strings.
        This method was previously _format_interface_result in MTController.
        """
        ipv6_present_indicator = ""
        ipv6_address_list = []

        if if_obj:
            ngfw_name = if_obj.virtual_router.ngfw.hostname if if_obj.virtual_router and if_obj.virtual_router.ngfw else 'Unknown'
            vr_name = if_obj.virtual_router.name if if_obj.virtual_router else 'Unknown'

            if if_obj.ipv6_enabled:
                 ipv6_present_indicator = "*"

            if hasattr(if_obj, 'ipv6_addresses') and if_obj.ipv6_addresses:
                 ipv6_address_list = [ipv6.address for ipv6 in if_obj.ipv6_addresses]

            result = {
                'ngfw': ngfw_name, 'virtual_router': vr_name,
                'name': if_obj.name, 'tag': if_obj.tag,
                'vsys': if_obj.vsys, 'ip': if_obj.ip,
                'zone': if_obj.zone,
                'ipv6_present': ipv6_present_indicator,
                'ipv6_address_list': ipv6_address_list
            }
            return self.null_value_check(result)

        elif if_dict:
            # No need for .copy() as null_value_check is modified to be non-in-place for top level
            ipv6_address_list = if_dict.get('ipv6_addresses', [])
            if isinstance(ipv6_address_list, list) and ipv6_address_list:
                 ipv6_present_indicator = "*"

            result = {
                'ngfw': if_dict.get('ngfw', None), 'virtual_router': if_dict.get('virtual_router', None),
                'name': if_dict.get('name', None), 'tag': if_dict.get('tag', None),
                'vsys': if_dict.get('vsys', None), 'ip': if_dict.get('ip', None),
                'zone': if_dict.get('zone', None),
                'ipv6_present': ipv6_present_indicator,
                'ipv6_address_list': ipv6_address_list
            }
            return self.null_value_check(result)
        return {}

    def format_bgp_peer_result(self, peer_obj=None, peer_dict=None) -> dict:
        """
        Formats a BGPPeer DB object or an API peer dict into the standard result structure.
        This method was previously _format_bgp_peer_result in MTController.
        """
        if peer_obj:
            ngfw_name = peer_obj.ngfw.hostname if peer_obj.ngfw else 'Unknown'
            vr_name = peer_obj.virtual_router.name if peer_obj.virtual_router else 'Unknown'
            return self.null_value_check({
                'ngfw': ngfw_name, 'virtual_router': vr_name,
                'peer_name': peer_obj.peer_name, 'peer_group': peer_obj.peer_group,
                'peer_router_id': peer_obj.peer_router_id, 'remote_as': peer_obj.remote_as,
                'status': peer_obj.status, 'status_duration': peer_obj.status_duration,
                'peer_address': peer_obj.peer_address, 'local_address': peer_obj.local_address
            })
        elif peer_dict:
            return self.null_value_check({
                'ngfw': peer_dict.get('ngfw', None), 'virtual_router': peer_dict.get('virtual_router', None),
                'peer_name': peer_dict.get('peer_name', None), 'peer_group': peer_dict.get('peer_group', None),
                'peer_router_id': peer_dict.get('peer_router_id', None), 'remote_as': peer_dict.get('remote_as', None),
                'status': peer_dict.get('status', None), 'status_duration': peer_dict.get('status_duration', None),
                'peer_address': peer_dict.get('peer_address', None), 'local_address': peer_dict.get('local_address', None)
            })
        return {}

    def format_arp_result(self, arp_obj=None, arp_dict=None) -> dict:
        """
        Formats an Arp DB object or an API ARP dict into the standard result structure.
        This method was previously _format_arp_result in MTController.
        """
        if arp_obj:
            ngfw_name = arp_obj.interface.virtual_router.ngfw.hostname if arp_obj.interface and arp_obj.interface.virtual_router and arp_obj.interface.virtual_router.ngfw else 'Unknown'
            if_name = arp_obj.interface.name if arp_obj.interface else 'Unknown'
            return self.null_value_check({
                'ngfw': ngfw_name, 'interface': if_name,
                'ip': arp_obj.ip, 'mac': arp_obj.mac,
                'port': arp_obj.port,
                'ttl': str(arp_obj.ttl) if arp_obj.ttl is not None else None,
                'status': arp_obj.status, 'zone': arp_obj.zone
            })
        elif arp_dict:
            return self.null_value_check({
                'ngfw': arp_dict.get('ngfw', None), 'interface': arp_dict.get('interface', None),
                'ip': arp_dict.get('ip', None), 'mac': arp_dict.get('mac', None),
                'port': arp_dict.get('port', None), 'ttl': str(arp_dict.get('ttl', '')) if arp_dict.get('ttl') is not None else None,
                'status': arp_dict.get('status', None), 'zone': arp_dict.get('zone', None)
            })
        return {}

    def format_neighbor_result(self, neighbor_obj=None, neighbor_dict=None) -> dict:
        """
        Formats a Neighbor DB object or an API neighbor dict into the standard result structure.
        This method was previously _format_neighbor_result in MTController.
        """
        if neighbor_obj:
            ngfw_name = neighbor_obj.ngfw.hostname if neighbor_obj.ngfw else 'Unknown'
            return self.null_value_check({
                'ngfw': ngfw_name, 'local_interface': neighbor_obj.local_interface,
                'remote_interface_id': neighbor_obj.remote_interface_id,
                'remote_interface_description': neighbor_obj.remote_interface_description,
                'remote_hostname': neighbor_obj.remote_hostname
            })
        elif neighbor_dict:
            return self.null_value_check({
                'ngfw': neighbor_dict.get('ngfw', None), 'local_interface': neighbor_dict.get('local_interface', None),
                'remote_interface_id': neighbor_dict.get('remote_interface_id', None),
                'remote_interface_description': neighbor_dict.get('remote_interface_description', None),
                'remote_hostname': neighbor_dict.get('remote_hostname', None)
            })
        return {}

    def format_ngfw_result(self, ngfw_obj: Ngfw) -> dict:
        """
        Formats an Ngfw DB object into the standard result structure.
        This method was previously _format_ngfw_result in MTController.
        """
        if not ngfw_obj: return {}

        result = {
            'hostname': ngfw_obj.hostname,
            'serial_number': ngfw_obj.serial_number,
            'ip_address': ngfw_obj.ip_address,
            'model': ngfw_obj.model,
            'alt_serial': ngfw_obj.alt_serial,
            'alt_ip': ngfw_obj.alt_ip,
            'active': 'yes' if ngfw_obj.active else 'no',
            'panorama': ngfw_obj.panorama.hostname if ngfw_obj.panorama else None,
            'last_update': ngfw_obj.last_update,
            'advanced_routing_enabled': 'yes' if ngfw_obj.advanced_routing_enabled else 'no',
            'ipv6_address': ngfw_obj.ipv6_address,
            'mac_address': ngfw_obj.mac_address,
            'uptime': ngfw_obj.uptime,
            'sw_version': ngfw_obj.sw_version,
            'app_version': ngfw_obj.app_version,
            'av_version': ngfw_obj.av_version,
            'wildfire_version': ngfw_obj.wildfire_version,
            'threat_version': ngfw_obj.threat_version,
            'url_filtering_version': ngfw_obj.url_filtering_version,
            'device_cert_present': ngfw_obj.device_cert_present,
            'device_cert_expiry_date': ngfw_obj.device_cert_expiry_date
        }
        return self.null_value_check(result)

    def format_panorama_result(self, pan_obj: Panorama) -> dict:
        """
        Formats a Panorama DB object into the standard result structure,
        including all new extended system information fields.
        This method was previously _format_panorama_result in MTController.
        """
        if not pan_obj:
            return {}

        ngfw_count = 0
        if hasattr(pan_obj, 'ngfws') and pan_obj.ngfws is not None:
            ngfw_count = len(pan_obj.ngfws)
        else:
            # If ngfws are not eagerly loaded, query the count via db_manager
            if self.db_manager:
                with self.db_manager.get_session() as session:
                    ngfw_count = session.query(Ngfw).filter(Ngfw.panorama_id == pan_obj.id).count()
            else:
                logging.warning("MTDataFormatter: db_manager not provided, cannot get NGFW count for Panorama.")


        result = {
            'hostname': pan_obj.hostname,
            'serial_number': pan_obj.serial_number,
            'ip_address': pan_obj.ip_address,
            'alt_ip': pan_obj.alt_ip,
            'active': 'yes' if pan_obj.active else 'no',
            'ngfws': ngfw_count, # This is an int, will be handled by null_value_check for None to '' if it ever happens

            'mac_address': pan_obj.mac_address,
            'uptime': pan_obj.uptime,
            'model': pan_obj.model,
            'sw_version': pan_obj.sw_version,
            'app_version': pan_obj.app_version,
            'av_version': pan_obj.av_version,
            'wildfire_version': pan_obj.wildfire_version,
            'logdb_version': pan_obj.logdb_version,
            'system_mode': pan_obj.system_mode,
            'licensed_device_capacity': pan_obj.licensed_device_capacity,
            'device_certificate_status': pan_obj.device_certificate_status,
            'ipv6_address': pan_obj.ipv6_address,
            'last_system_info_refresh': pan_obj.last_system_info_refresh
        }
        return self.null_value_check(result)

    def format_vr_result(self, vr_obj: VirtualRouter, include_counts: bool = True) -> dict:
        """
        Formats a VirtualRouter DB object into the standard result structure.
        This method was previously _format_vr_result in MTController.
        It now relies on db_manager for counts if include_counts is True.
        """
        if not vr_obj: return {}
        vr_dict = {
            'ngfw': vr_obj.ngfw.hostname if vr_obj.ngfw else 'Unknown',
            'virtual_router': vr_obj.name,
        }
        if include_counts and self.db_manager:
            with self.db_manager.get_session() as session:
                vr_dict['route_count'] = session.query(Route).filter(Route.virtual_router_id == vr_obj.id).count()
                vr_dict['fib_count'] = session.query(Fib).filter(Fib.virtual_router_id == vr_obj.id).count()
                vr_dict['interface_count'] = session.query(Interface).filter(Interface.virtual_router_id == vr_obj.id).count()
        elif include_counts and not self.db_manager:
            logging.warning("MTDataFormatter: db_manager not provided, cannot include counts for VRs.")
            vr_dict['route_count'] = 'N/A'
            vr_dict['fib_count'] = 'N/A'
            vr_dict['interface_count'] = 'N/A'
        return self.null_value_check(vr_dict)

    def format_fib_lookup_result(self, lookup_dict: dict) -> dict:
         """
         Formats a FIB lookup result dictionary (from API or calculation).
         This method was previously _format_fib_lookup_result in MTController.
         """
         # Directly set next_hop logic, then pass to null_value_check
         next_hop = lookup_dict.get('nexthop')
         if next_hop == "0.0.0.0":
             next_hop = "self"

         result = {
            'ngfw': lookup_dict.get('ngfw', None),
            'virtual_router': lookup_dict.get('virtual_router', None),
            'destination': lookup_dict.get('destination', None),
            'nexthop': next_hop,
            'flags': lookup_dict.get('flags', None),
            'interface': lookup_dict.get('interface', None),
            'zone': lookup_dict.get('zone', None) # Now correctly passed as None or actual zone
         }
         return self.null_value_check(result)