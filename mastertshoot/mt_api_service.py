# mastertshoot/mt_api_service.py

import logging
import json
import pan.xapi
import xmltodict

# Import device wrapper classes and their exceptions
from .mt_devices import MTpanorama, MTngfw, MTpanoramaException, MTngfwException

# --- Constants for API Commands (copied from mt_devices.py for self-containment or could be imported) ---
# General / System
_CMD_SHOW_SYSTEM_INFO = "<show><system><info></info></system></show>"
_CMD_SHOW_HA_STATE = "<show><high-availability><state></state></high-availability></show>"

# Panorama Specific
_CMD_PAN_SHOW_DEVICES_ALL = "<show><devices><all></all></devices></show>"

# NGFW Specific / Routing / Interfaces
_CMD_NGFW_SHOW_ROUTING_SUMMARY = "<show><routing><summary></summary></routing></show>"
_CMD_NGFW_SHOW_ADV_ROUTING_LOGICAL_ROUTER = "<show><advanced-routing><logical-router></logical-router></advanced-routing></show>"
_CMD_NGFW_SHOW_LLDP_NEIGHBORS_ALL = "<show><lldp><neighbors>all</neighbors></lldp></show>"
_CMD_NGFW_SHOW_INTERFACES_ALL = "<show><interface>all</interface></show>"
_CMD_NGFW_SHOW_ROUTING_ROUTE = "<show><routing><route>{vr_part}</route></routing></show>"
_CMD_NGFW_SHOW_ROUTING_FIB = "<show><routing><fib>{vr_part}</fib></routing></show>"
_CMD_NGFW_SHOW_ADV_ROUTING_ROUTE = "<show><advanced-routing><route>{vr_part}</route></advanced-routing></show>"
_CMD_NGFW_SHOW_ADV_ROUTING_FIB = "<show><advanced-routing><fib>{vr_part}</fib></advanced-routing></show>"
_CMD_NGFW_SHOW_ARP_ENTRY = "<show><arp><entry name = '{if_name}'/></arp></show>"
_CMD_NGFW_SHOW_BGP_PEER = "<show><routing><protocol><bgp><peer>{vr_part}</peer></bgp></protocol></routing></show>"
_CMD_NGFW_SHOW_ADV_ROUTING_BGP_PEER_DETAIL = "<show><advanced-routing><bgp><peer><detail>{vr_part}</detail></peer></bgp></advanced-routing></show>"
_CMD_NGFW_SHOW_ADV_ROUTING_BGP_PEER_GROUPS = "<show><advanced-routing><bgp><peer-groups></peer-groups></bgp></advanced-routing></show>"


# --- Helper Functions (Moved/Copied from mt_devices.py) ---
def _ensure_list(data):
    """
    Ensures the input data is a list. If None, returns empty list.
    If not a list, wraps it in a list.
    """
    if data is None:
        return []
    if isinstance(data, list):
        return data
    return [data]


# --- Exceptions ---
class MTAPIServiceException(Exception):
    """Custom exception for MTAPIService errors."""
    pass

class MTAPIService:
    """
    Manages all direct API interactions with Palo Alto Networks Panorama and NGFW devices.
    It instantiates and uses MTpanorama and MTngfw objects for communication,
    and handles common API response parsing and error propagation.
    """
    def __init__(self, timeout: int = 5):
        """
        Initializes the MTAPIService.

        Args:
            timeout (int): The default timeout for API calls in seconds.
        """
        self.timeout = int(timeout)
        logging.debug(f"MTAPIService initialized with timeout: {self.timeout}s")

    # --- API Fetch Methods (Moved and adapted from MTController) ---

    def fetch_panorama_devices(self, panorama_obj) -> list | None:
        """
        Fetches connected device list from a Panorama via API.
        This method replaces _fetch_api_panorama_devices in MTController.
        """
        logging.info(f"Fetching devices from Panorama {panorama_obj.hostname} via API...")
        try:
            mtp = MTpanorama(panorama=panorama_obj, timeout=self.timeout)
            devices_api = mtp.show_devices()
            return devices_api if devices_api else []
        except MTpanoramaException as e:
            logging.error(f"API error fetching devices from Panorama {panorama_obj.hostname}: {e}")
            return None
        except Exception as e:
            logging.error(f"Unexpected error fetching devices from Panorama {panorama_obj.hostname}: {e}", exc_info=True)
            return None

    def fetch_system_info(self, ngfw_obj) -> dict | None:
        """
        Fetches system info from an NGFW via API.
        This method replaces _fetch_api_system_info in MTController.
        """
        logging.info(f"Fetching system info from NGFW {ngfw_obj.hostname} via API...")
        try:
            mtd = MTngfw(ngfw=ngfw_obj, timeout=self.timeout)
            system_info = mtd.show_system_info()
            return system_info if system_info else None
        except MTngfwException as e:
            logging.error(f"API error fetching system info from {ngfw_obj.hostname}: {e}")
            return None
        except Exception as e:
            logging.error(f"Unexpected error fetching system info from {ngfw_obj.hostname}: {e}", exc_info=True)
            return None

    def fetch_virtual_routes(self, ngfw_obj) -> list | None:
        """
        Fetches virtual router names from an NGFW via API.
        This method replaces _fetch_api_virtual_routes in MTController.
        """
        logging.info(f"Fetching virtual router names from NGFW {ngfw_obj.hostname} via API...")
        try:
            mtd = MTngfw(ngfw=ngfw_obj, timeout=self.timeout)
            vr_names_api = mtd.show_virtual_routes()
            return vr_names_api if vr_names_api else []
        except MTngfwException as e:
            logging.error(f"API error fetching virtual routes from {ngfw_obj.hostname}: {e}")
            return None
        except Exception as e:
            logging.error(f"Unexpected error fetching virtual routes from {ngfw_obj.hostname}: {e}", exc_info=True)
            return None

    def fetch_interfaces(self, ngfw_obj, virtual_router=None) -> list | None:
        """
        Fetches interface details from an NGFW via API.
        This method replaces _fetch_api_interfaces in MTController.
        """
        logging.info(f"Fetching interfaces from NGFW {ngfw_obj.hostname} via API...")
        try:
            mtd = MTngfw(ngfw=ngfw_obj, timeout=self.timeout)
            interfaces_api = mtd.show_interfaces(virtual_router=virtual_router)
            return interfaces_api if interfaces_api else []
        except MTngfwException as e:
            logging.error(f"API error fetching interfaces from {ngfw_obj.hostname}: {e}")
            return None
        except Exception as e:
            logging.error(f"Unexpected error fetching interfaces from {ngfw_obj.hostname}: {e}", exc_info=True)
            return None

    def fetch_routes(self, ngfw_obj, virtual_router=None, destination=None, flags=None) -> list | None:
        """
        Fetches route data from an NGFW via API.
        This method replaces _fetch_api_routes in MTController.
        """
        logging.info(f"Fetching routes from NGFW {ngfw_obj.hostname} via API...")
        try:
            mtd = MTngfw(ngfw=ngfw_obj, timeout=self.timeout)
            routes_api = mtd.show_routes(virtual_router=virtual_router, dst=destination, flags=flags)
            return routes_api if routes_api else []
        except MTngfwException as e:
            logging.error(f"API error fetching routes from {ngfw_obj.hostname}: {e}")
            return None
        except Exception as e:
            logging.error(f"Unexpected error fetching routes from {ngfw_obj.hostname}: {e}", exc_info=True)
            return None

    def fetch_fibs(self, ngfw_obj, virtual_router=None, destination=None, flags=None) -> list | None:
        """
        Fetches FIB data from an NGFW via API.
        This method replaces _fetch_api_fibs in MTController.
        """
        logging.info(f"Fetching FIBs from NGFW {ngfw_obj.hostname} via API...")
        try:
            mtd = MTngfw(ngfw=ngfw_obj, timeout=self.timeout)
            fibs_api = mtd.show_fibs(virtual_router=virtual_router, dst=destination, flags=flags)
            return fibs_api if fibs_api else []
        except MTngfwException as e:
            logging.error(f"API error fetching FIBs from {ngfw_obj.hostname}: {e}")
            return None
        except Exception as e:
            logging.error(f"Unexpected error fetching FIBs from {ngfw_obj.hostname}: {e}", exc_info=True)
            return None

    def fetch_bgp_peers(self, ngfw_obj, virtual_router=None) -> list | None:
        """
        Fetches BGP peer data from an NGFW via API.
        This method replaces _fetch_api_bgp_peers in MTController.
        """
        logging.info(f"Fetching BGP peers from NGFW {ngfw_obj.hostname} via API...")
        try:
            mtd = MTngfw(ngfw=ngfw_obj, timeout=self.timeout)
            bgp_peers_api = mtd.show_bgp_peers(virtual_router=virtual_router)
            return bgp_peers_api if bgp_peers_api else []
        except MTngfwException as e:
            logging.error(f"API error fetching BGP peers from {ngfw_obj.hostname}: {e}")
            return None
        except Exception as e:
            logging.error(f"Unexpected error fetching BGP peers from {ngfw_obj.hostname}: {e}", exc_info=True)
            return None

    def fetch_arps(self, ngfw_obj, interface=None) -> list | None:
        """
        Fetches ARP data from an NGFW via API.
        This method replaces _fetch_api_arps in MTController.
        """
        logging.info(f"Fetching ARPs from NGFW {ngfw_obj.hostname} via API...")
        try:
            mtd = MTngfw(ngfw=ngfw_obj, timeout=self.timeout)
            arps_api = mtd.show_arps(interface=interface)
            return arps_api if arps_api else []
        except MTngfwException as e:
            logging.error(f"API error fetching ARPs from {ngfw_obj.hostname}: {e}")
            return None
        except Exception as e:
            logging.error(f"Unexpected error fetching ARPs from {ngfw_obj.hostname}: {e}", exc_info=True)
            return None

    def fetch_neighbors(self, ngfw_obj) -> list | None:
        """
        Fetches LLDP neighbor data from an NGFW via API.
        This method replaces _fetch_api_neighbors in MTController.
        """
        logging.info(f"Fetching LLDP neighbors from NGFW {ngfw_obj.hostname} via API...")
        try:
            mtd = MTngfw(ngfw=ngfw_obj, timeout=self.timeout)
            neighbors_api = mtd.show_neighbors()
            return neighbors_api if neighbors_api else []
        except MTngfwException as e:
            logging.error(f"API error fetching LLDP neighbors from {ngfw_obj.hostname}: {e}")
            return None
        except Exception as e:
            logging.error(f"Unexpected error fetching LLDP neighbors from {ngfw_obj.hostname}: {e}", exc_info=True)
            return None

    def fetch_fib_lookup_test(self, ngfw_obj, ip_address, vr_name) -> dict | None:
        """
        Performs a live FIB lookup test on an NGFW via API by calling the MTngfw method.
        This method replaces _fetch_api_fib_lookup_test in MTController.
        """
        logging.info(f"Performing FIB lookup test on {ngfw_obj.hostname}/{vr_name} for IP {ip_address}...")
        try:
            mtd = MTngfw(ngfw=ngfw_obj, timeout=self.timeout)
            result_dict = mtd.test_fib_lookup(ip_address=str(ip_address), virtual_router=vr_name)
            return result_dict
        except MTngfwException as e:
            logging.error(f"API error during FIB lookup test on {ngfw_obj.hostname}/{vr_name}: {e}")
            return None
        except Exception as e:
            logging.error(f"Unexpected error preparing for FIB lookup test on {ngfw_obj.hostname}/{vr_name}: {e}", exc_info=True)
            return None

    def fetch_panorama_ha_state(self, panorama_obj) -> dict | None:
        """
        Fetches HA state from a Panorama via API.
        This method replaces _fetch_api_panorama_ha_state in MTController.
        """
        logging.info(f"Fetching HA state from Panorama {panorama_obj.hostname} via API...")
        try:
            mtp = MTpanorama(panorama=panorama_obj, timeout=self.timeout)
            ha_info = mtp.show_ha_state()
            return ha_info
        except MTpanoramaException as e:
            logging.error(f"API error fetching HA state from Panorama {panorama_obj.hostname}: {e}")
            return None
        except Exception as e:
            logging.error(f"Unexpected error fetching HA state from Panorama {panorama_obj.hostname}: {e}", exc_info=True)
            return None

    def fetch_ngfw_ha_status(self, ngfw_obj) -> dict | None:
        """
        Fetches HA status from an NGFW via API.
        This method replaces _fetch_api_ngfw_ha_status in MTController.
        """
        logging.info(f"Fetching HA status from NGFW {ngfw_obj.hostname} via API...")
        try:
            mtd = MTngfw(ngfw=ngfw_obj, timeout=self.timeout)
            ha_info = mtd.show_ha_status()
            return ha_info
        except MTngfwException as e:
            logging.error(f"API error fetching HA status from NGFW {ngfw_obj.hostname}: {e}")
            return None
        except Exception as e:
            logging.error(f"Unexpected error fetching HA status from NGFW {ngfw_obj.hostname}: {e}", exc_info=True)
            return None