# MIT License
#
# Copyright (c) 2023 josephberger
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

"""
Provides classes for interacting with Palo Alto Networks Panorama and NGFW
devices via the PAN-OS XML API. Handles API command execution, basic parsing,
and error handling specific to the Master Troubleshooter application context.
"""

import time
import json
import pan.xapi
import xmltodict
import logging

# --- Constants for API Commands ---
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



# --- Helper Functions ---
def _ensure_list(data):
    """
    Ensures the input data is a list. If None, returns empty list.
    If not a list, wraps it in a list.

    Args:
        data: The data to process.

    Returns:
        list: The data as a list, or an empty list if input was None.
    """
    if data is None:
        return []
    if isinstance(data, list):
        return data
    return [data]


# --- Exceptions ---
class MTpanoramaException(Exception):
    """Custom exception for Panorama specific errors."""
    pass


class MTngfwException(Exception):
    """Custom exception for NGFW specific errors."""
    pass


# --- Panorama Class ---
class MTpanorama:
    """
    Represents a Panorama management server and provides methods to interact
    with it via the PAN-OS XML API.

    Manages the connection details and target selection (primary/alternate IP)
    based on the Panorama's HA state provided via the database object.
    """
    def __init__(self, panorama, timeout=5) -> None:
        """
        Initializes the MTpanorama instance.

        Args:
            panorama: The Panorama database model object containing
                      connection details (IPs, API key) and HA state.
                      Expected to have attributes like: `hostname`, `ip_address`,
                      `api_key`, `alt_ip`, `active`.
            timeout (int, optional): The timeout value in seconds for API requests. Defaults to 5.

        Raises:
            ValueError: If the provided panorama object is missing essential attributes.
        """
        if not hasattr(panorama, 'ip_address') or not hasattr(panorama, 'api_key') or not hasattr(panorama, 'hostname'):
            raise ValueError("Panorama object must have 'hostname', 'ip_address', and 'api_key' attributes.")
        if not hasattr(panorama, 'alt_ip'): # Ensure these exist even if None
             setattr(panorama, 'alt_ip', None)
        if not hasattr(panorama, 'active'):
             setattr(panorama, 'active', True) # Default to active if not present

        self.panorama = panorama
        self.timeout = int(timeout)

    def _get_xapi_client(self, use_primary_ip=False) -> pan.xapi.PanXapi:
        """
        Creates and configures a PanXapi client instance based on the
        Panorama's state (active/passive, alt_ip).

        Args:
            use_primary_ip (bool): If True, forces use of the primary IP address,
                                   ignoring the active/passive state (used for HA checks).

        Returns:
            pan.xapi.PanXapi: A configured XAPI client instance.

        Raises:
            MTpanoramaException: If the API key is missing or client initialization fails.
        """
        if not self.panorama.api_key:
            # Check API key existence first
            raise MTpanoramaException(f"Panorama {self.panorama.hostname}: API key is missing.")

        # Determine target hostname based on HA status and alt_ip presence
        target_hostname = self.panorama.ip_address
        if not use_primary_ip and self.panorama.alt_ip and not self.panorama.active:
            target_hostname = self.panorama.alt_ip

        try:
            xapi = pan.xapi.PanXapi(
                api_key=self.panorama.api_key,
                hostname=target_hostname,
                timeout=self.timeout
            )
            # Ensure serial is None for Panorama direct calls
            xapi.serial = None
            return xapi
        except Exception as e:
            # Catch potential errors during PanXapi instantiation
            raise MTpanoramaException(f"Panorama {self.panorama.hostname}: Failed to initialize XAPI client for {target_hostname}: {e}") from e

    def _execute_api_op(self, command: str, action_description: str = "operation", use_primary_ip: bool = False) -> dict:
        """
        Executes a generic PAN-OS API operational command ('op').

        Handles client creation, command execution, basic XML parsing, and
        common error handling, raising specific exceptions on failure.

        Args:
            command (str): The XML command string to execute.
            action_description (str, optional): A brief description of the action
                                                for error messages. Defaults to "operation".
            use_primary_ip (bool): Passed to _get_xapi_client. If True, forces use
                                   of primary IP.

        Returns:
            dict: The parsed XML content found under the <response><result> tags,
                  or directly under <response> if <result> is not present.

        Raises:
            MTpanoramaException: If the API call fails (connection, auth, timeout)
                                 or if the response cannot be parsed correctly.
        """
        # Pass use_primary_ip flag to client creation
        xapi = self._get_xapi_client(use_primary_ip=use_primary_ip)
        device_context = f"Panorama {self.panorama.hostname} ({xapi.hostname})" # Show actual target IP

        try:
            xapi.op(cmd=command, cmd_xml=False) # cmd_xml=False as command is a string
            # Add root element for robust parsing, handle empty results
            response_xml = f"<response>{xapi.xml_result() or ''}</response>"
            parsed_response = xmltodict.parse(response_xml)

            response_content = parsed_response.get('response', {})
            # Check status attribute; proceed if 'success' or if status is missing (some commands don't have it)
            if response_content.get('@status') == 'error':
                err_msg = 'Unknown API error reported by device.'
                # Try extracting specific error messages
                msg_content = response_content.get('msg')
                if isinstance(msg_content, dict):
                    err_msg = msg_content.get('line', err_msg)
                elif isinstance(msg_content, list) and len(msg_content) > 0:
                     # Handle list of messages, e.g., multiple lines/errors
                     first_line = msg_content[0]
                     if isinstance(first_line, dict):
                         err_msg = first_line.get('line', err_msg)
                     else:
                         err_msg = str(first_line) # Fallback

                raise MTpanoramaException(f"{device_context}: API {action_description} failed: {err_msg}")

            # Return the content under 'result' if present, otherwise the whole response content
            return response_content.get('result', response_content)

        except pan.xapi.PanXapiError as e:
            raise MTpanoramaException(f"{device_context}: API connection/command error during {action_description}: {e}") from e
        except (xmltodict.expat.ExpatError, TypeError, KeyError, IndexError) as e:
            raise MTpanoramaException(f"{device_context}: Failed to parse API response for {action_description}: {e}. XML: '{response_xml[:200]}...'") from e
        except Exception as e: # Catch any other unexpected errors
            raise MTpanoramaException(f"{device_context}: Unexpected error during {action_description}: {e}") from e

    def show_ha_state(self) -> dict:
        """
        Retrieves the high availability state from the Panorama device.

        Note: This method specifically targets the *primary* IP address
              to check the HA state directly, regardless of the 'active'
              status stored in the database object, as HA state needs to be
              verified from a potentially active node.

        Returns:
            dict: A dictionary containing the parsed HA state information
                  (typically the content under the <result> tag).

        Raises:
            MTpanoramaException: If the API call fails, the response cannot be parsed,
                                 or the device is not configured for HA.
        """
        action_desc = "show HA state"
        original_hostname = self.panorama.ip_address # Log primary IP for context
        try:
            # Use the helper, forcing it to use the primary IP
            result_content = self._execute_api_op(
                _CMD_SHOW_HA_STATE,
                action_desc,
                use_primary_ip=True
            )

            # Check if HA is actually enabled based on the response structure
            if not result_content or 'enabled' not in result_content or result_content['enabled'] != 'yes':
                raise MTpanoramaException(f"Panorama {self.panorama.hostname} (checked via {original_hostname}): Not configured for High Availability or HA response format unexpected.")

            return result_content # Return the content under <result>

        except pan.xapi.PanXapiError as e:
             # Check for specific "High availability is disabled" message from pan-python
             if hasattr(e, 'msg') and "High availability is disabled" in str(e.msg):
                 raise MTpanoramaException(f"Panorama {self.panorama.hostname} (checked via {original_hostname}): High Availability is disabled.") from e
             # Re-raise other API errors with context
             raise MTpanoramaException(f"Panorama {self.panorama.hostname} (checked via {original_hostname}): API connection/command error during {action_desc}: {e}") from e
        except MTpanoramaException as e:
             # Re-raise exceptions from _execute_api_op or the format check
             # Add primary IP context if not already present
             if original_hostname not in str(e):
                 raise MTpanoramaException(f"{e} (checked via {original_hostname})") from e
             else:
                 raise e
        except Exception as e: # Catch any other unexpected errors
             raise MTpanoramaException(f"Panorama {self.panorama.hostname} (checked via {original_hostname}): Unexpected error during {action_desc}: {e}") from e


    def show_devices(self) -> list:
        """
        Retrieves the list of connected devices managed by this Panorama instance.

        Returns:
            list: A list of dictionaries, where each dictionary represents a device.
                  Returns an empty list if no devices are found or connected.

        Raises:
            MTpanoramaException: If the API call fails or the response is invalid.
        """
        action_desc = "show devices all"
        result_content = self._execute_api_op(_CMD_PAN_SHOW_DEVICES_ALL, action_desc)

        devices_data = result_content.get('devices')
        if devices_data is None:
            # If the key exists but value is None (e.g., <devices/>), return empty list.
            # If the key doesn't exist at all, it's a format error.
            if 'devices' in result_content:
                 return []
            else:
                 raise MTpanoramaException(f"Panorama {self.panorama.hostname}: Unexpected API response format for {action_desc}. Missing 'devices' key.")

        device_entries = devices_data.get('entry')
        # Ensure the result is always a list for consistent processing
        return _ensure_list(device_entries)

# --- NGFW Class ---
class MTngfw:
    """
    Represents a Next-Generation Firewall (NGFW) and provides methods to interact
    with the device's API for various functionalities including monitoring and configuration.
    """
    
    def __init__(self, ngfw, timeout=5) -> None:
        """
        Initializes the MTngfw instance.

        Args:
            ngfw: The NGFW database model object containing connection
                  details (IPs, API key, Panorama association, HA state,
                  advanced_routing_enabled). # <<< Updated comment
                  Expected attributes: `hostname`, `serial_number`, `ip_address`,
                  `api_key`, `panorama` (or None), `active`, `alt_serial`, `alt_ip`,
                  `advanced_routing_enabled`. # <<< Updated comment
            timeout (int, optional): The timeout value in seconds for API requests. Defaults to 5.

        Raises:
            ValueError: If the provided ngfw object is missing essential attributes or
                        if keys are missing for standalone/managed configuration.
        """
        # Basic validation of the ngfw object
        required_attrs = ['hostname', 'serial_number', 'ip_address', 'active', 'advanced_routing_enabled'] # <<< Added check
        for attr in required_attrs:
            if not hasattr(ngfw, attr):
                raise ValueError(f"NGFW object is missing required attribute: '{attr}'.")
            
        # Ensure optional HA attributes exist
        if not hasattr(ngfw, 'alt_serial'): setattr(ngfw, 'alt_serial', None)
        if not hasattr(ngfw, 'alt_ip'): setattr(ngfw, 'alt_ip', None)
        if not hasattr(ngfw, 'panorama'): setattr(ngfw, 'panorama', None) # Ensure panorama attr exists
        if not hasattr(ngfw, 'api_key'): setattr(ngfw, 'api_key', None) # Ensure api_key attr exists


        # Validate keys based on managed/standalone status
        if not ngfw.panorama and not ngfw.api_key:
            raise ValueError(f"Standalone NGFW {ngfw.hostname} must have an 'api_key'.")
        if ngfw.panorama:
            # Ensure panorama object itself exists before checking its attributes
            if ngfw.panorama is None:
                 raise ValueError(f"Managed NGFW {ngfw.hostname} has a panorama_id but the Panorama object was not loaded.")
            # Now check attributes on the loaded panorama object
            if not hasattr(ngfw.panorama, 'api_key') or not ngfw.panorama.api_key:
                raise ValueError(f"Managed NGFW {ngfw.hostname}'s Panorama object {getattr(ngfw.panorama, 'hostname', '')} must have 'api_key'.")
            if not hasattr(ngfw.panorama, 'ip_address') or not ngfw.panorama.ip_address:
                 raise ValueError(f"Managed NGFW {ngfw.hostname}'s Panorama object {getattr(ngfw.panorama, 'hostname', '')} must have 'ip_address'.")
            # Ensure optional Panorama HA attributes exist for IP selection
            if not hasattr(ngfw.panorama, 'alt_ip'): setattr(ngfw.panorama, 'alt_ip', None)
            if not hasattr(ngfw.panorama, 'active'): setattr(ngfw.panorama, 'active', True)


        self.ngfw = ngfw
        self.timeout = int(timeout)

    def _get_xapi_client(self) -> pan.xapi.PanXapi:
        """
        Creates and configures a PanXapi client instance based on the
        NGFW's state (managed/standalone, active/passive, alt_ip/alt_serial).

        Returns:
            pan.xapi.PanXapi: A configured XAPI client instance ready for API calls.

        Raises:
            MTngfwException: If required API keys or connection details are missing or
                             if client initialization fails.
        """
        target_hostname = None
        api_key = None
        target_serial = None # Only used for Panorama-managed NGFWs

        if self.ngfw.panorama:
            # Managed by Panorama
            api_key = self.ngfw.panorama.api_key
            # API key presence already validated in __init__

            # Target Panorama's active IP
            target_hostname = self.ngfw.panorama.ip_address
            if self.ngfw.panorama.alt_ip and not self.ngfw.panorama.active:
                target_hostname = self.ngfw.panorama.alt_ip

            # Target NGFW's serial based on its HA state
            target_serial = self.ngfw.serial_number
            if self.ngfw.alt_serial and not self.ngfw.active:
                target_serial = self.ngfw.alt_serial
                if not target_serial:
                     # Handle case where passive state expected but no alt_serial defined
                     raise MTngfwException(f"NGFW {self.ngfw.hostname} is passive but 'alt_serial' is not defined.")

        else:
            # Standalone NGFW
            api_key = self.ngfw.api_key
            # API key presence validated in __init__

            # Target NGFW's active IP
            target_hostname = self.ngfw.ip_address
            if self.ngfw.alt_ip and not self.ngfw.active:
                target_hostname = self.ngfw.alt_ip
                if not target_hostname:
                    # Handle case where passive state expected but no alt_ip defined
                    raise MTngfwException(f"NGFW {self.ngfw.hostname} is passive but 'alt_ip' is not defined.")
            # serial remains None for direct connection

        if not target_hostname:
             # Should be caught by earlier checks, but as a safeguard
             raise MTngfwException(f"NGFW {self.ngfw.hostname}: Could not determine target IP address.")

        try:
            xapi = pan.xapi.PanXapi(
                api_key=api_key,
                hostname=target_hostname,
                serial=target_serial, # Pass serial (if managed), None otherwise
                timeout=self.timeout
            )
            return xapi
        except Exception as e:
            # Catch potential errors during PanXapi instantiation
            raise MTngfwException(f"NGFW {self.ngfw.hostname}: Failed to initialize XAPI client for target {target_hostname} (Serial: {target_serial}): {e}") from e

    def _execute_api_op(self, command: str, action_description: str = "operation") -> dict:
        """
        Executes a generic PAN-OS API operational command ('op') for this NGFW.

        Handles client creation, command execution, basic XML parsing, and
        common error handling, raising specific exceptions on failure.

        Args:
            command (str): The XML command string to execute.
            action_description (str, optional): A brief description of the action
                                                for error messages. Defaults to "operation".

        Returns:
            dict: The parsed XML content found under the <response><result> tags,
                  or directly under <response> if <result> is not present.

        Raises:
            MTngfwException: If the API call fails (connection, auth, timeout)
                             or if the response cannot be parsed correctly.
        """
        xapi = self._get_xapi_client()
        # Include target serial for managed firewalls in context
        target_info = f"({xapi.hostname})" if not xapi.serial else f"({xapi.hostname} -> {xapi.serial})"
        device_context = f"NGFW {self.ngfw.hostname} {target_info}"

        try:
            xapi.op(cmd=command, cmd_xml=False) # cmd_xml=False as command is a string
            response_xml = f"<response>{xapi.xml_result() or ''}</response>" # Handle empty result
            parsed_response = xmltodict.parse(response_xml)

            response_content = parsed_response.get('response', {})
            # Check status attribute; proceed if 'success' or if status is missing
            if response_content.get('@status') == 'error':
                err_msg = 'Unknown API error reported by device.'
                # Try extracting specific error messages
                msg_content = response_content.get('msg')
                if isinstance(msg_content, dict):
                    err_msg = msg_content.get('line', err_msg)
                elif isinstance(msg_content, list) and len(msg_content) > 0:
                     first_line = msg_content[0]
                     if isinstance(first_line, dict):
                         err_msg = first_line.get('line', err_msg)
                     else:
                         err_msg = str(first_line) # Fallback

                raise MTngfwException(f"{device_context}: API {action_description} failed: {err_msg}")

            # Return the content under 'result' if present, otherwise the whole response content
            return response_content.get('result', response_content)

        except pan.xapi.PanXapiError as e:
            raise MTngfwException(f"{device_context}: API connection/command error during {action_description}: {e}") from e
        except (xmltodict.expat.ExpatError, TypeError, KeyError, IndexError) as e:
             # Include snippet of XML in parse errors for easier debugging
            raise MTngfwException(f"{device_context}: Failed to parse API response for {action_description}: {e}. XML: '{response_xml[:200]}...'") from e
        except Exception as e: # Catch any other unexpected errors
            raise MTngfwException(f"{device_context}: Unexpected error during {action_description}: {e}") from e

    # --- Internal Helper ---
    def _clean_api_dict(self, data: dict) -> dict:
        """
        Replaces None values with empty strings within a dictionary.

        Modifies the dictionary in-place. Intended for cleaning raw API data
        if needed, though final formatting often happens in the controller.

        Args:
            data: The dictionary process.

        Returns:
            The modified dictionary.
        """
        if not isinstance(data, dict):
             return data # Return unchanged if not a dict
        for key, value in data.items():
            if value is None:
                data[key] = ''
        return data

    # --- Public Methods ---
    def show_system_info(self) -> dict:
        """
        Retrieves system information from the NGFW.

        Returns:
            dict: A dictionary containing the system information (content under the 'system' key).

        Raises:
            MTngfwException: If the API call fails, the response is invalid,
                             or the 'system' key is missing.
        """
        action_desc = "show system info"
        result_content = self._execute_api_op(_CMD_SHOW_SYSTEM_INFO, action_desc)

        system_info = result_content.get('system')
        if system_info is None:
            raise MTngfwException(f"NGFW {self.ngfw.hostname}: Required 'system' key not found in API response for {action_desc}.")

        # No need to call _clean_api_dict here, controller formats final output
        return system_info

    # --- MODIFIED Method START ---
    def show_virtual_routes(self) -> list:
        """
        Retrieves virtual router names configured on the NGFW.
        Uses different API commands and parsing based on the NGFW's
        advanced_routing_enabled status.

        Returns:
            list: A list of virtual router name strings. Returns an empty list
                  if no virtual routers are found or an error occurs during parsing.

        Raises:
            MTngfwException: If the API call itself fails (handled by _execute_api_op).
                             Specific parsing errors are logged and return an empty list.
        """
        vr_names = []
        try:
            # Check the flag on the associated Ngfw DB object
            if self.ngfw.advanced_routing_enabled:
                # Use the Advanced Routing (ARE) command
                command = _CMD_NGFW_SHOW_ADV_ROUTING_LOGICAL_ROUTER
                action_desc = "show advanced-routing logical-router (for VR names)"
                result_content = self._execute_api_op(command, action_desc)

                # Parse the embedded JSON response
                json_str = result_content.get('json')
                if json_str:
                    try:
                        # Handle potential escaped quotes or other JSON variations if needed
                        # Basic parsing:
                        vr_data = json.loads(json_str)
                        if isinstance(vr_data, dict):
                            # The keys of the top-level dict are the VR names
                            vr_names = list(vr_data.keys())
                        else:
                            # Log unexpected JSON structure
                            logging.warining(f"Warning: Unexpected JSON structure in ARE response for {self.ngfw.hostname}. Expected dict, got {type(vr_data)}.") 
                    except json.JSONDecodeError as e:
                         # Log JSON parsing error
                         logging.warining(f"Warning: Failed to parse JSON response for ARE VR names from {self.ngfw.hostname}: {e}") 
                    except Exception as e:
                        # Catch other potential errors during JSON processing
                        logging.warining(f"Warning: Error processing ARE JSON response from {self.ngfw.hostname}: {e}") 
                else:
                     # Log missing 'json' key
                     logging.warining(f"Warning: Missing 'json' key in ARE response for {self.ngfw.hostname}.") 

            else:
                # Use the standard routing command
                command = _CMD_NGFW_SHOW_ROUTING_SUMMARY
                action_desc = "show routing summary (for VR names)"
                result_content = self._execute_api_op(command, action_desc)

                # Parse the standard XML response
                # VR names are in the '@name' attribute of each 'entry'
                entries = _ensure_list(result_content.get('entry'))
                vr_names = [entry.get('@name') for entry in entries if entry.get('@name')] # Ensure name exists

        # MTngfwException from _execute_api_op will propagate up
        except MTngfwException:
            raise # Re-raise API communication errors
        except Exception as e:
            # Catch any unexpected errors during the conditional logic or parsing setup
             logging.error(f"Error determining/parsing VR names for {self.ngfw.hostname}: {e}") 
             return [] # Return empty list on unexpected error

        return vr_names
    # --- MODIFIED Method END ---

    # ... (keep remaining methods: show_neighbors, show_bgp_peers, show_interfaces, etc.) ...
    def show_neighbors(self) -> list:
        """
        Retrieves LLDP neighbor information from the NGFW.

        Returns:
            list: A list of dictionaries, each representing an LLDP neighbor relationship
                  with keys: 'ngfw', 'local_interface', 'remote_interface_id',
                  'remote_interface_description', 'remote_hostname'.
                  Returns an empty list if no neighbors are found.

        Raises:
            MTngfwException: If the API call fails or the response is invalid.
        """
        action_desc = "show LLDP neighbors"
        result_content = self._execute_api_op(_CMD_NGFW_SHOW_LLDP_NEIGHBORS_ALL, action_desc)

        response_list = []
        interface_entries = _ensure_list(result_content.get('entry'))

        for interface_entry in interface_entries:
            local_if_name = interface_entry.get('@name', '')
            neighbors_data = interface_entry.get('neighbors')
            if not neighbors_data:
                continue # Skip interfaces with no LLDP neighbors section

            neighbor_entries = _ensure_list(neighbors_data.get('entry'))

            for neighbor_entry in neighbor_entries:
                # Use .get() with defaults for robustness
                response_list.append({
                    'ngfw': self.ngfw.hostname, # Add context
                    'local_interface': local_if_name,
                    'remote_interface_id': neighbor_entry.get('port-id', ''),
                    'remote_interface_description': neighbor_entry.get('port-description', ''),
                    'remote_hostname': neighbor_entry.get('system-name', ''),
                })

        return response_list

    def show_bgp_peers(self, virtual_router: str = None) -> list:
        """
        Retrieves BGP peer information from the NGFW, optionally filtered by VR/LR.
        Handles both standard and Advanced Routing Engine (ARE) outputs.

        Args:
            virtual_router (str, optional): The name of the virtual router (or logical router for ARE)
                                             to filter by. If None and ARE is enabled, retrieves peers
                                             for all LRs that have BGP peer groups. If None and ARE is
                                             not enabled, retrieves peers from all VRs.

        Returns:
            list: A list of dictionaries, each representing a BGP peer with keys:
                  'ngfw', 'virtual_router', 'peer_name', 'peer_group', 'peer_router_id',
                  'remote_as', 'status', 'status_duration', 'peer_address', 'local_address'.
                  Returns an empty list if no peers are found or errors occur.

        Raises:
            MTngfwException: If a critical API call fails (e.g., initial discovery) or 
                             the base response for standard BGP is invalid.
        """
        response_list = []
        ngfw_hostname = self.ngfw.hostname

        try:
            if self.ngfw.advanced_routing_enabled:
                # --- ARE BGP Peer Logic ---
                lrs_to_query = []

                if virtual_router:
                    # A specific Logical Router is provided
                    lrs_to_query.append(virtual_router)
                else:
                    # No specific LR provided: Discover all LRs that have BGP peer groups configured
                    action_desc_groups = f"show advanced-routing bgp peer-groups (to discover LRs) on {ngfw_hostname}"
                    cmd_get_groups = _CMD_NGFW_SHOW_ADV_ROUTING_BGP_PEER_GROUPS
                    
                    try:
                        groups_result_content = self._execute_api_op(cmd_get_groups, action_desc_groups)
                        groups_json_str = groups_result_content.get('json')
                        
                        if not groups_json_str:
                            # self.logger.warning(...)
                            logging.warining(f"Warning: Missing 'json' key in ARE BGP peer-groups response for {ngfw_hostname}.")
                            return [] 
                        
                        peer_groups_data = json.loads(groups_json_str)
                        if not isinstance(peer_groups_data, dict):
                            # self.logger.warning(...)
                            logging.warining(f"Warning: Unexpected JSON structure in ARE BGP peer-groups response for {ngfw_hostname}. Expected dict.")
                            return []

                        discovered_lrs_set = set()
                        for group_data in peer_groups_data.values(): # Iterate over group objects
                            if isinstance(group_data, dict):
                                lr_name_from_group = group_data.get('lr-name')
                                if lr_name_from_group:
                                    discovered_lrs_set.add(lr_name_from_group)
                        
                        lrs_to_query.extend(list(discovered_lrs_set))
                                
                        if not lrs_to_query:
                            # self.logger.info(...)
                            logging.info(f"Info: No logical routers with BGP peer groups found on {ngfw_hostname} via peer-group discovery.")
                            return []
                            
                    except json.JSONDecodeError as e:
                        # self.logger.error(...)
                        logging.error(f"Error: Failed to parse JSON response for ARE BGP peer-groups from {ngfw_hostname}: {e}")
                        return [] # Critical failure for this path if JSON is malformed
                    # MTngfwException from _execute_api_op for peer-groups will be caught by the outer handler and re-raised.

                # Iterate through LRs (either the single specified one or all discovered ones)
                for lr_name in lrs_to_query:
                    current_lr_action_desc = f"show advanced-routing bgp peer detail (LR: {lr_name}) on {ngfw_hostname}"
                    vr_part_for_detail = f"<logical-router>{lr_name}</logical-router>"
                    cmd_get_peer_detail = _CMD_NGFW_SHOW_ADV_ROUTING_BGP_PEER_DETAIL.format(vr_part=vr_part_for_detail)

                    try:
                        peer_detail_result_content = self._execute_api_op(cmd_get_peer_detail, current_lr_action_desc)
                        peer_detail_json_str = peer_detail_result_content.get('json')

                        if not peer_detail_json_str:
                            # self.logger.warning(...)
                            logging.warining(f"Warning: Missing 'json' key in ARE BGP peer detail response for {ngfw_hostname}/{lr_name}.")
                            continue # Skip this LR, try next

                        are_peers_data_for_lr = json.loads(peer_detail_json_str)
                        if not isinstance(are_peers_data_for_lr, dict):
                            # self.logger.warning(...)
                            logging.warining(f"Warning: Unexpected JSON structure in ARE BGP peer detail response for {ngfw_hostname}/{lr_name}. Expected dict.")
                            continue 

                        for peer_key, peer_details in are_peers_data_for_lr.items():
                            if not isinstance(peer_details, dict):
                                # self.logger.warning(...)
                                logging.warining(f"Warning: Skipping invalid peer data entry (key: {peer_key}) for {ngfw_hostname}/{lr_name}.")
                                continue

                            detail_info = peer_details.get('detail', {})
                            if not isinstance(detail_info, dict): detail_info = {} # Ensure it's a dict for safe .get()


                            processed_peer = {
                                'ngfw': ngfw_hostname,
                                'virtual_router': lr_name, # Use the LR name from the current iteration
                                'peer_name': peer_details.get('peer-name', peer_key),
                                'peer_group': peer_details.get('peer-group-name', detail_info.get('peerGroup', '')), # Fallback to detail_info
                                'peer_router_id': detail_info.get('remoteRouterId', ''),
                                'remote_as': str(peer_details.get('remote-as', detail_info.get('remoteAs', ''))),
                                'status': peer_details.get('state', ''),
                                'status_duration': detail_info.get('bgpTimerUpString', ''), 
                                'peer_address': peer_details.get('peer-ip', ''),
                                'local_address': peer_details.get('local-ip', '')
                            }
                            response_list.append(processed_peer)
                    
                    except json.JSONDecodeError as e:
                        # self.logger.error(...)
                        logging.error(f"Error: Failed to parse JSON for ARE BGP peers from {ngfw_hostname}/{lr_name}: {e}")
                        # Continue to next LR if one fails
                    except MTngfwException as e: 
                        # self.logger.error(...)
                        logging.error(f"Error: API error fetching BGP peer details for {ngfw_hostname}/{lr_name}: {e}. Skipping this LR.")
                        # Continue to the next LR
                    except Exception as e: # Catch other unexpected errors for *this* LR
                        # self.logger.error(...)
                        logging.error(f"Error: Unexpected error processing ARE BGP peers for {ngfw_hostname}/{lr_name}: {e}")
                        # Continue to the next LR
            
            else:
                # --- Standard BGP Peer Logic (remains largely unchanged) ---
                action_desc = f"show BGP peers (VR: {virtual_router or 'all'}) on {ngfw_hostname}"
                vr_part_std = f"<virtual-router>{virtual_router}</virtual-router>" if virtual_router else ""
                command_std = _CMD_NGFW_SHOW_BGP_PEER.format(vr_part=vr_part_std)

                result_content_std = self._execute_api_op(command_std, action_desc)
                
                # Use self._ensure_list to handle single or multiple entries
                peer_entries = _ensure_list(result_content_std.get('entry'))

                for peer_entry in peer_entries:
                     if not isinstance(peer_entry, dict):
                         # self.logger.warning(...)
                         logging.warining(f"Warning: Skipping invalid peer entry in standard BGP response for {ngfw_hostname}/{virtual_router or 'all'}.")
                         continue
                     
                     # Extract peer_address and local_address, removing port if present
                     peer_addr_full = str(peer_entry.get('peer-address', ''))
                     local_addr_full = str(peer_entry.get('local-address', ''))

                     processed_peer = {
                        'ngfw': ngfw_hostname,
                        'virtual_router': peer_entry.get('@vr', virtual_router or 'default'), # Provide fallback if @vr missing
                        'peer_name': peer_entry.get('@peer', ''),
                        'peer_group': peer_entry.get('peer-group', ''),
                        'peer_router_id': peer_entry.get('peer-router-id', ''),
                        'remote_as': str(peer_entry.get('remote-as', '')), # Ensure string
                        'status': peer_entry.get('status', ''),
                        'status_duration': peer_entry.get('status-duration', ''),
                        'peer_address': peer_addr_full.split(':')[0] if ':' in peer_addr_full else peer_addr_full,
                        'local_address': local_addr_full.split(':')[0] if ':' in local_addr_full else local_addr_full,
                     }
                     response_list.append(processed_peer)

        except MTngfwException:
            # self.logger.exception("Critical API error during BGP peer retrieval.") # Example logging
            raise # Re-raise API errors from critical sections or standard BGP path
        except Exception as e:
            logging.error(f"Error: Top-level error processing BGP peers for {ngfw_hostname}: {e}")
            return [] # Return empty list on unexpected error not caught by more specific handlers

        return response_list
    
    def show_interfaces(self, virtual_router: str = None) -> list:
        """
        Retrieves interface information from the NGFW, optionally filtered by VR.
        Includes both IPv4 and IPv6 addresses. Handles 'vr:' and 'lr:' prefixes in fwd field.

        Args:
            virtual_router (str, optional): The name of the virtual router to filter by.
                                             If None, retrieves interfaces from all VRs.

        Returns:
            list: A list of dictionaries, each representing an interface with keys:
                  'ngfw', 'name', 'tag', 'vsys', 'ip', 'zone', 'virtual_router', 'ipv6_addresses'.
                  'ipv6_addresses' is a list of strings.
                  Returns an empty list if no interfaces are found or match the filter.

        Raises:
            MTngfwException: If the API call fails or the response is invalid.
        """
        action_desc = "show interfaces all"
        result_content = self._execute_api_op(_CMD_NGFW_SHOW_INTERFACES_ALL, action_desc)

        response_list = []
        ifnet_data = result_content.get('ifnet')
        if ifnet_data is None:
             if 'ifnet' in result_content: return []
             raise MTngfwException(f"NGFW {self.ngfw.hostname}: Unexpected API response format for {action_desc}. Missing 'ifnet' key.")

        interface_entries = _ensure_list(ifnet_data.get('entry'))

        for if_entry in interface_entries:
            # Skip entries without forwarding info ('fwd')
            fwd_info = if_entry.get('fwd')
            if not fwd_info:
                continue

            # --- MODIFIED VR/LR NAME EXTRACTION ---
            interface_vr = None # Initialize
            if isinstance(fwd_info, str): # Check if it's a string
                if fwd_info.startswith('vr:'):
                    interface_vr = fwd_info.replace('vr:', '', 1) # Replace only first 'vr:'
                elif fwd_info.startswith('lr:'):
                    # Treat 'lr:' the same as 'vr:' for internal consistency
                    interface_vr = fwd_info.replace('lr:', '', 1) # Replace only first 'lr:'

            # If no valid vr/lr name extracted (or fwd_info wasn't string), skip entry
            if interface_vr is None:
                 continue
            # --- END MODIFIED EXTRACTION ---

            # Apply VR filter if provided (filters based on the extracted name)
            if virtual_router and interface_vr != virtual_router:
                continue

            zone_info = if_entry.get('zone') # Get zone, may be None

            # IPv6 address parsing logic (remains the same)
            ipv6_address_list = []
            addr6_data = if_entry.get('addr6')
            # ... (keep existing ipv6 parsing logic here) ...
            if addr6_data:
                member_value = addr6_data.get('member') if isinstance(addr6_data, dict) else None
                member_list = _ensure_list(member_value)
                for member in member_list:
                    if isinstance(member, str):
                        ipv6_addr = member.strip()
                        if ipv6_addr: ipv6_address_list.append(ipv6_addr)
                    elif isinstance(member, dict) and '#text' in member:
                         ipv6_addr = member['#text'].strip()
                         if ipv6_addr: ipv6_address_list.append(ipv6_addr)


            # Create response dictionary (remains the same)
            response_list.append({
                'ngfw': self.ngfw.hostname,
                'name': if_entry.get('name', ''),
                'tag': if_entry.get('tag', ''),
                'vsys': if_entry.get('vsys', ''),
                'ip': if_entry.get('ip', ''),
                'zone': zone_info if zone_info is not None else '',
                'virtual_router': interface_vr, # Use the extracted name
                'ipv6_addresses': ipv6_address_list
            })

        return response_list
    
    def show_routes(self, virtual_router: str = None, dst: str = None, flags: str = None) -> list:
        """
        Retrieves routing table entries from the NGFW, with optional filters.
        Handles both standard and Advanced Routing Engine (ARE) outputs.

        Args:
            virtual_router (str, optional): Filter by virtual router name.
            dst (str, optional): Filter routes matching this destination prefix.
            flags (str, optional): Filter routes containing these flags (comma-separated).
                                   Note: Flag filtering on ARE output is limited/approximated.

        Returns:
            list: A list of dictionaries, each representing a route entry with standard keys
                  (e.g., 'ngfw', 'virtual_router', 'destination', 'nexthop', 'flags', etc.).
                  Returns an empty list if no routes match or errors occur during parsing.

        Raises:
            MTngfwException: If the API call fails or the base response is invalid.
                             Parsing errors for specific formats return an empty list with warnings.
        """
        response_list = []
        ngfw_hostname = self.ngfw.hostname # For adding context later

        try:
            if self.ngfw.advanced_routing_enabled:
                # --- ARE Route Logic ---
                action_desc = f"show advanced-routing route (LR: {virtual_router or 'all'})"
                # --- Construct vr_part for ARE ---
                vr_part = f"<logical-router>{virtual_router}</logical-router>" if virtual_router else ""
                command = _CMD_NGFW_SHOW_ADV_ROUTING_ROUTE.format(vr_part=vr_part)
                # --- End command construction ---

                result_content = self._execute_api_op(command, action_desc)
                json_str = result_content.get('json')
                if not json_str:
                    logging.warning(f"Warning: Missing 'json' key in ARE route response for {ngfw_hostname}.")
                    return []

                try:
                    are_routes_data = json.loads(json_str)
                    if not isinstance(are_routes_data, dict):
                        logging.warning(f"Warning: Unexpected JSON structure in ARE route response for {ngfw_hostname}. Expected dict.")
                        return []

                    # Process the ARE JSON structure: {"vr_name": {"prefix": [route_details_list]}}
                    for vr_name, prefixes in are_routes_data.items():
                        # Apply VR filter post-fetch
                        if virtual_router and vr_name != virtual_router:
                            continue

                        if isinstance(prefixes, dict):
                            for prefix, route_list in prefixes.items():
                                if isinstance(route_list, list):
                                    for route_data in route_list:
                                        # Apply Destination filter
                                        if dst and not prefix.startswith(dst):
                                             continue

                                        # Extract and map fields
                                        nexthop_ip = ''
                                        interface_name = ''
                                        is_active = route_data.get('selected', False) # Use 'selected' for active status

                                        if isinstance(route_data.get('nexthops'), list) and route_data['nexthops']:
                                            # Simplification: take first active nexthop, might need refinement for ECMP
                                            for nh in route_data['nexthops']:
                                                if nh.get('active', False):
                                                    nexthop_ip = nh.get('ip', '')
                                                    interface_name = nh.get('interfaceName', '')
                                                    break # Take the first active one found
                                            # Fallback if no active found (e.g., directly connected)
                                            if not nexthop_ip and route_data['nexthops']:
                                                 nexthop_ip = route_data['nexthops'][0].get('ip', '') # Get first IP if any
                                                 interface_name = route_data['nexthops'][0].get('interfaceName', '')

                                        # Approximate flags: 'A' if active, plus protocol name
                                        protocol = route_data.get('protocol', 'Unknown')
                                        flag_str = f"A {protocol}" if is_active else protocol

                                        # Apply Flags filter (approximate match on protocol or active)
                                        if flags:
                                            flag_list_req = [f.strip().upper() for f in flags.split(',')]
                                            # Simple check: if any requested flag isn't in our generated string, skip
                                            if not all(req_f in flag_str.upper() for req_f in flag_list_req):
                                                 continue

                                        processed_route = {
                                            'ngfw': ngfw_hostname,
                                            'virtual_router': vr_name,
                                            'destination': prefix,
                                            'nexthop': nexthop_ip,
                                            'metric': str(route_data.get('metric', '')),
                                            'flags': flag_str,
                                            'age': route_data.get('uptime', ''), # Store uptime string as age
                                            'interface': interface_name,
                                            'route_table': str(route_data.get('table', '')),
                                            'zone': '' # Needs enrichment later
                                        }
                                        response_list.append(processed_route)
                except json.JSONDecodeError as e:
                    logging.warning(f"Warning: Failed to parse JSON response for ARE routes from {ngfw_hostname}: {e}")
                    return []
                except Exception as e:
                    logging.warning(f"Warning: Error processing ARE routes JSON response from {ngfw_hostname}: {e}")
                    return []

            else:
                # --- Standard Route Logic ---
                action_desc = f"show routes (VR: {virtual_router or 'all'}, Dst: {dst or 'any'}, Flags: {flags or 'any'})"
                vr_part = f"<virtual-router>{virtual_router}</virtual-router>" if virtual_router else ""
                command = _CMD_NGFW_SHOW_ROUTING_ROUTE.format(vr_part=vr_part)
                result_content = self._execute_api_op(command, action_desc)

                route_entries = _ensure_list(result_content.get('entry'))
                flag_list_req = [f.strip().upper() for f in flags.split(',')] if flags else []

                for route_data in route_entries:
                    # Apply post-API filters (standard)
                    if dst and not str(route_data.get('destination', '')).startswith(dst): continue
                    route_flags_std = route_data.get('flags', '')
                    if flag_list_req and not all(flag in route_flags_std for flag in flag_list_req): continue

                    processed_route = {
                        'ngfw': ngfw_hostname,
                        'virtual_router': route_data.get('virtual-router', ''),
                        'destination': route_data.get('destination', ''),
                        'nexthop': route_data.get('nexthop', ''),
                        'metric': route_data.get('metric', ''),
                        'flags': route_flags_std,
                        'age': route_data.get('age', ''),
                        'interface': route_data.get('interface', ''),
                        'route_table': route_data.get('route-table', ''),
                        'zone': route_data.get('zone', '') # Include if present
                    }
                    response_list.append(processed_route)

        except MTngfwException:
            raise # Re-raise API errors
        except Exception as e:
            logging.error(f"Error processing routes for {ngfw_hostname}: {e}")
            return [] # Return empty list on unexpected error

        return response_list

    def show_fibs(self, virtual_router: str = None, dst: str = None, flags: str = None) -> list:
        """
        Retrieves FIB entries from the NGFW, with optional filters.
        Handles both standard and Advanced Routing Engine (ARE) outputs.
        Includes improved checks for missing XML elements during parsing.

        Args:
            virtual_router (str, optional): Filter by virtual router name.
            dst (str, optional): Filter FIB entries matching this destination prefix.
            flags (str, optional): Filter FIB entries containing these flags (comma-separated).

        Returns:
            list: A list of dictionaries, each representing a FIB entry with standard keys
                  (e.g., 'ngfw', 'virtual_router', 'destination', 'nexthop', 'interface', 'flags', etc.).
                  Returns an empty list if no FIB entries match or errors occur.

        Raises:
            MTngfwException: If the API call fails or the base response is invalid.
                             Parsing errors for specific formats return an empty list with warnings.
        """
        response_list = []
        ngfw_hostname = self.ngfw.hostname

        try:
            if self.ngfw.advanced_routing_enabled:
                # --- ARE FIB Logic ---
                action_desc = f"show advanced-routing fib (LR: {virtual_router or 'all'})"
                # --- Construct vr_part for ARE ---
                vr_part = f"<logical-router>{virtual_router}</logical-router>" if virtual_router else ""
                command = _CMD_NGFW_SHOW_ADV_ROUTING_FIB.format(vr_part=vr_part)
                # --- End command construction ---
                result_content = self._execute_api_op(command, action_desc)

                vr_fib_entries_outer = [] # Default to empty list
                # --- Robustness Check for 'fibs' key ---
                # Get the value associated with 'fibs' safely
                are_fibs_data = result_content.get('fibs')

                # Check if are_fibs_data exists (is not None) AND is a dictionary before getting 'entry'
                if isinstance(are_fibs_data, dict):
                    # Now it's safe to get 'entry', defaulting to None if 'entry' key is missing
                    entry_list_or_item = are_fibs_data.get('entry')
                    # Ensure vr_fib_entries_outer is always a list for iteration
                    vr_fib_entries_outer = _ensure_list(entry_list_or_item)
                elif are_fibs_data is not None:
                    # Log if 'fibs' key exists but is not a dictionary (unexpected)
                    logging.warining(f"Warning: Expected 'fibs' key to contain a dictionary, but got {type(are_fibs_data)} in ARE FIB response for {ngfw_hostname}.")
                else:
                    # Handle case where <fibs> tag is missing or result_content.get('fibs') returned None
                    logging.warining(f"Warning: No '<fibs>' data found or 'fibs' key missing in ARE FIB response for {ngfw_hostname}.")
                # --- End Robustness Check ---

                # Prepare flag filter list once
                flag_list_req = [f.strip().upper() for f in flags.split(',')] if flags else []

                # Iterate through the outer list (each item represents a VR's FIB table)
                for vr_fib_entry in vr_fib_entries_outer:
                    # --- Check if the item is a dictionary ---
                    if not isinstance(vr_fib_entry, dict):
                        logging.warining(f"Warning: Skipping non-dictionary item found in ARE FIB outer entries for {ngfw_hostname}.")
                        continue
                    # --- End Check ---

                    fib_vr_name = vr_fib_entry.get('vr')
                    # Apply VR filter post-fetch
                    if virtual_router and fib_vr_name != virtual_router:
                        continue

                    individual_fib_entries = [] # Default to empty list
                    # --- Robustness Check for 'entries' key ---
                    entries_data = vr_fib_entry.get('entries')
                    # Check if entries_data exists and is a dictionary before getting its 'entry'
                    if isinstance(entries_data, dict):
                        entry_list_or_item_inner = entries_data.get('entry')
                        # Ensure individual_fib_entries is always a list
                        individual_fib_entries = _ensure_list(entry_list_or_item_inner)
                    elif entries_data is not None:
                         # Log if 'entries' key exists but is not a dictionary
                         logging.warining(f"Warning: Expected 'entries' key to contain a dictionary, but got {type(entries_data)} in ARE FIB entry for VR '{fib_vr_name}' on {ngfw_hostname}.")
                    # else: entries key is missing or None, individual_fib_entries remains [] which is fine
                    # --- End Robustness Check ---


                    # Iterate through the actual FIB entries for this VR
                    for fib_data in individual_fib_entries:
                        # --- Check if the item is a dictionary ---
                        if not isinstance(fib_data, dict):
                            logging.warining(f"Warning: Skipping non-dictionary item found in ARE FIB inner entries for VR '{fib_vr_name}' on {ngfw_hostname}.")
                            continue
                        # --- End Check ---

                        # Apply Destination filter
                        destination = fib_data.get('dst', '')
                        if dst and not destination.startswith(dst):
                            continue

                        # Apply Flags filter
                        fib_flags_are = fib_data.get('flags', '').upper() # Use upper for case-insensitive compare
                        if flag_list_req and not all(flag in fib_flags_are for flag in flag_list_req):
                             continue

                        # Map ARE FIB fields to expected keys
                        processed_fib = {
                            'ngfw': ngfw_hostname,
                            'virtual_router': fib_vr_name,
                            'destination': destination,
                            'fib_id': fib_data.get('id', ''), # ARE FIB entry ID
                            'interface': fib_data.get('interface', ''),
                            'nexthop': fib_data.get('nexthop', ''),
                            'flags': fib_flags_are.lower(), # Store flags as lower case
                            'nh_type': str(fib_data.get('nh_type', '')), # Store ARE numeric type as string
                            'mtu': fib_data.get('mtu', ''),
                            'zone': '' # Needs enrichment later by controller
                        }
                        response_list.append(processed_fib)

            else:
                # --- Standard FIB Logic ---
                action_desc = f"show FIB (VR: {virtual_router or 'all'}, Dst: {dst or 'any'}, Flags: {flags or 'any'})"
                vr_part = f"<virtual-router>{virtual_router}</virtual-router>" if virtual_router else ""
                command = _CMD_NGFW_SHOW_ROUTING_FIB.format(vr_part=vr_part)
                # Execute API call (can raise MTngfwException)
                result_content = self._execute_api_op(command, action_desc)

                vr_fib_entries_std = [] # Default to empty
                # --- Robustness Check for 'fibs' key ---
                std_fibs_data = result_content.get('fibs')
                if isinstance(std_fibs_data, dict):
                    entry_list_or_item_std = std_fibs_data.get('entry')
                    vr_fib_entries_std = _ensure_list(entry_list_or_item_std)
                elif std_fibs_data is not None:
                     logging.warining(f"Warning: Expected 'fibs' key to contain a dictionary, but got {type(std_fibs_data)} in Standard FIB response for {ngfw_hostname}.")
                else:
                    logging.warining(f"Warning: No '<fibs>' data found or 'fibs' key missing in Standard FIB response for {ngfw_hostname}.")
                # --- End Robustness Check ---

                flag_list_req = [f.strip().upper() for f in flags.split(',')] if flags else []

                for vr_fib_entry in vr_fib_entries_std:
                    # --- Check item type ---
                    if not isinstance(vr_fib_entry, dict):
                        logging.warining(f"Warning: Skipping non-dictionary item found in Standard FIB outer entries for {ngfw_hostname}.")
                        continue
                    # --- End Check ---

                    fib_vr_name = vr_fib_entry.get('vr')
                    if not fib_vr_name: continue # Skip entries missing VR name

                    individual_fib_entries = [] # Default to empty
                    # --- Robustness Check for 'entries' key ---
                    entries_data_std = vr_fib_entry.get('entries')
                    if isinstance(entries_data_std, dict):
                         entry_list_or_item_inner_std = entries_data_std.get('entry')
                         individual_fib_entries = _ensure_list(entry_list_or_item_inner_std)
                    elif entries_data_std is not None:
                         logging.warining(f"Warning: Expected 'entries' key to contain a dictionary, but got {type(entries_data_std)} in Standard FIB entry for VR '{fib_vr_name}' on {ngfw_hostname}.")
                    # --- End Robustness Check ---


                    for fib_data in individual_fib_entries:
                         # --- Check item type ---
                        if not isinstance(fib_data, dict):
                            logging.warining(f"Warning: Skipping non-dictionary item found in Standard FIB inner entries for VR '{fib_vr_name}' on {ngfw_hostname}.")
                            continue
                        # --- End Check ---

                        # Apply post-API filters (standard)
                        destination = fib_data.get('dst', '')
                        if dst and not destination.startswith(dst): continue
                        fib_flags_std = fib_data.get('flags', '')
                        if flag_list_req and not all(flag in fib_flags_std.upper() for flag in flag_list_req): continue

                        processed_fib = {
                            'ngfw': ngfw_hostname,
                            'virtual_router': fib_vr_name,
                            'destination': destination,
                            'fib_id': fib_data.get('id', ''),
                            'interface': fib_data.get('interface', ''),
                            'nexthop': fib_data.get('nexthop', ''),
                            'flags': fib_flags_std,
                            'nh_type': fib_data.get('nh-type', ''), # Standard 'nh-type' expected here
                            'mtu': fib_data.get('mtu', ''),
                            'zone': fib_data.get('zone', '') # Include zone if present
                        }
                        response_list.append(processed_fib)

        # Catch API errors from _execute_api_op
        except MTngfwException as api_e:
            # Re-raise API specific errors to be handled by the caller (controller)
            raise api_e
        # Catch other unexpected errors during parsing/processing
        except Exception as e:
            logging.error(f"Error processing FIBs for {ngfw_hostname}: {e}")
            # It's often helpful to log the full traceback for unexpected errors
            import traceback
            traceback.print_exc()
            # Return an empty list to signify failure without crashing
            return []

        return response_list

    def show_arps(self, interface: str = None) -> list:
        """
        Retrieves ARP table entries from the NGFW, optionally filtered by interface.

        Args:
            interface (str, optional): Filter by interface name. If None, retrieves for 'all'.

        Returns:
            list: A list of dictionaries, each representing an ARP entry with standard keys
                  (e.g., 'ngfw', 'interface', 'ip', 'mac', 'status', 'ttl', etc.).
                  Raw values from API preserved (e.g., ttl as string).
                  Returns an empty list if no ARP entries match.

        Raises:
            MTngfwException: If the API call fails or the response is invalid.
        """
        target_interface = interface if interface else 'all'
        action_desc = f"show ARP entries (Interface: {target_interface})"
        command = _CMD_NGFW_SHOW_ARP_ENTRY.format(if_name=target_interface)

        try:
            result_content = self._execute_api_op(command, action_desc)
        except MTngfwException as e:
             # If a specific interface was queried and the error indicates "not found",
             # treat it as "no results found" rather than a critical API failure.
             if target_interface != 'all' and (f"'{target_interface}' not found" in str(e) or "Invalid interface" in str(e)):
                  return [] # Return empty list, signaling no entries for this interface
             else:
                  raise e # Re-raise other, more general API errors

        response_list = []
        # ARP entries are under 'entries', then 'entry'
        arp_entries = _ensure_list(result_content.get('entries', {}).get('entry'))

        for arp_data in arp_entries:
             # Create processed dict using .get with defaults
             processed_arp = {
                'ngfw': self.ngfw.hostname,
                'interface': arp_data.get('interface', ''),
                'ip': arp_data.get('ip', ''),
                'mac': arp_data.get('mac', ''),
                'port': arp_data.get('port', ''),
                'status': arp_data.get('status', ''),
                'ttl': arp_data.get('ttl', ''), # Keep as string
                # Zone info typically added later by controller
                'zone': arp_data.get('zone', '') # Include zone if present
             }
             response_list.append(processed_arp)

        return response_list

    def show_ha_status(self) -> dict:
        """
        Retrieves the high availability status/info from the NGFW.

        Returns:
            dict: A dictionary containing the HA status information
                  (typically content under 'group' -> 'local-info').

        Raises:
            MTngfwException: If the API call fails, the response is invalid,
                             or the device is not configured for HA or state cannot be determined.
        """
        action_desc = "show HA status"
        result_content = self._execute_api_op(_CMD_SHOW_HA_STATE, action_desc)

        # HA info often nested under 'group' -> 'local-info'
        # Handle cases where 'group' might be missing or 'local-info' is missing
        group_info = result_content.get('group', {})
        if not isinstance(group_info, dict): # Ensure group_info is a dict for .get()
            group_info = {}
        local_info = group_info.get('local-info')

        # Check various indicators of HA being disabled or state missing
        if result_content.get('enabled') == 'no':
             raise MTngfwException(f"NGFW {self.ngfw.hostname}: High Availability is disabled.")
        if local_info is None:
             # Try checking the top level for state if group structure isn't present (might occur in some versions/states)
             if 'state' in result_content:
                 # Found state at top level, maybe return result_content directly?
                 # For consistency, let's try to mimic the structure expected by controller
                 return {'state': result_content.get('state')}
             raise MTngfwException(f"NGFW {self.ngfw.hostname}: Could not find HA 'local-info' in API response for {action_desc}.")
        if 'state' not in local_info:
             raise MTngfwException(f"NGFW {self.ngfw.hostname}: Could not determine HA 'state' from API response for {action_desc}.")

        return local_info # Return the relevant part containing the state

    def test_fib_lookup(self, ip_address: str, virtual_router: str) -> dict:
        """
        Performs a live FIB lookup test on the NGFW via API.

        Args:
            ip_address (str): The IP address string to test.
            virtual_router (str): The name of the virtual router for the test.

        Returns:
            dict: The parsed API result dictionary (content under <result> or <response>).
                An empty dict or a dict containing error info might be returned
                by _execute_api_op on specific API errors handled internally.

        Raises:
            MTngfwException: If the API call fails critically (connection, auth, timeout)
                            or if the response parsing fails badly.
        """
        action_desc = f"test FIB lookup for {ip_address} in VR {virtual_router}"
        # Construct the specific XML command for the test
        command = (
            f"<test><routing><fib-lookup>"
            f"<ip>{ip_address}</ip>"
            f"<virtual-router>{virtual_router}</virtual-router>"
            f"</fib-lookup></routing></test>"
        )
        # Use the existing helper to execute and parse
        # _execute_api_op handles xapi call, xml_result, parsing, and basic error checks
        result_content = self._execute_api_op(command, action_desc)

        # _execute_api_op already returns the relevant part of the parsed dict
        return result_content