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

import pan.xapi
import xmltodict

from models import Ngfw, Panorama

class MTpanoramaException(Exception):
    pass

class MTpanorama:
    def __init__(self, panorama, timeout=5) -> None:
        """
        A class representing a Panorama device in the MT.

        Args:
            panorama (models.db.Panorama): Panorama database model object.
            timeout (int, optional): The timeout value for API requests. Defaults to 5 seconds.
        """
        self.panorama = panorama

        self.timeout = timeout

        self.xapi = None
        
        self.__set_xapi()

    def __set_xapi(self) -> None:
        """
        This method sets the xapi object based on the panorama
        """

        # if the panorama has an alt-ip
        if self.panorama.alt_ip:
            # if the panorama is active, build the appropriate xapi object
            if self.panorama.active:
                self.xapi = pan.xapi.PanXapi(api_key=self.panorama.api_key, hostname=self.panorama.ip_address)
            else:
                self.xapi = pan.xapi.PanXapi(api_key=self.panorama.api_key, hostname=self.panorama.alt_ip)
        
        # if the panorama has no alt-ip
        else:
            self.xapi = pan.xapi.PanXapi(api_key=self.panorama.api_key, hostname=self.panorama.ip_address)

        # ensure serial is none
        self.xapi.serial = None

        self.xapi.timeout = self.timeout
    
    def show_ha_state(self) -> dict:
        """
        Sends a request to the device to retrieve its high availability state.

        Raises:
            MTpanoramaException: If there is an error retrieving the high availability state.

        Returns:
        - A dictionary containing the high availability state of the device.
        """  
        self.xapi = pan.xapi.PanXapi(api_key=self.panorama.api_key, hostname=self.panorama.ip_address)

        try:
            self.xapi.op("<show><high-availability><state></state></high-availability></show>")
            results = xmltodict.parse("<root>" + self.xapi.xml_result() + "</root>")['root']
        except pan.xapi.PanXapiError as e:
            raise MTpanoramaException(f"Panorama {self.panorama.hostname} {e}")
        except TypeError:
            raise MTpanoramaException(f"Panorama {self.panorama.hostname} is not in ha")
        except KeyError:
            raise MTpanoramaException(f"Panorama {self.panorama.hostname} is not in ha")
        
        return results
    
    def show_devices(self) -> dict:
        """
        Returns a dictionary containing information about all devices on the Panorama instance.

        Raises:
            MTpanoramaException: If there is an error retrieving the device information.

        Returns:
            dict: A dictionary containing information about all devices on the Panorama instance.
        """
        # show devices all on the xapi object
        try:
            self.xapi.op("<show><devices><all></all></devices></show>")
            results = xmltodict.parse("<root>" + self.xapi.xml_result() + "</root>")['root']['devices']
        except pan.xapi.PanXapiError as e:
            raise MTpanoramaException(f"Panorama {self.panorama.hostname} {e}")
        except TypeError:
            raise MTpanoramaException(f"Panorama {self.panorama.hostname} no devices found")
        except KeyError:
            raise MTpanoramaException(f"Panorama {self.panorama.hostname} no devices found")
        
        if results:
            results = results['entry']
        else:
            raise MTpanoramaException(f"Panorama {self.panorama.hostname} no devices found")
        
        # if devices is not a list, make it a list
        if type(results) != list:
            results = [results]

        return results

class MTngfwException(Exception):
    pass

class MTngfw:
    def __init__(self, ngfw, timeout=5) -> None:
        """
        A class representing a Panorama device in the MT.

        Args:
            ngfw (models.db.NGFW): NGFW database model object.
            timeout (int, optional): The timeout value for API requests. Defaults to 5 seconds.
        """        
        self.ngfw = ngfw

        self.timeout = timeout

        self.xapi = None
        
        self.__set_xapi()

    def __set_xapi(self) -> None:
        """
        This method sets the xapi object based on the ngfw
        """

        # if the ngfw has no panorama, build the appropriate xapi object
        if not self.ngfw.panorama:
            if self.ngfw.active:
                self.xapi = pan.xapi.PanXapi(api_key=self.ngfw.api_key, hostname=self.ngfw.ip_address)
            else:
                self.xapi = pan.xapi.PanXapi(api_key=self.ngfw.api_key, hostname=self.ngfw.alt_ip)

        else:
            # if ngfw active set the serial number to the xapi object else set the alt_serial
            self.xapi = pan.xapi.PanXapi(api_key=self.ngfw.panorama.api_key, hostname=self.ngfw.panorama.ip_address)

            if self.ngfw.active:
                self.xapi.serial =  self.ngfw.serial_number
            else:
                self.xapi.serial =  self.ngfw.alt_serial

        self.xapi.timeout = self.timeout

    def show_neighbors(self) -> list:
        """
        Retrieves LLDP neighbor information from the device and returns it as a list of dictionaries.

        Raises:
            MTngfwException: If there is an error retrieving the LLDP neighbor information.

        Returns:
            A list of dictionaries containing the following keys:
            - local_interface: The name of the local interface.
            - remote_interface_id: The ID of the remote interface.
            - remote_interface_description: The description of the remote interface.
            - remote_hostname: The hostname of the remote device.
        """
        # for each ngfw in ngfws, set the serial of self.xapi to ngfw.serial_number and show lldp neighbors on the xapi object
        try:
            self.xapi.op("<show><lldp><neighbors>all</neighbors></lldp></show>")
            results = xmltodict.parse("<root>" + self.xapi.xml_result() + "</root>")['root']['entry']
        except pan.xapi.PanXapiError as e:
            raise MTngfwException(f"{self.ngfw.hostname}: {e}")
        except TypeError:
            raise MTngfwException(f"{self.ngfw.hostname} no neighbors found.")

        # if results is not a list, make it a list
        if type(results) != list:
            results = [results]

        response = []

        # for each result, build a dictionary and append to the formatted_results list
        for r in results:
            
            if r['neighbors']:
                lldp_neighbors = r['neighbors']['entry']
            else:
                continue

            if type(lldp_neighbors) != list:
                lldp_neighbors = [lldp_neighbors]
            
            for lldp_n in lldp_neighbors:
                response.append({
                    'local_interface': r['@name'] or "None",
                    'remote_interface_id': lldp_n['port-id'] or "None",
                    'remote_interface_description': lldp_n['port-description'] or "",
                    'remote_hostname': lldp_n['system-name'] or "None",
                })
        
        return response
    
    def show_bgp_peers(self) -> list:
        """
        Retrieves BGP peer information from the device and returns it as a list of dictionaries.

        Raises:
            MTngfwException: If there is an error retrieving the BGP peer information.

        Returns:
            A list of dictionaries containing the following keys:
            - virtual_router: The virtual router the peer is configured on.
            - peer_name: The name of the peer.
            - peer_group: The peer group the peer is configured in.
            - peer_router_id: The router ID of the peer.
            - remote_as: The remote AS of the peer.
            - status: The status of the peer.
            - status_duration: The duration of the peer status.
            - peer_address: The IP address of the peer.
            - local_address: The local IP address of the peer.
        """

        # for each ngfw in ngfw_list, set the serial of self.xapi to ngfw.serial_number and show lldp neighbors on the xapi object
        try:
            self.xapi.op("<show><routing><protocol><bgp><peer></peer></bgp></protocol></routing></show>")
            results = xmltodict.parse("<root>" + self.xapi.xml_result() + "</root>")['root']['entry']
        except pan.xapi.PanXapiError as e:
            raise MTngfwException(f"{self.ngfw.hostname} {e}")
        except TypeError:
            raise MTngfwException(f"{self.ngfw.hostname} no bgp-peers found.")

        # if results is not a list, make it a list
        if type(results) != list:
            results = [results]

        response = []

        # for each result, build a dictionary and append to the formatted_results list
        for bgp in results:
            
            response.append({
                    'virtual_router':bgp['@vr'],
                    'peer_name': bgp['@peer'], 
                    'peer_group': bgp['peer-group'],
                    'peer_router_id': bgp['peer-router-id'],
                    'remote_as': bgp['remote-as'],
                    'status': bgp['status'],
                    'status_duration': bgp['status-duration'],
                    'peer_address': bgp['peer-address'].split(':')[0],
                    'local_address': bgp['local-address'].split(':')[0],
            })

        return response
    
    def show_interfaces(self) -> list:
        """
        Returns a list of dictionaries containing information about interfaces from the API.

        Returns:
        list: A list of dictionaries containing the following keys:
            - name: The name of the interface.
            - tag: The tag of the interface.
            - vsys: The vsys of the interface.
            - ip: The IP address of the interface.
            - zone: The zone of the interface.
            - virtual_router: The ID of the virtual router based on name and ngfw.
        Raises:
        MTngfwException: If there is an error with the API call or no interfaces are found.
        """
        
        try:  
            self.xapi.op("<show><interface>all</interface></show>")
            results = xmltodict.parse("<root>" + self.xapi.xml_result() + "</root>")['root']['ifnet']['entry']
        except pan.xapi.PanXapiError as e:
            raise MTngfwException(f"{self.ngfw.hostname}: {e}")
        except TypeError:
            raise MTngfwException(f"{self.ngfw.hostname} no interfaces found")

        # if results is not a list, make it a list
        if type(results) != list:
            results = [results]

        response = []

        # for each interface, get the id of the virtual router based on name and ngfw, add to the database
        for i in results:
            if 'fwd' not in i:
                continue
            if 'vr' not in i['fwd']:
                continue
            if i['zone'] == None:
                continue

            response.append({
                'name': i.get('name', 'N/A'),
                'tag': i.get('tag', 'N/A'),
                'vsys': i.get('vsys', 'N/A'),
                'ip': i.get('ip', 'N/A'),
                'zone': i.get('zone', 'N/A'),
                'virtual_router': i['fwd'].replace('vr:', '')
            })

        return response
    
    def show_routes(self) -> list:
        """
        Returns a list of routes from the API.

        Raises:
            MTngfwException: If there is an error with the API call or no routes are found.

        Returns:
            - list of dictionaries containing route information
        """

        try:
            self.xapi.op("<show><routing><route><afi>ipv4</afi></route></routing></show>")
            results = xmltodict.parse("<root>" + self.xapi.xml_result() + "</root>")['root']['entry']
        except pan.xapi.PanXapiError as e:
            raise MTngfwException(f"{self.ngfw.hostname}: {e}")
        except TypeError:
            raise MTngfwException(f"{self.ngfw.hostname} no routes found.")

        # if results is not a list, make it a list
        if type(results) != list:
            results = [results]

        return results
    
    def show_ha_status(self) -> dict:
        """
        Sends a request to the device to retrieve its high availability status.

        Raises:
            MTngfwException: If there is an error retrieving the high availability status.

        Returns:
            - A dictionary containing the high availability status of the device.
        """
        try:
            self.xapi.op("<show><high-availability><state></state></high-availability></show>")
            results = xmltodict.parse("<root>" + self.xapi.xml_result() + "</root>")['root']['group']['local-info']
        except pan.xapi.PanXapiError as e:
            raise MTngfwException(f"NGFW {self.ngfw.hostname}: {e}")
        except TypeError:
            raise MTngfwException(f"NGFW {self.ngfw.hostname} not in ha")
        except KeyError:
            raise MTngfwException(f"NGFW {self.ngfw.hostname} not in ha")
        
        if 'state' not in results:
            raise MTngfwException(f"NGFW {self.ngfw.hostname} not in ha")
        
        return results