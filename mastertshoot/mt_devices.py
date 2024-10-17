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
import functools

import pan.xapi
import xmltodict
import time

# from models import Ngfw, Panorama

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
            dict: A dictionary containing the high availability state of the device.
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

    def __null_value_check(self, result) -> dict:
        """
        This method checks for null values in the value dictionary and replaces with an empty string.

        Args:
            result (dict): The value to check.

        Returns:
            dict: The value or an empty string.
        """

        for key, value in result.items():
            if not value:
                result[key] = ''
        return result

    
    def show_system_info(self) -> dict:
        """
        Sends a request to the device to retrieve its system information.

        Raises:
            MTngfwException: If there is an error retrieving the system information.

        Returns:
            dict: A dictionary containing the system information of the device.
        """
        try:
            self.xapi.op("<show><system><info></info></system></show>")
            results = xmltodict.parse("<root>" + self.xapi.xml_result() + "</root>")['root']
        except pan.xapi.PanXapiError as e:
            raise MTngfwException(f"NGFW {self.ngfw.hostname}: {e}")
        except TypeError:
            raise MTngfwException(f"NGFW {self.ngfw.hostname} no system info found")
        except TimeoutError:
            raise MTngfwException(f"NGFW {self.ngfw.hostname} timeout error")
        
        return results
    
    
    def show_virtual_routes(self) -> list:
        """
        Retrieves virtual router information from the device and returns it as a list of dictionaries.

        Raises:
            MTngfwException: If there is an error retrieving the virtual router information.

        Returns:
            list: A list of dictionaries containing the following keys:
                - name: The name of the virtual router.
                - interfaces: The interfaces assigned to the virtual router.
        """
        # for each ngfw in ngfws, set the serial of self.xapi to ngfw.serial_number and show lldp neighbors on the xapi object
        try:
            self.xapi.op("<show><routing><summary></summary></routing></show>")
            results = xmltodict.parse("<root>" + self.xapi.xml_result() + "</root>")['root']['entry']
        except pan.xapi.PanXapiError as e:
            raise MTngfwException(f"{self.ngfw.hostname}: {e}")
        except TypeError:
            raise MTngfwException(f"{self.ngfw.hostname} no virtual routers found.")

        # if results is not a list, make it a list
        if type(results) != list:
            results = [results]

        response = []

        # for each result if @name is in the result append the name to the response list
        for r in results:
            if '@name' in r:
                response.append(r['@name'])

        return response

    
    def show_neighbors(self) -> list:
        """
        Retrieves LLDP neighbor information from the device and returns it as a list of dictionaries.

        Raises:
            MTngfwException: If there is an error retrieving the LLDP neighbor information.

        Returns:
            list: A list of dictionaries containing the following keys:
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
                    'ngfw': self.ngfw.hostname,
                    'local_interface': r['@name'] or "",
                    'remote_interface_id': lldp_n['port-id'] or "",
                    'remote_interface_description': lldp_n['port-description'] or "",
                    'remote_hostname': lldp_n['system-name'] or "",
                })
        
        return response
    
    
    def show_bgp_peers(self, virtual_router=None) -> list:
        """
        Retrieves BGP peer information from the device and returns it as a list of dictionaries.

        Raises:
            MTngfwException: If there is an error retrieving the BGP peer information.

        Returns:
            list: A list of dictionaries containing the following keys:
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

        # if virtual_router is set, set the virtual-router tag in the cmd
        if virtual_router:
            cmd = f"<virtual-router>{virtual_router}</virtual-router>"
        else:
            cmd = ""
        
        cmd = f"<show><routing><protocol><bgp><peer>{cmd}</peer></bgp></protocol></routing></show>"

        try:
            self.xapi.op(cmd=cmd)
            results = xmltodict.parse("<root>" + self.xapi.xml_result() + "</root>")['root']['entry']
        except pan.xapi.PanXapiError as e:
            raise MTngfwException(f"{self.ngfw.hostname} {e}")
        except TypeError:
            if virtual_router:
                raise MTngfwException(f"{self.ngfw.hostname} no bgp-peers found on vr: {virtual_router}")
            else:
                raise MTngfwException(f"{self.ngfw.hostname} has no bgp-peers")

        # if results is not a list, make it a list
        if type(results) != list:
            results = [results]

        response = []

        # for each result, build a dictionary and append to the formatted_results list
        for bgp in results:
            
            response.append({
                    'ngfw': self.ngfw.hostname,
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
    
    
    def show_interfaces(self, virtual_router=None) -> list:
        """
        Returns a list of dictionaries containing information about interfaces from the API.

        Raises:
            MTngfwException: If there is an error with the API call or no interfaces are found.

        Returns:
            list: A list of dictionaries containing the following keys:
                - name: The name of the interface.
                - tag: The tag of the interface.
                - vsys: The vsys of the interface.
                - ip: The IP address of the interface.
                - zone: The zone of the interface.
                - virtual_router: The ID of the virtual router based on name and ngfw.
        """
        
        try:  
            self.xapi.op("<show><interface>all</interface></show>")
            results = xmltodict.parse("<root>" + self.xapi.xml_result() + "</root>")['root']['ifnet']['entry']
        except pan.xapi.PanXapiError as e:
            raise MTngfwException(f"{self.ngfw.hostname}: {e}")
        except TypeError:
            raise MTngfwException(f"{self.ngfw.hostname} has no interfaces")

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
            
            i_vr = i['fwd'].replace('vr:', '')

            if virtual_router:
                if i_vr != virtual_router:
                    continue

            response.append({
                'ngfw': self.ngfw.hostname,
                'name': i.get('name', ''),
                'tag': i.get('tag', ''),
                'vsys': i.get('vsys', ''),
                'ip': i.get('ip', ''),
                'zone': i.get('zone', ''),
                'virtual_router': i_vr,
            })

        return response
    
    
    def show_routes(self, virtual_router=None, dst=None, flags=None) -> list:
        """
        Returns a list of routes from the API.

        Raises:
            MTngfwException: If there is an error with the API call or no routes are found.

        Returns:
            list: dictionaries containing route information
        """
        
        cmd = "<afi>ipv4</afi>"

        if virtual_router:
            cmd += f"<virtual-router>{virtual_router}</virtual-router>"

        cmd = f"<show><routing><route>{cmd}</route></routing></show>"

        try:
            self.xapi.op(cmd=cmd)
            results = xmltodict.parse("<root>" + self.xapi.xml_result() + "</root>")['root']['entry']
        except pan.xapi.PanXapiError as e:
            raise MTngfwException(f"{self.ngfw.hostname}: {e}")
        except TypeError:
            raise MTngfwException(f"{self.ngfw.hostname} no routes found.")
        except KeyError:
            raise MTngfwException(f"{self.ngfw.hostname} no routes found.")

        # if results is not a list, make it a list
        if type(results) != list:
            results = [results]

        new_routes = []

        for r in results:
            self.__null_value_check(r)
            
            # if flags is set, check if it is in the route entry, if not continue
            if flags:
                if flags not in r['flags']:
                    continue
            
            # if dst is set, check if it is in the route entry, if not continue
            if dst:
                if dst not in r['destination']:
                    continue
            
            # change virtual-router to virtual_router
            r['virtual_router'] = r.pop('virtual-router')

            # change route-table to route_table
            r['route_table'] = r.pop('route-table')

            # add the ngfw hostname to the route entry
            r['ngfw'] = self.ngfw.hostname
            # add zone to the route entry
            r['zone'] = ''
            
            new_routes.append(r)

        return new_routes
    
    
    def show_fibs(self, virtual_router=None, dst=None, flags=None) -> list:
        """
        Returns a list of FIB routes from the API.

        Raises:
            MTngfwException: If there is an error with the API call or no FIB routes are found.

        Returns:
            list: dictionaries containing FIB route information
        """

        cmd = "<afi>ipv4</afi>"

        if virtual_router:
            cmd += f"<virtual-router>{virtual_router}</virtual-router>"
        
        cmd = f"<show><routing><fib>{cmd}</fib></routing></show>"

        try:
            self.xapi.op(cmd=cmd)
            results = xmltodict.parse("<root>" + self.xapi.xml_result() + "</root>")['root']['fibs']['entry']

        except pan.xapi.PanXapiError as e:
            if f"{virtual_router} is invalid virtual-router" in str(e):
                err_msg = "{virtual_router} is invalid virtual-router"
            else:
                err_msg = str(e)
            raise MTngfwException(f"{self.ngfw.hostname}: {err_msg}")
        
        except TypeError:
            raise MTngfwException(f"{self.ngfw.hostname} no fib entries found.")

        # if results is not a list, make it a list
        if type(results) != list:
            results = [results]

        fibs = []

        # Add the virtual_router to each entry to aline with the show routes command
        for r in results:
            try:
                fib_vr = r['vr']

                if r['nentries'] == '0':
                    continue

                if type(r['entries']['entry']) != list:
                    r['entries']['entry'] = [r['entries']['entry']]

                for fib in r['entries']['entry']:
                    
                    # if dst is set, check if it is in the fib entry, if not continue
                    if dst:
                        if dst not in fib['dst']:
                            continue

                    # if flags is set, check if it is in the fib entry, if not continue
                    if flags:
                        if flags not in fib['flags']:
                            continue

                    # check all values in fib, if None set to 'None'
                    fib = self.__null_value_check(fib)
                    # add the ngfw hostname to the fib entry
                    fib['ngfw'] = self.ngfw.hostname
                    # add the virtual_router to the fib entry
                    fib['virtual_router'] = fib_vr
                    # change the key 'dst' to 'destination'
                    fib['destination'] = fib.pop('dst')
                    # change the key 'id' to 'fib_id'
                    fib['fib_id'] = fib.pop('id')
                    # set zone to None
                    fib['zone'] = ''
                    fibs.append(fib)
            except KeyError:
                continue

        return fibs

    
    def show_arps(self, interface=None) -> list:
        """
        Returns a list of ARP entries from the API.

        Raises:
            MTngfwException: If there is an error with the API call or no ARP entries are found.

        Returns:
            list: dictionaries containing ARP entry information
        """

        if interface:
            cmd_if = interface
        else:
            cmd_if = 'all'

        try:
            self.xapi.op(f"<show><arp><entry name = '{cmd_if}'/></arp></show>")
            results = xmltodict.parse("<root>" + self.xapi.xml_result() + "</root>")['root']['entries']['entry']
        except pan.xapi.PanXapiError as e:
            raise MTngfwException(f"{self.ngfw.hostname}: {e}")
        except TypeError:
            raise MTngfwException(f"{self.ngfw.hostname} no arp entries found")
        except KeyError:
            if interface:
                raise MTngfwException(f"{self.ngfw.hostname} no arp entries found for {interface}")
            else:
                raise MTngfwException(f"{self.ngfw.hostname} no arp entries found")

        # if results is not a list, make it a list
        if type(results) != list:
            results = [results]

        arps = []
        for a in results:
            a = self.__null_value_check(a)
            a['ngfw'] = self.ngfw.hostname
            a['zone'] = ''
            arps.append(a)

        return arps
    
    
    def show_ha_status(self) -> dict:
        """
        Sends a request to the device to retrieve its high availability status.

        Raises:
            MTngfwException: If there is an error retrieving the high availability status.

        Returns:
            dict: Containing the high availability status of the device.
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
    
    
    def test_policy_match(self, src_ip, src_zone, dst_ip, dst_zone, protocol, dst_port, application) -> dict:
        """
        Sends a request to the device to test a security policy match.

        Args:
            src_ip (str): The source IP address.
            src_zone (str): The source zone.
            dst_ip (str): The destination IP address.
            dst_zone (str): The destination zone.
            protocol (str): The protocol.
            dst_port (str): The destination port.
            application (str): The application.

        Raises:
            MTngfwException: If there is an error testing the security policy match.

        Returns:
            dict: Containing the results of the security policy match test.
        """
        cmd_start = "<test><security-policy-match>"
        cmd_end = "</security-policy-match></test>"

        cmd = f"<source>{src_ip}</source>"
        cmd += f"<from>{src_zone}</from>"
        cmd += f"<destination>{dst_ip}</destination>"
        cmd += f"<to>{dst_zone}</to>"
        cmd += f"<protocol>{protocol}</protocol>"
        cmd += f"<destination-port>{dst_port}</destination-port>"
        cmd += f"<application>{application}</application>"

        cmd = cmd_start + cmd + cmd_end

        try:
            self.xapi.op(cmd)
            results = xmltodict.parse("<root>" + self.xapi.xml_result() + "</root>")['root']['rules']['entry']
        except pan.xapi.PanXapiError as e:
            raise MTngfwException(f"NGFW {self.ngfw.hostname}: {e}")
        except TypeError as e:
            print(self.xapi.xml_result())
            raise MTngfwException(f"NGFW {self.ngfw.hostname}: {e}")
        
        if type(results) != list:
            results = [results]

        rules = []
        for r in results:
            r['ngfw'] = self.ngfw.hostname
            r = self.__null_value_check(r)
            rules.append(r)

        return rules

    
    def export_tsf(self, serial) -> dict:
        """
        Exports the tech support file from the device.

        Raises:
            MTngfwException: If there is an error exporting the tech support file.

        Returns:
            bytes: Containing the tech support file (tar.gz).
        """
        
        # if the ngfw is managed by panorama raise an exception informing the user it is not supported
        if self.ngfw.panorama:
            raise MTngfwException(f"NGFW {self.ngfw.hostname} is managed by Panorama and does not support exporting tech support files.")

        if serial == self.ngfw.alt_serial:
            self.xapi.hostname = self.ngfw.alt_ip

        try:
            self.xapi.export(category="tech-support")
            job = xmltodict.parse("<root>" + self.xapi.xml_result() + "</root>")['root']
        except pan.xapi.PanXapiError as e:
            raise MTngfwException(f"NGFW {self.ngfw.hostname}: {e}")
        except TypeError as e:
            raise MTngfwException(f"NGFW {self.ngfw.hostname} error exporting tech support file")
        
        try:
            job_status = "PEND"
            job_result = None
            job_id = job['job']
            while job_status != "FIN" and job_result != "OK":
                time.sleep(10)
                self.xapi.op(f"<show><jobs><id>{job_id}</id></jobs></show>")
                job_check = xmltodict.parse("<root>" + self.xapi.xml_result() + "</root>")['root']['job']
                job_status = job_check['status']
                job_result = job_check['result']
                if job_result == "FAIL":
                    raise MTngfwException(f"NGFW {self.ngfw.hostname} tech support file export failed")

            self.xapi.export(category="tech-support", extra_qs={"action":"get","job-id":job['job']})

            tsf = self.xapi.export_result['content']

        except pan.xapi.PanXapiError as e:
            raise MTngfwException(f"NGFW {self.ngfw.hostname}: {e}")
        except TypeError as e:
            raise MTngfwException(f"NGFW {self.ngfw.hostname} error exporting tech support file")

        # return the binary TSF
        print(type(tsf))
        return tsf