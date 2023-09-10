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
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from models import Ngfw, Route, VirtualRouter, Interface, Panorama

class MTControllerException(Exception):
    """
    This is the base class for all exceptions raised by the MTController class
    """
    pass

class MTController:
    """
    This class is used to interact with the database and the PanXapi object
    """
    def __init__(self, db_uri) -> None:
        """
        This method initializes the MTController class
        """

        # Verify db_uri is present
        if not db_uri:
            raise MTControllerException("No db_uri provided")
        self.db_uri = db_uri

        try:
            engine = create_engine(db_uri, echo=False)
            Session = sessionmaker(bind=engine)
            self.session = Session()
        except Exception as e:
            raise MTControllerException(f"Issue communicating with database {db_uri}.  Error: {str(e)}")

        # Create a PanXapi object from Panorama ID and credentials
        try:
            self.panorama = self.session.query(Panorama).first()
        except Exception as e:
            raise MTControllerException(f"Issue querying database.  Likley need to run mt-tools first.")

        # If no panorama in database, raise exception
        if self.panorama:
            if self.panorama.active:
                hostname = self.panorama.ip_address
            else:
                hostname = self.panorama.alt_ip
            self.xapi = pan.xapi.PanXapi(api_key=self.panorama.api_key, hostname=hostname)
        else:
            raise MTControllerException("No Panorama in database")


    def import_panorama_devices(self) -> list:
        """
        This method imports the devices from the Panorama
        """

        # show devices all on the xapi object
        try:
            self.xapi.op("<show><devices><all></all></devices></show>")
        except pan.xapi.PanXapiError as e:
            raise MTControllerException(f"Issue connecting to Panorama.  Error: {e}")
        
        devices = xmltodict.parse("<root>" + self.xapi.xml_result() + "</root>")['root']['devices']['entry']

        message = []

        serial_numbers = []

        # Query the database for ngfws and add serial numbers to serial_numbers list
        ngfws = self.session.query(Ngfw).all()
        for n in ngfws:
            serial_numbers.append(n.serial_number)
            if n.alt_serial is not None:
                serial_numbers.append(n.alt_serial)

        # if devices is not a list, make it a list
        if type(devices) != list:
            devices = [devices]

        # for each device, add to the database
        for d in devices:

            ngfw_info = {
                'hostname': d['hostname'],
                'serial_number': d['serial'],
                'ip_address': d['ip-address'],
                'panorama_id': self.panorama.id
            } 
            # If ha in d
            if 'ha' in d:
                if d['ha']['state'] == 'active':
                    ngfw_info['active'] = True
                    ngfw_info['alt_serial'] = d['ha']['peer']['serial'] 
                else:
                    continue
            else:
                ngfw_info['active'] = True
                ngfw_info['alt_serial'] = None
            
            new_ngfw = Ngfw(**ngfw_info)

            # If connected is not yes continue
            if d['connected'] != 'yes':
                continue

            # If serial number is not in serial_numbers, add to the database
            if new_ngfw.serial_number not in serial_numbers:
                self.session.add(new_ngfw)
                message.append(f"{ngfw_info['hostname']} {new_ngfw.serial_number} added to database")
            else:
                message.append(f"{ngfw_info['hostname']} {new_ngfw.serial_number} already in database.  Skipping...")
            
        self.session.commit()
        return message


    def refresh_ngfws(self, ngfw=None) -> None:
        """
        This method refreshes the ngfws in the database
        """

        interface_query = self.session.query(Interface)
        route_query = self.session.query(Route)
        vr_query = self.session.query(VirtualRouter)
        ngfw_query = self.session.query(Ngfw)

        if ngfw:
            interface_query = interface_query.join(Interface.virtual_router).join(VirtualRouter.ngfw).filter(Ngfw.hostname == ngfw)
            route_query = route_query.join(Route.virtual_router).join(VirtualRouter.ngfw).filter(Ngfw.hostname == ngfw)
            vr_query = vr_query.join(VirtualRouter.ngfw).filter(Ngfw.hostname == ngfw)
            ngfw_query = ngfw_query.filter(Ngfw.hostname == ngfw)

        interfaces = interface_query.all()
        routes = route_query.all()
        virtual_routers = vr_query.all()
        ngfw_list = ngfw_query.all()

        # for each interface, route and virtual router, delete from the database
        for i in interfaces:
            self.session.delete(i)
        for r in routes:
            self.session.delete(r)
        for vr in virtual_routers:
            self.session.delete(vr)

        # for each ngfw
        for n in ngfw_list:

            # if ngfw active set the serial number to the xapi object else set the alt_serial

            if n.active:
                self.xapi.serial =  n.serial_number
            else:
                self.xapi.serial =  n.alt_serial


            # show routing route for ipv4 on the xapi object

            try:
                self.xapi.op("<show><routing><route><afi>ipv4</afi></route></routing></show>")
            except pan.xapi.PanXapiError as e:
                raise MTControllerException(f"Issue connecting to Panorama.  Error: {e}")

            try:
                routes = xmltodict.parse("<root>" + self.xapi.xml_result() + "</root>")['root']['entry']
            except:
                continue

            # if routes is not a list, make it a list
            if type(routes) != list:
                routes = [routes]

            # set object for virtual router
            virtual_routers = set()

            for r in routes:
                virtual_routers.add(r.get('virtual-router', 'N/A'))

            # add all the virtual_routers to the database, capture the id given by the database
            for vr in virtual_routers:
                new_vr = VirtualRouter(name=vr, ngfw_id=n.id)
                self.session.add(new_vr)

            self.session.commit()

            # for each route, get the id of the virtual router based on name and ngfw, add to the database
            for r in routes:
                vr = self.session.query(VirtualRouter).filter(VirtualRouter.name == r.get('virtual-router', 'N/A')).filter(VirtualRouter.ngfw_id == n.id).first()
                new_route = Route(virtual_router_id=vr.id, destination=r.get('destination', 'N/A'), nexthop=r.get('nexthop', 'N/A'), metric=r.get('metric', 'N/A'), flags=r.get('flags', 'N/A'), age=r.get('age', 'N/A'), interface=r.get('interface', 'N/A'), route_table=r.get('route-table', 'N/A'))
                self.session.add(new_route)

            self.session.commit()

            # if ngfw.active set the serial number to the xapi object else set the alt_serial
            if n.active:
                self.xapi.serial =  n.serial_number
            else:
                self.xapi.serial =  n.alt_serial

            # show the interfaces on the xapi object
            try:
                self.xapi.op("<show><interface>all</interface></show>")
            except pan.xapi.PanXapiError as e:
                raise MTControllerException(f"Issue connecting to Panorama.  Error: {e}")
            
            interfaces = xmltodict.parse("<root>" + self.xapi.xml_result() + "</root>")['root']['ifnet']['entry']

            # if interfaces is not a list, make it a list
            if type(interfaces) != list:
                interfaces = [interfaces]

            # For each interface, get the id of the virtual router based on name and ngfw, add to the database
            for i in interfaces:
                if 'fwd' not in i:
                    continue
                if 'vr' not in i['fwd']:
                    continue
                if i['zone'] == None:
                    continue
                
                # Verify the vr exists in the database
                vr_name = i['fwd'].replace('vr:', '')
                vr = self.session.query(VirtualRouter).filter(VirtualRouter.name == vr_name).filter(VirtualRouter.ngfw_id == n.id).first()

                if not vr:
                    continue

                new_interface = Interface(name=i.get('name', 'N/A'),
                                            tag=i.get('tag', 'N/A'),
                                            vsys=i.get('vsys', 'N/A'),
                                            zone=i.get('zone', 'N/A'),
                                            fwd=i.get('fwd', 'N/A'),
                                            ip=i.get('ip', 'N/A'),
                                            addr=i.get('addr', 'N/A'),
                                            virtual_router_id=vr.id)
                self.session.add(new_interface)
            self.session.commit()     
        


    def refresh_routes(self, ngfw=None, virtual_router=None) -> None:
        """
        This method refreshes the routes in the database
        """

        query = self.session.query(Route).join(Route.virtual_router)
        ngfw_query = self.session.query(Ngfw)
        if ngfw:
            query = query.join(VirtualRouter.ngfw).filter(Ngfw.hostname == ngfw)
            ngfw_query = ngfw_query.filter(Ngfw.hostname == ngfw)
        if virtual_router:
            query = query.filter(VirtualRouter.name == virtual_router)
            ngfw_query = ngfw_query.join(Ngfw.virtual_routers).filter(VirtualRouter.name == virtual_router)

        ngfw_list = ngfw_query.all()
        routes = query.all()

        if not routes:
            return None
    
        # delete all queried routes from database
        for r in routes:
            self.session.delete(r)

        self.session.commit()

        for n in ngfw_list:

            # if ngfw.active set the serial number to the xapi object else set the alt_serial
            if n.active:
                self.xapi.serial =  n.serial_number
            else:
                self.xapi.serial =  n.alt_serial

            # show routing route for ipv4 on the xapi object
            try:
                self.xapi.op("<show><routing><route><afi>ipv4</afi></route></routing></show>")
            except pan.xapi.PanXapiError as e:
                raise MTControllerException(f"Issue connecting to Panorama.  Error: {e}")

            try:
                routes = xmltodict.parse("<root>" + self.xapi.xml_result() + "</root>")['root']['entry']
            except KeyError:
                continue

            # if routes is not a list, make it a list
            if type(routes) != list:
                routes = [routes]

            # for each route, get the id of the virtual router based on name and ngfw, add to the database
            for r in routes:
                vr = self.session.query(VirtualRouter).filter(VirtualRouter.name == r.get('virtual-router', 'N/A')).filter(VirtualRouter.ngfw_id == n.id).first()
                
                route_data = {
                    'virtual_router_id': vr.id,
                    'destination': r.get('destination', 'N/A'),
                    'nexthop': r.get('nexthop', 'N/A'),
                    'metric': r.get('metric', 'N/A'),
                    'flags': r.get('flags', 'N/A'),
                    'age': r.get('age', 'N/A'),
                    'interface': r.get('interface', 'N/A'),
                    'route_table': r.get('route-table', 'N/A')
                }

                # Create a new Route instance with the dictionary as kwargs
                new_route = Route(**route_data)

                # Add the new_route to the session
                self.session.add(new_route)

        self.session.commit()
        

    def refresh_interfaces(self, ngfw=None) -> None:
        """
        This method refreshes the interfaces in the database
        """

        query = self.session.query(Interface).join(Interface.virtual_router)

        if ngfw:
            query = query.join(VirtualRouter.ngfw).filter(Ngfw.hostname == ngfw)
            ngfw_list = self.session.query(Ngfw).filter(Ngfw.hostname == ngfw).all()
        else:
            ngfw_list = self.session.query(Ngfw).all()
        
        interfaces = query.all()

        if not interfaces:
            return None
        
        # delete all queried interfaces from database
        for i in interfaces:
            self.session.delete(i)
        
        self.session.commit()

        # for each ngfw
        for n in ngfw_list:

            # if ngfw.active set the serial number to the xapi object else set the alt_serial
            if n.active:
                self.xapi.serial =  n.serial_number
            else:
                self.xapi.serial =  n.alt_serial

            # show the interfaces on the xapi object
            try:
                self.xapi.op("<show><interface>all</interface></show>")
            except pan.xapi.PanXapiError as e:
                raise MTControllerException(f"Issue connecting to Panorama.  Error: {e}")
            
            interfaces = xmltodict.parse("<root>" + self.xapi.xml_result() + "</root>")['root']['ifnet']['entry']

            # if interfaces is not a list, make it a list
            if type(interfaces) != list:
                interfaces = [interfaces]

            # For each interface, get the id of the virtual router based on name and ngfw, add to the database
            for i in interfaces:
                if 'fwd' not in i:
                    continue
                if 'vr' not in i['fwd']:
                    continue
                if i['zone'] == None:
                    continue
                
                # Verify the vr exists in the database
                vr_name = i['fwd'].replace('vr:', '')
                vr = self.session.query(VirtualRouter).filter(VirtualRouter.name == vr_name).filter(VirtualRouter.ngfw_id == n.id).first()

                if not vr:
                    continue

                new_interface = Interface(name=i.get('name', 'N/A'),
                                            tag=i.get('tag', 'N/A'),
                                            vsys=i.get('vsys', 'N/A'),
                                            zone=i.get('zone', 'N/A'),
                                            fwd=i.get('fwd', 'N/A'),
                                            ip=i.get('ip', 'N/A'),
                                            addr=i.get('addr', 'N/A'),
                                            virtual_router_id=vr.id)
                self.session.add(new_interface)

        self.session.commit()

    def get_routes(self, ngfw=None, virtual_router=None, destination=None, flags=None) -> list:
        """
        This method returns a list of routes
        """

        query = self.session.query(Route).join(Route.virtual_router)

        if ngfw:
            query = query.join(VirtualRouter.ngfw).filter(Ngfw.hostname == ngfw)
        if virtual_router:
            query = query.filter(VirtualRouter.name == virtual_router)
        if destination:
            query = query.filter(Route.destination.contains(destination))
        if flags:
            for f in flags.split(","):
                query = query.filter(Route.flags.contains(f.upper().strip()))
        
        routes = query.all()

        if not routes:
            return None

        formatted_routes = []
        
        # For each route, build a dictionary and append to the formatted_routes list
        for r in routes:
            route_data = {
                'ngfw': r.virtual_router.ngfw.hostname,
                'virtual_router': r.virtual_router.name,
                'destination': r.destination,
                'nexthop': r.nexthop,
                'metric': str(r.metric) if r.metric is not None else 'None',
                'flags': r.flags,
                'interface': str(r.interface) if r.interface is not None else 'None',
                'route_table': r.route_table,
                'age': str(r.age) if r.age is not None else 'None'
            }

            # If H (Host) is present in the flags string, query the database for interface based on destination, where destination is in the interface ip address range
            if 'H' in route_data['flags']:
                interface_info = self.session.query(Interface).filter(Interface.ip.contains(route_data['destination'].replace("/32",""))).first()
                if interface_info:
                    route_data['interface'] = interface_info.name
                    route_data['zone'] = interface_info.zone
                else:
                    route_data['zone'] = "None"
                    route_data['interface'] = "None"

            # Zone based on query of interface table from interface name, ngfw, and virtual router
            else:
                interface_info = self.session.query(Interface).filter(Interface.name == r.interface).filter(Interface.virtual_router_id == r.virtual_router_id).first()
                if interface_info:
                    route_data['zone'] = interface_info.zone
                else:
                    route_data['zone'] = "none"

            formatted_routes.append(route_data)

        return formatted_routes
    
    def get_interfaces(self, ngfw=None, virtual_router=None) -> list:
        """
        This method returns a list of interfaces
        """

        query = self.session.query(Interface).join(Interface.virtual_router)

        if ngfw:
            query = query.join(VirtualRouter.ngfw).filter(Ngfw.hostname == ngfw)
        if virtual_router and not ngfw:
            query = query.filter(VirtualRouter.name == virtual_router)
        
        interfaces = query.all()

        if not interfaces:
            return None
            
        formatted_interfaces = []

        # Print each interface in a formatted way and append to the formatted_interfaces list
        for i in interfaces:
            interface_dict = {
                'ngfw': i.virtual_router.ngfw.hostname,
                'virtual_router': i.virtual_router.name,
                'name': i.name,
                'tag': i.tag,
                'vsys': i.vsys,
                'ip': i.ip,
                'zone': i.zone,
            }
            
            formatted_interfaces.append(interface_dict)

        return formatted_interfaces
    
    def get_virtual_routers(self, ngfw=None):
        """
        This method returns a list of virtual routers
        """

        query = self.session.query(VirtualRouter)

        if ngfw:
            query = query.join(VirtualRouter.ngfw).filter(Ngfw.hostname == ngfw)
        
        virtual_routers = query.all()

        if not virtual_routers:
            return None
        
        formatted_virtual_routers = []

        # For each virtual-router in virtual_routers, build a dictionary and append to the formatted_virtual_routers list
        for vr in virtual_routers:
            vr_dict = {
                'hostname': vr.ngfw.hostname,
                'virtual_router': vr.name,
                'route_count': len(vr.routes),
                'interface_count': len(vr.interfaces)
            }

            formatted_virtual_routers.append(vr_dict)

        return formatted_virtual_routers
    
    def get_ngfws(self, panorama=None) -> list:
        """
        This method returns a list of ngfws
        """

        query = self.session.query(Ngfw)

        if panorama:
            query = query.join(Ngfw.panorama).filter(Panorama.hostname == panorama)
        
        ngfws = query.all()

        if not ngfws:
            return None
        
        formatted_ngfws = []

        # For each ngfw in ngfws, build a dictionary and append to the formatted_ngfws list
        for ngfw in ngfws:
            ngfw_dict = {
                'hostname': ngfw.hostname,
                'serial_number': ngfw.serial_number,
                'ip_address': ngfw.ip_address,
                'alt_serial': ngfw.alt_serial,
                'active': ngfw.active,
               'panorama': ngfw.panorama.hostname if ngfw.panorama else 'None'  # Handle if panorama is None
            }

            formatted_ngfws.append(ngfw_dict)

        return formatted_ngfws
    
    # Get the panorama
    def get_panoramas(self) -> list:
        """
        This method returns a list of panoramas
        """

        panorama = self.session.query(Panorama).all()

        formatted_panorama = []

        # For each panorama get the hostname, ip address, alt ip, and active
        for p in panorama:
            pan_info = {
                'hostname': p.hostname,
                'ip_address': p.ip_address,
                'alt_ip': p.alt_ip,
                'active': p.active
            }

            formatted_panorama.append(pan_info)
        
        return formatted_panorama
    
    def test_fib_lookup(self, ip_address, vr_query=None, ngfw_query=None) -> list:
        """
        This method returns a list of fib lookups
        """

        # If ngfw_query and vr_query are present, query the database for the virtual router on the ngfw
        if ngfw_query and vr_query:
            virtual_routers = self.session.query(VirtualRouter).\
                    join(VirtualRouter.ngfw).filter(VirtualRouter.name == vr_query, Ngfw.hostname == ngfw_query).all()
            if not virtual_routers:
                return
            
        # If ngfw_query is present, query the database for the virtual routers on the ngfw
        elif ngfw_query and not vr_query:
            virtual_routers = self.session.query(VirtualRouter).join(VirtualRouter.ngfw).filter(Ngfw.hostname == ngfw_query).\
                    all()

            if not virtual_routers:
                return
            
        # If vr_query is present, query the database for the virtual router
        elif vr_query and not ngfw_query:
            virtual_routers = self.session.query(VirtualRouter).filter(VirtualRouter.name == vr_query).all()
            if not virtual_routers:
                return
        # If neither ngfw_query nor vr_query are present, query the database for all virtual routers
        else:
            virtual_routers = self.session.query(VirtualRouter).all()
            if not virtual_routers:
                    return

        formatted_results = []

        # For each virtual-router build an xapi object
        for vr in virtual_routers:

            # if ngfw.active set the serial number to the xapi object else set the alt_serial
            if vr.ngfw.active:
                self.xapi.serial =  vr.ngfw.serial_number
            else:
                self.xapi.serial =  vr.ngfw.alt_serial

            # show routing fib ip-address <ip_address> on the xapi object
            try:
                self.xapi.op(f"<test><routing><fib-lookup><ip>{ip_address}</ip><virtual-router>{vr.name}</virtual-router></fib-lookup></routing></test>")
            except pan.xapi.PanXapiError as e:
                raise MTControllerException(f"Issue connecting to Panorama.  Error: {e}")

            try:
                result = xmltodict.parse("<root>" + self.xapi.xml_result() + "</root>")['root']
            except:
                continue
            
            # If 'interface' is not in result, set result to none fields and continue
            if 'interface' not in result:
                result = {'hostname': vr.ngfw.hostname, 'virtual_router': vr.name, 'interface': 'none', 'nexthop': 'none', 'zone': 'none'}
                formatted_results.append(result)
                continue

            # Zone based on query of interface table from interface name, ngfw, and virtual router
            zone_info = self.session.query(Interface).filter(Interface.name == result['interface']).filter(Interface.virtual_router_id == vr.id).first()
            if zone_info:
                zone = zone_info.zone
            else:
                zone = "none"

            #check if nh is a valid key
            if result['nh'] not in result:
                next_hop = 'self'
            else:
                next_hop = result[result['nh']]

            # Create dictionary with these values: vr.ngfw.hostname, vr.name, result['interface'], result[result['nh']], zone
            result = {'hostname': vr.ngfw.hostname, 'virtual_router': vr.name, 'interface': result['interface'], 'nexthop': next_hop, 'zone': zone}

            formatted_results.append(result)

        return formatted_results
    

    def show_lldp_neighbors(self, ngfw=None) -> list:
        """
        This method returns a list of lldp neighbors
        """

        # IF ngfw is present, query the database for the ngfw based on the self.panorama.id and ngfw
        if ngfw:
            ngfws = self.session.query(Ngfw).filter(Ngfw.hostname == ngfw).all()

        # IF ngfw is NOT present, query the database for all ngfws based on self.panorama.id
        else:
            ngfws = self.session.query(Ngfw).all()

        if not ngfws:
            return None
        
        formatted_lldp_neighbors = []
        
        # For each ngfw in ngfws, set the serial of self.xapi to ngfw.serial_number and show lldp neighbors on the xapi object
        for n in ngfws:
            self.xapi.serial = n.serial_number
            try:
                self.xapi.op("<show><lldp><neighbors>all</neighbors></lldp></show>")
            except pan.xapi.PanXapiError as e:
                raise MTControllerException(f"Issue connecting to Panorama.  Error: {e}")
            
            results = xmltodict.parse("<root>" + self.xapi.xml_result() + "</root>")['root']['entry']

            # If results is not a list, make it a list
            if type(results) != list:
                results = [results]

            # For each result, build a dictionary and append to the formatted_results list
            for r in results:
                
                lldp_neighbors = r['neighbors']['entry']

                if type(lldp_neighbors) != list:
                    lldp_neighbors = [lldp_neighbors]
                
                for lldp_n in lldp_neighbors:
                    neighbor_dict = {
                        'ngfw': n.hostname,
                        'local_interface': r['@name'],
                        'remote_interface_id': lldp_n['port-id'],
                        'remote_interface_description': lldp_n['port-description'],
                        'remote_hostname': lldp_n['system-name'],
                    }

                    formatted_lldp_neighbors.append(neighbor_dict)

        return formatted_lldp_neighbors


    def show_bgp_peers(self, ngfw=None, virtual_router=None) -> list:
        """
        This method returns a list of bgp peers
        """

        query = self.session.query(Ngfw)

        if ngfw:
            query = query.filter(Ngfw.hostname == ngfw)
        if virtual_router:
            query = query.join(Ngfw.virtual_routers).filter(VirtualRouter.name == virtual_router)

        ngfw_list = query.all()

        if not ngfw_list:
            return None
        
        formatted_bgp_peers = []

        # For each ngfw in ngfw_list, set the serial of self.xapi to ngfw.serial_number and show lldp neighbors on the xapi object
        for n in ngfw_list:
            self.xapi.serial = n.serial_number
            try:
                self.xapi.op("<show><routing><protocol><bgp><peer></peer></bgp></protocol></routing></show>")
            except pan.xapi.PanXapiError as e:
                raise MTControllerException(f"Issue connecting to Panorama.  Error: {e}")
            
            try:
                bgp_peers = xmltodict.parse("<root>" + self.xapi.xml_result() + "</root>")['root']['entry']
            except:
                continue

            # If results is not a list, make it a list
            if type(bgp_peers) != list:
                bgp_peers = [bgp_peers]
            # For each result, build a dictionary and append to the formatted_results list
            for bgp_p in bgp_peers:
                
                for bgp_p in bgp_peers:
                    bgp_peer_dict = {
                            'ngfw': n.hostname,
                            'virtual_router':bgp_p['@vr'],
                            'peer_name': bgp_p['@peer'], 
                            'peer_group': bgp_p['peer-group'],
                            'peer_router_id': bgp_p['peer-router-id'],
                            'remote_as': bgp_p['remote-as'],
                            'status': bgp_p['status'],
                            'status_duration': bgp_p['status-duration'],
                            'peer_address': bgp_p['peer-address'].split(':')[0],
                            'local_address': bgp_p['local-address'].split(':')[0],
                    }

                    formatted_bgp_peers.append(bgp_peer_dict)

        return formatted_bgp_peers

    def update_ha_status(self, ngfw=None) -> list:
        """
        This method updates the ha status of the ngfws in the database
        """

        message = []

        # Verify panorama ha status
        if self.panorama.alt_ip is not None:

            self.xapi.serial = None

            try:
                self.xapi.op("<show><high-availability><state></state></high-availability></show>")
            except pan.xapi.PanXapiError as e:
                raise MTControllerException(f"Issue connecting to Panorama.  Error: {e}")
            
            ha_info = xmltodict.parse("<root>" + self.xapi.xml_result() + "</root>")['root']

            if ha_info['enabled'] == 'yes':
                if 'active' in ha_info['local-info']['state']:
                    message.append(f"Panorama {self.panorama.hostname} is active")
                else:
                    # Set the sql database entry for panorama.active to False
                    self.panorama.active = False
                    message.append(f"Panorama {self.panorama.hostname} is passive.  Using alt-ip")
                    # Update database
                    self.session.commit()
        else:
            message.append(f"Panorama {self.panorama.hostname} is standalone")

        # If ngfw is present, query the database for the ngfw
        if ngfw:
            ngfws = self.session.query(Ngfw).filter(Ngfw.hostname == ngfw).all()
        # If ngfw is NOT present, query the database for all ngfws
        else:
            ngfws = self.session.query(Ngfw).all()
        
        if not ngfws:
            return None

        # For each ngfw in ngfws, 
        for n in ngfws:
            #if alt_serial is present set self.xapi.serial to ngfw.serial_number
            if n.alt_serial:
                self.xapi.serial = n.serial_number
            else:
                continue
            
            try:
                self.xapi.op("<show><high-availability><state></state></high-availability></show>")
            except pan.xapi.PanXapiError as e:
                raise MTControllerException(f"Issue connecting to Panorama.  Error: {e}")
            
            ha = xmltodict.parse("<root>" + self.xapi.xml_result() + "</root>")['root']['group']['local-info']

            # if ha['state'] is not active set database ngfw.active to False
            if ha['state'] != 'active':
                n.active = False
                message.append(f"{n.hostname} is not active, using alternate serial")
            else:
                n.active = True
                message.append(f"{n.hostname} is active")

        self.session.commit()

        return message