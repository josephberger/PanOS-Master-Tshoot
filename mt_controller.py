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

import pan.xapi
import xmltodict
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from models import Base, Ngfw, Route, VirtualRouter, Interface, Panorama, Neighbor, BGPPeer

class MTBuilderException(Exception):
    pass

class MTBuilder:
    def __init__(self, db_uri='sqlite:///mtdb.db', timeout=5) -> None:
        self.db_uri = db_uri

        try:
            self.timeout = int(timeout)
        except:
            raise MTBuilderException(f"timeout must be an integer")

    def build_database(self) -> str:
        """
        Builds the sqlite database
        """

        try:
            # create the database engine
            engine = create_engine(self.db_uri)

            # create the tables in the database
            Base.metadata.create_all(engine)

            return "Empty database successfully created!"
        except Exception as e:
            return "Issue connecting to the database.  Error: {e}"
        
    def add_panorama(self, ip_address, username, password) -> str:
        """
        Adds a panorama to the database
        """

        # create the database engine
        try:
            engine = create_engine(self.db_uri)
            Session = sessionmaker(bind=engine)
            session = Session()
        except Exception as e:
            raise MTBuilderException(f"Error: database communication with {self.db_uri}.")

        # query the database for all panoramas
        try:
            pan_list = session.query(Panorama).all()
        except Exception as e:
            raise MTBuilderException(f"Error: database communication with {self.db_uri}.")

        # if the panorama is already in the database
        for p in pan_list:
            if p.ip_address == ip_address:
                raise MTBuilderException(f"Error: Panorama {ip_address} already in database.")

        try:
            xapi = pan.xapi.PanXapi(api_username=username, api_password=password, hostname=ip_address)
            xapi.timeout = self.timeout

            # show the system info
            xapi.op("<show><system><info></info></system></show>")
            system_info = xmltodict.parse('<root>' + xapi.xml_result() + '</root>')['root']

            if 'system-mode' not in system_info['system']:
                raise MTBuilderException(f"Error: Device at {ip_address} is not a Panorama.")

            serial = system_info['system']['serial']

            # show the HA info
            xapi.op("<show><high-availability><state></state></high-availability></show>")
            ha_info = xmltodict.parse('<root>' + xapi.xml_result() + '</root>')['root']

            if ha_info['enabled'] == 'yes':
                if 'active' in ha_info['local-info']['state']:
                    active = True
                else:
                    active = False
                alt_ip = ha_info['peer-info']['mgmt-ip']
            else:
                active = True
                alt_ip = None


        except pan.xapi.PanXapiError as e:

            raise MTBuilderException(f"{e}")
        
        except Exception as e:

            raise MTBuilderException(f"{e}")
        
        new_panorama = Panorama(hostname=system_info['system']['hostname'], serial_number=serial, ip_address=ip_address, alt_ip=alt_ip, active=active, api_key=xapi.api_key)

        session.add(new_panorama)

        session.commit()

        return f"{system_info['system']['hostname']} successfully added to database."
    
    def add_ngfw(self, ip_address, username, password) -> str:
        """
        Adds a ngfw to the database
        """

        # create the database engine
        try:
            engine = create_engine(self.db_uri)
            Session = sessionmaker(bind=engine)
            session = Session()
        except Exception as e:
            raise MTBuilderException(f"Error: database communication with {self.db_uri}.")

        # create list of serial numbers in the database
        serial_numbers = []

        try:
            ngfw_list = session.query(Ngfw).all()
        except Exception as e:
            raise MTBuilderException(f"Error: database communication with {self.db_uri}.")

        for n in ngfw_list:
            serial_numbers.append(n.serial_number)
        
        try:
            xapi = pan.xapi.PanXapi(api_username=username, api_password=password, hostname=ip_address)
            xapi.timeout = self.timeout
            
            # show the system info
            xapi.op("<show><system><info></info></system></show>")
            device_info = xmltodict.parse('<root>' + xapi.xml_result() + '</root>')['root']
            
            # if PA- not in model, exit
            if 'PA-' not in device_info['system']['model']:
                raise MTBuilderException(f"Error: Device at {ip_address} is not a NGFW.")

            # show the HA info
            xapi.op("<show><high-availability><state></state></high-availability></show>")
            ha_info = xmltodict.parse('<root>' + xapi.xml_result() + '</root>')['root']

            ngfw_info = {
                'hostname': device_info['system']['hostname'],
                'serial_number': device_info['system']['serial'],
                'ip_address': ip_address,
                'model': device_info['system']['model'],
                'api_key': xapi.api_key,
                'panorama_id': None
            }

            # if serial number is not in serial_numbers, add to the database
            if ngfw_info['serial_number'] in serial_numbers:
                raise MTBuilderException(f"Error: NGFW {ngfw_info['hostname']} {ngfw_info['serial_number']} already in database.")

            # determine HA status
            if ha_info['enabled'] == 'yes':

                # If ha state is active, set active to true and alt_serial to peer serial number
                if ha_info['group']['local-info']['state'] == 'active':
                    ngfw_info['active'] = True
                else:
                    ngfw_info['active'] = False
                
                ngfw_info['alt_serial'] = device_info['serial'],
                ngfw_info['alt_ip'] = device_info['group']['peer-info']['mgmt-ip']

            else:
                ngfw_info['active'] = True
                ngfw_info['alt_serial'] = None
                ngfw_info['alt_ip'] = None
            
            new_ngfw = Ngfw(**ngfw_info)

            session.add(new_ngfw)
                
            session.commit()

            return f"{ngfw_info['hostname']} {new_ngfw.serial_number} successfully added to database"

        except pan.xapi.PanXapiError as e:
            raise MTBuilderException(f"{e}")
    
    def delete_panorama(self, serial_number) -> str:
        """
        Deletes a panorama from the database
        """

        message = []
        # query database for panorama based on ip address
        try:
            engine = create_engine(self.db_uri)
            Session = sessionmaker(bind=engine)
            session = Session()
            panorama = session.query(Panorama).filter(Panorama.serial_number == serial_number).first()
        except Exception as e:
            raise MTBuilderException(f"Issue communicating with database {self.db_uri}.")
        
        if not panorama:
            raise MTBuilderException(f"Panorama {serial_number} not found in database.")
        
        # query the database for all ngfws associated with the panorama
        ngfws = session.query(Ngfw).join(Ngfw.panorama).filter(Panorama.serial_number == serial_number).all()

        # delete the ngfws associated with the panorama
        for n in ngfws:
            try:
                message.append(self.delete_ngfw(n.serial_number))
            except Exception as e:
                message.append(str(e))
        
        # delete the panorama
        try:
            session.delete(panorama)
        except Exception as e:
            raise MTBuilderException(f"Error: {serial_number} not deleted from database.")
        
        session.commit()

        message.append(f"{panorama.hostname} {panorama.serial_number} successfully deleted from database")

        return message

    def delete_ngfw(self, serial_number) -> str:
        """
        Deletes a ngfw from the database
        """

        # query database for ngfw based on serial number
        try:
            engine = create_engine(self.db_uri)
            Session = sessionmaker(bind=engine)
            session = Session()
            ngfw = session.query(Ngfw).filter(Ngfw.serial_number == serial_number).first()
        except Exception as e:
            raise MTBuilderException(f"Erorr: communicating with database {self.db_uri}.")
        
        if not ngfw:
            raise MTBuilderException(f"Error: NGFW {serial_number} not found in database.")
        
        # query the database for all routes, interfaces, virtual routers, bgp peers and neighbors associated with the ngfw
        routes = session.query(Route).join(Route.virtual_router).join(VirtualRouter.ngfw).filter(Ngfw.serial_number == serial_number).all()
        interfaces = session.query(Interface).join(Interface.virtual_router).join(VirtualRouter.ngfw).filter(Ngfw.serial_number == serial_number).all()
        virtual_routers = session.query(VirtualRouter).join(VirtualRouter.ngfw).filter(Ngfw.serial_number == serial_number).all()
        bgp_peers = session.query(BGPPeer).join(BGPPeer.ngfw).filter(Ngfw.serial_number == serial_number).all()
        neighbors = session.query(Neighbor).join(Neighbor.ngfw).filter(Ngfw.serial_number == serial_number).all()

        
        # delete the routes, interfaces, virtual routers, bgp peers and neighbors associated with the ngfw

        for r in routes:
            session.delete(r)
        for i in interfaces:
            session.delete(i)
        for bgp in bgp_peers:
            session.delete(bgp)
        for vr in virtual_routers:
            session.delete(vr)
        for n in neighbors:
            session.delete(n)
        
        # delete the ngfw
        try:
            session.delete(ngfw)
        except Exception as e:
            raise MTBuilderException(f"Error: NGFW {serial_number} not deleted from database.")
        
        session.commit()

        return f"{ngfw.hostname} {ngfw.serial_number} deleted from database"

class MTControllerException(Exception):
    pass

class MTController:

    def __init__(self, db_uri, timeout=5) -> None:

        # verify db_uri is present
        if not db_uri:
            raise MTControllerException("No db_uri provided")
        self.db_uri = db_uri

        try:
            engine = create_engine(db_uri, echo=False)
            Session = sessionmaker(bind=engine)
            self.session = Session()
        except Exception as e:
            raise MTControllerException(f"Issue communicating with database {db_uri}.  Error: {str(e)}")

        self.timeout = timeout

    def __set_xapi(self, ngfw) -> None:
        """
        This method sets the xapi object based on the ngfw
        """

        # if the ngfw has no panorama, build the appropriate xapi object
        if not ngfw.panorama:
            if ngfw.active:
                self.xapi = pan.xapi.PanXapi(api_key=ngfw.api_key, hostname=ngfw.ip_address)
            else:
                self.xapi = pan.xapi.PanXapi(api_key=ngfw.api_key, hostname=ngfw.alt_ip)

        else:
            # if ngfw active set the serial number to the xapi object else set the alt_serial
            self.xapi = pan.xapi.PanXapi(api_key=ngfw.panorama.api_key, hostname=ngfw.panorama.ip_address)

            if ngfw.active:
                self.xapi.serial =  ngfw.serial_number
            else:
                self.xapi.serial =  ngfw.alt_serial

        self.xapi.timeout = self.timeout

    def get_inventory(self) -> dict:
        """
        Returns database inventory
        """

        # for each table in the database, get the count
        inventory = {
            'Panoramas' : self.session.query(Panorama).count(),
            'NGFWs': self.session.query(Ngfw).count(),
            'Virtual Routers': self.session.query(VirtualRouter).count(),
            'Interfaces': self.session.query(Interface).count(),
            'Routes': self.session.query(Route).count(),
            'BGP Peers': self.session.query(BGPPeer).count(),
            'Neighbors': self.session.query(Neighbor).count()
        }

        return inventory

    def import_panorama_devices(self, pan_filter=None) -> list:
        """
        This method imports the devices from the Panorama
        """

        message = []

        pan_query = self.session.query(Panorama)

        if pan_filter:
            pan_query = pan_query.filter(Panorama.hostname == pan_filter)
        
        panorama_list = pan_query.all()

        if not panorama_list:
            message.append("No Panoramas in database.")
            return message

        if panorama_list:

            serial_numbers = [] # for checking if serial number is in database

            for panorama in panorama_list:
                # create the xapi object
                self.xapi = pan.xapi.PanXapi(api_key=panorama.api_key, hostname=panorama.ip_address)

                # show devices all on the xapi object
                try:
                    self.xapi.op("<show><devices><all></all></devices></show>")
                except pan.xapi.PanXapiError as e:
                    message.append(f"{panorama.hostname}: {e}")
                    continue
                
                devices = xmltodict.parse("<root>" + self.xapi.xml_result() + "</root>")['root']['devices']

                if devices:
                    devices = devices['entry']
                else:
                    message.append(f"No devices found in {panorama.hostname}")
                    continue

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

                    # if serial number is not in serial_numbers, add to the database
                    if d['serial'] in serial_numbers:
                        message.append(f"{d['hostname']} {d['serial']} already in database.  Skipping...")
                        continue
                    
                    # if connected is not yes continue
                    if d['connected'] != 'yes':
                        message.append(f"{d['hostname']} {d['serial']} not connected.  Skipping...")
                        continue
                    
                    ngfw_info = {
                        'hostname': d['hostname'],
                        'serial_number': d['serial'],
                        'ip_address': d['ip-address'],
                        'model': d['model'],
                        'panorama_id': panorama.id
                    }

                    # determine HA status
                    if 'ha' in d:
                        # if ha state is active, set active to true and alt_serial to peer serial number
                        if d['ha']['state'] == 'active':
                            ngfw_info['active'] = True
                            ngfw_info['alt_serial'] = d['ha']['peer']['serial'] 
                        else:
                            message.append(f"{ngfw_info['hostname']} {ngfw_info['serial_number']} is not active.  Skipping...")
                            continue
                    else:
                        ngfw_info['active'] = True
                        ngfw_info['alt_serial'] = None
                    
                    new_ngfw = Ngfw(**ngfw_info)

                    self.session.add(new_ngfw)

                    message.append(f"{ngfw_info['hostname']} {new_ngfw.serial_number} successfully added to database") 
                    
            self.session.commit()

        return message

    def refresh_ngfws(self, ngfw=None) -> list:
        """
        Refreshes the ngfws in the database
        """

        message = []

        # create a query for ngfws
        ngfw_query = self.session.query(Ngfw)

        # if ngfw is present, filter the query for the ngfw
        if ngfw:
            ngfw_query = ngfw_query.filter(Ngfw.hostname == ngfw)

        
        ngfw_list = ngfw_query.all()

        if not ngfw_list:
            message.append("No ngfws found in database.  Exiting...")
            return message

        # for each ngfw
        for n in ngfw_list:

            # time of refresh
            refresh_time = str(datetime.datetime.now().isoformat())

            # set hte MTD object
            mtd = MTDevice(ngfw=n, timeout=self.timeout)

            ## interfaces block ##
            interface_list = []

            response = self.show_interfaces(n.hostname)
            interfaces = response['results']
            m = response['message']

            # if no interfaces are found, skip the ngfw and append the message
            if m:
                message.append(m[0])
                continue

            # create a query for interfaces, routes, virtual routers, and ngfws
            iq = self.session.query(Interface).join(Interface.virtual_router).join(VirtualRouter.ngfw).filter(Ngfw.id == n.id).all()
            rq = self.session.query(Route).join(Route.virtual_router).join(VirtualRouter.ngfw).filter(Ngfw.id == n.id).all()
            bq = self.session.query(BGPPeer).join(BGPPeer.ngfw).filter(Ngfw.id == n.id).all()
            vq = self.session.query(VirtualRouter).join(VirtualRouter.ngfw).filter(Ngfw.id == n.id).all()
            nq = self.session.query(Neighbor).join(Neighbor.ngfw).filter(Ngfw.id == n.id).all()

            # create a list of lists containing the objects to delete
            objects_to_delete = [iq, rq, bq, vq, nq]

            for obj_list in objects_to_delete:
                for obj in obj_list:
                    self.session.delete(obj)

            ## virtual routers block ##
            virtual_routers = set()

            for i in interfaces:
                virtual_routers.add(i['virtual_router'])

            for vr in virtual_routers:
                new_vr = VirtualRouter(name=vr, ngfw_id=n.id)
                self.session.add(new_vr)
            
            self.session.commit()

            ## continue interfaces block ##
            for i in interfaces:
                vr = self.session.query(VirtualRouter).filter(VirtualRouter.name == i['virtual_router']).filter(VirtualRouter.ngfw_id == n.id).first()

                new_interface = Interface(
                                            name=i['name'],
                                            tag=i['tag'],
                                            vsys=i['vsys'],
                                            zone=i['zone'],
                                            ip=i['ip'],
                                            virtual_router_id=vr.id
                                        )
                
                interface_list.append(new_interface)

                self.session.add(new_interface)

            self.session.commit()

            ## routes block ##
            try:
                self.xapi.op("<show><routing><route><afi>ipv4</afi></route></routing></show>")
            except pan.xapi.PanXapiError as e:
                message.append(f"{n.hostname}: {e}")
                continue
            
            try:
                routes = xmltodict.parse("<root>" + self.xapi.xml_result() + "</root>")['root']['entry']
            except:
                continue

            # if routes is not a list, make it a list
            if type(routes) != list:
                routes = [routes]

            # for each route, get the id of the virtual router based on name and ngfw, add to the database
            for r in routes:

                vr = self.session.query(VirtualRouter).filter(VirtualRouter.name == r.get('virtual-router', 'N/A')).filter(VirtualRouter.ngfw_id == n.id).first()
                new_route = Route(virtual_router_id=vr.id, 
                                  destination=r.get('destination', 'N/A'), 
                                  nexthop=r.get('nexthop', 'N/A'), 
                                  metric=r.get('metric', 'N/A'), 
                                  flags=r.get('flags', 'N/A'), 
                                  age=r.get('age', 'N/A'), 
                                  interface=r.get('interface', 'N/A'), 
                                  route_table=r.get('route-table', 'N/A'))

                # try to determine BGP route egress interface
                if "B" in new_route.flags:

                    bgp_nexthop = ipaddress.IPv4Address(new_route.nexthop)
                    
                    for i in interface_list:

                        try:
                            cidr = ipaddress.IPv4Network(i.ip, strict=False)
                        except Exception as e:
                            continue

                        if bgp_nexthop in cidr:
                            new_route.interface = i.name
                            break

                self.session.add(new_route)

            self.session.commit()

            ## BGP peers block ##

            try:
                bgp_peers = mtd.show_bgp_peers()
            except MTDeviceException as e:
                bgp_peers = []

            if bgp_peers:
                for bgp_p in bgp_peers:
                    vr = self.session.query(VirtualRouter).filter(VirtualRouter.name == bgp_p['virtual_router']).filter(VirtualRouter.ngfw_id == n.id).first()
                    self.session.add(BGPPeer(
                                            ngfw_id=n.id,
                                            virtual_router_id=vr.id,
                                            peer_name=bgp_p['peer_name'],
                                            peer_group=bgp_p['peer_group'],
                                            peer_router_id=bgp_p['peer_router_id'],
                                            remote_as=bgp_p['remote_as'],
                                            status=bgp_p['status'],
                                            status_duration=bgp_p['status_duration'],
                                            peer_address=bgp_p['peer_address'],
                                            local_address=bgp_p['local_address']
                                        ))

            ## neighbors block ##

            try:
                lldp_neighbors = mtd.show_neighbors()
            except MTDeviceException as e:
                lldp_neighbors = []

            for lldp_n in lldp_neighbors:
                    self.session.add(Neighbor(
                            ngfw_id=n.id,
                            local_interface=lldp_n['local_interface'],
                            remote_interface_id=lldp_n['remote_interface_id'] or None,
                            remote_interface_description=lldp_n['remote_interface_description'] or None,
                            remote_hostname=lldp_n['remote_hostname'] or None
                            ))

            # set the ngfw refresh time
            n.last_update = refresh_time

            self.session.commit()

            message.append(f"{n.hostname} {n.serial_number} refreshed")
        
        return message
    
    def get_routes(self, ngfw=None, virtual_router=None, destination=None, flags=None) -> dict:
        """
        Returns routes
        """

        response = {'message':[], 'results':None}

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
            response['message'].append("No routes found.")
            return response

        formatted_routes = []
        
        # for each route, build a dictionary and append to the formatted_routes list
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

            # if H (Host) is present in the flags string, query the database for interface based on destination, where destination is in the interface ip address range
            if 'H' in route_data['flags']:
                interface_info = self.session.query(Interface).filter(Interface.ip.contains(route_data['destination'].replace("/32",""))).first()
                if interface_info:
                    route_data['interface'] = interface_info.name
                    route_data['zone'] = interface_info.zone
                else:
                    route_data['zone'] = "None"
                    route_data['interface'] = "None"

            # zone based on query of interface table from interface name, ngfw, and virtual router
            else:
                interface_info = self.session.query(Interface).filter(Interface.name == r.interface).filter(Interface.virtual_router_id == r.virtual_router_id).first()
                if interface_info:
                    route_data['zone'] = interface_info.zone
                else:
                    route_data['zone'] = "None"

            formatted_routes.append(route_data)

        response['results'] = formatted_routes

        return response
    
    def get_interfaces(self, ngfw=None, virtual_router=None) -> dict:
        """
        Rreturns interfaces
        """

        response = {'message':[], 'results':None}

        query = self.session.query(Interface).join(Interface.virtual_router)

        if ngfw:
            query = query.join(VirtualRouter.ngfw).filter(Ngfw.hostname == ngfw)
        if virtual_router:
            query = query.filter(VirtualRouter.name == virtual_router)
        
        interfaces = query.all()

        if not interfaces:
            response['message'].append("No interfaces found.")
            return response
            
        formatted_interfaces = []

        # format each interface dictionary and append
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

        response['results'] = formatted_interfaces

        return response
    
    def get_bgp_peers(self, ngfw=None, virtual_router=None) -> dict:
        """
        Returns BGP peers
        """

        response = {'message':[], 'results':None}

        query = self.session.query(BGPPeer)

        if ngfw:
            query = query.join(BGPPeer.ngfw).filter(Ngfw.hostname == ngfw)
        if virtual_router:
            query = query.join(BGPPeer.virtual_router).filter(VirtualRouter.name == virtual_router)
        
        bgp_peers = query.all()

        if not bgp_peers:
            response['message'].append("No BGP peers found.")
            return response
        
        formatted_bgp_peers = []

        # for each bgp peer in bgp_peers, build a dictionary and append to the formatted_bgp_peers list
        for bgp_p in bgp_peers:
            bgp_peer_dict = {
                'ngfw': bgp_p.ngfw.hostname,
                'virtual_router': bgp_p.virtual_router.name,
                'peer_name': bgp_p.peer_name,
                'peer_group': bgp_p.peer_group,
                'peer_router_id': bgp_p.peer_router_id,
                'remote_as': bgp_p.remote_as,
                'status': bgp_p.status,
                'status_duration': bgp_p.status_duration,
                'peer_address': bgp_p.peer_address,
                'local_address': bgp_p.local_address
            }

            formatted_bgp_peers.append(bgp_peer_dict)

        response['results'] = formatted_bgp_peers

        return response
        
    def get_virtual_routers(self, ngfw=None, virtual_router=None) -> dict:
        """
        Returns virtual routers
        """

        response = {'message':[], 'results':None}

        query = self.session.query(VirtualRouter)

        if ngfw:
            query = query.join(VirtualRouter.ngfw).filter(Ngfw.hostname == ngfw)
        if virtual_router:
            query = query.filter(VirtualRouter.name == virtual_router)
        
        vr_list = query.all()

        if not vr_list:
            response['message'].append("No virtual routers found.")
            return response
        
        formatted_virtual_routers = []

        # for each virtual-router in virtual_routers, build a dictionary and append to the formatted_virtual_routers list
        for vr in vr_list:
            vr_dict = {
                'ngfw_id': vr.ngfw_id,
                'ngfw': vr.ngfw.hostname,
                'virtual_router': vr.name,
                'route_count': len(vr.routes),
                'interface_count': len(vr.interfaces)
            }

            formatted_virtual_routers.append(vr_dict)

        response['results'] = formatted_virtual_routers
        return response
    
    def get_ngfws(self, panorama=None) -> dict:
        """
        Returns ngfws
        """

        response = {'message':[], 'results':None}

        query = self.session.query(Ngfw)

        if panorama:
            query = query.join(Ngfw.panorama).filter(Panorama.hostname == panorama)
        
        ngfws = query.all()

        if ngfws:
        
            formatted_ngfws = []

            # for each ngfw in ngfws, build a dictionary and append to the formatted_ngfws list
            for ngfw in ngfws:
                ngfw_dict = {
                    'hostname': ngfw.hostname,
                    'serial_number': ngfw.serial_number,
                    'ip_address': ngfw.ip_address,
                    'model': ngfw.model,
                    'alt_serial': ngfw.alt_serial or '',
                    'active': 'yes' if ngfw.active else 'no',
                    'panorama': ngfw.panorama.hostname if ngfw.panorama else '',  # Handle if panorama is None
                    'last_update': ngfw.last_update or '',
                    'ngfw_id': ngfw.id,
                }

                formatted_ngfws.append(ngfw_dict)
            response['results'] = formatted_ngfws
        else:
            response['message'].append("No ngfws found.")

        return response
    
    def get_neighbors(self, ngfw=None) -> dict:
        """
        Returns neighbors
        """

        response = {'message':[], 'results':None}

        query = self.session.query(Neighbor)

        if ngfw:
            query = query.join(Neighbor.ngfw).filter(Ngfw.hostname == ngfw)

        neighbors = query.all()

        if neighbors:
        
            formatted_neighbors = []

            # for each neighbor in neighbors, build a dictionary and append to the formatted_neighbors list
            for n in neighbors:
                neighbor_dict = {
                    'ngfw': n.ngfw.hostname,
                    'local_interface': n.local_interface,
                    'remote_interface_id': n.remote_interface_id or '',
                    'remote_interface_description': n.remote_interface_description or '',
                    'remote_hostname': n.remote_hostname or ''
                }

                formatted_neighbors.append(neighbor_dict)
            response['results'] = formatted_neighbors
        else:
            response['message'].append("No neighbors found.")

        return response

    def get_panoramas(self) -> dict:
        """
        Returns panoramas
        """
        response = {'message':[], 'results':None}

        panorama = self.session.query(Panorama).all()

        if panorama:
            formatted_panorama = []

            # for each panorama get the hostname, ip address, alt ip, and active
            for p in panorama:
                pan_info = {
                    'hostname': p.hostname,
                    'serial_number': p.serial_number,
                    'ip_address': p.ip_address,
                    'alt_ip': p.alt_ip or "",
                    'active': 'yes' if p.active else 'no',
                    'ngfws': len(p.ngfws)
                }

                formatted_panorama.append(pan_info)
            
            response['results'] = formatted_panorama
        else:
            response['message'].append("No panoramas found.")

        return response
    
    def calculate_fib_lookup(self, ip_address, vr_query=None, ngfw_query=None) -> dict:
        """
        Returns fib calculations
        """

        response = {'message':[], 'results':None}

        query = self.session.query(VirtualRouter)

        if ngfw_query:
            query = query.join(VirtualRouter.ngfw).filter(Ngfw.hostname == ngfw_query)
        if vr_query:
            query = query.filter(VirtualRouter.name == vr_query)

        virtual_router_list = query.all()

        if not virtual_router_list:
            response['message'].append("No virtual routers found.")
            return response

        # results to be returned
        formatted_results = []

        # convert ip_address to ipaddress object
        try:
            ip_address = ipaddress.IPv4Address(ip_address)
        except:
            raise MTControllerException(f"Invalid IPv4 Address: {ip_address}")

        # for each virtual-router get routes and compare ip_address to destination
        for vr in virtual_router_list:
            routes = self.session.query(Route).join(Route.virtual_router).filter(VirtualRouter.name == vr.name).filter(VirtualRouter.ngfw_id == vr.ngfw_id).all()

            # if routes is empty, continue
            if not routes:
                continue
            
            dst = {}
            prefix = 0

            # for each route, if the destination is not in the ip_address, continue
            for r in routes:

                # if the route is not active, continue
                if "A" not in r.flags:
                    continue

                destination = ipaddress.IPv4Network(r.destination)
                if ip_address in destination:
                    dst[destination.prefixlen] = r
                    if int(destination.prefixlen) > prefix:
                        prefix = int(destination.prefixlen)

            # if no results found for prefixs' (likley caused by a vr with no default route), continue
            if len(dst) == 0:

                formatted_results.append( {
                'ngfw': vr.ngfw.hostname,
                'virtual_router': vr.name,
                'destination': "None",
                'nexthop': "None",
                'flags': "None",
                'interface': "None",
                'zone': 'None'
                })

                continue
            
            # route data to be returned
            route_data = {
                'ngfw': vr.ngfw.hostname,
                'virtual_router': vr.name,
                'destination': dst[prefix].destination,
                'nexthop': dst[prefix].nexthop,
                'flags': dst[prefix].flags,
                'interface': dst[prefix].interface or "None",
            }

            # if H (host) is present in the flags string, query the database for interface based on destination, where destination is in the interface ip address range
            if 'H' in route_data['flags']:
                interface_info = self.session.query(Interface).filter(Interface.ip.contains(route_data['destination'].replace("/32",""))).first()
                if interface_info:
                    route_data['interface'] = interface_info.name
                    route_data['zone'] = interface_info.zone
                else:
                    route_data['zone'] = "None"
                    route_data['interface'] = "None"

            # zone based on query of interface table from interface name, ngfw, and virtual router
            else:
                interface_info = self.session.query(Interface).filter(Interface.name == route_data['interface']).filter(Interface.virtual_router_id == r.virtual_router_id).first()
                if interface_info:
                    route_data['zone'] = interface_info.zone
                else:
                    route_data['zone'] = "none"

            # verify next hop
            if route_data['nexthop'] == "0.0.0.0":
                route_data['nexthop'] = "self"

            formatted_results.append(route_data)

        response['results'] = formatted_results
        return response
     
    def test_fib_lookup(self, ip_address, vr_query=None, ngfw_query=None) -> dict:
        """
        Returns fib lookup test results from API
        """

        response = {'message':[], 'results':None}

        query = self.session.query(VirtualRouter)

        if ngfw_query:
            query = query.join(VirtualRouter.ngfw).filter(Ngfw.hostname == ngfw_query)
        if vr_query:
            query = query.filter(VirtualRouter.name == vr_query)

        virtual_routers = query.all()
        
        if not virtual_routers:
            response['message'].append("No virtual routers found.")
            return response

        formatted_results = []

        # for each virtual-router build an xapi object
        for vr in virtual_routers:
            
            self.__set_xapi(vr.ngfw)

            # show routing fib ip-address <ip_address> on the xapi object
            try:
                self.xapi.op(f"<test><routing><fib-lookup><ip>{ip_address}</ip><virtual-router>{vr.name}</virtual-router></fib-lookup></routing></test>")
            except pan.xapi.PanXapiError as e:
                response['message'].append(f"{vr.ngfw.hostname}: {e}")
                continue

            try:
                result = xmltodict.parse("<root>" + self.xapi.xml_result() + "</root>")['root']
            except:
                continue
            
            # if 'interface' is not in result, set result to none fields and continue
            if 'interface' not in result:
                result = {'ngfw': vr.ngfw.hostname, 'virtual_router': vr.name, 'interface': 'None', 'nexthop': 'None', 'zone': 'None'}
                formatted_results.append(result)
                continue

            # zone based on query of interface table from interface name, ngfw, and virtual router
            zone_info = self.session.query(Interface).filter(Interface.name == result['interface']).filter(Interface.virtual_router_id == vr.id).first()
            if zone_info:
                zone = zone_info.zone
            else:
                zone = "None"

            # check if nh is a valid key
            if result['nh'] not in result:
                next_hop = 'self'
            else:
                next_hop = result[result['nh']]

            # create dictionary with these values: vr.ngfw.hostname, vr.name, result['interface'], result[result['nh']], zone
            result = {
                    'ngfw': vr.ngfw.hostname,
                    'virtual_router': vr.name,
                    'interface': result['interface'],
                    'nexthop': next_hop,
                    'zone': zone
                    }

            formatted_results.append(result)

        response['results'] = formatted_results
        return response
    
    def show_interfaces(self, ngfw=None, virtual_router=None) -> dict:
        """
        Returns interfaces from API
        """
        
        response = {'message':None, 'results':None}

        query = self.session.query(Ngfw)

        if ngfw:
            query = query.filter(Ngfw.hostname == ngfw)
        
        ngfw_list = query.all()

        if not ngfw_list:
            response['message'] = ["No NGFWs found to check interfaces."]
            return response
        
        formatted_interfaces = []
        message = []

        for n in ngfw_list:

            self.__set_xapi(n)

            try:  
                self.xapi.op("<show><interface>all</interface></show>")
            except pan.xapi.PanXapiError as e:
                message.append(f"{n.hostname}: {e}")
                continue
            
            interfaces = xmltodict.parse("<root>" + self.xapi.xml_result() + "</root>")['root']['ifnet']['entry']

            # if interfaces is not a list, make it a list
            if type(interfaces) != list:
                interfaces = [interfaces]

            # for each interface, get the id of the virtual router based on name and ngfw, add to the database
            for i in interfaces:
                if 'fwd' not in i:
                    continue
                if 'vr' not in i['fwd']:
                    continue
                if i['zone'] == None:
                    continue
                
                vr_name = i['fwd'].replace('vr:', '')

                if virtual_router:
                    if vr_name != virtual_router:
                        continue

                new_interface = {
                    'ngfw': n.hostname,
                    'name': i.get('name', 'N/A'),
                    'tag': i.get('tag', 'N/A'),
                    'vsys': i.get('vsys', 'N/A'),
                    'ip': i.get('ip', 'N/A'),
                    'zone': i.get('zone', 'N/A'),
                    'virtual_router': vr_name
                }
                formatted_interfaces.append(new_interface)

        response['results'] = formatted_interfaces
        response['message'] = message
        return response
    
    def show_neighbors(self, ngfw=None) -> dict:
        """
        Returns neighbors from API
        """

        response = {'message':[], 'results':None}

        query = self.session.query(Ngfw)

        if ngfw:
            query = query.filter(Ngfw.hostname == ngfw)
        
        ngfw_list = query.all()

        if not ngfw_list:
            response['message'].append("No NGFWs found to check neighbors.")
            return response
        
        formatted_lldp_neighbors = []

        # for each ngfw in ngfws, set the serial of self.xapi to ngfw.serial_number and show lldp neighbors on the xapi object
        for n in ngfw_list:
            
            mtdevice = MTDevice(n)

            try:
                results = mtdevice.show_neighbors()
                results = [{'ngfw': n.hostname, **d} for d in results]
            except MTDeviceException as e:
                response['message'].append(str(e))
                continue

            formatted_lldp_neighbors.extend(results)

            continue
        
        response['results'] = formatted_lldp_neighbors
        return response

    def show_bgp_peers(self, ngfw=None, virtual_router=None) -> dict:
        """
        Returns BGP peers from API
        """

        response = {'message':[], 'results':None}

        query = self.session.query(Ngfw)

        if ngfw:
            query = query.filter(Ngfw.hostname == ngfw)
        if virtual_router:
            query = query.join(Ngfw.virtual_routers).filter(VirtualRouter.name == virtual_router)

        ngfw_list = query.all()

        if not ngfw_list:
            response['message'] = ["No NGFWs found to check BGP."]
            return response
        
        formatted_bgp_peers = []

        # for each ngfw in ngfw_list, set the serial of self.xapi to ngfw.serial_number and show lldp neighbors on the xapi object
        for n in ngfw_list:
            
            mtdevice = MTDevice(n)

            try:
                results = mtdevice.show_bgp_peers()
            except MTDeviceException as e:
                response['message'].append(str(e))
                continue

            for bgp_p in results:
                bgp_p['ngfw'] = n.hostname
                if virtual_router:
                    if bgp_p['virtual_router'] == virtual_router:
                        formatted_bgp_peers.append(bgp_p)
                else:
                    formatted_bgp_peers.append(bgp_p)

        response['results'] = formatted_bgp_peers

        return response

    def update_ha_status(self, ngfw=None) -> list:
        """
        Updates the database with HA status and returns a list of messages
        """

        message = []

        panorama_list = self.session.query(Panorama).all()

        # verify panorama ha status
        for panorama in panorama_list:
            if panorama.alt_ip is not None:

                self.xapi = pan.xapi.PanXapi(api_key=panorama.api_key, hostname=panorama.ip_address)

                try:
                    self.xapi.op("<show><high-availability><state></state></high-availability></show>")
                except pan.xapi.PanXapiError as e:
                    message.append("{panorama.hostname} {e}")
                    continue
                
                ha_info = xmltodict.parse("<root>" + self.xapi.xml_result() + "</root>")['root']

                if ha_info['enabled'] == 'yes':
                    if 'active' in ha_info['local-info']['state']:
                        message.append(f"Panorama {panorama.hostname} is active")
                    else:
                        # Set the sql database entry for panorama.active to False
                        panorama.active = False
                        message.append(f"Panorama {panorama.hostname} is passive.  Using alt-ip")
                        # Update database
                        self.session.commit()
            else:
                message.append(f"Panorama {panorama.hostname} is not ha")

        # if ngfw is present, query the database for the ngfw
        if ngfw:
            ngfws = self.session.query(Ngfw).filter(Ngfw.hostname == ngfw).all()
        # if ngfw is NOT present, query the database for all ngfws
        else:
            ngfws = self.session.query(Ngfw).all()
        
        if not ngfws:
            return None

        # for each ngfw in ngfws, 
        for n in ngfws:
            # if alt_serial is present set self.xapi.serial to ngfw.serial_number
            if n.alt_serial:
                self.__set_xapi(n)
            else:
                message.append(f"NGFW {n.hostname} is not ha")
                continue
            
            try:
                self.xapi.op("<show><high-availability><state></state></high-availability></show>")
            except pan.xapi.PanXapiError as e:
                message.append(f"{n.hostname}: {e}")
                continue
            
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
    
class MTDeviceException(Exception):
    pass

class MTDevice:
    def __init__(self, ngfw, timeout=5) -> None:
        
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
        Returns neighbors from API
        """
        # for each ngfw in ngfws, set the serial of self.xapi to ngfw.serial_number and show lldp neighbors on the xapi object
        
        try:
            self.xapi.op("<show><lldp><neighbors>all</neighbors></lldp></show>")
        except pan.xapi.PanXapiError as e:
            raise MTDeviceException(f"{self.ngfw.hostname}: {e}")
        
        results = xmltodict.parse("<root>" + self.xapi.xml_result() + "</root>")['root']['entry']

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
                neighbor_dict = {
                    'local_interface': r['@name'] or "None",
                    'remote_interface_id': lldp_n['port-id'] or "None",
                    'remote_interface_description': lldp_n['port-description'] or "",
                    'remote_hostname': lldp_n['system-name'] or "None",
                }
                response.append(neighbor_dict)
        
        return response
    
    def show_bgp_peers(self) -> list:
        """
        Returns BGP peers from API
        """
        
        response = []

        # for each ngfw in ngfw_list, set the serial of self.xapi to ngfw.serial_number and show lldp neighbors on the xapi object

        try:
            self.xapi.op("<show><routing><protocol><bgp><peer></peer></bgp></protocol></routing></show>")
            bgp_peers = xmltodict.parse("<root>" + self.xapi.xml_result() + "</root>")['root']['entry']
        except pan.xapi.PanXapiError as e:
            raise MTDeviceException(f"{self.ngfw.hostname} {e}")
        except TypeError:
            raise MTDeviceException(f"{self.ngfw.hostname} No BGP peers found.")

        # if results is not a list, make it a list
        if type(bgp_peers) != list:
            bgp_peers = [bgp_peers]

        # for each result, build a dictionary and append to the formatted_results list
        for bgp_p in bgp_peers:
            
            bgp_peer_dict = {
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

            
            response.append(bgp_peer_dict)

        return response