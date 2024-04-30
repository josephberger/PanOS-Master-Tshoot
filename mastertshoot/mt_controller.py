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

import pan.xapi
import xmltodict
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from models import Base, Ngfw, Route, VirtualRouter, Interface, Panorama, Neighbor, BGPPeer, Fib, Arp

from .mt_devices import MTpanorama, MTngfw, MTpanoramaException, MTngfwException

from config import db_uri, timeout



class MTBuilderException(Exception):
    pass

class MTBuilder:
    def __init__(self, db_uri=db_uri, timeout=timeout) -> None:
        self.db_uri = db_uri

        try:
            self.timeout = int(timeout)
        except:
            raise MTBuilderException(f"Timeout must be an integer")

    def build_database(self) -> str:
        """
        Builds the sqlite database
        """

        try:
            # create the database engine
            engine = create_engine(self.db_uri)

            # create the tables in the database
            Base.metadata.create_all(engine)

            return "Empty database successfully created"
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
            raise MTBuilderException(f"Database communication issue with {self.db_uri}")

        # query the database for all panoramas
        try:
            pan_list = session.query(Panorama).all()
        except Exception as e:
            raise MTBuilderException(f"Database communication issue with {self.db_uri}")

        # if the panorama is already in the database
        for p in pan_list:
            if p.ip_address == ip_address:
                raise MTBuilderException(f"Panorama {ip_address} already in database")

        try:
            xapi = pan.xapi.PanXapi(api_username=username, api_password=password, hostname=ip_address)
            xapi.timeout = self.timeout

            # show the system info
            xapi.op("<show><system><info></info></system></show>")
            system_info = xmltodict.parse('<root>' + xapi.xml_result() + '</root>')['root']

            if 'system-mode' not in system_info['system']:
                raise MTBuilderException(f"Device at {ip_address} is not a Panorama")

            serial = system_info['system']['serial']

            hostname = system_info['system']['hostname']

            # if hostname is in the database, append -1 to the hostname
            for p in pan_list:
                if hostname == p.hostname:
                    hostname = hostname + "-1"
                    break

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
            if "URLError" in str(e):
                raise MTBuilderException(f"Unable to connect to {ip_address}")
            else:
                raise MTBuilderException(f"{e}")
        
        new_panorama = Panorama(hostname=hostname, 
                                serial_number=serial, 
                                ip_address=ip_address, 
                                alt_ip=alt_ip, active=active, 
                                api_key=xapi.api_key)

        session.add(new_panorama)

        session.commit()

        return f"{new_panorama.hostname} successfully added to database"
    
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
            raise MTBuilderException(f"Database communication issue with {self.db_uri}")

        # create list of serial numbers in the database
        serial_numbers = []

        try:
            ngfw_list = session.query(Ngfw).all()
        except Exception as e:
            raise MTBuilderException(f"Database communication issue with {self.db_uri}")

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
                raise MTBuilderException(f"Device at {ip_address} is not a NGFW.")

            # show the HA info
            xapi.op("<show><high-availability><state></state></high-availability></show>")
            ha_info = xmltodict.parse('<root>' + xapi.xml_result() + '</root>')['root']

            hostname = device_info['system']['hostname']

            # if hostname is in the database, append -1 to the hostname
            for n in ngfw_list:
                if hostname == n.hostname:
                    hostname = hostname + "-1"
                    break

            ngfw_info = {
                'hostname': hostname,
                'serial_number': device_info['system']['serial'],
                'ip_address': ip_address,
                'model': device_info['system']['model'],
                'api_key': xapi.api_key,
                'panorama_id': None
            }

            # if serial number is not in serial_numbers, add to the database
            if ngfw_info['serial_number'] in serial_numbers:
                raise MTBuilderException(f"NGFW {ngfw_info['hostname']} {ngfw_info['serial_number']} already in database")

            # determine HA status
            if ha_info['enabled'] == 'yes':

                # If ha state is active, set active to true and alt_serial to peer serial number
                if ha_info['group']['local-info']['state'] == 'active':
                    ngfw_info['active'] = True
                else:
                    ngfw_info['active'] = False
                

                ngfw_info['alt_serial'] = ha_info['group']['peer-info']['serial-num']
                ngfw_info['alt_ip'] = ha_info['group']['peer-info']['mgmt-ip']

            else:
                ngfw_info['active'] = True
                ngfw_info['alt_serial'] = None
                ngfw_info['alt_ip'] = None
            
            new_ngfw = Ngfw(**ngfw_info)

            session.add(new_ngfw)
                
            session.commit()

            return f"{ngfw_info['hostname']} {new_ngfw.serial_number} successfully added to database"

        except pan.xapi.PanXapiError as e:
            if "URLError" in str(e):
                raise MTBuilderException(f"Unable to connect to {ip_address}")
            else:
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
            raise MTBuilderException(f"Database communication issue with {self.db_uri}")
        
        if not panorama:
            raise MTBuilderException(f"Panorama {serial_number} not found in database")
        
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
            raise MTBuilderException(f"Panorama {serial_number} not deleted from database")
        
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
            raise MTBuilderException(f"Database communication issue with {self.db_uri}")
        
        if not ngfw:
            raise MTBuilderException(f"NGFW {serial_number} not found in database")
        
        # query the database for all routes, interfaces, virtual routers, bgp peers and neighbors associated with the ngfw
        routes = session.query(Route).join(Route.virtual_router).join(VirtualRouter.ngfw).filter(Ngfw.serial_number == serial_number).all()
        interfaces = session.query(Interface).join(Interface.virtual_router).join(VirtualRouter.ngfw).filter(Ngfw.serial_number == serial_number).all()
        virtual_routers = session.query(VirtualRouter).join(VirtualRouter.ngfw).filter(Ngfw.serial_number == serial_number).all()
        bgp_peers = session.query(BGPPeer).join(BGPPeer.ngfw).filter(Ngfw.serial_number == serial_number).all()
        neighbors = session.query(Neighbor).join(Neighbor.ngfw).filter(Ngfw.serial_number == serial_number).all()

        
        # delete the routes, interfaces, virtual routers, bgp peers and neighbors associated with the ngfw
        delete_items = [routes, interfaces, virtual_routers, bgp_peers, neighbors]

        for item in delete_items:
            for i in item:
                session.delete(i)
        
        # delete the ngfw
        try:
            session.delete(ngfw)
        except Exception as e:
            raise MTBuilderException(f"NGFW {serial_number} not deleted from database")
        
        session.commit()

        return f"{ngfw.hostname} {ngfw.serial_number} deleted from database"

class MTControllerException(Exception):
    pass

class MTController:

    def __init__(self, db_uri, timeout=5) -> None:

        # verify db_uri is present
        if not db_uri:
            raise MTControllerException("No 'db_uri' provided")
        
        self.db_uri = db_uri

        try:
            engine = create_engine(db_uri, echo=False)
            Session = sessionmaker(bind=engine)
            self.session = Session()
        except Exception as e:
            raise MTControllerException(f"Issue communicating with database {db_uri}")

        try:
            self.timeout = int(timeout)
        except:
            raise MTControllerException(f"'timeout' must be an integer")

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
            'FIBs': self.session.query(Fib).count(),
            'ARPs': self.session.query(Arp).count(),
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
            message.append("No Panoramas in database")
            return message

        serial_numbers = [] # for checking if serial number is in database

        for panorama in panorama_list:

            try:
                mtp = MTpanorama(panorama=panorama, timeout=self.timeout)
                devices = mtp.show_devices()
            except MTpanoramaException as e:
                message.append(str(e))
                continue

            ngfws = self.session.query(Ngfw).all()
            for n in ngfws:
                serial_numbers.append(n.serial_number)
                if n.alt_serial is not None:
                    serial_numbers.append(n.alt_serial)

            # for each device, add to the database
            for d in devices:

                # if serial number is not in serial_numbers, add to the database
                if d['serial'] in serial_numbers:
                    message.append(f"{d['hostname']} {d['serial']} already in database - skipping...")
                    continue
                
                # if connected is not yes continue
                if d['connected'] != 'yes':
                    message.append(f"{d['hostname']} {d['serial']} not connected - skipping...")
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
                        if 'peer' in d['ha']:
                            ngfw_info['alt_serial'] = d['ha']['peer']['serial'] 
                        else:
                            ngfw_info['alt_serial'] = None
                    else:
                        message.append(f"{ngfw_info['hostname']} {ngfw_info['serial_number']} is not active - skipping...")
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
            message.append("No ngfws found in database")
            return message

        # for each ngfw
        for n in ngfw_list:

            # time of refresh
            refresh_time = str(datetime.datetime.now().isoformat())

            # set hte MTD object
            mtd = MTngfw(ngfw=n, timeout=self.timeout)

            # test connectivity to the mtd
            try:
                mtd.show_system_info()
            except MTngfwException as e:
                message.append(f"{n.hostname} {n.serial_number} not connecting - skipping refresh...")
                continue
            
            # set the refresh time on the ngfw
            n.last_update = refresh_time

            # create a query for interfaces, routes, fibs, virtual routers, bgp peers and neighbors
            iq = self.session.query(Interface).join(Interface.virtual_router).join(VirtualRouter.ngfw).filter(Ngfw.id == n.id).all()
            rq = self.session.query(Route).join(Route.virtual_router).join(VirtualRouter.ngfw).filter(Ngfw.id == n.id).all()
            fq = self.session.query(Fib).join(Fib.virtual_router).join(VirtualRouter.ngfw).filter(Ngfw.id == n.id).all()
            bq = self.session.query(BGPPeer).join(BGPPeer.ngfw).filter(Ngfw.id == n.id).all()
            vq = self.session.query(VirtualRouter).join(VirtualRouter.ngfw).filter(Ngfw.id == n.id).all()
            nq = self.session.query(Neighbor).join(Neighbor.ngfw).filter(Ngfw.id == n.id).all()

            # create a list of lists containing the objects to delete
            objects_to_delete = [iq, rq, bq, vq, nq, fq]

            for obj_list in objects_to_delete:
                for obj in obj_list:
                    self.session.delete(obj)

            ## virtual routers block ##
            virtual_routers = mtd.show_virtual_routes()

            for vr in virtual_routers:
                new_vr = VirtualRouter(name=vr, ngfw_id=n.id)
                self.session.add(new_vr)
            
            self.session.commit()

            ## interfaces block ##
            interface_list = []

            try:
                interfaces = mtd.show_interfaces()
            except MTngfwException:
                message.append(f"{n.hostname} has no interfaces assigned to a vr and zone - skipping...")
                continue

            # get all the vrs for this ngfw from the database
            vr_list = {}
            for item in self.session.query(VirtualRouter).filter(VirtualRouter.ngfw_id == n.id).all():
                vr_list[item.name] = item.id

            for i in interfaces:

                new_interface = Interface(
                                            name=i['name'],
                                            tag=i['tag'],
                                            vsys=i['vsys'],
                                            zone=i['zone'],
                                            ip=i['ip'],
                                            virtual_router_id=vr_list[i['virtual_router']]
                                        )
                
                interface_list.append(new_interface)

                self.session.add(new_interface)

            self.session.commit()

            message.append(f"{n.hostname} {n.serial_number} refreshed")
        
        return message
    
    def get_routes(self, ngfw=None, virtual_router=None, destination=None, flags=None, on_demand=False) -> dict:
        """
        Returns routes
        """

        response = {'message':[], 'results':None}

        if on_demand:

            query = self.session.query(Ngfw)

            if ngfw:
                query = query.filter(Ngfw.hostname == ngfw)
            
            ngfw_list = query.all()

            if not ngfw_list:
                response['message'].append("No NGFWs found to check routes")
                return response
            
            for n in ngfw_list:
                    
                    mt_ngfw = MTngfw(n)
    
                    try:
                        results = mt_ngfw.show_routes(virtual_router=virtual_router, dst=destination, flags=flags)
                    except MTngfwException as e:
                        response['message'].append(str(e))
                        continue
    
                    # if virtual_router
                    if virtual_router:
                        # get the interface_list for the current ngfw and virtual_router
                        interface_list = self.session.query(Interface).join(Interface.virtual_router).filter(VirtualRouter.ngfw_id == n.id, VirtualRouter.name == virtual_router).all()
                        fib_list = self.session.query(Fib).join(Fib.virtual_router).filter(VirtualRouter.ngfw_id == n.id, VirtualRouter.name == virtual_router).all()
                    else:
                        interface_list = self.session.query(Interface).join(Interface.virtual_router).filter(VirtualRouter.ngfw_id == n.id).all()
                        fib_list = self.session.query(Fib).join(Fib.virtual_router).filter(VirtualRouter.ngfw_id == n.id).all()

                    formatted_routes = []

                    for route in results:
                        for f in fib_list:
                            if route['destination'] == f.destination and f.virtual_router.name == route['virtual_router']:
                                route['zone'] = f.zone
                                route['interface'] = f.interface
                                break
                        
                        formatted_routes.append(route)

                    response['results'] = formatted_routes
        
        else:

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
                response['message'].append("No routes found")
                return response

            formatted_routes = []
            
            # for each route, build a dictionary and append to the formatted_routes list
            for r in routes:
                route_data = {
                    'ngfw': r.virtual_router.ngfw.hostname,
                    'virtual_router': r.virtual_router.name,
                    'destination': r.destination,
                    'nexthop': r.nexthop,
                    'metric': str(r.metric) if r.metric is not None else '',
                    'flags': r.flags,
                    'interface': str(r.interface) if r.interface is not None else '',
                    'route_table': r.route_table,
                    'age': str(r.age) if r.age is not None else '',
                    'zone': r.zone if r.zone else ''
                }

                formatted_routes.append(route_data)

            response['results'] = formatted_routes

        return response
    
    def get_fibs(self, ngfw=None, virtual_router=None, destination=None, flags=None, on_demand=False) -> dict:
        """
        Returns fibs
        """

        response = {'message':[], 'results':None}

        formatted_fibs = []
        
        # if on demand is true, get the fibs from the device
        if on_demand:

            query = self.session.query(Ngfw)

            if ngfw:
                query = query.filter(Ngfw.hostname == ngfw)
            
            ngfw_list = query.all()

            if not ngfw_list:
                response['message'] = ["No NGFWs found to check fibs"]
                return response
            
            formatted_fibs = []

            for n in ngfw_list:
                
                mt_ngfw = MTngfw(n)

                try:
                    results = mt_ngfw.show_fibs(virtual_router=virtual_router, dst=destination, flags=flags)
                    #results = [{'ngfw': n.hostname, **d} for d in results]
                except MTngfwException as e:
                    response['message'].append(str(e))
                    continue
                
                ngfw_fibs = []

                # if virtual_router
                if virtual_router:
                    # get the interface_list for the current ngfw and virtual_router
                    interface_list = self.session.query(Interface).join(Interface.virtual_router).filter(VirtualRouter.ngfw_id == n.id, VirtualRouter.name == virtual_router).all()
                    for r in results:
                        # if virtual_router is present filter the results and add to the ngfw_fibs list
                        if r['virtual_router'] == virtual_router:
                            ngfw_fibs.append(r)
                else:
                    interface_list = self.session.query(Interface).join(Interface.virtual_router).filter(VirtualRouter.ngfw_id == n.id).all()
                    # add all the results to the ngfw_fibs list
                    ngfw_fibs = results

                # if an interface is present in the fib, determine the zone based in interface_list
                for r in ngfw_fibs:
                    for i in interface_list:
                        if r['interface'] == i.name:
                            r['zone'] = i.zone
                            break
                    formatted_fibs.append(r)
                
            response['results'] = formatted_fibs

        # if on demand is false, get the fibs from the database
        else:
            query = self.session.query(Fib).join(Fib.virtual_router)

            if ngfw:
                query = query.join(VirtualRouter.ngfw).filter(Ngfw.hostname == ngfw)
            if virtual_router:
                query = query.filter(VirtualRouter.name == virtual_router)
            if destination:
                query = query.filter(Fib.destination.contains(destination))
            if flags:
                for f in flags.split(","):
                    query = query.filter(Fib.flags.contains(f.upper().strip()))
            
            fibs = query.all()

            if not fibs:
                response['message'].append("No fibs found")
                return response
            # for each fib, build a dictionary and append to the formatted_fibs list
            for f in fibs:
                fib_data = {
                    'ngfw': f.virtual_router.ngfw.hostname,
                    'virtual_router': f.virtual_router.name,
                    'destination': f.destination,
                    'interface': f.interface,
                    'nh_type': f.nh_type,
                    'flags': f.flags,
                    'nexthop': f.nexthop,
                    'mtu': f.mtu,
                    'zone': f.zone,
                }

                formatted_fibs.append(fib_data)

            response['results'] = formatted_fibs

        return response

    def get_interfaces(self, ngfw=None, virtual_router=None, on_demand=False) -> dict:
        """
        Rreturns interfaces
        """

        response = {'message':[], 'results':None}

        # if on_demand is true, get the interfaces from the device
        if on_demand:
            query = self.session.query(Ngfw)

            if ngfw:
                query = query.filter(Ngfw.hostname == ngfw)
            
            ngfw_list = query.all()

            if not ngfw_list:
                response['message'] = ["No NGFWs found to check interfaces"]
                return response
            
            formatted_interfaces = []

            for n in ngfw_list:
                
                mt_ngfw = MTngfw(n)

                try:
                    results = mt_ngfw.show_interfaces(virtual_router=virtual_router)
                except MTngfwException as e:
                    response['message'].append(str(e))
                    continue

                for i in results:
                    formatted_interfaces.append(i)

            response['results'] = formatted_interfaces
        
        # if on_demand is false, get the interfaces from the database
        else:
            query = self.session.query(Interface).join(Interface.virtual_router)

            if ngfw:
                query = query.join(VirtualRouter.ngfw).filter(Ngfw.hostname == ngfw)
            if virtual_router:
                query = query.filter(VirtualRouter.name == virtual_router)
            
            interfaces = query.all()

            if not interfaces:
                response['message'].append("No interfaces found")
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
    
    def get_bgp_peers(self, ngfw=None, virtual_router=None, on_demand=False) -> dict:
        """
        Returns BGP peers
        """

        response = {'message':[], 'results':None}
        
        # if on_demand is true, get the bgp peers from the device
        if on_demand:
            query = self.session.query(Ngfw)

            if ngfw:
                query = query.filter(Ngfw.hostname == ngfw)
            if virtual_router:
                query = query.join(Ngfw.virtual_routers).filter(VirtualRouter.name == virtual_router)

            ngfw_list = query.all()

            if not ngfw_list:
                response['message'] = ["No NGFWs found to check bgp-peers"]
                return response
            
            formatted_bgp_peers = []

            # for each ngfw in ngfw_list, set the serial of self.xapi to ngfw.serial_number and show lldp neighbors on the xapi object
            for n in ngfw_list:
                
                mt_ngfw = MTngfw(n)

                try:
                    results = mt_ngfw.show_bgp_peers(virtual_router=virtual_router)
                except MTngfwException as e:
                    response['message'].append(str(e))
                    continue

                for bgp_p in results:
                    formatted_bgp_peers.append(bgp_p)

            response['results'] = formatted_bgp_peers

        # if on_demand is false, get the bgp peers from the database
        else:
            query = self.session.query(BGPPeer)

            if ngfw:
                query = query.join(BGPPeer.ngfw).filter(Ngfw.hostname == ngfw)
            if virtual_router:
                query = query.join(BGPPeer.virtual_router).filter(VirtualRouter.name == virtual_router)
            
            bgp_peers = query.all()

            if not bgp_peers:
                response['message'].append("No BGP peers found")
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
    
    def get_arps(self, ngfw=None, interface=None, on_demand=False) -> dict:
        """
        Returns ARPs
        """

        response = {'message':[], 'results':None}

        # if on_demand is true, get the arps from the device
        if on_demand:
            query = self.session.query(Ngfw)

            if ngfw:
                query = query.filter(Ngfw.hostname == ngfw)
            
            ngfw_list = query.all()

            if not ngfw_list:
                response['message'] = ["No NGFWs found to check ARPs"]
                return response
            
            formatted_arps = []

            for n in ngfw_list:
                
                mt_ngfw = MTngfw(n)

                try:
                    results = mt_ngfw.show_arps(interface=interface)
                except MTngfwException as e:
                    response['message'].append(str(e))
                    continue

                # get interface list and build dictionary with interface name as key
                interface_list = {}
                for i in self.session.query(Interface).join(Interface.virtual_router).filter(VirtualRouter.ngfw_id == n.id).all():
                    interface_list[i.name] = i

                for r in results:
                    # set the zone
                    r['zone'] = interface_list[r['interface']].zone
                    # append to the formatted_arps list
                    formatted_arps.append(r)

            response['results'] = formatted_arps

        else:
            query = self.session.query(Arp)

            if ngfw:
                query = query.join(Arp.interface).join(Interface.virtual_router).join(VirtualRouter.ngfw).filter(Ngfw.hostname == ngfw)
            if interface:
                query = query.join(Arp.interface).filter(Interface.name == interface)
            
            arps = query.all()

            if not arps:
                response['message'].append("No ARPs found")
                return response
            
            formatted_arps = []

            # for each arp in arps, build a dictionary and append to the formatted_arps list
            for arp in arps:
                arp_dict = {
                    'ngfw': arp.interface.virtual_router.ngfw.hostname,
                    'interface': arp.interface.name,
                    'ip': arp.ip,
                    'mac': arp.mac,
                    'port': arp.port,
                    'ttl': arp.ttl,
                    'status': arp.status,
                    'zone': arp.zone
                }

                formatted_arps.append(arp_dict)

            response['results'] = formatted_arps

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
            response['message'].append("No virtual routers found")
            return response
        
        formatted_virtual_routers = []

        # for each virtual-router in virtual_routers, build a dictionary and append to the formatted_virtual_routers list
        for vr in vr_list:
            vr_dict = {
                'ngfw_id': vr.ngfw_id,
                'ngfw': vr.ngfw.hostname,
                'virtual_router': vr.name,
                'route_count': len(vr.routes),
                'fib_count': len(vr.fib),
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
    
    def get_neighbors(self, ngfw=None, on_demand=False) -> dict:
        """
        Returns neighbors
        """

        response = {'message':[], 'results':None}

        # if on_demand is true, get the neighbors from the device
        if on_demand:
            query = self.session.query(Ngfw)

            if ngfw:
                query = query.filter(Ngfw.hostname == ngfw)
            
            ngfw_list = query.all()

            if not ngfw_list:
                response['message'].append("No NGFWs found to check neighbors")
                return response
            
            formatted_lldp_neighbors = []

            for n in ngfw_list:
                
                mt_ngfw = MTngfw(n)

                try:
                    results = mt_ngfw.show_neighbors()
                except MTngfwException as e:
                    response['message'].append(str(e))
                    continue

                for flp in results:
                    formatted_lldp_neighbors.append(flp)
            
            response['results'] = formatted_lldp_neighbors
        
        # if on_demand is false, get the neighbors from the database
        else:
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
                        'remote_interface_id': n.remote_interface_id,
                        'remote_interface_description': n.remote_interface_description,
                        'remote_hostname': n.remote_hostname
                    }

                    formatted_neighbors.append(neighbor_dict)
                    
                response['results'] = formatted_neighbors
            else:
                response['message'].append("No neighbors found")

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
            response['message'].append("No panoramas found")

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
            fibs = self.session.query(Fib).join(Fib.virtual_router).filter(VirtualRouter.name == vr.name).filter(VirtualRouter.ngfw_id == vr.ngfw_id).all()

            # if fibs is empty, continue
            if not fibs:
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
            
            dst = {}
            prefix = 0

            # for each route, if the destination is not in the ip_address, continue
            for r in fibs:

                # if the route is not up, continue
                if "u" not in r.flags:
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
                'zone': dst[prefix].zone or "None"
            }

            # verify next hop
            if route_data['nexthop'] == "0.0.0.0":
                route_data['nexthop'] = "self"

            formatted_results.append(route_data)

        response['results'] = formatted_results
        return response
     
    def update_routes(self, ngfw=None, virtual_router=None) -> list:
        """
        Updates routes and fibs
        """

        # message to be returned
        message = []

        # create a query for ngfws
        query = self.session.query(Ngfw)

        # if ngfw is present, filter the query for the ngfw
        if ngfw:
            query = query.filter(Ngfw.hostname == ngfw)
        
        # get the ngfws
        ngfw_list = query.all()

        # if no ngfws are found, return message
        if not ngfw_list:
            message.append("No NGFWs found to update routes")
            return message

        # for each ngfw from the query
        for n in ngfw_list:

            # get the vr_list for this ngfw
            vr_list = {}
            for item in self.session.query(VirtualRouter).filter(VirtualRouter.ngfw_id == n.id).all():
                vr_list[item.name] = item.id

            # if no virtual routers are found, continue
            if not vr_list:
                message.append(f"No virtual routers found for {n.hostname} try refreshing the NGFW")
                continue

            # update fibs #
            try:
                fibs = self.get_fibs(ngfw=n.hostname,virtual_router=virtual_router, on_demand=True)['results']
            except MTngfwException as e:
                message.append(f"{e}")
                continue

            # delete the existing fibs from the database
            ef_query = self.session.query(Fib).join(Fib.virtual_router).join(VirtualRouter.ngfw).filter(Ngfw.id == n.id)
            if virtual_router:
                ef_query = ef_query.filter(VirtualRouter.name == virtual_router)
            existing_fibs = ef_query.all()
            for ef in existing_fibs:
                self.session.delete(ef)

            # if no fibs are returned, continue
            if not fibs:
                # if virtual_router is present, append the message
                if virtual_router:
                    message.append(f"{n.hostname} vr:{virtual_router} has no fibs")
                else:
                    message.append(f"{n.hostname} has no fibs")
                continue
            else:
                fib_count = len(fibs)

            # for each fib, add to the database
            for f in fibs:
                new_fib = Fib(
                                virtual_router_id=vr_list[f['virtual_router']],
                                fib_id=f['fib_id'],
                                destination=f['destination'],
                                interface=f['interface'],
                                nh_type=f['nh_type'],
                                flags=f['flags'],
                                nexthop=f['nexthop'],
                                mtu=f['mtu'],
                                zone=f['zone']
                            )

                self.session.add(new_fib)

            self.session.commit()

            # update routes #

            try:
                routes = self.get_routes(ngfw=n.hostname, 
                                         virtual_router=virtual_router, 
                                         on_demand=True)['results']
            except MTngfwException as e:
                message.append(f"{e}")
                continue

            # if no routes are returned, continue
            if not routes:
                # if virtual_router is present, append the message
                if virtual_router:
                    message.append(f"{n.hostname} vr:{virtual_router} has no routes")
                else:
                    message.append(f"{n.hostname} has no routes")
                continue
            else:
                route_count = len(routes)

            # delete the existing routes from the database
            ef_query = self.session.query(Route).join(Route.virtual_router).join(VirtualRouter.ngfw).filter(Ngfw.id == n.id)
            if virtual_router:
                ef_query = ef_query.filter(VirtualRouter.name == virtual_router)
            existing_routes = ef_query.all()
            for er in existing_routes:
                self.session.delete(er)

            # for each route, add to the database
            for r in routes:

                new_route = Route(virtual_router_id=vr_list[r['virtual_router']],
                                    destination=r.get('destination', ''), 
                                    nexthop=r.get('nexthop', ''), 
                                    metric=r.get('metric', ''), 
                                    flags=r.get('flags', ''), 
                                    age=r.get('age', ''), 
                                    interface=r.get('interface', ''), 
                                    route_table=r.get('route_table', ''),
                                    zone=r.get('zone', ''))
                
                # add the new route to the database
                self.session.add(new_route)
            
            self.session.commit()

            # append the message
            message.append(f"{n.hostname} {route_count} routes updated and {fib_count} fibs updated")

        return message
    
    def update_arps(self, ngfw=None, interface=None) -> list:
        """
        Updates ARPs
        """

        message = []

        query = self.session.query(Ngfw)

        if ngfw:
            query = query.filter(Ngfw.hostname == ngfw)
        
        ngfw_list = query.all()

        if not ngfw_list:
            message.append("No NGFWs found to update ARPs")
            return message

        for n in ngfw_list:
            try:
                arps = self.get_arps(ngfw=n.hostname, interface=interface, on_demand=True)['results']
            except MTngfwException as e:
                message.append(f"{e}")
                continue

            if not arps:
                if interface:
                    message.append(f"{n.hostname} no arp entries found on interface {interface}")
                else:
                    message.append(f"{n.hostname} no arp entries found")
                continue
            else:
                arp_count = len(arps)
            
            # get the interface_list for the current ngfw
            ngfw_interfaces = self.session.query(Interface).join(Interface.virtual_router).filter(VirtualRouter.ngfw_id == n.id).all()
            #build dictionary with the interface name as the key
            interface_list = {}
            for i in ngfw_interfaces:
                interface_list[i.name] = i

            if interface:
                existing_arps = (
                    self.session.query(Arp)
                    .join(Arp.interface)  # Join Arp with Interface
                    .join(Interface.virtual_router)  # Join Interface with VirtualRouter
                    .join(VirtualRouter.ngfw)  # Join VirtualRouter with Ngfw
                    .filter(Ngfw.id == n.id)  # Filter by Ngfw.id
                    .filter(Interface.name == interface)  # Filter by Interface name
                    .all()
                )
            else:
                existing_arps = (
                    self.session.query(Arp)
                    .join(Arp.interface)
                    .join(Interface.virtual_router)
                    .join(VirtualRouter.ngfw)
                    .filter(Ngfw.id == n.id)
                    .all()
                )
            for ea in existing_arps:
                self.session.delete(ea)

            for arp in arps:
                self.session.add(Arp(
                    interface_id=interface_list[arp['interface']].id,
                    ip=arp['ip'],
                    mac=arp['mac'],
                    port=arp['port'],
                    ttl=arp['ttl'],
                    status=arp['status'],
                    zone=arp['zone']
                ))

            message.append(f"{n.hostname} {arp_count} ARPs updated")
            self.session.commit()

        return message

    def update_neighbors(self, ngfw=None) -> list:
        """
        Updates neighbors
        """

        message = []

        query = self.session.query(Ngfw)

        if ngfw:
            query = query.filter(Ngfw.hostname == ngfw)
        
        ngfw_list = query.all()

        if not ngfw_list:
            message.append("No NGFWs found to update neighbors")
            return message

        for n in ngfw_list:
            try:
                neighbors = self.get_neighbors(ngfw=n.hostname, on_demand=True)['results']
            except MTngfwException as e:
                message.append(f"{e}")
                continue

            if not neighbors:
                message.append(f"{n.hostname} has no neighbors")
                continue
            else:
                neighbor_count = len(neighbors)

            existing_neighbors = self.session.query(Neighbor).join(Neighbor.ngfw).filter(Ngfw.id == n.id).all()
            for en in existing_neighbors:
                self.session.delete(en)

            for neighbor in neighbors:
                self.session.add(Neighbor(
                    ngfw_id=n.id,
                    local_interface=neighbor['local_interface'],
                    remote_interface_id=neighbor['remote_interface_id'] or None,
                    remote_interface_description=neighbor['remote_interface_description'] or None,
                    remote_hostname=neighbor['remote_hostname'] or None
                ))

            message.append(f"{n.hostname} {neighbor_count} neighbors updated")
            self.session.commit()

        return message

    def update_bgp_peers(self, ngfw=None, virtual_router=None) -> list:
        """
        Updates BGP peers
        """

        message = []

        query = self.session.query(Ngfw)

        if ngfw:
            query = query.filter(Ngfw.hostname == ngfw)
        
        ngfw_list = query.all()

        if not ngfw_list:
            message.append("No NGFWs found to update BGP peers")
            return message

        for n in ngfw_list:
            try:
                bgp_peers = self.get_bgp_peers(ngfw=n.hostname, virtual_router=virtual_router, on_demand=True)['results']
            except MTngfwException as e:
                message.append(f"{e}")
                continue

            if not bgp_peers:
                message.append(f"{n.hostname} has no BGP peers")
                continue
            else:
                bgp_peer_count = len(bgp_peers)

            # if virtual_router is present, filter the query for the virtual_router
            ebp_query = self.session.query(VirtualRouter).filter(VirtualRouter.ngfw_id == n.id)
            if virtual_router:
                ebp_query = ebp_query.filter(VirtualRouter.name == virtual_router)
            existing_bgp_peers = self.session.query(BGPPeer).join(BGPPeer.ngfw).filter(Ngfw.id == n.id).all()
            for ebp in existing_bgp_peers:
                self.session.delete(ebp)
            
            vr_list = {}
            for item in self.session.query(VirtualRouter).filter(VirtualRouter.ngfw_id == n.id).all():
                vr_list[item.name] = item.id

            for bgp_peer in bgp_peers:
                self.session.add(BGPPeer(
                    ngfw_id=n.id,
                    virtual_router_id=vr_list[bgp_peer['virtual_router']],
                    peer_name=bgp_peer['peer_name'],
                    peer_group=bgp_peer['peer_group'],
                    peer_router_id=bgp_peer['peer_router_id'],
                    remote_as=bgp_peer['remote_as'],
                    status=bgp_peer['status'],
                    status_duration=bgp_peer['status_duration'],
                    peer_address=bgp_peer['peer_address'],
                    local_address=bgp_peer['local_address']
                ))

            message.append(f"{n.hostname} {bgp_peer_count} BGP peers updated")
            self.session.commit()

        return message
    
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
            response['message'].append("No virtual routers found")
            return response

        formatted_results = []

        # for each virtual-router build an xapi object
        for vr in virtual_routers:
            
            mt_ngfw = MTngfw(vr.ngfw)
            #self.__set_xapi(vr.ngfw)

            # show routing fib ip-address <ip_address> on the xapi object
            try:
                mt_ngfw.xapi.op(f"<test><routing><fib-lookup><ip>{ip_address}</ip><virtual-router>{vr.name}</virtual-router></fib-lookup></routing></test>")
            except pan.xapi.PanXapiError as e:
                response['message'].append(f"{vr.ngfw.hostname}: {e}")
                continue

            try:
                result = xmltodict.parse("<root>" + mt_ngfw.xapi.xml_result() + "</root>")['root']
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

    def update_ha_status(self, ngfw=None, panorama=None) -> list:
        """
        Updates the database with HA status and returns a list of messages
        """

        message = []

        pan_query = self.session.query(Panorama)

        if panorama:
            pan_query = pan_query.filter(Panorama.hostname == panorama)

        panorama_list = pan_query.all()

        # verify panorama ha status
        for p in panorama_list:
            if p.alt_ip is not None:
                
                mtp = MTpanorama(panorama=p, timeout=5)
                try:
                    ha_info = mtp.show_ha_state()
                except MTpanoramaException as e:
                    message.append(str(e))

                if ha_info['enabled'] == 'yes':
                    if 'active' in ha_info['local-info']['state']:
                        message.append(f"Panorama {p.hostname} is active")
                    else:
                        # Set the sql database entry for panorama.active to False
                        p.active = False
                        message.append(f"Panorama {p.hostname} is passive.  Using alt-ip")
                        # Update database
                        self.session.commit()
            else:
                message.append(f"Panorama {p.hostname} is not ha")

        # if ngfw is present, query the database for the ngfw
        if ngfw:
            ngfws = self.session.query(Ngfw).filter(Ngfw.hostname == ngfw).all()
        # if ngfw is NOT present, query the database for all ngfws
        else:
            ngfws = self.session.query(Ngfw).all()

        # for each ngfw in ngfws, 
        for n in ngfws:
            # if alt_serial is present set self.xapi.serial to ngfw.serial_number
            if n.alt_serial:
                try:
                    mtd = MTngfw(n)
                    ha = mtd.show_ha_status()
                except MTngfwException as e:
                    message.append(str(e))
                    continue
            else:
                message.append(f"NGFW {n.hostname} is not ha")
                continue

            # if ha['state'] is not active set database ngfw.active to False
            if ha['state'] != 'active':
                n.active = False
                message.append(f"NGFW {n.hostname} is not active, using alternate serial")
            else:
                n.active = True
                message.append(f"NGFW {n.hostname} is active")

        self.session.commit()

        return message
    
    def collect_tsf(self, serial) -> list:
        """
        Collects tsf from the ngfw or panorama via API based on serial number
        """

        message = []

        # query the database for the ngfw based on serial number
        ngfw = self.session.query(Ngfw).filter(Ngfw.serial_number == serial).first()

        if not ngfw:
            message.append(f"Serial number {serial} not found in database")
            return message
        
        #create the mtd object
        mtd = MTngfw(ngfw)

        try:
            tsf = mtd.export_tsf(serial=serial)
        except MTngfwException as e:
            message.append(str(e))
            return message
        
        # write the binary tsf to a file using ngfw hostname, serial number, and all numeric timestamp as a tar.gz file
        filename = f"{ngfw.hostname}_{ngfw.serial_number}_{int(time.time())}.tar.gz"

        with open(filename, "wb") as f:
            f.write(tsf)

        message.append(f"TSF file {filename} created")

        return message