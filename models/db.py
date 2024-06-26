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

from sqlalchemy import Column, Integer, String, ForeignKey, Boolean, Text
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base

# Create a base class for declarative models
Base = declarative_base()

class Panorama(Base):
    __tablename__ = 'panorama'
    
    id = Column(Integer, primary_key=True)
    hostname = Column(String)
    serial_number = Column(String)
    ip_address = Column(String)
    alt_ip = Column(String)
    active = Column(Boolean, default=True)
    api_key = Column(Text) 
    
    # Establish the one-to-many relationship with Ngfw
    ngfws = relationship('Ngfw', back_populates='panorama') 
    
class Ngfw(Base):
    __tablename__ = 'ngfw'
    
    id = Column(Integer, primary_key=True)
    hostname = Column(String)
    serial_number = Column(String)
    ip_address = Column(String)
    model = Column(String)
    alt_serial = Column(String, default=None)
    active = Column(Boolean, default=True)
    alt_ip = Column(String, default=None)
    api_key = Column(Text, default=None)
    last_update = Column(String, default=None)

    # ForeignKey to associate with Panorama
    panorama_id = Column(Integer, ForeignKey('panorama.id'))

    # Establish the many-to-one relationship with Panorama, and the one-to-many relationship with VirtualRouter
    panorama = relationship('Panorama', back_populates='ngfws')
    virtual_routers = relationship('VirtualRouter', back_populates='ngfw')
    neighbors = relationship('Neighbor', back_populates='ngfw')
    bgp_peers = relationship('BGPPeer', back_populates='ngfw')


class VirtualRouter(Base):
    __tablename__ = 'virtual_router'
    
    id = Column(Integer, primary_key=True)
    name = Column(String)

    # ForeignKey to associate with Ngfw
    ngfw_id = Column(Integer, ForeignKey('ngfw.id'))

    # Establish the many-to-one relationship with Ngfw, and the one-to-many relationship with Routes, Interfaces
    ngfw = relationship('Ngfw', back_populates='virtual_routers')
    interfaces = relationship('Interface', back_populates='virtual_router')
    routes = relationship('Route', back_populates='virtual_router')
    fib = relationship('Fib', back_populates='virtual_router')
    bgp_peers = relationship('BGPPeer', back_populates='virtual_router')


class Route(Base):
    __tablename__ = 'routes'
    
    id = Column(Integer, primary_key=True)
    destination = Column(String)
    nexthop = Column(String)
    metric = Column(Integer, default=0)
    flags = Column(String)
    age = Column(Integer)
    interface = Column(String)
    route_table = Column(String)
    zone = Column(String, default=None)
    
    # ForeignKey to associate with VirtualRouter
    virtual_router_id = Column(Integer, ForeignKey('virtual_router.id'))

    # Establish the many-to-one relationship with VirtualRouter
    virtual_router = relationship('VirtualRouter', back_populates='routes')

class Fib(Base):
    __tablename__ = 'fibs'
    
    id = Column(Integer, primary_key=True)
    fib_id = Column(Integer)
    destination = Column(String)
    interface = Column(String)
    nh_type = Column(String)
    flags = Column(String)
    nexthop = Column(String)
    mtu = Column(Integer)
    zone = Column(String, default=None)
    
    # ForeignKey to associate with VirtualRouter
    virtual_router_id = Column(Integer, ForeignKey('virtual_router.id'))

    # Establish the many-to-one relationship with VirtualRouter
    virtual_router = relationship('VirtualRouter', back_populates='fib')

class Interface(Base):
    __tablename__ = 'interfaces'
    
    id = Column(Integer, primary_key=True)
    name = Column(String)
    tag = Column(String)
    vsys = Column(String)
    zone = Column(String)
    fwd = Column(String)
    ip = Column(String)
    addr = Column(String)
    
    # ForeignKey to associate with VirtualRouter
    virtual_router_id = Column(Integer, ForeignKey('virtual_router.id'))
    
    # Establish the many-to-one relationship with VirtualRouter
    virtual_router = relationship('VirtualRouter', back_populates='interfaces') 
    arps = relationship('Arp', back_populates='interface')

class Neighbor(Base):
    __tablename__ = 'neighbors'

    id = Column(Integer, primary_key=True)
    local_interface = Column(String)
    remote_interface_id = Column(String)
    remote_interface_description = Column(String)
    remote_hostname = Column(String)

    # ForeignKey to associate with Ngfw
    ngfw_id = Column(Integer, ForeignKey('ngfw.id')) 

    # Establish the many-to-one relationship with Ngfw
    ngfw = relationship('Ngfw', back_populates='neighbors')

class BGPPeer(Base):
    __tablename__ = 'bgp_peers'

    id = Column(Integer, primary_key=True)
    peer_name = Column(String)
    peer_group = Column(String)
    peer_router_id = Column(String)
    remote_as = Column(String)
    status = Column(String)
    status_duration = Column(String)
    peer_address = Column(String)
    local_address = Column(String)

    # ForeignKey to associate with Ngfw and VirtualRouter
    ngfw_id = Column(Integer, ForeignKey('ngfw.id'))  
    virtual_router_id = Column(Integer, ForeignKey('virtual_router.id'))

    # Establish the many-to-one relationship with Ngfw and VirtualRouter
    ngfw = relationship('Ngfw', back_populates='bgp_peers')
    virtual_router = relationship('VirtualRouter', back_populates='bgp_peers')

class Arp(Base):
    __tablename__ = 'arps'
    
    id = Column(Integer, primary_key=True)
    ip = Column(String)
    mac = Column(String)
    status = Column(String)
    port = Column(String)
    ttl = Column(Integer)
    zone = Column(String, default=None)
    
    # ForeignKey to associate with Interface
    interface_id = Column(Integer, ForeignKey('interfaces.id'))

    # Establish the many-to-one relationship with Interface
    interface = relationship('Interface', back_populates='arps')
