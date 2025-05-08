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
    """
    Represents a Panorama management device in the database.
    """
    __tablename__ = 'panorama'

    id = Column(Integer, primary_key=True)
    hostname = Column(String)
    serial_number = Column(String, unique=True) # Added unique constraint
    ip_address = Column(String)
    alt_ip = Column(String)
    active = Column(Boolean, default=True)
    api_key = Column(Text)

    # Establish the one-to-many relationship with Ngfw
    # Added cascade delete: Deleting a Panorama will delete its associated NGFWs.
    ngfws = relationship('Ngfw',
                         back_populates='panorama',
                         cascade="all, delete-orphan")

class Ngfw(Base):
    """
    Represents an NGFW (Next-Generation Firewall) device in the database.
    """
    __tablename__ = 'ngfw'

    id = Column(Integer, primary_key=True)
    hostname = Column(String)
    serial_number = Column(String, unique=True) # Added unique constraint
    ip_address = Column(String)
    model = Column(String)
    alt_serial = Column(String, default=None)
    advanced_routing_enabled = Column(Boolean, default=False, nullable=False)
    active = Column(Boolean, default=True)
    alt_ip = Column(String, default=None)
    api_key = Column(Text, default=None)
    last_update = Column(String, default=None)

    # ForeignKey to associate with Panorama
    panorama_id = Column(Integer, ForeignKey('panorama.id'))

    # Establish the many-to-one relationship with Panorama
    panorama = relationship('Panorama', back_populates='ngfws')

    # Establish one-to-many relationships with dependent objects
    # Added cascade delete: Deleting an NGFW will delete its associated VRs, Neighbors, and BGP Peers.
    virtual_routers = relationship('VirtualRouter',
                                   back_populates='ngfw',
                                   cascade="all, delete-orphan")
    neighbors = relationship('Neighbor',
                             back_populates='ngfw',
                             cascade="all, delete-orphan")
    # Note: BGPPeer cascade is primarily handled via VirtualRouter below.
    # Defining cascade here might be redundant or cause issues if a BGPPeer
    # could exist without a VR (unlikely).
    bgp_peers = relationship('BGPPeer', back_populates='ngfw')


class VirtualRouter(Base):
    """
    Represents a Virtual Router configured on an NGFW.
    """
    __tablename__ = 'virtual_router'

    id = Column(Integer, primary_key=True)
    name = Column(String)

    # ForeignKey to associate with Ngfw
    ngfw_id = Column(Integer, ForeignKey('ngfw.id'))

    # Establish the many-to-one relationship with Ngfw
    ngfw = relationship('Ngfw', back_populates='virtual_routers')

    # Establish one-to-many relationships with dependent objects
    # Added cascade delete: Deleting a VirtualRouter will delete its associated Interfaces, Routes, FIB entries, and BGP Peers.
    interfaces = relationship('Interface',
                              back_populates='virtual_router',
                              cascade="all, delete-orphan")
    routes = relationship('Route',
                          back_populates='virtual_router',
                          cascade="all, delete-orphan")
    fib = relationship('Fib',
                       back_populates='virtual_router',
                       cascade="all, delete-orphan")
    bgp_peers = relationship('BGPPeer',
                             back_populates='virtual_router',
                             cascade="all, delete-orphan")


class Route(Base):
    """
    Represents a route entry (IPv4 or IPv6) within a Virtual Router's routing table.
    """
    __tablename__ = 'routes'

    id = Column(Integer, primary_key=True)
    afi = Column(String(4), nullable=False, index=True)
    destination = Column(String(64))
    nexthop = Column(String(64))
    metric = Column(Integer, default=0)
    flags = Column(String)
    age = Column(Integer) # Age might not apply or differ for IPv6, keep for now
    interface = Column(String)
    route_table = Column(String)
    zone = Column(String, default=None)

    # ForeignKey to associate with VirtualRouter
    virtual_router_id = Column(Integer, ForeignKey('virtual_router.id'))

    # Establish the many-to-one relationship with VirtualRouter
    virtual_router = relationship('VirtualRouter', back_populates='routes')

    # Optional: Add a unique constraint or index if needed, e.g., for VR+AFI+Destination
    # __table_args__ = (Index('idx_route_lookup', 'virtual_router_id', 'afi', 'destination'), )

class Fib(Base):
    """
    Represents a FIB entry (IPv4 or IPv6) within a Virtual Router.
    """
    __tablename__ = 'fibs'

    id = Column(Integer, primary_key=True)
    afi = Column(String(4), nullable=False, index=True)
    fib_id = Column(Integer)
    destination = Column(String(64))
    nexthop = Column(String(64))
    interface = Column(String)
    nh_type = Column(String)
    flags = Column(String)
    mtu = Column(Integer)
    zone = Column(String, default=None)

    # ForeignKey to associate with VirtualRouter
    virtual_router_id = Column(Integer, ForeignKey('virtual_router.id'))

    # Establish the many-to-one relationship with VirtualRouter
    virtual_router = relationship('VirtualRouter', back_populates='fib')

    # Optional: Add indexes if needed
    # __table_args__ = (Index('idx_fib_lookup', 'virtual_router_id', 'afi', 'destination'), )

class Interface(Base):
    """
    Represents a network interface configured on an NGFW and associated with a Virtual Router.
    """
    __tablename__ = 'interfaces'

    id = Column(Integer, primary_key=True)
    name = Column(String)
    tag = Column(String) # VLAN tag for subinterfaces
    vsys = Column(String)
    zone = Column(String)
    # 'fwd' and 'addr' seem unused/unpopulated based on controller logic, potentially removable
    fwd = Column(String) # Forwarding info (e.g., vr:default)
    ip = Column(String) # Configured IP/mask (e.g., 10.0.0.1/24)
    addr = Column(String) # Resolved IP/mask (might be same as ip)
    ipv6_enabled = Column(Boolean, default=False, nullable=False) # Flag indicating presence of IPv6 config

    # ForeignKey to associate with VirtualRouter
    virtual_router_id = Column(Integer, ForeignKey('virtual_router.id'))

    # Establish the many-to-one relationship with VirtualRouter
    virtual_router = relationship('VirtualRouter', back_populates='interfaces')

    # Establish one-to-many relationship with Arp entries
    # Added cascade delete: Deleting an Interface will delete its associated ARP entries.
    arps = relationship('Arp',
                        back_populates='interface',
                        cascade="all, delete-orphan")
    
    # Establish one-to-many relationship with InterfaceIPv6Address entries
    # Cascade delete ensures that if an Interface is deleted,
    # all its associated IPv6 address entries are also deleted.
    ipv6_addresses = relationship('InterfaceIPv6Address',
                                   back_populates='interface',
                                   cascade="all, delete-orphan",
                                   lazy='select') # 'select' loads related objects when accessed

class InterfaceIPv6Address(Base):
    """
    Represents a single IPv6 address configured on a network Interface.
    """
    __tablename__ = 'interface_ipv6_addresses'

    id = Column(Integer, primary_key=True)
    # Store the full IPv6 address, potentially including the prefix length (e.g., '/64')
    address = Column(String, nullable=False)

    # ForeignKey to link back to the Interface table
    interface_id = Column(Integer, ForeignKey('interfaces.id'), nullable=False)

    # Establish the many-to-one relationship back to Interface
    interface = relationship('Interface', back_populates='ipv6_addresses')

    def __repr__(self):
        # Optional: Add a representation for easier debugging
        return f"<InterfaceIPv6Address(address='{self.address}', interface_id={self.interface_id})>"

class Neighbor(Base):
    """
    Represents an LLDP neighbor discovered by an NGFW.
    """
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
    """
    Represents a BGP peering session configured on an NGFW within a Virtual Router.
    """
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
    """
    Represents an ARP (Address Resolution Protocol) entry associated with an Interface.
    """
    __tablename__ = 'arps'

    id = Column(Integer, primary_key=True)
    ip = Column(String)
    mac = Column(String)
    status = Column(String)
    port = Column(String) # Physical port if available
    ttl = Column(Integer)
    zone = Column(String, default=None)

    # ForeignKey to associate with Interface
    interface_id = Column(Integer, ForeignKey('interfaces.id'))

    # Establish the many-to-one relationship with Interface
    interface = relationship('Interface', back_populates='arps')
