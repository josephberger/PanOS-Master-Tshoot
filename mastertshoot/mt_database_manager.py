# mastertshoot/mt_database_manager.py

import logging
from sqlalchemy.orm import sessionmaker, Session, joinedload
from sqlalchemy import create_engine, select, inspect as sqlalchemy_inspect, exc as sqlalchemy_exc

# Import your models
# Assuming models.py defines the Base and specific table classes correctly
# and includes cascade delete configurations.
from models import (
    Base, Ngfw, Route, VirtualRouter, Interface, Panorama,
    Neighbor, BGPPeer, Fib, Arp, InterfaceIPv6Address
)

# Define a custom exception for this module
class MTDatabaseManagerException(Exception):
    """Custom exception for MTDatabaseManager errors."""
    pass

class MTDatabaseManager:
    """
    Manages direct database interactions for the application.
    Provides methods for querying, adding, updating, and deleting data.
    """
    def __init__(self, db_uri: str, session_factory=None):
        """
        Initializes the Database Manager.

        Args:
            db_uri (str): The database URI.
            session_factory: An existing SQLAlchemy sessionmaker to use.
                             If None, a new one will be created.
        """
        self.db_uri = db_uri
        self._engine = None
        self._Session = session_factory

        if not self._Session:
            try:
                self._engine = create_engine(self.db_uri, echo=False)
                self._Session = sessionmaker(bind=self._engine)
                logging.debug("MTDatabaseManager: New SQLAlchemy engine and sessionmaker created.")
            except sqlalchemy_exc.SQLAlchemyError as e:
                raise MTDatabaseManagerException(f"Database connection error during initialization: {e}") from e
            except Exception as e:
                raise MTDatabaseManagerException(f"Unexpected error during MTDatabaseManager initialization: {e}") from e
        else:
            logging.debug("MTDatabaseManager: Using provided session_factory.")
            # If a session_factory is provided, try to get its bind (engine) if possible
            if hasattr(self._Session, 'kw') and 'bind' in self._Session.kw:
                self._engine = self._Session.kw['bind']

    def get_session(self) -> Session:
        """Provides a new session instance from the session factory."""
        if not self._Session:
            raise MTDatabaseManagerException("Session factory not initialized.")
        return self._Session()

    def check_schema_exists(self) -> bool:
        """
        Checks if the basic database schema (e.g., 'ngfw' table) exists.
        """
        if not self._engine:
            # Attempt to create engine if it's None, might happen if only session_factory was provided initially
            try:
                self._engine = create_engine(self.db_uri, echo=False)
                # Re-bind session factory if engine was created dynamically
                if self._Session and not self._Session.kw.get('bind'):
                    self._Session.configure(bind=self._engine)
            except sqlalchemy_exc.SQLAchmyError as e:
                raise MTDatabaseManagerException(f"Could not create engine for schema check: {e}") from e


        try:
            inspector = sqlalchemy_inspect(self._engine)
            return inspector.has_table("ngfw")
        except sqlalchemy_exc.SQLAlchemyError as e:
            logging.error(f"Database error during schema check: {e}")
            raise MTDatabaseManagerException(f"Database error during schema check: {e}") from e
        except Exception as e:
            logging.error(f"An unexpected error occurred during schema check: {e}")
            raise MTDatabaseManagerException(f"Unexpected error during schema check: {e}") from e

    # --- Generic Query Helpers (Moved from MTController) ---
    def get_ngfws_by_filter(self, session: Session, ngfw_filter: str = None) -> list[Ngfw]:
        """ Queries NGFW objects by filter (hostname, IP, serial). """
        query = session.query(Ngfw).options(joinedload(Ngfw.panorama))
        if ngfw_filter:
            query = query.filter(
                (Ngfw.hostname == ngfw_filter) |
                (Ngfw.ip_address == ngfw_filter) |
                (Ngfw.serial_number == ngfw_filter) |
                (Ngfw.alt_ip == ngfw_filter) |
                (Ngfw.alt_serial == ngfw_filter)
            )
        return query.all()

    def get_vrs_by_ngfw_and_filter(self, session: Session, ngfw_id: int = None, vr_filter: str = None) -> list[VirtualRouter]:
        """ Queries VirtualRouter objects by NGFW ID and/or VR name. """
        query = session.query(VirtualRouter)
        if ngfw_id is not None:
            query = query.filter(VirtualRouter.ngfw_id == ngfw_id)
        # Only join Ngfw if a vr_filter is present and ngfw_id is None, to avoid unnecessary joins
        elif vr_filter:
            query = query.join(VirtualRouter.ngfw)
        if vr_filter:
            query = query.filter(VirtualRouter.name == vr_filter)
        query = query.options(joinedload(VirtualRouter.ngfw))
        return query.all()

    def get_interfaces_by_ngfw_and_filter(self, session: Session, ngfw_id: int, interface_filter: str = None) -> list[Interface]:
        """ Queries Interface objects by NGFW ID and/or interface name. """
        # Join VirtualRouter to filter by ngfw_id, as interface is linked to VR
        query = session.query(Interface).join(VirtualRouter).filter(VirtualRouter.ngfw_id == ngfw_id)
        if interface_filter:
            query = query.filter(Interface.name == interface_filter)
        query = query.options(joinedload(Interface.virtual_router).joinedload(VirtualRouter.ngfw))
        return query.all()

    # --- Add other direct database query/manipulation methods here as they are extracted ---
    # Methods for general data retrieval
    def get_all_vrs(self, session: Session) -> list[VirtualRouter]:
        return session.query(VirtualRouter).all()

    def get_all_ngfws(self, session: Session, load_panorama=False) -> list[Ngfw]:
        query = session.query(Ngfw)
        if load_panorama:
            query = query.options(joinedload(Ngfw.panorama))
        return query.all()

    def get_ngfw_by_serial(self, session: Session, serial: str) -> Ngfw | None:
        return session.query(Ngfw).options(joinedload(Ngfw.panorama)).filter(Ngfw.serial_number == serial).first()

    def get_panorama_by_serial(self, session: Session, serial: str) -> Panorama | None:
        return session.query(Panorama).options(joinedload(Panorama.ngfws)).filter(Panorama.serial_number == serial).first()

    def get_all_panoramas(self, session: Session, load_ngfws=False) -> list[Panorama]:
        query = session.query(Panorama)
        if load_ngfws:
            query = query.options(joinedload(Panorama.ngfws))
        return query.all()

    def get_all_lldp_entries(self, session: Session) -> list[Neighbor]:
        # Filter where Neighbor has an associated Ngfw to avoid orphaned entries if Ngfw was deleted
        return session.query(Neighbor).options(joinedload(Neighbor.ngfw)).filter(Neighbor.ngfw.has()).all()

    def get_lldp_entries_for_ngfw(self, session: Session, ngfw_id: int) -> list[Neighbor]:
        return session.query(Neighbor).filter_by(ngfw_id=ngfw_id).all()

    # Methods for data insertion/deletion (used by MTBuilder as well, and by MTController updates)
    def add_object(self, session: Session, obj: Base | list[Base]):
        """Adds a single object or a list of objects to the session."""
        if isinstance(obj, list):
            session.add_all(obj)
        else:
            session.add(obj)

    def delete_object(self, session: Session, obj: Base):
        """Deletes a single object from the session."""
        session.delete(obj)

    def delete_vrs_by_ngfw_id(self, session: Session, ngfw_id: int) -> int:
        """Deletes VirtualRouters and cascaded data for a given NGFW ID."""
        # Due to cascade rules, deleting VRs will delete associated interfaces, fibs, routes, etc.
        # It's better to fetch and delete objects to ensure cascades run properly
        vrs_to_delete = session.query(VirtualRouter).filter(VirtualRouter.ngfw_id == ngfw_id).all()
        deleted_count = 0
        for vr in vrs_to_delete:
            session.delete(vr)
            deleted_count += 1
        return deleted_count

    def delete_fibs_by_vr_ids(self, session: Session, vr_ids: list[int]) -> int:
        """Deletes Fib entries for given VirtualRouter IDs."""
        deleted_count = session.query(Fib).filter(Fib.virtual_router_id.in_(vr_ids)).delete(synchronize_session=False)
        return deleted_count

    def delete_routes_by_vr_ids(self, session: Session, vr_ids: list[int]) -> int:
        """Deletes Route entries for given VirtualRouter IDs."""
        deleted_count = session.query(Route).filter(Route.virtual_router_id.in_(vr_ids)).delete(synchronize_session=False)
        return deleted_count

    def delete_arps_by_interface_ids(self, session: Session, interface_ids: list[int]) -> int:
        """Deletes ARP entries for given Interface IDs."""
        deleted_count = session.query(Arp).filter(Arp.interface_id.in_(interface_ids)).delete(synchronize_session=False)
        return deleted_count

    def delete_neighbors_by_ngfw_id(self, session: Session, ngfw_id: int) -> int:
        """Deletes Neighbor entries for a given NGFW ID."""
        deleted_count = session.query(Neighbor).filter(Neighbor.ngfw_id == ngfw_id).delete(synchronize_session=False)
        return deleted_count

    def delete_bgp_peers_by_ngfw_vr_ids(self, session: Session, ngfw_id: int, vr_ids: list[int]) -> int:
        """Deletes BGPPeer entries for a given NGFW ID and VirtualRouter IDs."""
        deleted_count = session.query(BGPPeer).filter(BGPPeer.ngfw_id == ngfw_id, BGPPeer.virtual_router_id.in_(vr_ids)).delete(synchronize_session=False)
        return deleted_count

    def count_table_entries(self, session: Session, model_class: Base) -> int:
        """Returns the count of entries in a given table."""
        return session.query(model_class).count()

    # Methods for data explorer queries (pulled from MTController.get_* methods)
    def get_routes_for_query(self, session: Session, ngfw_filter: str | None, vr_filter: str | None, destination: str | None, flags: str | None, afi: str | None) -> list[Route]:
        query = session.query(Route).join(Route.virtual_router).join(VirtualRouter.ngfw)
        if ngfw_filter:
            query = query.filter((Ngfw.hostname == ngfw_filter) | (Ngfw.ip_address == ngfw_filter) | (Ngfw.serial_number == ngfw_filter) | (Ngfw.alt_ip == ngfw_filter) | (Ngfw.alt_serial == ngfw_filter))
        if vr_filter:
            query = query.filter(VirtualRouter.name == vr_filter)
        if destination:
            query = query.filter(Route.destination.like(f"{destination}%"))
        if flags:
            for f in [fl.strip().upper() for fl in flags.split(',')]:
                query = query.filter(Route.flags.contains(f))
        if afi and afi.lower() in ['ipv4', 'ipv6']:
            query = query.filter(Route.afi == afi.lower())
        query = query.options(joinedload(Route.virtual_router).joinedload(VirtualRouter.ngfw))
        return query.all()

    def get_fibs_for_query(self, session: Session, ngfw_filter: str | None, vr_filter: str | None, destination: str | None, flags: str | None, afi: str | None) -> list[Fib]:
        query = session.query(Fib).join(Fib.virtual_router).join(VirtualRouter.ngfw)
        if ngfw_filter:
            query = query.filter((Ngfw.hostname == ngfw_filter) | (Ngfw.ip_address == ngfw_filter) | (Ngfw.serial_number == ngfw_filter) | (Ngfw.alt_ip == ngfw_filter) | (Ngfw.alt_serial == ngfw_filter))
        if vr_filter:
            query = query.filter(VirtualRouter.name == vr_filter)
        if destination:
            query = query.filter(Fib.destination.like(f"{destination}%"))
        if flags:
            for f in [fl.strip().upper() for fl in flags.split(',')]:
                query = query.filter(Fib.flags.contains(f))
        if afi and afi.lower() in ['ipv4', 'ipv6']:
            query = query.filter(Fib.afi == afi.lower())
        query = query.options(joinedload(Fib.virtual_router).joinedload(VirtualRouter.ngfw))
        return query.all()

    def get_interfaces_for_query(self, session: Session, ngfw_filter: str | None, vr_filter: str | None, ipv6_enabled_only: bool) -> list[Interface]:
        query = session.query(Interface).join(Interface.virtual_router).join(VirtualRouter.ngfw)
        if ngfw_filter:
            query = query.filter((Ngfw.hostname == ngfw_filter) | (Ngfw.ip_address == ngfw_filter) | (Ngfw.serial_number == ngfw_filter) | (Ngfw.alt_ip == ngfw_filter) | (Ngfw.alt_serial == ngfw_filter))
        if vr_filter:
            query = query.filter(VirtualRouter.name == vr_filter)
        if ipv6_enabled_only:
            query = query.filter(Interface.ipv6_enabled == True)
        query = query.options(
            joinedload(Interface.virtual_router).joinedload(VirtualRouter.ngfw),
            joinedload(Interface.ipv6_addresses)
        )
        return query.all()

    def get_bgp_peers_for_query(self, session: Session, ngfw_filter: str | None, vr_filter: str | None) -> list[BGPPeer]:
        query = session.query(BGPPeer).join(BGPPeer.virtual_router).join(VirtualRouter.ngfw)
        if ngfw_filter:
            query = query.filter((Ngfw.hostname == ngfw_filter) | (Ngfw.ip_address == ngfw_filter) | (Ngfw.serial_number == ngfw_filter) | (Ngfw.alt_ip == ngfw_filter) | (Ngfw.alt_serial == ngfw_filter))
        if vr_filter:
            query = query.filter(VirtualRouter.name == vr_filter)
        return query.options(joinedload(BGPPeer.virtual_router).joinedload(VirtualRouter.ngfw), joinedload(BGPPeer.ngfw)).all()

    def get_arps_for_query(self, session: Session, ngfw_filter: str | None, interface_filter: str | None) -> list[Arp]:
        query = session.query(Arp).join(Arp.interface).join(Interface.virtual_router).join(VirtualRouter.ngfw)
        if ngfw_filter:
            query = query.filter((Ngfw.hostname == ngfw_filter) | (Ngfw.ip_address == ngfw_filter) | (Ngfw.serial_number == ngfw_filter) | (Ngfw.alt_ip == ngfw_filter) | (Ngfw.alt_serial == ngfw_filter))
        if interface_filter:
            query = query.filter(Interface.name == interface_filter)
        return query.options(joinedload(Arp.interface).joinedload(Interface.virtual_router).joinedload(VirtualRouter.ngfw)).all()

    def get_neighbors_for_query(self, session: Session, ngfw_filter: str | None) -> list[Neighbor]:
        query = session.query(Neighbor).join(Neighbor.ngfw)
        if ngfw_filter:
            query = query.filter((Ngfw.hostname == ngfw_filter) | (Ngfw.ip_address == ngfw_filter) | (Ngfw.serial_number == ngfw_filter) | (Ngfw.alt_ip == ngfw_filter) | (Ngfw.alt_serial == ngfw_filter))
        return query.options(joinedload(Neighbor.ngfw)).all()

    # Methods related to the _enrich_results_with_zone helper
    def get_all_interfaces_for_zone_enrichment(self, session: Session, ngfw_ids: list[int]) -> list[Interface]:
        return session.query(Interface).join(VirtualRouter)\
            .options(joinedload(Interface.virtual_router).joinedload(VirtualRouter.ngfw))\
            .filter(VirtualRouter.ngfw_id.in_(ngfw_ids)).all()

    def get_all_ipv6_addrs_for_zone_enrichment(self, session: Session, ngfw_ids: list[int]) -> list[InterfaceIPv6Address]:
        return session.query(InterfaceIPv6Address).join(Interface)\
            .options(joinedload(InterfaceIPv6Address.interface))\
            .filter(Interface.virtual_router_id.in_(
                session.query(VirtualRouter.id).filter(VirtualRouter.ngfw_id.in_(ngfw_ids))
            )).all()

    def get_all_fibs_for_zone_enrichment(self, session: Session, ngfw_ids: list[int]) -> list[Fib]:
        return session.query(Fib).join(VirtualRouter)\
            .options(joinedload(Fib.virtual_router).joinedload(VirtualRouter.ngfw))\
            .filter(VirtualRouter.ngfw_id.in_(ngfw_ids)).all()