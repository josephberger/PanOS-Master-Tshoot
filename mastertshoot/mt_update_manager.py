# mastertshoot/mt_update_manager.py

import datetime
import logging
import ipaddress # Needed for _detect_address_family, which is moved here
import copy # If any moved methods use it, though often it's for API data copies

# --- SQLAlchemy Imports ---
from sqlalchemy import exc as sqlalchemy_exc # Corrected: Added this import
from sqlalchemy.orm import Session, joinedload # Session might be used in some helper methods, joinedload for queries


# Import models
from models import (
    Ngfw, Route, VirtualRouter, Interface, Panorama,
    Neighbor, BGPPeer, Fib, Arp, InterfaceIPv6Address
)

# Import dependencies
from mastertshoot.mt_database_manager import MTDatabaseManager, MTDatabaseManagerException
from mastertshoot.mt_api_service import MTAPIService, MTAPIServiceException
from mastertshoot.mt_data_formatter import MTDataFormatter
from mastertshoot.mt_analyzer import MTAnalyzer # Needed for _enrich_results_with_zone and _detect_address_family

class MTUpdateManagerException(Exception):
    """Custom exception for MTUpdateManager errors."""
    pass

class MTUpdateManager:
    """
    Orchestrates the process of fetching data from devices and updating the database.
    Also centralizes the creation of database objects from raw API data.
    """

    def __init__(self, db_manager: MTDatabaseManager, api_service: MTAPIService,
                 data_formatter: MTDataFormatter, analyzer: MTAnalyzer):
        """
        Initializes the MTUpdateManager.

        Args:
            db_manager (MTDatabaseManager): An instance of MTDatabaseManager for database interactions.
            api_service (MTAPIService): An instance of MTAPIService for live API calls.
            data_formatter (MTDataFormatter): An instance of MTDataFormatter for data presentation/null checking.
            analyzer (MTAnalyzer): An instance of MTAnalyzer for analysis methods like zone enrichment.
        """
        self.db_manager = db_manager
        self.api_service = api_service
        self.data_formatter = data_formatter
        self.analyzer = analyzer # Inject the analyzer for zone enrichment and AFI detection
        logging.debug("MTUpdateManager initialized.")

    def import_panorama_devices(self, pan_filter=None):
        """
        Imports NGFW details from Panoramas. This is a GENERATOR that yields
        status messages during its execution.
        """
        logging.info(f"Starting import of Panorama devices. Filter: '{pan_filter or 'All'}'")
        try:
            with self.db_manager.get_session() as session:
                pan_query = self.db_manager.get_all_panoramas(session)
                if pan_filter:
                    pan_list = [p for p in pan_query if p.hostname == pan_filter or p.ip_address == pan_filter]
                else:
                    pan_list = pan_query

                if not pan_list:
                    yield f"Panorama '{pan_filter or 'Any'}' not found in database."
                    return

                existing_serials = {s for s, in session.query(Ngfw.serial_number).all()} | \
                                   {s for s, in session.query(Ngfw.alt_serial).filter(Ngfw.alt_serial.isnot(None)).all()}

                for panorama_obj in pan_list:
                    yield f"--- Processing Panorama: {panorama_obj.hostname} ({panorama_obj.ip_address}) ---"
                    devices_api = self.api_service.fetch_panorama_devices(panorama_obj)

                    if devices_api is None:
                        yield f"  ERROR: Failed to fetch devices via API. Skipping."
                        continue
                    if not devices_api:
                        yield f"  INFO: No connected devices reported by API."
                        continue

                    added_count, skipped_count, error_count = 0, 0, 0
                    for device_data in devices_api:
                        try:
                            serial = device_data.get('serial')
                            hostname = device_data.get('hostname', f"Unnamed-{serial[:4]}" if serial else "Unknown")
                            if not serial or serial in existing_serials or device_data.get('connected') != 'yes':
                                skipped_count += 1; continue

                            active, alt_serial = True, None
                            ha_info = device_data.get('ha', {})
                            if ha_info and 'active' not in ha_info.get('state', 'active').lower():
                                skipped_count += 1; continue
                            if ha_info: alt_serial = ha_info.get('peer', {}).get('serial') or None

                            advanced_routing = False
                            if 'advanced-routing' in device_data:
                                if device_data['advanced-routing'] == 'yes':
                                    advanced_routing = True

                            ipv6_address_val = device_data.get('ipv6-address', '')
                            if str(ipv6_address_val).lower() in ['unknown', 'none']: ipv6_address_val = ''
                            
                            mac_address_val = device_data.get('mac-addr', '')
                            uptime_val = device_data.get('uptime', '')
                            sw_version_val = device_data.get('sw-version', '')
                            app_version_val = device_data.get('app-version', '')
                            av_version_val = device_data.get('av-version', '')
                            wildfire_version_val = device_data.get('wildfire-version', '')
                            threat_version_val = device_data.get('threat-version', '')
                            url_filtering_version_val = device_data.get('url-filtering-version', '')
                            
                            device_cert_present_val = device_data.get('device-cert-present', '')
                            if str(device_cert_present_val).lower() in ['none', 'n/a']: device_cert_present_val = ''
                                
                            device_cert_expiry_date_val = device_data.get('device-cert-expiry-date', '')
                            if str(device_cert_expiry_date_val).lower() == 'n/a': device_cert_expiry_date_val = ''
                            
                            ngfw_data = {
                                'hostname': hostname,
                                'serial_number': serial,
                                'ip_address': device_data.get('ip-address',''),
                                'model': device_data.get('model',''),
                                'panorama_id': panorama_obj.id,
                                'active': active,
                                'alt_serial': alt_serial,
                                'alt_ip': None,
                                'api_key': None,
                                'advanced_routing_enabled': advanced_routing,
                                'last_update': None,
                                'ipv6_address': ipv6_address_val,
                                'mac_address': mac_address_val,
                                'uptime': uptime_val,
                                'sw_version': sw_version_val,
                                'app_version': app_version_val,
                                'av_version': av_version_val,
                                'wildfire_version': wildfire_version_val,
                                'threat_version': threat_version_val,
                                'url_filtering_version': url_filtering_version_val,
                                'device_cert_present': device_cert_present_val,
                                'device_cert_expiry_date': device_cert_expiry_date_val
                            }
                            new_ngfw = Ngfw(**ngfw_data)
                            self.db_manager.add_object(session, new_ngfw)
                            existing_serials.add(serial)
                            if new_ngfw.alt_serial: existing_serials.add(new_ngfw.alt_serial)
                            added_count += 1
                            yield f"  SUCCESS: NGFW '{hostname}' ({serial}) queued for addition."
                        except Exception as e:
                            error_count += 1
                            yield f"  ERROR processing device data (Serial: {serial or 'Unknown'}): {e}"
                            session.rollback()
                    
                    yield f"  Import summary: Added {added_count}, Skipped {skipped_count}, Errors {error_count}."
                    session.commit()
        except sqlalchemy_exc.SQLAlchemyError as e:
            yield f"FATAL DB ERROR: {e}"
            session.rollback()
        except Exception as e:
            yield f"FATAL UNEXPECTED ERROR: {e}"
            session.rollback()

    def refresh_ngfws(self, ngfw_filter=None):
        """
        Refreshes NGFW data. This is a GENERATOR that yields status messages.
        """
        logging.info(f"Starting NGFW refresh. Filter: '{ngfw_filter or 'All'}'")
        try:
            with self.db_manager.get_session() as session:
                ngfw_list = self.db_manager.get_ngfws_by_filter(session, ngfw_filter)
                if not ngfw_list:
                    yield f"No NGFWs found matching '{ngfw_filter or 'Any'}'."
                    return

                for ngfw_obj in ngfw_list:
                    yield f"--- Refreshing NGFW: {ngfw_obj.hostname} ({ngfw_obj.serial_number}) ---"
                    commit_needed = False
                    
                    system_info = self.api_service.fetch_system_info(ngfw_obj)
                    if system_info is None:
                        yield f"  ERROR: Could not connect. Skipping refresh."
                        continue
                    yield "  SUCCESS: Connected to device."
                    
                    yield "  Checking for Advanced Routing Engine status..."
                    are_status_from_api_raw = system_info.get('advanced-routing', 'off')
                    are_enabled_from_api = str(are_status_from_api_raw).lower() == 'on'

                    if are_enabled_from_api != ngfw_obj.advanced_routing_enabled:
                        yield (f"    Status mismatch found (DB: {ngfw_obj.advanced_routing_enabled}, "
                               f"Device: {are_enabled_from_api}). Updating database.")
                        ngfw_obj.advanced_routing_enabled = are_enabled_from_api
                        commit_needed = True
                    else:
                        yield f"    Status confirmed: Advanced Routing is {'enabled' if are_enabled_from_api else 'disabled'}."

                    try:
                        yield "  Deleting existing virtual routers and related data..."
                        deleted_vr_count = self.db_manager.delete_vrs_by_ngfw_id(session, ngfw_obj.id)

                        if deleted_vr_count > 0:
                            yield f"  Deleted {deleted_vr_count} existing VR(s) and associated data."
                            session.flush()
                            commit_needed = True
                        else:
                            yield "  No existing VRs found to delete."

                        vr_map = {}
                        yield "  Fetching new virtual router configuration..."
                        vr_names_api = self.api_service.fetch_virtual_routes(ngfw_obj)
                        if vr_names_api is None:
                            yield "  ERROR: Failed to fetch VRs via API. Aborting interface processing."
                        elif not vr_names_api:
                            yield "  INFO: No VRs reported by API."
                        else:
                            yield f"  Found {len(vr_names_api)} VRs via API. Adding them..."
                            for vr_name in vr_names_api:
                                new_vr = VirtualRouter(name=vr_name, ngfw_id=ngfw_obj.id)
                                self.db_manager.add_object(session, new_vr)
                                vr_map[vr_name] = new_vr
                            session.flush()
                            yield f"  Added {len(vr_map)} new VR(s)."
                            commit_needed = True

                            yield "  Fetching new interface configuration..."
                            interfaces_api = self.api_service.fetch_interfaces(ngfw_obj)
                            if interfaces_api is None:
                                yield "  ERROR: Failed to fetch Interfaces via API."
                            elif not interfaces_api:
                                yield "  INFO: No interfaces reported by API."
                            else:
                                yield f"  Found {len(interfaces_api)} Interfaces via API. Processing..."
                                added_if_count, skipped_if_count, added_ipv6_count = 0, 0, 0
                                new_interfaces_to_add = []
                                ipv6_addresses_to_add = []

                                for if_data in interfaces_api:
                                    vr_name = if_data.get('virtual_router')
                                    if vr_name in vr_map:
                                        vr_obj = vr_map[vr_name]
                                        ipv6_list = if_data.get('ipv6_addresses', [])
                                        has_ipv6 = bool(ipv6_list)

                                        new_if = Interface(
                                            name=if_data.get('name', ''), tag=if_data.get('tag', ''),
                                            vsys=if_data.get('vsys', ''), zone=if_data.get('zone', ''),
                                            ip=if_data.get('ip', ''), virtual_router_id=vr_obj.id,
                                            ipv6_enabled=has_ipv6
                                        )
                                        new_interfaces_to_add.append(new_if)
                                        added_if_count += 1

                                        for ipv6_addr in ipv6_list:
                                            ipv6_addresses_to_add.append(InterfaceIPv6Address(address=ipv6_addr, interface=new_if))
                                            added_ipv6_count += 1
                                    else:
                                        skipped_if_count += 1

                                if new_interfaces_to_add:
                                    self.db_manager.add_object(session, new_interfaces_to_add)
                                    self.db_manager.add_object(session, ipv6_addresses_to_add)
                                    commit_needed = True
                                
                                yield f"  Processed {added_if_count} Interface(s) and {added_ipv6_count} IPv6 Address(es). Skipped {skipped_if_count}."

                        ngfw_obj.last_update = datetime.datetime.now().isoformat(timespec='seconds')
                        if commit_needed:
                            yield "  Committing changes to database..."
                            session.commit()
                            yield "  Refresh successful."
                        else:
                            session.merge(ngfw_obj)
                            session.commit()
                            yield "  Refresh complete (timestamp updated, no other data changes)."

                    except sqlalchemy_exc.SQLAlchemyError as db_op_err:
                        yield f"  DB ERROR during processing: {db_op_err}. Rolling back changes for this NGFW."
                        session.rollback()
                        continue
                    except Exception as proc_err:
                        yield f"  UNEXPECTED ERROR during processing: {proc_err}. Rolling back."
                        session.rollback()
                        continue

        except Exception as e:
            yield f"FATAL ERROR during refresh: {e}"

    def update_routes(self, ngfw=None, virtual_router=None) -> list:
            """
            Updates routes and FIBs (IPv4 & IPv6) in the database using API data,
            including zone enrichment before saving.
            """
            logging.info(f"Starting update_routes. NGFW filter: '{ngfw if ngfw else 'All'}', VR filter: '{virtual_router if virtual_router else 'All'}'")
            messages = []
            try:
                with self.db_manager.get_session() as session:
                    ngfw_list = self.db_manager.get_ngfws_by_filter(session, ngfw)
                    if not ngfw_list:
                        return [f"No NGFWs found matching '{ngfw or 'Any'}'."]

                    for ngfw_obj in ngfw_list:
                        messages.append(f"--- Updating Routes/FIBs (v4/v6) for NGFW: {ngfw_obj.hostname} ---")

                        vr_list_db = self.db_manager.get_vrs_by_ngfw_and_filter(session, ngfw_obj.id, virtual_router)
                        target_vr_ids = [vr.id for vr in vr_list_db]
                        vr_map = {vr.name: vr.id for vr in vr_list_db}
                        if not vr_map:
                            messages.append(f"  No VRs matching '{virtual_router or 'Any'}' found on this NGFW. Skipping.")
                            continue

                        interface_map = {}
                        if target_vr_ids:
                            interfaces_for_ngfw = session.query(Interface).filter(Interface.virtual_router_id.in_(target_vr_ids)).all()
                            interface_map = {(iface.virtual_router_id, iface.name): iface.id for iface in interfaces_for_ngfw}

                        commit_needed = False
                        try:
                            if target_vr_ids:
                                messages.append(f"  Deleting existing Routes/FIBs for VR ID(s): {target_vr_ids}...")
                                deleted_fib_count = self.db_manager.delete_fibs_by_vr_ids(session, target_vr_ids)
                                deleted_route_count = self.db_manager.delete_routes_by_vr_ids(session, target_vr_ids)
                                messages.append(f"  Deleted {deleted_fib_count} FIB(s) and {deleted_route_count} Route(s).")
                                commit_needed = commit_needed or deleted_fib_count > 0 or deleted_route_count > 0
                                session.flush()
                        except sqlalchemy_exc.SQLAlchemyError as db_del_err:
                             messages.append(f"  DB error deleting existing entries: {db_del_err}. Aborting update for this NGFW.")
                             session.rollback()
                             continue

                        fib_count, route_count = 0, 0
                        db_fibs_to_add = []
                        db_routes_to_add = []

                        try:
                            messages.append(f"  Fetching FIBs for VR(s): {', '.join(vr_map.keys())}...")
                            fibs_api = self.api_service.fetch_fibs(ngfw_obj, virtual_router=virtual_router)

                            if fibs_api is None:
                                messages.append("  Warning: Failed to fetch FIBs via API. Skipping FIB update.")
                            elif fibs_api:
                                messages.append(f"  Enriching {len(fibs_api)} FIB entries with zone information...")
                                for f_data in fibs_api: f_data['ngfw'] = ngfw_obj.hostname
                                self.analyzer._enrich_results_with_zone(session, [ngfw_obj.id], fibs_api) # Use analyzer's method
                                
                                messages.append(f"  Processing {len(fibs_api)} enriched FIB entries...")
                                for f_data in fibs_api:
                                    dest = f_data.get('destination', '')
                                    afi = self.analyzer._detect_address_family(dest) # Use analyzer's method
                                    vr_name = f_data.get('virtual_router')
                                    if afi and vr_name in vr_map:
                                        vr_id = vr_map[vr_name]

                                        interface_name = f_data.get('interface')
                                        interface_id = interface_map.get((vr_id, interface_name))

                                        db_fibs_to_add.append(self._create_fib_object(vr_id, afi, f_data, interface_id))
                                    elif not afi:
                                         messages.append(f"  Skipping FIB entry with unidentifiable AFI: {dest}")

                            messages.append(f"  Fetching Routes for VR(s): {', '.join(vr_map.keys())}...")
                            routes_api = self.api_service.fetch_routes(ngfw_obj, virtual_router=virtual_router)

                            if routes_api is None:
                                messages.append("  Warning: Failed to fetch Routes via API. Skipping Route update.")
                            elif routes_api:
                                messages.append(f"  Enriching {len(routes_api)} Route entries with zone information...")
                                for r_data in routes_api: r_data['ngfw'] = ngfw_obj.hostname
                                self.analyzer._enrich_results_with_zone(session, [ngfw_obj.id], routes_api) # Use analyzer's method

                                messages.append(f"  Processing {len(routes_api)} enriched Route entries...")
                                for r_data in routes_api:
                                    dest = r_data.get('destination', '')
                                    afi = self.analyzer._detect_address_family(dest) # Use analyzer's method
                                    vr_name = r_data.get('virtual_router')
                                    if afi and vr_name in vr_map:
                                        vr_id = vr_map[vr_name]
                                        db_routes_to_add.append(self._create_route_object(vr_id, afi, r_data))
                                    elif not afi:
                                         messages.append(f"  Skipping Route entry with unidentifiable AFI: {dest}")

                            if db_fibs_to_add:
                                self.db_manager.add_object(session, db_fibs_to_add)
                                fib_count = len(db_fibs_to_add)
                                messages.append(f"  Prepared {fib_count} new FIB(s).")
                                commit_needed = True
                            else:
                                messages.append("  No new valid FIBs found/processed.")

                            if db_routes_to_add:
                                self.db_manager.add_object(session, db_routes_to_add)
                                route_count = len(db_routes_to_add)
                                messages.append(f"  Prepared {route_count} new Route(s).")
                                commit_needed = True
                            else:
                                messages.append("  No new valid Routes found/processed.")

                        except MTAPIServiceException as api_err: # Specific API service exception
                             messages.append(f"  API error during fetch/process: {api_err}. Aborting update for this NGFW.")
                             session.rollback(); commit_needed = False; continue
                        except Exception as update_err:
                             logging.error(f"Error during update processing for {ngfw_obj.hostname}: {update_err}", exc_info=True)
                             messages.append(f"  Error during update processing: {update_err}. Rolling back.")
                             session.rollback(); commit_needed = False; continue

                        if commit_needed:
                            try:
                                session.commit()
                                messages.append(f"  Successfully updated {route_count} route(s) and {fib_count} FIB(s).")
                            except sqlalchemy_exc.SQLAlchemyError as commit_err:
                                messages.append(f"  DB commit error: {commit_err}. Rolled back.")
                                session.rollback()
                        else:
                            messages.append(f"  No database changes were committed for routes/FIBs.")

                        messages.append(f"--- Update complete for {ngfw_obj.hostname} ---")
            except sqlalchemy_exc.SQLAlchemyError as db_err: # Corrected SQLAlchemyError
                 raise MTUpdateManagerException(f"DB error during update_routes setup: {db_err}")
            except Exception as e:
                 logging.error(f"Unexpected error during update_routes: {e}", exc_info=True)
                 raise MTUpdateManagerException(f"Unexpected error during update_routes: {e}")

            return messages


    def update_arps(self, ngfw=None, interface=None) -> list:
        """ Updates ARP entries in the database using API data. """
        logging.info(f"Starting update_arps. NGFW filter: '{ngfw if ngfw else 'All'}', Interface filter: '{interface if interface else 'All'}'")
        messages = []
        try:
            with self.db_manager.get_session() as session:
                ngfw_list = self.db_manager.get_ngfws_by_filter(session, ngfw)
                if not ngfw_list: return [f"No NGFWs found matching '{ngfw or 'Any'}'."]

                for ngfw_obj in ngfw_list:
                    messages.append(f"--- Updating ARPs for NGFW: {ngfw_obj.hostname} ---")
                    interfaces_db = self.db_manager.get_interfaces_by_ngfw_and_filter(session, ngfw_obj.id, interface)
                    target_interface_ids = [i.id for i in interfaces_db]
                    interface_map = {i.name: {'id': i.id, 'zone': i.zone} for i in interfaces_db}
                    if not interface_map: messages.append(f"  No Interfaces matching '{interface or 'Any'}'. Skipping."); continue

                    arp_count = 0
                    commit_needed = False
                    try:
                        messages.append(f"  Fetching ARPs for interface(s): {interface or 'All'}...")
                        arps_api = self.api_service.fetch_arps(ngfw_obj, interface=interface)
                        if arps_api is None: messages.append("  Failed to fetch ARPs via API."); raise MTUpdateManagerException("API Fetch Failed")
                        if target_interface_ids:
                            deleted_arp_count = self.db_manager.delete_arps_by_interface_ids(session, target_interface_ids)
                            messages.append(f"  Deleted {deleted_arp_count} existing ARP(s)."); commit_needed = commit_needed or deleted_arp_count > 0
                        db_arps = [self._create_arp_object(interface_map[a_data['interface']]['id'], interface_map[a_data['interface']]['zone'], a_data)
                                   for a_data in arps_api if a_data.get('interface') in interface_map]
                        if db_arps:
                            self.db_manager.add_object(session, db_arps); arp_count = len(db_arps); messages.append(f"  Added {arp_count} new ARP(s)."); commit_needed = True
                        else: messages.append("  No new ARPs to add.")
                    except Exception as update_err: messages.append(f"  Error during update: {update_err}. Rolling back."); session.rollback(); commit_needed = False
                    finally:
                         if commit_needed:
                              try: session.commit(); messages.append(f"  Successfully updated {arp_count} ARP(s).")
                              except sqlalchemy_exc.SQLAlchemyError as commit_err: messages.append(f"  DB commit error: {commit_err}. Rolled back."); session.rollback()
                         else: messages.append(f"  No database changes to commit.")
                         messages.append(f"--- ARP Update complete for {ngfw_obj.hostname} ---")
        except sqlalchemy_exc.SQLAlchemyError as db_err: raise MTUpdateManagerException(f"DB error during update_arps setup: {db_err}")
        except Exception as e: raise MTUpdateManagerException(f"Unexpected error during update_arps: {e}")
        return messages

    def update_neighbors(self, ngfw=None) -> list:
        """ Updates LLDP neighbors in the database using API data. """
        logging.info(f"Starting update_neighbors. NGFW filter: '{ngfw if ngfw else 'All'}'")
        messages = []
        try:
            with self.db_manager.get_session() as session:
                ngfw_list = self.db_manager.get_ngfws_by_filter(session, ngfw)
                if not ngfw_list: return [f"No NGFWs found matching '{ngfw or 'Any'}'."]

                for ngfw_obj in ngfw_list:
                    messages.append(f"--- Updating LLDP Neighbors for NGFW: {ngfw_obj.hostname} ---")
                    neighbor_count = 0
                    commit_needed = False
                    try:
                        messages.append(f"  Fetching LLDP neighbors from API...")
                        neighbors_api = self.api_service.fetch_neighbors(ngfw_obj)
                        if neighbors_api is None: messages.append("  Failed to fetch neighbors via API."); raise MTUpdateManagerException("API Fetch Failed")
                        deleted_neighbor_count = self.db_manager.delete_neighbors_by_ngfw_id(session, ngfw_obj.id)
                        messages.append(f"  Deleted {deleted_neighbor_count} existing Neighbor(s)."); commit_needed = commit_needed or deleted_neighbor_count > 0
                        db_neighbors = [self._create_neighbor_object(ngfw_obj.id, ne_data) for ne_data in neighbors_api]
                        if db_neighbors:
                            self.db_manager.add_object(session, db_neighbors); neighbor_count = len(db_neighbors); messages.append(f"  Added {neighbor_count} new Neighbor(s)."); commit_needed = True
                        else: messages.append("  No new LLDP neighbors to add.")
                    except Exception as update_err: messages.append(f"  Error during update: {update_err}. Rolling back."); session.rollback(); commit_needed = False
                    finally:
                         if commit_needed:
                              try: session.commit(); messages.append(f"  Successfully updated {neighbor_count} LLDP neighbor(s).")
                              except sqlalchemy_exc.SQLAlchemyError as commit_err: messages.append(f"  DB commit error: {commit_err}. Rolled back."); session.rollback()
                         else: messages.append(f"  No database changes to commit.")
                         messages.append(f"--- Neighbor Update complete for {ngfw_obj.hostname} ---")
        except sqlalchemy_exc.SQLAlchemyError as db_err: raise MTUpdateManagerException(f"DB error during update_neighbors setup: {db_err}")
        except Exception as e: raise MTUpdateManagerException(f"Unexpected error during update_neighbors: {e}")
        return messages

    def update_bgp_peers(self, ngfw=None, virtual_router=None) -> list:
        """ Updates BGP peers in the database using API data. """
        logging.info(f"Starting update_bgp_peers. NGFW filter: '{ngfw if ngfw else 'All'}', VR filter: '{virtual_router if virtual_router else 'All'}'")
        messages = []
        try:
            with self.db_manager.get_session() as session:
                ngfw_list = self.db_manager.get_ngfws_by_filter(session, ngfw)
                if not ngfw_list: return [f"No NGFWs found matching '{ngfw or 'Any'}'."]

                for ngfw_obj in ngfw_list:
                    messages.append(f"--- Updating BGP Peers for NGFW: {ngfw_obj.hostname} ---")
                    vr_list_db = self.db_manager.get_vrs_by_ngfw_and_filter(session, ngfw_obj.id, virtual_router)
                    target_vr_ids = [vr.id for vr in vr_list_db]
                    vr_map = {vr.name: vr.id for vr in vr_list_db}
                    if not vr_map: messages.append(f"  No VRs matching '{virtual_router or 'Any'}'. Skipping."); continue

                    bgp_peer_count = 0
                    commit_needed = False
                    try:
                        messages.append(f"  Fetching BGP peers for VR(s): {', '.join(vr_map.keys())}...")
                        bgp_peers_api = self.api_service.fetch_bgp_peers(ngfw_obj, virtual_router=virtual_router)
                        if bgp_peers_api is None: messages.append("  Failed to fetch BGP peers via API."); raise MTUpdateManagerException("API Fetch Failed")
                        if target_vr_ids:
                            deleted_bgp_count = self.db_manager.delete_bgp_peers_by_ngfw_vr_ids(session, ngfw_obj.id, target_vr_ids)
                            messages.append(f"  Deleted {deleted_bgp_count} existing BGP Peer(s)."); commit_needed = commit_needed or deleted_bgp_count > 0
                        db_bgp_peers = [self._create_bgp_peer_object(ngfw_obj.id, vr_map[p_data['virtual_router']], p_data)
                                        for p_data in bgp_peers_api if p_data.get('virtual_router') in vr_map]
                        if db_bgp_peers:
                            self.db_manager.add_object(session, db_bgp_peers); bgp_peer_count = len(db_bgp_peers); messages.append(f"  Added {bgp_peer_count} new BGP Peer(s)."); commit_needed = True
                        else: messages.append("  No new BGP peers to add.")
                    except Exception as update_err: messages.append(f"  Error during update: {update_err}. Rolling back."); session.rollback(); commit_needed = False
                    finally:
                         if commit_needed:
                              try: session.commit(); messages.append(f"  Successfully updated {bgp_peer_count} BGP peer(s).")
                              except sqlalchemy_exc.SQLAlchemyError as commit_err: messages.append(f"  DB commit error: {commit_err}. Rolled back."); session.rollback()
                         else: messages.append(f"  No database changes to commit.")
                         messages.append(f"--- BGP Peer Update complete for {ngfw_obj.hostname} ---")
        except sqlalchemy_exc.SQLAlchemyError as db_err: raise MTUpdateManagerException(f"DB error during update_bgp_peers setup: {db_err}")
        except Exception as e: raise MTUpdateManagerException(f"Unexpected error during update_bgp_peers: {e}")
        return messages

    def update_ha_status(self, ngfw_filter=None, pan_filter=None) -> list:
        """ Updates HA status in the database using API data. """
        logging.info(f"Starting HA status update. NGFW filter: '{ngfw_filter or 'All'}', Panorama filter: '{pan_filter or 'All'}'")
        messages = []
        updated_devices = []
        try:
            with self.db_manager.get_session() as session:
                pan_query_list = self.db_manager.get_all_panoramas(session)
                if pan_filter:
                    pan_list = [p for p in pan_query_list if p.hostname == pan_filter or p.ip_address == pan_filter]
                else:
                    pan_list = pan_query_list
                
                messages.append(f"--- Checking HA Status for {len(pan_list)} Panorama(s) ---")
                for p in pan_list:
                    if p.alt_ip:
                        messages.append(f"  Checking Panorama: {p.hostname}...")
                        ha_info = self.api_service.fetch_panorama_ha_state(p)
                        if ha_info is None: messages.append(f"    Failed to fetch HA state via API."); continue
                        is_active_api = ha_info.get('enabled') == 'yes' and 'local-info' in ha_info and 'active' in ha_info['local-info'].get('state', '').lower()
                        if p.active != is_active_api: messages.append(f"    Status Change: Now {'ACTIVE'}. Updating DB." if is_active_api else f"    Status Change: Now {'PASSIVE'}. Updating DB."); p.active = is_active_api; updated_devices.append(p)
                        else: messages.append(f"    Status Verified: {'ACTIVE' if p.active else 'PASSIVE'}. No change.")
                    else: messages.append(f"  Skipping Panorama {p.hostname}: Not HA configured.")
                
                ngfw_list = self.db_manager.get_ngfws_by_filter(session, ngfw_filter)
                if ngfw_filter == '__IGNORE__':
                    ngfw_list = []
                
                messages.append(f"--- Checking HA Status for {len(ngfw_list)} NGFW(s) ---")
                for n in ngfw_list:
                    if n.alt_serial:
                        messages.append(f"  Checking NGFW: {n.hostname}...")
                        ha_info = self.api_service.fetch_ngfw_ha_status(n)
                        if ha_info is None: messages.append(f"    Failed to fetch HA status via API."); continue
                        is_active_api = 'active' in ha_info.get('state', 'unknown').lower()
                        if n.active != is_active_api: messages.append(f"    Status Change: Now {'ACTIVE'}. Updating DB." if is_active_api else f"    Status Change: Now {'PASSIVE'}. Updating DB."); n.active = is_active_api; updated_devices.append(n)
                        else: messages.append(f"    Status Verified: {'ACTIVE' if n.active else 'PASSIVE'}. No change.")
                    else: messages.append(f"  Skipping NGFW {n.hostname}: Not HA configured.")
                
                if updated_devices:
                    messages.append(f"--- Committing {len(updated_devices)} HA status update(s) ---")
                    try: session.commit(); messages.append("--- DB commit successful ---")
                    except sqlalchemy_exc.SQLAlchemyError as commit_err: messages.append(f"--- DB commit FAILED: {commit_err}. Rolled back. ---"); session.rollback()
                else: messages.append("--- No HA status changes detected ---")
        except sqlalchemy_exc.SQLAlchemyError as db_err: raise MTUpdateManagerException(f"DB error during update_ha_status: {db_err}")
        except Exception as e: raise MTUpdateManagerException(f"Unexpected error during update_ha_status: {e}")
        return messages

    # --- Helpers for creating DB objects (Internal) ---
    def _create_route_object(self, vr_id, afi, data):
        """ Creates a Route object from a dictionary, handling type conversions and AFI. """
        # Using self.data_formatter.null_value_check to handle None to '' conversion for data.get() results
        metric_val = self.data_formatter.null_value_check(data.get('metric'))
        try: metric = int(metric_val) if metric_val != '' else 0
        except (ValueError, TypeError): metric = 0

        age_val = self.data_formatter.null_value_check(data.get('age'))
        age = None
        if age_val != '': # Check for empty string after null_value_check
             try: age = int(age_val)
             except (ValueError, TypeError): age = None

        flags = self.data_formatter.null_value_check(data.get('flags',''))

        return Route(virtual_router_id=vr_id, afi=afi, destination=self.data_formatter.null_value_check(data.get('destination','')),
                     nexthop=self.data_formatter.null_value_check(data.get('nexthop','')), metric=metric, flags=flags,
                     age=age, interface=self.data_formatter.null_value_check(data.get('interface','')),
                     route_table=self.data_formatter.null_value_check(data.get('route_table','')), zone=self.data_formatter.null_value_check(data.get('zone','')))

    def _create_fib_object(self, vr_id, afi, data, interface_id=None):
        """ Creates a Fib object from a dictionary, handling type conversions and AFI. """
        mtu_val = self.data_formatter.null_value_check(data.get('mtu'))
        try: mtu = int(mtu_val) if mtu_val != '' else 0
        except (ValueError, TypeError): mtu = 0

        fib_id_val = self.data_formatter.null_value_check(data.get('fib_id'))
        try: fib_id = int(fib_id_val) if fib_id_val != '' else None
        except (ValueError, TypeError): fib_id = None

        nh_type = self.data_formatter.null_value_check(data.get('nh_type',''))

        flags = self.data_formatter.null_value_check(data.get('flags',''))

        return Fib(virtual_router_id=vr_id, afi=afi, fib_id=fib_id,
                   destination=self.data_formatter.null_value_check(data.get('destination','')), interface=self.data_formatter.null_value_check(data.get('interface','')),
                   nh_type=nh_type, flags=flags,
                   nexthop=self.data_formatter.null_value_check(data.get('nexthop','')), mtu=mtu, zone=self.data_formatter.null_value_check(data.get('zone','')), interface_id=interface_id)

    def _create_arp_object(self, interface_id, zone, data):
         """ Creates an Arp object from a dictionary, handling type conversions. """
         ttl_val = self.data_formatter.null_value_check(data.get('ttl'))
         try: ttl = int(ttl_val) if ttl_val != '' else None
         except (ValueError, TypeError): ttl = None
         return Arp(interface_id=interface_id, ip=self.data_formatter.null_value_check(data.get('ip')), mac=self.data_formatter.null_value_check(data.get('mac')), port=self.data_formatter.null_value_check(data.get('port')),
                    ttl=ttl, status=self.data_formatter.null_value_check(data.get('status')), zone=self.data_formatter.null_value_check(zone))

    def _create_neighbor_object(self, ngfw_id, data):
         """ Creates a Neighbor object from a dictionary. """
         return Neighbor(ngfw_id=ngfw_id, local_interface=self.data_formatter.null_value_check(data.get('local_interface')), remote_interface_id=self.data_formatter.null_value_check(data.get('remote_interface_id')),
                         remote_interface_description=self.data_formatter.null_value_check(data.get('remote_interface_description')), remote_hostname=self.data_formatter.null_value_check(data.get('remote_hostname')))

    def _create_bgp_peer_object(self, ngfw_id, vr_id, data):
         """ Creates a BGPPeer object from a dictionary. """
         return BGPPeer(ngfw_id=ngfw_id, virtual_router_id=vr_id, peer_name=self.data_formatter.null_value_check(data.get('peer_name')), peer_group=self.data_formatter.null_value_check(data.get('peer_group')),
                        peer_router_id=self.data_formatter.null_value_check(data.get('peer_router_id')), remote_as=self.data_formatter.null_value_check(data.get('remote_as')), status=self.data_formatter.null_value_check(data.get('status')),
                        status_duration=self.data_formatter.null_value_check(data.get('status_duration')), peer_address=self.data_formatter.null_value_check(data.get('peer_address')), local_address=self.data_formatter.null_value_check(data.get('local_address')))

