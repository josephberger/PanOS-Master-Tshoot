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

# Standard library imports (if any needed specifically for builder)
import datetime
import logging

# Third-party imports
import pan.xapi
import xmltodict
# Removed direct sqlalchemy imports for create_engine, sessionmaker as they are now
# managed by MTDatabaseManager. Keep sqlalchemy_exc for exception handling.
from sqlalchemy import exc as sqlalchemy_exc
# from sqlalchemy.orm import sessionmaker # Not needed directly anymore

# Local application/library specific imports
from models import Base, Ngfw, Panorama

# Import the new Database Manager
from mastertshoot.mt_database_manager import MTDatabaseManager, MTDatabaseManagerException


# Assuming config.py provides db_uri and timeout
# If config.py is not in the same directory, adjust the import path accordingly
# e.g., from ..config import db_uri, timeout
try:
    from config import db_uri, timeout
except ImportError:
    # Provide default fallbacks or raise a more specific error if config is mandatory
    logging.warning("Warning: Could not import db_uri and timeout from config. Using defaults or potentially failing.")
    db_uri = 'sqlite:///master_tshoot.db' # Example fallback
    timeout = 5 # Example fallback


## CONSTANTS ##
PANORRAMA_MODES = ['panorama', 'management-only']
NGFW_MODELS = ['PA-', 'VM-']

class MTBuilderException(Exception):
    """Custom exception for MTBuilder errors."""
    pass

class MTBuilder:
    """
    Handles database schema creation and initial device addition/deletion (Panorama, NGFW).
    Now delegates direct database interactions to MTDatabaseManager.
    """

    def __init__(self, db_uri=db_uri, timeout=timeout) -> None:
        """
        Initializes an instance of the MTBuilder class.

        Args:
            db_uri (str): The URI of the database (e.g., 'sqlite:///mydatabase.db').
            timeout (int): The timeout value in seconds for API calls to devices.

        Raises:
            MTBuilderException: If the timeout value is not an integer, db_uri is missing,
                                or database connection/engine creation fails during initialization.
        """
        if not db_uri:
             raise MTBuilderException("Database URI ('db_uri') is required.")
        self.db_uri = db_uri

        try:
            self.timeout = int(timeout)
        except (ValueError, TypeError): # Catch specific errors
            raise MTBuilderException(f"Timeout must be an integer, received: {timeout}")

        try:
            # Task 2.2: Add self.db_manager initialization.
            # The MTDatabaseManager now manages the engine and session factory.
            self.db_manager = MTDatabaseManager(db_uri=self.db_uri)
            # Remove self._engine and self._Session initialization.
            # self._engine and self._Session are no longer direct attributes of MTBuilder.
            # If `Base.metadata.create_all` still requires a direct engine, we can access it via `self.db_manager._engine`
            # or `self.db_manager.get_session().__enter__().bind` if needed for schema management.
            # For `Base.metadata.create_all`, `self.db_manager._engine` is the simplest way.

        except MTDatabaseManagerException as e: # Task 2.2: Handle MTDatabaseManagerException
            raise MTBuilderException(f"Failed to initialize database manager: {e}") from e
        except Exception as e: # Catch any other unexpected errors
             raise MTBuilderException(f"Unexpected error during MTBuilder initialization: {e}")

    def build_database(self) -> str:
        """
        Builds the database schema if tables defined in the models do not exist.
        It checks for table existence before creating.

        Returns:
            str: A message indicating the status of the database schema creation/verification.

        Raises:
            MTBuilderException: If there's an error interacting with the database engine
                                during schema creation or verification.
        """
        logging.info("Attempting to build database schema.")

        try:
            # Task 2.3: Update Base.metadata.create_all to use self.db_manager._engine.
            if self.db_manager._engine is None: # Ensure engine is available
                raise MTBuilderException("Database engine is not initialized in MTDatabaseManager.")
            Base.metadata.create_all(self.db_manager._engine)
            return "Empty database successfully created or schema verified."
        except sqlalchemy_exc.SQLAlchemyError as e:
            raise MTBuilderException(f"Issue creating/verifying database schema. Error: {e}") from e
        except Exception as e:
            raise MTBuilderException(f"Unexpected error during build_database: {e}")

    def add_panorama(self, ip_address, username, password) -> str:
        """
        Adds a Panorama device to the database after querying its system and HA info via API.
        Validates the device type and handles potential duplicate hostnames.

        Args:
            ip_address (str): IP address or FQDN of the Panorama device.
            username (str): Username for API access to the Panorama.
            password (str): Password for API access to the Panorama.

        Returns:
            str: Success message indicating the Panorama was added, including its hostname.

        Raises:
            MTBuilderException: If the device already exists in the database (by IP or serial),
                                if the target device is not identified as a Panorama,
                                if API communication fails (connection, credentials, timeout),
                                if the API response format is unexpected,
                                or if a database error occurs during the add operation.
        """
        logging.info(f"Attempting to add Panorama with IP: {ip_address}")

        try:
            # Task 2.4: Change with self._Session() as session: to with self.db_manager.get_session() as session:.
            with self.db_manager.get_session() as session:
                # Task 2.4: Update all session.query(Model) calls.
                existing_pan = session.query(Panorama).filter(
                    (Panorama.ip_address == ip_address) |
                    (Panorama.alt_ip == ip_address)
                ).first()
                if existing_pan:
                    raise MTBuilderException(f"Panorama with IP {ip_address} or its HA peer already in database")

                # --- API Call Logic (Original logic preserved as per parameters) ---
                try:
                    xapi = pan.xapi.PanXapi(api_username=username, api_password=password, hostname=ip_address)
                    xapi.timeout = self.timeout

                    xapi.op("<show><system><info></info></system></show>")
                    system_info = xmltodict.parse('<root>' + xapi.xml_result() + '</root>').get('root', {}).get('system', {})
                    if not system_info:
                         raise MTBuilderException(f"Could not parse system info from {ip_address}.")

                    system_mode = system_info.get('system-mode', '').lower()
                    if system_mode not in PANORRAMA_MODES:
                        raise MTBuilderException(f"Device at {ip_address} is not a Panorama (system-mode: {system_mode or 'Unknown'}).")

                    serial = system_info.get('serial')
                    hostname = system_info.get('hostname')
                    if not serial or not hostname:
                         raise MTBuilderException(f"Missing serial or hostname in API response from {ip_address}.")

                    # Task 2.4: Update session.query(Model) calls.
                    existing_serial_pan = session.query(Panorama).filter(Panorama.serial_number == serial).first()
                    if existing_serial_pan:
                         raise MTBuilderException(f"Panorama with serial {serial} already exists in database.")

                    # Task 2.4: Update session.query(Model) calls.
                    existing_hostnames = {p.hostname for p in session.query(Panorama.hostname).all()}
                    if hostname in existing_hostnames:
                        original_hostname = hostname
                        hostname = f"{hostname}-{serial[:4]}"
                        logging.warning("Warning: Hostname '%s' already exists. Using '%s' instead.", original_hostname, hostname)

                    mac_address_val = system_info.get('mac-address', '')
                    uptime_val = system_info.get('uptime', '')
                    model_val = system_info.get('model', '')
                    sw_version_val = system_info.get('sw-version', '')
                    app_version_val = system_info.get('app-version', '')
                    av_version_val = system_info.get('av-version', '')
                    wildfire_version_val = system_info.get('wildfire-version', '')
                    logdb_version_val = system_info.get('logdb-version', '')
                    
                    licensed_device_cap_val = system_info.get('licensed-device-capacity', '')
                    
                    device_cert_status_val = system_info.get('device-certificate-status', '')
                    if str(device_cert_status_val).lower() in ['none', 'n/a']: device_cert_status_val = ''
                    
                    ipv6_address_val = system_info.get('ipv6-address', '')
                    if str(ipv6_address_val).lower() in ['unknown', 'none']: ipv6_address_val = ''
                    
                    last_refresh_ts = datetime.datetime.now().isoformat(timespec='seconds')

                    active = True
                    alt_ip = None
                    try:
                        if 'management-only' not in system_mode:
                            xapi.op("<show><high-availability><state></state></high-availability></show>")
                            ha_info = xmltodict.parse('<root>' + xapi.xml_result() + '</root>').get('root', {})

                            if ha_info.get('enabled') == 'yes':
                                local_info = ha_info.get('local-info', {})
                                peer_info = ha_info.get('peer-info', {})
                                if local_info and peer_info:
                                    active = 'active' in local_info.get('state', '').lower()
                                    alt_ip = peer_info.get('mgmt-ip')
                                    if not alt_ip or 'unknown' in alt_ip.lower():
                                        alt_ip = None
                    except (pan.xapi.PanXapiError, KeyError, TypeError) as ha_e:
                         logging.warning("Warning: Could not retrieve or parse HA info for %s (Error: %s). Assuming non-HA or active.", ip_address, ha_e)
                         active = True
                         alt_ip = None

                except pan.xapi.PanXapiError as e:
                    err_str = str(e).lower()
                    if "urlerror" in err_str or "timeout" in err_str or "connection refused" in err_str:
                        raise MTBuilderException(f"Unable to connect to {ip_address}. Check IP/FQDN and network connectivity.")
                    elif "invalid credentials" in err_str:
                        raise MTBuilderException(f"Invalid credentials provided for {ip_address}.")
                    else:
                        raise MTBuilderException(f"API Error communicating with {ip_address}: {e}")
                except (KeyError, TypeError) as e:
                     raise MTBuilderException(f"Unexpected API response format from {ip_address} (Error: {e}). Check device type and API version.")

                new_panorama = Panorama(
                    hostname=hostname,
                    serial_number=serial,
                    ip_address=ip_address,
                    alt_ip=alt_ip,
                    active=active,
                    api_key=xapi.api_key,
                    mac_address=mac_address_val,
                    uptime=uptime_val,
                    model=model_val,
                    sw_version=sw_version_val,
                    app_version=app_version_val,
                    av_version=av_version_val,
                    wildfire_version=wildfire_version_val,
                    logdb_version=logdb_version_val,
                    system_mode=system_mode,
                    licensed_device_capacity=licensed_device_cap_val,
                    device_certificate_status=device_cert_status_val,
                    ipv6_address=ipv6_address_val,
                    last_system_info_refresh=last_refresh_ts
                )

                # Task 2.4: Change session.add(new_panorama) to self.db_manager.add_object(session, new_panorama).
                self.db_manager.add_object(session, new_panorama)
                session.commit()

                return f"Panorama '{new_panorama.hostname}' ({new_panorama.serial_number}) successfully added to database."

        except sqlalchemy_exc.SQLAlchemyError as db_err:
            session.rollback()
            raise MTBuilderException(f"Database communication issue: {db_err}")
        except MTBuilderException: # Re-raise custom builder exceptions
            raise
        except Exception as e: # Catch any other unexpected errors
             session.rollback()
             raise MTBuilderException(f"An unexpected error occurred: {e}")


    def add_ngfw(self, ip_address, username, password) -> str:
        """
        Adds a standalone NGFW (not managed by a Panorama in the DB) to the database
        after querying its system and HA info via API.

        Args:
            ip_address (str): IP address or FQDN of the NGFW device.
            username (str): Username for API access to the NGFW.
            password (str): Password for API access to the NGFW.

        Returns:
            str: Success message indicating the NGFW was added, including hostname and serial.

        Raises:
            MTBuilderException: If the device already exists (by IP or serial), is not an NGFW,
                                API communication fails, the API response is unexpected,
                                or a database error occurs.
        """
        logging.info(f"Attempting to add NGFW with IP: {ip_address}")

        try:
            # Task 2.5: Apply the same changes as add_panorama.
            with self.db_manager.get_session() as session:
                existing_ip = session.query(Ngfw).filter(
                    (Ngfw.ip_address == ip_address) | (Ngfw.alt_ip == ip_address)
                ).first()
                if existing_ip:
                    raise MTBuilderException(f"NGFW with IP {ip_address} or its HA peer already exists in database.")

                try:
                    xapi = pan.xapi.PanXapi(api_username=username, api_password=password, hostname=ip_address)
                    xapi.timeout = self.timeout

                    xapi.op("<show><system><info></info></system></show>")
                    device_info = xmltodict.parse('<root>' + xapi.xml_result() + '</root>').get('root', {}).get('system', {})
                    if not device_info:
                         raise MTBuilderException(f"Could not parse system info from {ip_address}.")

                    model = device_info.get('model', '')
                    if not any(m in model for m in NGFW_MODELS):
                        raise MTBuilderException(f"Device at {ip_address} is not a supported NGFW model (Model: {model or 'Unknown'}).")

                    serial = device_info.get('serial')
                    hostname = device_info.get('hostname')
                    if not serial or not hostname:
                         raise MTBuilderException(f"Missing serial or hostname in API response from {ip_address}.")

                    are_status_raw = device_info.get('advanced-routing', 'off')
                    advanced_routing = True if str(are_status_raw).lower() == 'on' else False

                    ipv6_address_val = device_info.get('ipv6-address', '')
                    if str(ipv6_address_val).lower() in ['unknown', 'none']: ipv6_address_val = ''
                    
                    mac_address_val = device_info.get('mac-address', device_info.get('mac_addr', ''))
                    
                    uptime_val = device_info.get('uptime', '')
                    sw_version_val = device_info.get('sw-version', '')
                    
                    app_version_val = device_info.get('app-version', '')
                    av_version_val = device_info.get('av-version', '')
                    wildfire_version_val = device_info.get('wildfire-version', '')
                    threat_version_val = device_info.get('threat-version', '')
                    url_filtering_version_val = device_info.get('url-filtering-version', '')

                    device_cert_present_val = device_info.get('device-certificate-status', '') 
                    if str(device_cert_present_val).lower() in ['none', 'n/a']: device_cert_present_val = ''
                        
                    device_cert_expiry_date_val = device_info.get('device-cert-expiry-date', '') 
                    if str(device_cert_expiry_date_val).lower() == 'n/a': device_cert_expiry_date_val = ''

                    existing_serial = session.query(Ngfw).filter(
                         (Ngfw.serial_number == serial) | (Ngfw.alt_serial == serial)
                    ).first()
                    if existing_serial:
                         raise MTBuilderException(f"NGFW {hostname} ({serial}) or its HA peer already in database.")

                    existing_hostnames = {n.hostname for n in session.query(Ngfw.hostname).all()}
                    if hostname in existing_hostnames:
                         original_hostname = hostname
                         hostname = f"{hostname}-{serial[:4]}"
                         logging.warning("Warning: Hostname '%s' already exists. Using '%s' instead.", original_hostname, hostname)

                    active = True
                    alt_serial = None
                    alt_ip = None
                    try:
                        xapi.op("<show><high-availability><state></state></high-availability></show>")
                        ha_info = xmltodict.parse('<root>' + xapi.xml_result() + '</root>').get('root', {})

                        if ha_info.get('enabled') == 'yes':
                            local_info = ha_info.get('local-info') or ha_info.get('group', {}).get('local-info')
                            peer_info = ha_info.get('peer-info') or ha_info.get('group', {}).get('peer-info')

                            if local_info and peer_info:
                                active = 'active' in local_info.get('state', '').lower()
                                alt_serial = peer_info.get('serial-num')
                                alt_ip = peer_info.get('mgmt-ip')
                                if not alt_ip or 'unknown' in alt_ip.lower(): alt_ip = None
                                if not alt_serial: alt_serial = None
                    except (pan.xapi.PanXapiError, KeyError, TypeError) as ha_e:
                         logging.warning("Warning: Could not retrieve or parse HA info for %s (Error: %s). Assuming non-HA or active.", ip_address, ha_e)
                         active = True
                         alt_serial = None
                         alt_ip = None

                except pan.xapi.PanXapiError as e:
                    err_str = str(e).lower()
                    if "urlerror" in err_str or "timeout" in err_str or "connection refused" in err_str:
                        raise MTBuilderException(f"Unable to connect to {ip_address}. Check IP/FQDN and network connectivity.")
                    elif "invalid credentials" in err_str:
                         raise MTBuilderException(f"Invalid credentials provided for {ip_address}.")
                    else:
                        raise MTBuilderException(f"API Error communicating with {ip_address}: {e}")
                except (KeyError, TypeError) as e:
                     raise MTBuilderException(f"Unexpected API response format from {ip_address} (Error: {e}). Check device type and API version.")

                ngfw_info = {
                    'hostname': hostname, 'serial_number': serial, 'ip_address': ip_address,
                    'model': model, 'api_key': xapi.api_key, 'panorama_id': None,
                    'active': active, 'alt_serial': alt_serial, 'alt_ip': alt_ip,
                    'advanced_routing_enabled': advanced_routing, 'last_update': None,
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

                # Task 2.5: Apply the same changes as add_panorama.
                self.db_manager.add_object(session, Ngfw(**ngfw_info))
                session.commit()

                return f"NGFW '{ngfw_info['hostname']}' ({ngfw_info['serial_number']}) successfully added to database."

        except sqlalchemy_exc.SQLAlchemyError as db_err:
            session.rollback()
            raise MTBuilderException(f"Database communication issue: {db_err}")
        except MTBuilderException:
            raise
        except Exception as e:
             session.rollback()
             raise MTBuilderException(f"An unexpected error occurred: {e}")

    def delete_panorama(self, serial_number) -> list:
        """
        Deletes a Panorama and all its associated NGFWs and their related data from the database.
        Relies on cascade delete rules defined in the database models (db.py).

        Args:
            serial_number (str): The serial number of the Panorama to delete.

        Returns:
            list: A list of messages detailing the deletion process.

        Raises:
            MTBuilderException: If the Panorama is not found or a database error occurs during deletion.
        """
        logging.info(f"Attempting to delete Panorama with serial number: {serial_number}")

        messages = []
        try:
            # Task 2.6: Change with self._Session() as session: to with self.db_manager.get_session() as session:.
            with self.db_manager.get_session() as session:
                # Task 2.6: Update session.query(Model) calls.
                panorama_to_delete = session.query(Panorama).filter(Panorama.serial_number == serial_number).first()

                if not panorama_to_delete:
                    raise MTBuilderException(f"Panorama {serial_number} not found in database")

                hostname = panorama_to_delete.hostname
                messages.append(f"Found Panorama: {hostname} ({serial_number})")
                messages.append(f"Deleting Panorama '{hostname}' and all associated NGFWs/data (using cascade delete)...")

                # Task 2.6: Change session.delete(panorama_to_delete) to self.db_manager.delete_object(session, panorama_to_delete).
                self.db_manager.delete_object(session, panorama_to_delete)
                session.commit()

                messages.append(f"Panorama '{hostname}' ({serial_number}) and associated data successfully deleted.")

        except sqlalchemy_exc.SQLAlchemyError as db_err:
            session.rollback()
            raise MTBuilderException(f"Database error during Panorama deletion: {db_err}")
        except MTBuilderException:
            raise
        except Exception as e:
             session.rollback()
             raise MTBuilderException(f"An unexpected error occurred: {e}")

        return messages

    def delete_ngfw(self, serial_number) -> str:
        """
        Deletes an NGFW and all its associated data (VRs, Routes, Interfaces, etc.) from the database.
        Relies on cascade delete rules defined in the database models (db.py).

        Args:
            serial_number (str): The serial number of the NGFW to delete.

        Returns:
            str: A success message indicating the NGFW was deleted.

        Raises:
            MTBuilderException: If the NGFW is not found or a database error occurs during deletion.
        """
        logging.info(f"Attempting to delete NGFW with serial number: {serial_number}")

        try:
            # Task 2.7: Apply the same changes as delete_panorama.
            with self.db_manager.get_session() as session:
                ngfw_to_delete = session.query(Ngfw).filter(Ngfw.serial_number == serial_number).first()

                if not ngfw_to_delete:
                    raise MTBuilderException(f"NGFW {serial_number} not found in database")

                hostname = ngfw_to_delete.hostname

                logging.info("Deleting NGFW '%s' (%s) and all associated data (using cascade delete)...", hostname, serial_number)

                self.db_manager.delete_object(session, ngfw_to_delete)
                session.commit()

                logging.info("NGFW '%s' (%s) and associated data successfully deleted from database.", hostname, serial_number)

        except sqlalchemy_exc.SQLAlchemyError as db_err:
            session.rollback()
            raise MTBuilderException(f"Database error during NGFW deletion: {db_err}")
        except MTBuilderException:
            raise
        except Exception as e:
             session.rollback()
             raise MTBuilderException(f"An unexpected error occurred: {e}")
        return f"NGFW '{hostname}' ({serial_number}) and associated data successfully deleted."