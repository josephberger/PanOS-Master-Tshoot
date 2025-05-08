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
# (None seem required here beyond what dependencies bring in)

# Third-party imports
import pan.xapi
import xmltodict
from sqlalchemy import create_engine, exc as sqlalchemy_exc
from sqlalchemy.orm import sessionmaker

# Local application/library specific imports
# Assuming models.py defines the Base and specific table classes correctly
# and includes cascade delete configurations.
from models import Base, Ngfw, Panorama

# Assuming config.py provides db_uri and timeout
# If config.py is not in the same directory, adjust the import path accordingly
# e.g., from ..config import db_uri, timeout
try:
    from config import db_uri, timeout
except ImportError:
    # Provide default fallbacks or raise a more specific error if config is mandatory
    print("Warning: Could not import db_uri and timeout from config. Using defaults or potentially failing.")
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
    Manages its own database connection and session factory. Assumes the underlying
    database models (in models.py/db.py) define cascade delete rules.
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
            # Ensure timeout is a valid integer
            self.timeout = int(timeout)
        except (ValueError, TypeError): # Catch specific errors
            raise MTBuilderException(f"Timeout must be an integer, received: {timeout}")

        try:
            # Create engine and session factory once during initialization
            # echo=False is recommended for production/general use
            self._engine = create_engine(self.db_uri, echo=False)
            # Store the session factory (class) itself, not an instance
            self._Session = sessionmaker(bind=self._engine)

            # Optional: Test connection during initialization to fail early.
            # This adds a small overhead but catches config issues sooner.
            # with self._engine.connect() as connection:
            #     pass # Connection successful if no exception
        except sqlalchemy_exc.SQLAlchemyError as e:
            # Catch engine/sessionmaker creation errors or connection test errors
            raise MTBuilderException(f"Database communication issue during initialization: {e}")
        except Exception as e: # Catch other potential errors
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
        try:
            # Use the engine created during initialization
            # create_all checks for table existence and only creates missing ones.
            Base.metadata.create_all(self._engine)
            # Consistent message with CLI
            return "Empty database successfully created or schema verified."
        except sqlalchemy_exc.SQLAlchemyError as e:
            # Catch errors specifically during table creation/check
            raise MTBuilderException(f"Issue creating/verifying database schema. Error: {e}")
        except Exception as e: # Catch other unexpected errors
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
        # Use context manager for the session to ensure it's closed properly
        try:
            with self._Session() as session: # Create session from factory
                # Check if panorama already exists (by primary IP, alternate IP, or serial)
                existing_pan = session.query(Panorama).filter(
                    (Panorama.ip_address == ip_address) |
                    (Panorama.alt_ip == ip_address)
                ).first()
                if existing_pan:
                    raise MTBuilderException(f"Panorama with IP {ip_address} or its HA peer already in database")

                # --- API Call Logic (Original logic preserved as per parameters) ---
                try:
                    # Initialize PanXapi object for API communication
                    xapi = pan.xapi.PanXapi(api_username=username, api_password=password, hostname=ip_address)
                    xapi.timeout = self.timeout

                    # Get system information
                    xapi.op("<show><system><info></info></system></show>")
                    system_info = xmltodict.parse('<root>' + xapi.xml_result() + '</root>').get('root', {}).get('system', {})
                    if not system_info:
                         raise MTBuilderException(f"Could not parse system info from {ip_address}.")

                    # Check if it's a Panorama (accepts 'panorama' or 'management-only' modes)
                    system_mode = system_info.get('system-mode', '').lower()
                    # Allow 'panorama' or 'management-only'
                    if system_mode not in PANORRAMA_MODES:
                        raise MTBuilderException(f"Device at {ip_address} is not a Panorama (system-mode: {system_mode or 'Unknown'}).")

                    serial = system_info.get('serial')
                    hostname = system_info.get('hostname')
                    if not serial or not hostname:
                         raise MTBuilderException(f"Missing serial or hostname in API response from {ip_address}.")

                    # Check for existing serial number
                    existing_serial_pan = session.query(Panorama).filter(Panorama.serial_number == serial).first()
                    if existing_serial_pan:
                         raise MTBuilderException(f"Panorama with serial {serial} already exists in database.")

                    # Check for duplicate hostname *within the session* and adjust if necessary
                    existing_hostnames = {p.hostname for p in session.query(Panorama.hostname).all()}
                    if hostname in existing_hostnames:
                        # Simple approach: append first 4 chars of serial to make unique.
                        original_hostname = hostname
                        hostname = f"{hostname}-{serial[:4]}"
                        print(f"Warning: Hostname '{original_hostname}' already exists. Using '{hostname}' instead.")


                    # Get High Availability (HA) information
                    # Default values assume non-HA or primary active
                    active = True
                    alt_ip = None
                    try:
                        # Check HA state only if it's not management-only
                        if 'management-only' not in system_mode:
                            xapi.op("<show><high-availability><state></state></high-availability></show>")
                            ha_info = xmltodict.parse('<root>' + xapi.xml_result() + '</root>').get('root', {})

                            # Check if HA is enabled and parse state if possible
                            if ha_info.get('enabled') == 'yes':
                                local_info = ha_info.get('local-info', {})
                                peer_info = ha_info.get('peer-info', {})
                                if local_info and peer_info:
                                    # Determine if this node is active based on its state string
                                    active = 'active' in local_info.get('state', '').lower()
                                    # Get the peer's management IP if available
                                    alt_ip = peer_info.get('mgmt-ip')
                                    # Clean up potential 'unknown' values
                                    if not alt_ip or 'unknown' in alt_ip.lower():
                                        alt_ip = None
                        # else: management-only, keep defaults

                    except (pan.xapi.PanXapiError, KeyError, TypeError) as ha_e:
                         # Treat failure to get HA info (or parse it) as non-HA for simplicity
                         print(f"Warning: Could not retrieve or parse HA info for {ip_address} (Error: {ha_e}). Assuming non-HA or active.")
                         active = True
                         alt_ip = None

                except pan.xapi.PanXapiError as e:
                    # Consolidate common API errors into user-friendly messages
                    err_str = str(e).lower()
                    if "urlerror" in err_str or "timeout" in err_str or "connection refused" in err_str:
                        raise MTBuilderException(f"Unable to connect to {ip_address}. Check IP/FQDN and network connectivity.")
                    elif "invalid credentials" in err_str:
                        raise MTBuilderException(f"Invalid credentials provided for {ip_address}.")
                    else:
                        # Re-raise other PanXapiErrors
                        raise MTBuilderException(f"API Error communicating with {ip_address}: {e}")
                except (KeyError, TypeError) as e:
                     # Handle unexpected API response format gracefully
                     raise MTBuilderException(f"Unexpected API response format from {ip_address} (Error: {e}). Check device type and API version.")
                # --- End API Call Logic ---

                # Create and add the new Panorama object to the session
                new_panorama = Panorama(hostname=hostname,
                                        serial_number=serial,
                                        ip_address=ip_address, # IP used for the initial connection
                                        alt_ip=alt_ip,
                                        active=active,
                                        api_key=xapi.api_key) # Store the generated API key

                session.add(new_panorama)
                session.commit() # Commit the transaction

                # Consistent success message with CLI
                return f"Panorama '{new_panorama.hostname}' ({new_panorama.serial_number}) successfully added to database."

        except sqlalchemy_exc.SQLAlchemyError as db_err:
            # Catch potential DB errors during query or commit
            session.rollback() # Ensure rollback on error
            raise MTBuilderException(f"Database communication issue: {db_err}")
        # Note: MTBuilderExceptions from inner logic are re-raised automatically

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
        try:
            with self._Session() as session:
                # Check if NGFW already exists by primary or alternate IP address
                existing_ip = session.query(Ngfw).filter(
                    (Ngfw.ip_address == ip_address) | (Ngfw.alt_ip == ip_address)
                ).first()
                if existing_ip:
                    raise MTBuilderException(f"NGFW with IP {ip_address} or its HA peer already exists in database.")

                # --- API Call Logic (Original logic preserved) ---
                try:
                    # Initialize PanXapi for direct NGFW communication
                    xapi = pan.xapi.PanXapi(api_username=username, api_password=password, hostname=ip_address)
                    xapi.timeout = self.timeout

                    # Get system information
                    xapi.op("<show><system><info></info></system></show>")
                    device_info = xmltodict.parse('<root>' + xapi.xml_result() + '</root>').get('root', {}).get('system', {})
                    if not device_info:
                         raise MTBuilderException(f"Could not parse system info from {ip_address}.")

                    # Validate model type (must contain 'PA-', 'VM-', or any other supported models)
                    model = device_info.get('model', '')
                    if not any(m in model for m in NGFW_MODELS):
                        raise MTBuilderException(f"Device at {ip_address} is not a supported NGFW model (Model: {model or 'Unknown'}).")

                    serial = device_info.get('serial')
                    hostname = device_info.get('hostname')
                    if not serial or not hostname:
                         raise MTBuilderException(f"Missing serial or hostname in API response from {ip_address}.")

                    # --- Check for Advanced Routing ---
                    # Default to False if key is missing or value is not 'on'
                    are_status_raw = device_info.get('advanced-routing', 'off') # Default to 'off' if key missing
                    advanced_routing = True if str(are_status_raw).lower() == 'on' else False
                    # ----------------------------------

                    # Check if NGFW with this serial or alternate serial already exists
                    existing_serial = session.query(Ngfw).filter(
                         (Ngfw.serial_number == serial) | (Ngfw.alt_serial == serial)
                    ).first()
                    if existing_serial:
                         raise MTBuilderException(f"NGFW {hostname} ({serial}) or its HA peer already in database.")

                    # Check for duplicate hostname and adjust if needed
                    existing_hostnames = {n.hostname for n in session.query(Ngfw.hostname).all()}
                    if hostname in existing_hostnames:
                         original_hostname = hostname
                         hostname = f"{hostname}-{serial[:4]}" # Append first 4 of serial
                         print(f"Warning: Hostname '{original_hostname}' already exists. Using '{hostname}' instead.")


                    # Get High Availability (HA) information
                    # Default values assume non-HA or primary active
                    active = True
                    alt_serial = None
                    alt_ip = None
                    try:
                        xapi.op("<show><high-availability><state></state></high-availability></show>")
                        ha_info = xmltodict.parse('<root>' + xapi.xml_result() + '</root>').get('root', {})

                        # Check if HA is enabled and parse state
                        if ha_info.get('enabled') == 'yes':
                            # HA structure differs slightly between PanOS versions/platforms
                            # Try finding state in common locations
                            local_info = ha_info.get('local-info') or ha_info.get('group', {}).get('local-info')
                            peer_info = ha_info.get('peer-info') or ha_info.get('group', {}).get('peer-info')

                            if local_info and peer_info:
                                # Determine if this node is active
                                active = 'active' in local_info.get('state', '').lower()
                                # Get peer serial and management IP
                                alt_serial = peer_info.get('serial-num') # Key might vary
                                alt_ip = peer_info.get('mgmt-ip')
                                # Clean up missing or 'unknown' values
                                if not alt_ip or 'unknown' in alt_ip.lower(): alt_ip = None
                                if not alt_serial: alt_serial = None
                            # else: HA enabled but info missing/unparseable, keep defaults
                        # else: HA not enabled, keep defaults
                    except (pan.xapi.PanXapiError, KeyError, TypeError) as ha_e:
                         # Treat failure to get HA info as non-HA
                         print(f"Warning: Could not retrieve or parse HA info for {ip_address} (Error: {ha_e}). Assuming non-HA or active.")
                         active = True
                         alt_serial = None
                         alt_ip = None

                except pan.xapi.PanXapiError as e:
                    # Consolidate common API errors
                    err_str = str(e).lower()
                    if "urlerror" in err_str or "timeout" in err_str or "connection refused" in err_str:
                        raise MTBuilderException(f"Unable to connect to {ip_address}. Check IP/FQDN and network connectivity.")
                    elif "invalid credentials" in err_str:
                         raise MTBuilderException(f"Invalid credentials provided for {ip_address}.")
                    else:
                        raise MTBuilderException(f"API Error communicating with {ip_address}: {e}")
                except (KeyError, TypeError) as e:
                     # Handle unexpected API response format
                     raise MTBuilderException(f"Unexpected API response format from {ip_address} (Error: {e}). Check device type and API version.")
                # --- End API Call Logic ---

                # Prepare NGFW data dictionary
                ngfw_info = {
                    'hostname': hostname,
                    'serial_number': serial,
                    'ip_address': ip_address, # Primary IP used for connection
                    'model': model,
                    'api_key': xapi.api_key, # Store API key obtained from direct connection
                    'panorama_id': None, # Mark as Standalone
                    'active': active,
                    'alt_serial': alt_serial,
                    'alt_ip': alt_ip,
                    'advanced_routing_enabled': advanced_routing,
                    'last_update': None # No data refreshed yet
                }

                # Create and add the new NGFW object
                new_ngfw = Ngfw(**ngfw_info)
                session.add(new_ngfw)
                session.commit() # Commit the transaction

                # Consistent success message with CLI
                return f"NGFW '{new_ngfw.hostname}' ({new_ngfw.serial_number}) successfully added to database."

        except sqlalchemy_exc.SQLAlchemyError as db_err:
            session.rollback() # Ensure rollback on error
            raise MTBuilderException(f"Database communication issue: {db_err}")
        # Note: MTBuilderExceptions from inner logic are re-raised automatically

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
        messages = []
        try:
            with self._Session() as session:
                # Find the Panorama by serial number
                panorama_to_delete = session.query(Panorama).filter(Panorama.serial_number == serial_number).first()

                if not panorama_to_delete:
                    # Use consistent message format
                    raise MTBuilderException(f"Panorama {serial_number} not found in database")

                hostname = panorama_to_delete.hostname # Store for message before deletion
                messages.append(f"Found Panorama: {hostname} ({serial_number})")
                messages.append(f"Deleting Panorama '{hostname}' and all associated NGFWs/data (using cascade delete)...")

                # Delete the Panorama object. SQLAlchemy, using the cascade rules in db.py,
                # will handle deleting associated Ngfw objects, which in turn will cascade
                # to delete their associated VirtualRouters, Interfaces, Routes, etc.
                session.delete(panorama_to_delete)
                session.commit() # Commit the deletion

                messages.append(f"Panorama '{hostname}' ({serial_number}) and associated data successfully deleted.")

        except sqlalchemy_exc.SQLAlchemyError as db_err:
            session.rollback() # Rollback on error
            raise MTBuilderException(f"Database error during Panorama deletion: {db_err}")
        except Exception as e:
             # Catch any other unexpected errors
             session.rollback()
             raise MTBuilderException(f"Unexpected error during delete_panorama: {e}")

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
        try:
            with self._Session() as session:
                # Find the NGFW by serial number
                ngfw_to_delete = session.query(Ngfw).filter(Ngfw.serial_number == serial_number).first()

                if not ngfw_to_delete:
                    # Consistent message format
                    raise MTBuilderException(f"NGFW {serial_number} not found in database")

                hostname = ngfw_to_delete.hostname # Store for message before deletion

                print(f"Deleting NGFW '{hostname}' ({serial_number}) and all associated data (using cascade delete)...")

                # Delete the NGFW object. SQLAlchemy, using the cascade rules defined in db.py,
                # will handle deleting associated VirtualRouters, Neighbors, BGP Peers,
                # which will further cascade to Interfaces, Routes, FIBs, ARPs etc.
                session.delete(ngfw_to_delete)
                session.commit() # Commit the deletion

                # Consistent success message with CLI
                return f"NGFW '{hostname}' ({serial_number}) and associated data successfully deleted from database."

        except sqlalchemy_exc.SQLAlchemyError as db_err:
            session.rollback() # Rollback on error
            raise MTBuilderException(f"Database error during NGFW deletion: {db_err}")
        except Exception as e:
             # Catch any other unexpected errors
             session.rollback()
             raise MTBuilderException(f"Unexpected error during delete_ngfw: {e}")