import logging
import time
import uuid
from threading import Thread
import ipaddress
import json
from flask import Flask, jsonify, render_template, Response, request

# Import controller exceptions, including the specific schema error
from mastertshoot.mt_controller import MTController, MTControllerException, MTDatabaseSchemaError
from mastertshoot.mt_builder import MTBuilder, MTBuilderException
from config import db_uri, timeout

# --- App and Component Setup ---
app = Flask(__name__)
controller = None
builder = None

# It's safest to initialize the builder first.
try:
    builder = MTBuilder(db_uri=db_uri, timeout=timeout)
except MTBuilderException as e:
    logging.fatal(f"FATAL: Could not initialize the database builder: {e}")
    # The application cannot run without the builder.
    builder = None 

# Now, initialize the controller, with a fallback to create the database if needed.
if builder:
    try:
        # Attempt to initialize the controller normally.
        controller = MTController(db_uri=db_uri, timeout=timeout)
        logging.info("Controller initialized successfully on existing database.")
    except MTDatabaseSchemaError:
        # This specific error means the database file exists but is empty or missing tables.
        logging.warning("Database schema not found. Attempting to create a new database...")
        try:
            # Use the builder to create the database schema.
            build_message = builder.build_database()
            logging.info(f"Database creation status: {build_message}")
            
            # Now, retry initializing the controller, which should succeed.
            controller = MTController(db_uri=db_uri, timeout=timeout)
            logging.info("Controller initialized successfully on newly created database.")
            
        except (MTBuilderException, MTControllerException) as e:
            # If creating the DB or re-initializing the controller fails, it's a fatal error.
            logging.fatal(f"FATAL: Failed to create database and initialize controller: {e}")
            controller = None # Ensure controller is None on failure
            
    except MTControllerException as e:
        # Catch other controller initialization errors (e.g., bad DB connection, permissions).
        logging.fatal(f"FATAL: Failed to initialize controller: {e}")
        controller = None
else:
    logging.fatal("FATAL: Builder could not be initialized, cannot proceed with controller setup.")

# The rest of your mt-ui.py file remains the same...

# --- In-memory store for background tasks ---
tasks = {}

TASK_METHOD_MAP = {
    'refresh': controller.refresh_ngfws if controller else None,
    'update_routes': controller.update_routes if controller else None,
    'update_arps': controller.update_arps if controller else None,
    'update_lldp': controller.update_neighbors if controller else None,
    'update_bgp': controller.update_bgp_peers if controller else None,
    'update_ha': controller.update_ha_status if controller else None,
}

PAN_TASK_METHOD_MAP = {
    'import': controller.import_panorama_devices if controller else None,
    'update_ha': controller.update_ha_status if controller else None,
}


def run_task(task_id, target_function, *args, **kwargs):
    """A wrapper to run a controller method and store its yielded output."""
    if not target_function:
        tasks[task_id]['log'].append("FATAL ERROR: Controller is not available.")
        tasks[task_id]['status'] = 'failed'
        return
    try:
        tasks[task_id]['status'] = 'running'
        for message in target_function(*args, **kwargs):
            tasks[task_id]['log'].append(message)
        tasks[task_id]['status'] = 'complete'
    except Exception as e:
        logging.error(f"Task {task_id} failed: {e}", exc_info=True)
        tasks[task_id]['log'].append(f"FATAL ERROR: {e}")
        tasks[task_id]['status'] = 'failed'

# --- HTML Rendering Routes ---

@app.route('/')
def index():
    """Renders the main map visualization page."""
    return render_template('index.html')

@app.route('/devices')
def device_management():
    """Renders the new device management page."""
    return render_template('devices.html')

@app.route('/explorer')
def data_explorer():
    """Renders the new Data Explorer page."""
    return render_template('explorer.html')

@app.route('/lldp-map')
def lldp_map():
    """Renders the LLDP neighbor map page."""
    return render_template('lldp.html')

# --- API Endpoints ---

@app.route('/api/maps/all', methods=['GET'])
def get_all_maps():
    if not controller: return jsonify({"error": "Controller not available"}), 503
    try:
        return jsonify(controller.get_all_maps_for_ui())
    except MTControllerException as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/maps/single/<path:map_key>', methods=['GET'])
def get_single_map(map_key):
    """
    API endpoint to retrieve the data for a single, specific map.
    The <path:map_key> allows the key (e.g., "NGFW-1 - vr:default") to be passed in the URL.
    """
    if not controller:
        return jsonify({"error": "Controller not available"}), 503
    try:
        # This will call the robust get_map_by_key method from the controller
        map_data = controller.get_map_by_key(map_key)
        if map_data:
            return jsonify(map_data)
        else:
            # If the controller returns None, it means the map wasn't found
            logging.warning(f"404 - Map key not found in controller: '{map_key}'")
            return jsonify({"error": f"Map key '{map_key}' not found"}), 404
    except MTControllerException as e:
        logging.error(f"API Error in get_single_map for key {map_key}: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/maps/keys', methods=['GET'])
def get_map_keys():
    if not controller: return jsonify({"error": "Controller not available"}), 503
    try:
        return jsonify(controller.get_all_map_keys())
    except MTControllerException as e:
        return jsonify({"error": str(e)}), 500

# NEW DEDICATED ENDPOINT FOR GLOBAL LLDP MAP
@app.route('/api/lldp-map/all', methods=['GET'])
def get_all_lldp_map_data():
    """
    API endpoint to retrieve consolidated, global LLDP network data (nodes and links)
    for a force-directed graph visualization.
    """
    if not controller:
        return jsonify({"error": "Controller not available"}), 503
    try:
        global_lldp_data = controller.get_global_lldp_map_for_ui()
        if global_lldp_data:
            return jsonify(global_lldp_data)
        else:
            return jsonify({"nodes": [], "links": []}) # Return empty lists if no data
    except MTControllerException as e:
        return jsonify({"error": str(e)}), 500

# --- Task Endpoints ---
@app.route('/api/tasks/import/start', methods=['POST'])
def start_import_task():
    if not controller: return jsonify({"error": "Controller not available"}), 503
    task_id = str(uuid.uuid4())
    tasks[task_id] = {'status': 'pending', 'log': []}
    thread = Thread(target=run_task, args=(task_id, controller.import_panorama_devices))
    thread.daemon = True
    thread.start()
    return jsonify({"message": "Import task started", "task_id": task_id}), 202

@app.route('/api/tasks/refresh/start', methods=['POST'])
def start_refresh_task():
    if not controller: return jsonify({"error": "Controller not available"}), 503
    task_id = str(uuid.uuid4())
    tasks[task_id] = {'status': 'pending', 'log': []}
    thread = Thread(target=run_task, args=(task_id, controller.refresh_ngfws))
    thread.daemon = True
    thread.start()
    return jsonify({"message": "Refresh task started", "task_id": task_id}), 202

@app.route('/api/tasks/update-ha/start', methods=['POST'])
def start_update_ha_task():
    """Starts a background task to update HA status for all devices."""
    if not controller: return jsonify({"error": "Controller not available"}), 503
    task_id = str(uuid.uuid4())
    tasks[task_id] = {'status': 'pending', 'log': []}
    # Call update_ha_status with no arguments to run on all devices
    thread = Thread(target=run_task, args=(task_id, controller.update_ha_status))
    thread.daemon = True
    thread.start()
    return jsonify({"message": "Update HA Status task started for all devices", "task_id": task_id}), 202

@app.route('/api/tasks/stream/<task_id>')
def stream_task_status(task_id):
    def generate():
        if task_id not in tasks:
            yield f"data: ERROR: Task ID {task_id} not found.\n\n"
            return
        log_index = 0
        while tasks.get(task_id) and tasks[task_id]['status'] in ['pending', 'running']:
            while log_index < len(tasks[task_id]['log']):
                message = tasks[task_id]['log'][log_index]
                yield f"data: {message}\n\n"
                log_index += 1
            time.sleep(0.5)
        if task_id in tasks:
            while log_index < len(tasks[task_id]['log']):
                message = tasks[task_id]['log'][log_index]
                yield f"data: {message}\n\n"
                log_index += 1
            final_status = tasks[task_id]['status'].upper()
            yield f"data: \n"
            yield f"data: --- TASK {final_status} ---\n\n"
            if 'status' in tasks[task_id] and tasks[task_id]['status'] != 'running':
                del tasks[task_id]
    return Response(generate(), mimetype='text/event-stream')

@app.route('/api/tasks/device-action/start', methods=['POST'])
def start_device_action_task():
    """
    A generic endpoint to start tasks for a specific device (NGFW or Panorama).
    """
    if not controller:
        return jsonify({"error": "Controller not available"}), 503

    data = request.get_json()
    platform = data.get('platform')
    task_type = data.get('task_type')
    filter_value = data.get('filter_value')

    if not all([platform, task_type, filter_value]):
        return jsonify({"error": "Missing 'platform', 'task_type', or 'filter_value' in request"}), 400

    target_function = None
    kwargs = {}

    if platform == 'ngfw':
        target_function = TASK_METHOD_MAP.get(task_type)
        
        # --- START: CORRECTED LOGIC ---
        if task_type == 'update_ha':
            # For this specific task, pass a dummy pan_filter to prevent
            # the controller from checking all Panoramas.
            kwargs = {
                'ngfw_filter': filter_value,
                'pan_filter': '__IGNORE__'
            }
        elif task_type == 'refresh':
            kwargs['ngfw_filter'] = filter_value
        else:
            # For other tasks like update_routes, update_arps, etc.
            kwargs['ngfw'] = filter_value
        # --- END: CORRECTED LOGIC ---

    elif platform == 'panorama':
        target_function = PAN_TASK_METHOD_MAP.get(task_type)
        if task_type == 'update_ha':
            kwargs = {
                'pan_filter': filter_value,
                'ngfw_filter': '__IGNORE__' 
            }
        else:
            kwargs['pan_filter'] = filter_value
    
    if not target_function:
        return jsonify({"error": f"Invalid task type '{task_type}' for platform '{platform}'"}), 400

    task_id = str(uuid.uuid4())
    tasks[task_id] = {'status': 'pending', 'log': []}
    thread = Thread(target=run_task, args=(task_id, target_function), kwargs=kwargs)
    thread.daemon = True
    thread.start()
    
    return jsonify({"message": f"Task '{task_type}' started for {platform} {filter_value}", "task_id": task_id}), 202

# In mt-ui.py, add these new endpoints

@app.route('/api/inventory/count', methods=['GET'])
def get_inventory_count():
    """Returns the current count of NGFWs in the database."""
    if not controller: return jsonify({"error": "Controller not available"}), 503
    try:
        inventory = controller.get_inventory()
        ngfw_count = inventory.get('NGFWs', 0)
        return jsonify({"ngfw_count": ngfw_count})
    except MTControllerException as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/tasks/update-routes/start', methods=['POST'])
def start_update_routes_task():
    """Starts a background task to update routes for all devices."""
    if not controller: return jsonify({"error": "Controller not available"}), 503
    task_id = str(uuid.uuid4())
    tasks[task_id] = {'status': 'pending', 'log': []}
    thread = Thread(target=run_task, args=(task_id, controller.update_routes))
    thread.daemon = True
    thread.start()
    return jsonify({"message": "Update Routes task started for all devices", "task_id": task_id}), 202

@app.route('/api/tasks/update-arps/start', methods=['POST'])
def start_update_arps_task():
    """Starts a background task to update ARPs for all devices."""
    if not controller: return jsonify({"error": "Controller not available"}), 503
    task_id = str(uuid.uuid4())
    tasks[task_id] = {'status': 'pending', 'log': []}
    thread = Thread(target=run_task, args=(task_id, controller.update_arps))
    thread.daemon = True
    thread.start()
    return jsonify({"message": "Update ARPs task started for all devices", "task_id": task_id}), 202

@app.route('/api/tasks/update-bgp/start', methods=['POST'])
def start_update_bgp_task():
    """Starts a background task to update BGP peers for all devices."""
    if not controller: return jsonify({"error": "Controller not available"}), 503
    task_id = str(uuid.uuid4())
    tasks[task_id] = {'status': 'pending', 'log': []}
    thread = Thread(target=run_task, args=(task_id, controller.update_bgp_peers))
    thread.daemon = True
    thread.start()
    return jsonify({"message": "Update BGP Peers task started for all devices", "task_id": task_id}), 202

@app.route('/api/tasks/update-lldp/start', methods=['POST'])
def start_update_lldp_task():
    """Starts a background task to update LLDP neighbors for all devices."""
    if not controller: return jsonify({"error": "Controller not available"}), 503
    task_id = str(uuid.uuid4())
    tasks[task_id] = {'status': 'pending', 'log': []}
    thread = Thread(target=run_task, args=(task_id, controller.update_neighbors))
    thread.daemon = True
    thread.start()
    return jsonify({"message": "Update LLDP Neighbors task started for all devices", "task_id": task_id}), 202

# --- Device Management API Endpoints ---
@app.route('/api/devices', methods=['GET'])
def get_all_devices():
    if not controller: return jsonify({"error": "Controller not available"}), 503
    try:
        return jsonify(controller.get_all_devices_for_ui())
    except MTControllerException as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/devices/add', methods=['POST'])
def add_device():
    if not builder: return jsonify({"error": "Builder not available"}), 503
    data = request.get_json()
    platform = data.get('platform')
    host = data.get('host')
    username = data.get('username')
    password = data.get('password')
    if not all([platform, host, username, password]): return jsonify({"error": "Missing required fields"}), 400
    try:
        if platform == 'panorama': message = builder.add_panorama(host, username, password)
        elif platform == 'ngfw': message = builder.add_ngfw(host, username, password)
        else: return jsonify({"error": "Invalid platform specified"}), 400
        return jsonify({"message": message})
    except MTBuilderException as e:
        return jsonify({"error": str(e)}), 409

@app.route('/api/devices/delete', methods=['POST'])
def delete_device():
    if not builder: return jsonify({"error": "Builder not available"}), 503
    data = request.get_json()
    platform = data.get('platform')
    serial = data.get('serial')
    if not all([platform, serial]): return jsonify({"error": "Missing required fields"}), 400
    try:
        if platform == 'panorama': message = " ".join(builder.delete_panorama(serial))
        elif platform == 'ngfw':
            builder.delete_ngfw(serial)
            message = f"NGFW {serial} and associated data successfully deleted."
        else: return jsonify({"error": "Invalid platform specified"}), 400
        return jsonify({"message": message})
    except MTBuilderException as e:
        return jsonify({"error": str(e)}), 404

# --- NEW Endpoint for Single Device Details ---
@app.route('/api/devices/ngfw/<serial>', methods=['GET'])
def get_ngfw_details(serial):
    """Returns the detailed information for a single NGFW."""
    if not controller:
        return jsonify({"error": "Controller not available"}), 503
    try:
        device_details = controller.get_ngfw_details(serial)
        if device_details:
            return jsonify(device_details)
        else:
            return jsonify({"error": "NGFW not found"}), 404
    except MTControllerException as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/devices/panorama/<serial>', methods=['GET'])
def get_panorama_details(serial):
    """Returns the detailed information for a single Panorama."""
    if not controller:
        return jsonify({"error": "Controller not available"}), 503
    try:
        device_details = controller.get_panorama_details(serial)
        if device_details:
            return jsonify(device_details)
        else:
            return jsonify({"error": "Panorama not found"}), 404
    except MTControllerException as e:
        return jsonify({"error": str(e)}), 500
    
@app.route('/api/data/query', methods=['GET'])
def query_data():
    """
    A single, flexible endpoint to query different types of data.
    Uses request arguments to call the appropriate controller method.
    """
    if not controller:
        return jsonify({"error": "Controller not available"}), 503

    # Extract query parameters from the request URL
    data_type = request.args.get('type')
    ngfw_filter = request.args.get('ngfw')
    vr_filter = request.args.get('vr')
    on_demand = request.args.get('on_demand', 'false').lower() == 'true'
    
    # New contextual filters
    dst_filter = request.args.get('dst')
    flag_filter = request.args.get('flag')
    int_filter = request.args.get('int')
    afi_filter = request.args.get('afi', 'ipv4') # Default to ipv4 if not specified
    
    response_data = {}

    try:
        if data_type == 'routes':
            response_data = controller.get_routes(
                ngfw=ngfw_filter, virtual_router=vr_filter, on_demand=on_demand,
                destination=dst_filter, flags=flag_filter, afi=afi_filter
            )
        elif data_type == 'fibs':
            response_data = controller.get_fibs(
                ngfw=ngfw_filter, virtual_router=vr_filter, on_demand=on_demand,
                destination=dst_filter, flags=flag_filter, afi=afi_filter
            )
        elif data_type == 'arps':
            response_data = controller.get_arps(
                ngfw=ngfw_filter, on_demand=on_demand, interface=int_filter
            )
        elif data_type == 'bgp-peers':
            response_data = controller.get_bgp_peers(
                ngfw=ngfw_filter, virtual_router=vr_filter, on_demand=on_demand
            )
        elif data_type == 'lldp-neighbors':
            response_data = controller.get_neighbors(
                ngfw=ngfw_filter, on_demand=on_demand
            )
        elif data_type == 'interfaces':
            response_data = controller.get_interfaces(
                ngfw=ngfw_filter, virtual_router=vr_filter, on_demand=on_demand
            )
        elif data_type == 'interfacesv6':
            # Call get_interfaces with the ipv6_enabled_only flag set to True
            response_data = controller.get_interfaces(
                ngfw=ngfw_filter, virtual_router=vr_filter, on_demand=on_demand, ipv6_enabled_only=True
            )
        else:
            return jsonify({"error": "Invalid data type specified"}), 400
        
        print(response_data)  # Debugging output to see the response structure

        return jsonify(response_data)

    except MTControllerException as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/data/virtual-routers', methods=['GET'])
def get_all_virtual_routers():
    """
    API endpoint to retrieve a list of all virtual routers and their stats.
    """
    if not controller:
        return jsonify({"error": "Controller not available"}), 503
    try:
        # The get_virtual_routers method already returns the data in the format we need.
        # We call it with no arguments to get all VRs.
        vr_data = controller.get_virtual_routers()
        return jsonify(vr_data)
    except MTControllerException as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/data/fib-lookup', methods=['GET'])
def fib_lookup():
    """
    Handles FIB lookup requests, either on-demand or calculated.
    """
    if not controller:
        return jsonify({"error": "Controller not available"}), 503

    ip = request.args.get('ip')
    ngfw = request.args.get('ngfw')
    vr = request.args.get('vr')
    on_demand = request.args.get('on_demand', 'false').lower() == 'true'

    if not ip:
        return jsonify({"error": "IP address is required for lookup."}), 400

    try:
        # Validate the IP address format before passing to controller
        ipaddress.ip_address(ip)
    except ValueError:
        return jsonify({"error": f"Invalid IP address format: {ip}"}), 400

    try:
        if on_demand:
            result = controller.test_fib_lookup(ip, ngfw_query=ngfw, vr_query=vr)
        else:
            result = controller.calculate_fib_lookup(ip_address_str=ip, ngfw_query=ngfw, vr_query=vr)
        
        return jsonify(result)
    except MTControllerException as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/maps/fib-lookup', methods=['GET'])
def map_fib_lookup():
    """
    Handles a calculated FIB lookup and returns a modified map structure
    showing only the resulting path.
    """
    if not controller:
        return jsonify({"error": "Controller not available"}), 503

    ip = request.args.get('ip')
    map_key = request.args.get('map_key') # Will be present for single map, absent for global

    if not ip:
        return jsonify({"error": "IP address is required for lookup."}), 400

    try:
        # This new controller method will perform the lookup and filter the map data
        filtered_map_data = controller.calculate_fib_lookup_for_map(ip, map_key)
        
        if not filtered_map_data:
            return jsonify({"error": "No matching route found for the given IP."}), 404
            
        return jsonify(filtered_map_data)

    except MTControllerException as e:
        return jsonify({"error": str(e)}), 500
    
@app.route('/api/maps/trace', methods=['GET'])
def map_trace():
    """
    Handles a calculated FIB trace for a src/dst pair and returns a modified 
    map structure showing only the ingress and egress trace nodes.
    """
    if not controller:
        return jsonify({"error": "Controller not available"}), 503

    src_ip = request.args.get('src_ip')
    dst_ip = request.args.get('dst_ip')
    map_key = request.args.get('map_key') # Will be present for single map, absent for global

    if not src_ip or not dst_ip:
        return jsonify({"error": "Both source and destination IP addresses are required for a trace."}), 400

    try:
        # Call the new controller method for tracing
        traced_map_data = controller.trace_path_on_map(src_ip, dst_ip, map_key)
        
        if not traced_map_data or (map_key and not traced_map_data.get('ngfw')):
            return jsonify({"error": "Could not trace a complete path for the given IPs."}), 404
            
        return jsonify(traced_map_data)

    except MTControllerException as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/lldp-map/single/<string:ngfw_hostname>', methods=['GET'])
def get_single_lldp_map_data(ngfw_hostname):
    """
    API endpoint to retrieve grouped LLDP neighbor data for a specific NGFW,
    pre-compiled for the LLDP map visualization.
    """
    if not controller:
        return jsonify({"error": "Controller not available"}), 503
    try:
        grouped_lldp_data = controller.get_lldp_map_for_ui(ngfw_hostname)
        if grouped_lldp_data:
            with open('lldp_map_debug.json', 'w') as f:
                json.dump(grouped_lldp_data, f, indent=4)
            return jsonify(grouped_lldp_data)
        else:
            return jsonify({"error": f"LLDP map data not found for NGFW '{ngfw_hostname}'"}), 404
    except MTControllerException as e:
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':
    # Add a final check before running the app
    if not controller or not builder:
        logging.fatal("Application cannot start because a core component failed to initialize.")
    else:
        logging.info("Starting Flask development server.")
        app.run(debug=True, port=5001)