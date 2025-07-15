// static/scripts/main-lldp-app.js

// Declare global variables that will hold D3 elements/simulation
let mapGroup;
let tooltip;
let simulation; // D3 force simulation instance
let link, node; // D3 selections for global map links and nodes

let currentMapMode = 'single'; // 'single' or 'all' to track current view
let currentNgfwSerial = null; // Store the currently selected NGFW serial (for export filename)

// Global tooltip state variables
let tooltipLocked = false;
let activeTooltipNode = null; // Stores the D3 node data that owns the locked tooltip

// --- Constants for NGFW Icons (Copied from device-manager.js, placed in global scope) ---
const NGFW_EXACT_ICON_MAP = {
    'pa-440': '/static/images/pa-440.svg',
    'pa-5450': '/static/images/pa-5450.svg',
    'pa-7050': '/static/images/pa-7050.svg',
    'pa-vm': '/static/images/pa-vm.svg',
};

const NGFW_SERIES_ICON_MAP = {
    'pa-2': '/static/images/pa-200.svg',
    'pa-8': '/static/images/pa-800.svg',
    'pa-34': '/static/images/pa-3400.svg',
    'pa-52': '/static/images/pa-5200.svg',
};

const getIconPath = (platform, model) => {
    if (platform === 'panorama') { // While not used in LLDP map, kept for consistency if needed later
        return '/static/images/panorama.svg';
    }

    if (platform === 'ngfw' && model) {
        const lowerModel = model.toLowerCase();
        if (NGFW_EXACT_ICON_MAP[lowerModel]) {
            return NGFW_EXACT_ICON_MAP[lowerModel];
        }
        for (const prefix in NGFW_SERIES_ICON_MAP) {
            if (lowerModel.startsWith(prefix)) {
                return NGFW_SERIES_ICON_MAP[prefix];
            }
        }
        return '/static/images/ngfw.svg'; // Default NGFW icon if no specific match
    }
    return '/static/images/ngfw.svg'; // Fallback for NGFW
};

document.addEventListener('DOMContentLoaded', () => {
    // --- Global Constants and Initial Setup ---
    const svg = d3.select("#visualization").append("svg");
    mapGroup = svg.append("g"); // Assign to global variable
    tooltip = d3.select(".tooltip"); // Assign to global variable

    // --- D3 Force Layout Setup (for Global Map) ---
    simulation = d3.forceSimulation() // Assign to global variable
        .force("link", d3.forceLink().id(d => d.id).distance(250).strength(0.7))
        .force("charge", d3.forceManyBody().strength(-3000))
        .force("center", d3.forceCenter(0, 0))
        .force("collide", d3.forceCollide(120))
        .alphaDecay(0.02)
        .on("tick", ticked);

    // --- D3 Zoom Setup (for both maps) ---
    const zoom = d3.zoom().scaleExtent([0.05, 4]).on("zoom", (event) => {
        mapGroup.attr("transform", event.transform);
    });

    // --- DOM Element References ---
    const searchInput = document.getElementById('searchInput');
    const ngfwSelector = document.getElementById('ngfwSelector');
    const resetViewBtn = document.getElementById('resetViewBtn');
    const exportSvgBtn = document.getElementById('exportSvgBtn');
    const controls = document.querySelector('.controls');
    const controlsHeader = document.getElementById('controls-header'); // Sidebar toggle is handled by global.js
    const loadAllLldpBtn = document.getElementById('loadAllLldpBtn');
    const toggleAllNodesLockBtn = document.getElementById('toggleAllNodesLockBtn');

    // Inspector panel elements
    const inspectorPanel = document.getElementById('inspector-panel');
    // const mainControls = document.getElementById('main-controls'); // Not directly used here, no need for reference
    const inspectorOverlay = document.getElementById('inspector-overlay');
    const inspectorCloseBtn = document.getElementById('inspector-close-btn');

    // --- DOM Element References for Add Neighbor Form (NEW) ---
    const addLldpNeighborForm = document.getElementById('add-lldp-neighbor-form');
    const addNgfwHostnameSelect = document.getElementById('addNgfwHostname');


    window.setupSvgSize = function() {
        const viz = document.getElementById('visualization');
        if (viz) {
            svg.attr("width", viz.clientWidth).attr("height", viz.clientHeight);
            simulation.force("center", d3.forceCenter(viz.clientWidth / 2, viz.clientHeight / 2));
            if (simulation.nodes().length > 0 && currentMapMode === 'all') simulation.alpha(0.3).restart();
        }
    }

    // --- Helper to hide tooltip (used by both draw functions and global click) ---
    window.hideTooltip = function() {
        tooltip.transition().duration(500).style("opacity", 0);
        tooltip.classed("locked", false); // Always remove locked class on hide
        tooltipLocked = false; // Always reset global locked state
        activeTooltipNode = null; // Always reset active node
    }

     // --- Inspector Panel Functions (UPDATED FOR SLIDE-IN FROM RIGHT AND GLOBAL MAP DETAILS) ---
    window.showInspector = function(nodeData) {
        if (inspectorPanel) {
            inspectorPanel.classList.add('inspector-open'); // Apply class to slide in
        }
        if (inspectorOverlay) {
            inspectorOverlay.classList.remove('hidden'); // Show overlay
        }
        
        // Store the node data that is currently being inspected
        // This is useful for re-rendering if status changes (e.g., locking)
        window.activeInspectorNode = nodeData; 

        const titleElement = document.getElementById('inspector-title');
        const content = document.getElementById('inspector-content');
        content.innerHTML = ''; // Clear previous content

        const detailsList = document.createElement('ul');
        detailsList.className = 'inspector-details-list';
        let detailsHtml = '';

        if (nodeData.type === 'ngfw') {
            const iconPath = getIconPath('ngfw', nodeData.model);
            // Set innerHTML to include the image and text
            titleElement.innerHTML = `<img src="${iconPath}" class="device-icon inspector-title-icon" alt="${nodeData.model || 'NGFW'} Icon"> ${nodeData.name}`;

            detailsHtml += `<li><span class="detail-label">Type:</span><span class="detail-value">NGFW</span></li>`;
            detailsHtml += `<li><span class="detail-label">Hostname:</span><span class="detail-value">${nodeData.name}</span></li>`;
            detailsHtml += `<li><span class="detail-label">Serial:</span><span class="detail-value">${nodeData.serial_number || 'N/A'}</span></li>`;
            detailsHtml += `<li><span class="detail-label">Model:</span><span class="detail-value">${nodeData.model || 'N/A'}</span></li>`;
            
            // Status for lockable nodes (global map)
            if (typeof nodeData.locked !== 'undefined') {
                detailsHtml += `<li><span class="detail-label">Status:</span><span class="detail-value">${nodeData.locked ? 'Locked' : 'Unlocked'} (Double-click to ${nodeData.locked ? 'unlock' : 'lock'})</span></li>`;
            }

            // Connections for NGFW (from global map)
            if (nodeData.connections && nodeData.connections.length > 0) {
                detailsHtml += `<hr class="section-divider">`;
                detailsHtml += `<h5>Connections:</h5>`;
                
                const groupedConnections = {};
                nodeData.connections.forEach(conn => {
                    const groupKey = `${conn.connected_device_name}-${conn.connected_device_type}`; // Group by connected device
                    if (!groupedConnections[groupKey]) {
                        groupedConnections[groupKey] = {
                            name: conn.connected_device_name,
                            type: conn.connected_device_type,
                            interfaces: []
                        };
                    }
                    groupedConnections[groupKey].interfaces.push(conn);
                });

                for (const groupKey in groupedConnections) {
                    const group = groupedConnections[groupKey];
                    detailsHtml += `<div class="inspector-item">`;
                    // Title for the connected device (e.g., "JBSW-CLOSET.berger.local")
                    detailsHtml += `<strong class="connection-group-title">${group.name}</strong>`;
                    
                    detailsHtml += `<table>`;
                    detailsHtml += `<thead><tr><th>NGFW Int</th><th>Remote Int</th><th>Description</th></tr></thead>`;
                    detailsHtml += `<tbody>`;

                    group.interfaces.forEach(conn => {
                        detailsHtml += `<tr>`;
                        detailsHtml += `<td>${conn.local_interface}</td>`;
                        detailsHtml += `<td>${conn.remote_interface_id || 'N/A'}</td>`;
                        detailsHtml += `<td>${conn.remote_interface_description || 'N/A'}</td>`;
                        detailsHtml += `</tr>`;
                    });
                    detailsHtml += `</tbody>`;
                    detailsHtml += `</table>`;
                    detailsHtml += `</div>`;
                }
            } else {
                detailsHtml += `<li><span class="detail-value">No LLDP neighbors discovered.</span></li>`;
            }

        } else if (nodeData.type === 'remote_device') {
            titleElement.textContent = nodeData.name; // For remote devices, just show name
            detailsHtml += `<li><span class="detail-label">Type:</span><span class="detail-value">LLDP Neighbor</span></li>`;
            detailsHtml += `<li><span class="detail-label">Hostname:</span><span class="detail-value">${nodeData.name}</span></li>`; // Use nodeData.name as it's the hostname for remote_device
            
            // Status for lockable nodes (global map)
            if (typeof nodeData.locked !== 'undefined') {
                detailsHtml += `<li><span class="detail-label">Status:</span><span class="detail-value">${nodeData.locked ? 'Locked' : 'Unlocked'} (Double-click to ${nodeData.locked ? 'unlock' : 'lock'})</span></li>`;
            }

            // Connections for LLDP Neighbor (from global map)
            if (nodeData.connections && nodeData.connections.length > 0) {
                detailsHtml += `<hr class="section-divider">`;
                detailsHtml += `<h5>Connections:</h5>`;

                const groupedConnections = {};
                nodeData.connections.forEach(conn => {
                    // Group by the NGFW this neighbor is connected to
                    const groupKey = conn.ngfw_hostname;
                    if (!groupedConnections[groupKey]) {
                        groupedConnections[groupKey] = {
                            hostname: conn.ngfw_hostname,
                            interfaces: []
                        };
                    }
                    groupedConnections[groupKey].interfaces.push(conn);
                });

                for (const ngfwHostname in groupedConnections) {
                    const group = groupedConnections[ngfwHostname];
                    detailsHtml += `<div class="inspector-item">`;
                    // Title for the connected NGFW (e.g., "NGFW jbfw-edge02")
                    detailsHtml += `<strong class="connection-group-title">NGFW ${group.hostname}</strong>`;

                    detailsHtml += `<table>`;
                    detailsHtml += `<thead><tr><th>NGFW Int</th><th>Remote Int</th><th>Description</th></tr></thead>`;
                    detailsHtml += `<tbody>`;

                    group.interfaces.forEach(conn => {
                        detailsHtml += `<tr>`;
                        detailsHtml += `<td>${conn.local_interface}</td>`;
                        detailsHtml += `<td>${conn.remote_interface_id || 'N/A'}</td>`;
                        detailsHtml += `<td>${conn.remote_interface_description || 'N/A'}</td>`;
                        detailsHtml += `</tr>`;
                    });
                    detailsHtml += `</tbody>`;
                    detailsHtml += `</table>`;
                    detailsHtml += `</div>`;
                }
            } else {
                detailsHtml += `<li><span class="detail-value">No connections found for this neighbor.</span></li>`;
            }
        }

        detailsList.innerHTML = detailsHtml;
        content.appendChild(detailsList);
        content.style.maxHeight = 'calc(100vh - 150px)';
        content.style.overflowY = 'auto';
    }

    window.hideInspector = function() {
        if (inspectorPanel) inspectorPanel.classList.remove('inspector-open');
        if (inspectorOverlay) {
            inspectorOverlay.classList.add('hidden');
        }
    }

    // --- Core API Functions ---
    async function populateNgfwDropdown() {
        console.log("Fetching NGFW list from API...");
        try {
            const response = await fetch('/api/devices');
            if (!response.ok) throw new Error(`API Error: ${response.statusText}`);
            const data = await response.json();
            const ngfws = data.ngfws.sort((a, b) => {
                const hostnameA = a.hostname || a.serial_number;
                const hostnameB = b.hostname || b.serial_number;
                return hostnameA.localeCompare(hostnameB);
            });
            
            // Populate the existing ngfwSelector for map view
            ngfwSelector.innerHTML = '<option value="">-- Select an NGFW --</option>';
            ngfws.forEach(ngfw => {
                const option = document.createElement('option');
                option.value = ngfw.hostname;
                option.textContent = ngfw.hostname || ngfw.serial_number;
                option.dataset.serial = ngfw.serial_number;
                ngfwSelector.appendChild(option);
            });

            // Populate the new addNgfwHostnameSelect for the form
            addNgfwHostnameSelect.innerHTML = '<option value="">-- Select NGFW --</option>'; // Add a default option
            ngfws.forEach(ngfw => {
                const option = document.createElement('option');
                option.value = ngfw.hostname;
                option.textContent = ngfw.hostname || ngfw.serial_number;
                addNgfwHostnameSelect.appendChild(option);
            });

            console.log("NGFW dropdowns populated.");
        } catch (error) {
            console.error("Failed to populate NGFW dropdowns:", error);
            alert("Could not load NGFW list from server.");
        }
    }

    window.loadAndDrawLldpMap = async function(ngfwHostname) {
        currentMapMode = 'single';
        const selectedOption = ngfwSelector.options[ngfwSelector.selectedIndex];
        currentNgfwSerial = selectedOption ? selectedOption.dataset.serial || selectedOption.value : null;

        toggleAllNodesLockBtn.style.display = 'none';
        window.hideTooltip();
        window.hideInspector(); // Hide inspector on new map load

        if (!ngfwHostname) {
            mapGroup.selectAll("*").remove();
            simulation.stop();
            return;
        }
        console.log(`Fetching LLDP neighbors for NGFW: ${ngfwHostname}`);
        try {
            const response = await fetch(`/api/lldp-map/single/${encodeURIComponent(ngfwHostname)}`);
            if (!response.ok) throw new Error(`API Error: ${response.statusText}`);
            const mapData = await response.json();
            mapGroup.selectAll("*").remove();
            simulation.stop();
            mapGroup.attr("transform", d3.zoomIdentity);

            // Pass the NGFW's serial number AND model to the draw function
            // Ensure mapData.ngfw_model is available from your Flask backend
            drawSingleLldpMap(mapGroup, tooltip, mapData.unique_neighbors, mapData.ngfw_hostname, mapData.ngfw_serial, mapData.ngfw_model, svg.attr("width") / 2, svg.attr("height") / 2);

        } catch (error) {
            console.error("Failed to load LLDP map:", error);
            alert(`Could not load LLDP neighbors for ${ngfwHostname}.`);
        }
    }

    window.loadAndDrawAllLldpMaps = async function() {
        currentMapMode = 'all';
        ngfwSelector.value = "";
        searchInput.value = "";
        console.log("Fetching all LLDP neighbors for global map...");

        toggleAllNodesLockBtn.style.display = 'block';
        toggleAllNodesLockBtn.textContent = 'Lock All Nodes';
        window.hideTooltip();
        window.hideInspector(); // Hide inspector on new map load

        try {
            const response = await fetch('/api/lldp-map/all');
            if (!response.ok) throw new Error(`API Error: ${response.statusText}`);
            const graphData = await response.json();

            mapGroup.selectAll("*").remove();
            simulation.stop();

            if (!graphData || !graphData.nodes || graphData.nodes.length === 0) {
                 mapGroup.append("text")
                    .attr("x", svg.attr("width") / 2)
                    .attr("y", svg.attr("height") / 2)
                    .attr("text-anchor", "middle")
                    .style("font-size", "20px")
                    .style("fill", "#555")
                    .text("No global LLDP data found to display.");
                toggleAllNodesLockBtn.style.display = 'none';
                return;
            }

            drawGlobalLldpMap(mapGroup, tooltip, simulation, graphData.nodes, graphData.links);

            mapGroup.attr("transform", d3.zoomIdentity);

        } catch (error) {
            console.error("Failed to load all LLDP maps:", error);
            alert("Could not load global LLDP map from server.");
        }
    }

    window.exportSvg = async function() {
        let filenamePrefix = `lldp-map-${currentMapMode}`;
        if (currentMapMode === 'single' && currentNgfwSerial) {
            filenamePrefix += `-${currentNgfwSerial}`;
        }
        window.exportSvg(svg, mapGroup, filenamePrefix);
    }

    function ticked() {
        if (!link || !node) return;

        link
            .attr("x1", d => d.source.x)
            .attr("y1", d => d.source.y)
            .attr("x2", d => d.target.x)
            .attr("y2", d => d.target.y);

        node
            .attr("transform", d => `translate(${d.x},${d.y})`);
    }

    function dragstarted(event, d) {
        if (!event.active) simulation.alphaTarget(0.3).restart();
        d.fx = d.x;
        d.fy = d.y;
    }

    function dragged(event, d) {
        d.fx = event.x;
        d.fy = event.y;
    }

    function dragended(event, d) {
        if (!event.active) simulation.alphaTarget(0);
        if (!d.locked) {
            d.fx = null;
            d.fy = null;
        }
    }
    window.dragstarted = dragstarted;
    window.dragged = dragged;
    window.dragended = dragended;

    window.toggleAllNodesLock = function() {
        if (currentMapMode !== 'all' || !node || node.empty()) {
            console.warn("Toggle All Nodes Lock: Not in global map mode or no nodes present.");
            return;
        }

        let shouldLockAll = false;
        node.each(d => {
            if (!d.locked) {
                shouldLockAll = true;
            }
        });

        node.each(function(d) {
            d.locked = shouldLockAll;
            d3.select(this).classed("locked-node", d.locked);

            if (d.locked) {
                d.fx = d.x;
                d.fy = d.y;
            } else {
                d.fx = null;
                d.fy = null;
            }
        });

        toggleAllNodesLockBtn.textContent = shouldLockAll ? 'Unlock All Nodes' : 'Lock All Nodes';

        simulation.alpha(0.3).restart();
        console.log(`All nodes ${shouldLockAll ? 'locked' : 'unlocked'}.`);
    };

    window.handleSearch = function(event) {
        const searchTerm = event.target.value.trim().toLowerCase();

        if (currentMapMode === 'single') {
            const allNeighborGroups = d3.selectAll(".lldp-neighbor-group");

            if (!searchTerm) {
                allNeighborGroups.classed("faded", false).classed("highlight", false);
                return;
            }

            allNeighborGroups.classed("faded", true).classed("highlight", false);

            allNeighborGroups.each(function(d) {
                if (!d) return;
                let searchableContent = [d.remote_hostname];
                d.connections.forEach(conn => {
                    searchableContent.push(conn.local_interface, conn.remote_interface_id, conn.remote_interface_description);
                });
                searchableContent = searchableContent.filter(Boolean).map(s => String(s).toLowerCase());

                if (searchableContent.some(c => c.includes(searchTerm))) {
                    d3.select(this).classed("faded", false).classed("highlight", true);
                }
            });
        } else if (currentMapMode === 'all') {
            const allNodes = mapGroup.selectAll(".node");

            if (!searchTerm) {
                allNodes.classed("faded", false).classed("highlight", false);
                return;
            }

            allNodes.classed("faded", true).classed("highlight", false);

            allNodes.each(function(d) {
                if (!d) return;
                let searchableContent = [d.name, d.serial_number, d.label];
                const nodeLinks = simulation.force("link").links().filter(link => link.source.id === d.id || link.target.id === d.id);

                nodeLinks.forEach(link => {
                    searchableContent.push(link.local_interface, link.remote_interface_id, link.remote_interface_description, link.ngfw_hostname);
                });
                searchableContent = searchableContent.filter(Boolean).map(s => String(s).toLowerCase());

                if (searchableContent.some(c => c.includes(searchTerm))) {
                    d3.select(this).classed("faded", false).classed("highlight", true);
                }
            });
        }
    }

    // --- Attach Event Listeners ---
    // controlsHeader.addEventListener is handled by global.js
    resetViewBtn.addEventListener('click', () => {
        ngfwSelector.value = "";
        searchInput.value = "";
        loadAndDrawLldpMap(null);
        toggleAllNodesLockBtn.style.display = 'none';
    });
    ngfwSelector.addEventListener('change', (event) => {
        searchInput.value = "";
        loadAndDrawLldpMap(event.target.value);
    });
    loadAllLldpBtn.addEventListener('click', () => {
        loadAndDrawAllLldpMaps();
    });
    toggleAllNodesLockBtn.addEventListener('click', window.toggleAllNodesLock);
    searchInput.addEventListener('input', handleSearch);
    exportSvgBtn.addEventListener('click', window.exportSvg);

    // --- NEW: Handle Add LLDP Neighbor Form Submission ---
    if (addLldpNeighborForm) {
        addLldpNeighborForm.addEventListener('submit', async (event) => {
            event.preventDefault(); // Prevent default form submission

            const ngfw_hostname = addNgfwHostnameSelect.value;
            const local_interface = document.getElementById('addLocalInterface').value;
            const remote_hostname = document.getElementById('addRemoteHostname').value;
            const remote_interface_id = document.getElementById('addRemoteInterfaceId').value;
            const remote_interface_description = document.getElementById('addRemoteInterfaceDescription').value;

            // Basic client-side validation (all fields required)
            if (!ngfw_hostname || !local_interface || !remote_hostname || !remote_interface_id || !remote_interface_description) {
                window.showAppModal("All fields are required to add a manual LLDP neighbor."); // Use global AppModal
                return;
            }

            try {
                const response = await fetch('/api/lldp-neighbor/add', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        ngfw_hostname,
                        local_interface,
                        remote_hostname,
                        remote_interface_id,
                        remote_interface_description
                    })
                });

                const result = await response.json();

                if (!response.ok) {
                    // Handle API errors (e.g., validation errors from controller)
                    throw new Error(result.error || `Failed to add neighbor: ${response.statusText}`);
                }

                window.showAppModal(result.message); // Show success message
                addLldpNeighborForm.reset(); // Clear the form
                
                // After adding, refresh the current map view if it matches the NGFW
                // This assumes loadAndDrawLldpMap can take the current selector value
                if (currentMapMode === 'single' && ngfwSelector.value === ngfw_hostname) {
                    window.loadAndDrawLldpMap(ngfw_hostname);
                } else if (currentMapMode === 'all') {
                    window.loadAndDrawAllLldpMaps();
                }

            } catch (error) {
                console.error("Error adding manual LLDP neighbor:", error);
                window.showAppModal(`Error adding neighbor: ${error.message}`);
            }
        });
    }

    // --- Initial Load ---
    window.setupSvgSize();
    svg.call(zoom);
    window.addEventListener('resize', window.setupSvgSize);
    populateNgfwDropdown(); // Call this to populate BOTH dropdowns now

    // Initially hide the "Lock All Nodes" button as we start in single mode
    toggleAllNodesLockBtn.style.display = 'none';

    // Global click listener to hide locked tooltip
    document.body.addEventListener('click', (event) => {
        if (tooltipLocked && !tooltip.node().contains(event.target)) {
            if (!event.target.closest('.node') && !event.target.closest('.lldp-neighbor-group') && !event.target.closest('.ngfw-node-group')) {
                window.hideTooltip();
            }
        }
    });

    if (inspectorCloseBtn) { // Now declared at the top, just check and add listener
        inspectorCloseBtn.addEventListener('click', window.hideInspector);
    }

    if (inspectorOverlay) { // Now declared at the top, just check and add listener
        inspectorOverlay.addEventListener('click', window.hideInspector);
    }
});