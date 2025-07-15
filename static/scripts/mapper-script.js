// static/scripts/mapper-script.js

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
    if (platform === 'panorama') { // While not used in Mapper, kept for consistency
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
    const mapGroup = svg.append("g");
    const tooltip = d3.select(".tooltip"); 

    // --- DOM Element References ---
    const searchInput = document.getElementById('searchInput');
    const vrSelector = document.getElementById('vrSelector');
    const resetViewBtn = document.getElementById('resetViewBtn');
    const loadAllBtn = document.getElementById('loadAllBtn');
    const exportSvgBtn = document.getElementById('exportSvgBtn'); 
    const mapTraceForm = document.getElementById('map-trace-form');
    // Inspector elements
    const inspectorPanel = document.getElementById('inspector-panel'); 
    const inspectorCloseBtn = document.getElementById('inspector-close-btn');
    // REMOVED: const inspectorOverlay = document.getElementById('inspector-overlay'); // This line caused the redeclaration error

    // --- D3 Zoom Setup ---
    const zoom = d3.zoom().scaleExtent([0.05, 4]).on("zoom", (event) => {
        mapGroup.attr("transform", event.transform);
    });

    function setupSvgSize() {
        const viz = document.getElementById('visualization');
        if (viz) {
            svg.attr("width", viz.clientWidth).attr("height", viz.clientHeight);
        }
    }

    // --- Core API Functions ---
    async function populateDropdown() {
        console.log("Fetching map keys from API...");
        try {
            const response = await fetch('/api/maps/keys');
            if (!response.ok) throw new Error(`API Error: ${response.statusText}`);
            const keys = await response.json();
            
            vrSelector.innerHTML = '<option value="">-- Select a map --</option>';
            keys.forEach(key => {
                const option = document.createElement('option');
                option.value = key;
                option.textContent = key;
                vrSelector.appendChild(option);
            });
            console.log("Dropdown populated.");
        } catch (error) {
            console.error("Failed to populate dropdown:", error);
            window.showAppModal("Could not load map list from server.");
        }
    }

    async function loadAndDrawSingleMap(key) {
        if (!key) {
            mapGroup.selectAll("*").remove();
            // Ensure inspector is closed if no map is loaded
            window.hideInspector();
            return;
        }
        console.log(`Fetching single map: ${key}`);
        try {
            const response = await fetch(`/api/maps/single/${encodeURIComponent(key)}`);
            if (!response.ok) throw new Error(`API Error: ${response.statusText}`);
            const mapData = await response.json();
            if (!mapData) {
                window.showAppModal(`Map data for ${key} is empty or not found.`);
                window.hideInspector();
                return;
            }
            mapGroup.selectAll("*").remove();
            const viz = document.getElementById('visualization');
            drawSingleMap(mapData, mapGroup, viz.clientWidth / 2, viz.clientHeight / 2);
            svg.transition().duration(750).call(zoom.transform, d3.zoomIdentity);
            // After loading a new map, close any open inspector
            window.hideInspector();
        } catch (error) {
            console.error("Failed to load single map:", error);
            window.showAppModal(`Could not load map for ${key}.`);
            window.hideInspector();
        }
    }

    async function loadAndDrawAllMaps() {
        console.log("Fetching all maps from API...");
        try {
            const response = await fetch('/api/maps/all');
            if (!response.ok) throw new Error(`API Error: ${response.statusText}`);
            const allMapsData = await response.json();
            mapGroup.selectAll("*").remove();
            const mapKeys = Object.keys(allMapsData);
            if (mapKeys.length === 0) {
                window.showAppModal("No saved maps found to display.");
                window.hideInspector();
                return;
            }
            drawAllMaps(allMapsData);
            svg.transition().duration(750).call(zoom.transform, d3.zoomIdentity);
            // After loading all maps, close any open inspector
            window.hideInspector();
        } catch (error) {
            console.error("Failed to load all maps:", error);
            window.showAppModal("Could not load all maps from server.");
            window.hideInspector();
        }
    }
    
    // --- Task Management and Log Modal Logic ---

    // Function to start a task, now using global showLogModal
    async function startTask(startUrl) {
        window.showLogModal();
        try {
            const startResponse = await fetch(startUrl, { method: 'POST' });
            if (!startResponse.ok) throw new Error(`Failed to start task: ${startResponse.statusText}`);
            const data = await startResponse.json();
            document.getElementById('log-output').textContent = `Task started with ID: ${data.task_id}\nConnecting to log stream...\n\n`;
            connectToStream(data.task_id);
        } catch (error) {
            document.getElementById('log-output').textContent += `\n\nERROR: Could not start task.\n${error.message}`;
        }
    }

    // Connect to stream, now using window.globalEventSource
    function connectToStream(taskId) {
        if (window.globalEventSource) window.globalEventSource.close();
        window.globalEventSource = new EventSource(`/api/tasks/stream/${taskId}`);
        window.globalEventSource.onopen = () => document.getElementById('log-output').textContent += 'Connection to log stream established.\n----------------------------------------\n';
        window.globalEventSource.onmessage = (event) => {
            const logOutput = document.getElementById('log-output');
            logOutput.textContent += event.data + '\n';
            if (logOutput.parentElement) logOutput.parentElement.scrollTop = logOutput.parentElement.scrollHeight;
            if (event.data.includes('--- TASK')) {
                window.globalEventSource.close();
                window.globalEventSource = null;
                populateDropdown();
            }
        };
        window.globalEventSource.onerror = () => {
            document.getElementById('log-output').textContent += '\n----------------------------------------\nConnection to log stream lost.';
            if (window.globalEventSource) window.globalEventSource.close();
            window.globalEventSource = null;
        };
    }

    // --- Map-based Path Trace handler ---
    async function handleMapPathTrace(event) {
        event.preventDefault();
        const srcIp = document.getElementById('map-src-ip-input').value;
        const dstIp = document.getElementById('map-dst-ip-input').value;
        if (!srcIp || !dstIp) {
            window.showAppModal('Please enter both a source and destination IP address.');
            return;
        }

        const currentMapKey = vrSelector.value;
        let url = `/api/maps/trace?src_ip=${encodeURIComponent(srcIp)}&dst_ip=${encodeURIComponent(dstIp)}`;
        if (currentMapKey) {
            url += `&map_key=${encodeURIComponent(currentMapKey)}`;
        }

        try {
            const response = await fetch(url);
            const data = await response.json();
            if (!response.ok) {
                window.showAppModal(data.error || 'Path trace failed.');
                throw new Error(data.error || 'Path trace failed.');
            }
            
            mapGroup.selectAll("*").remove();
            const viz = document.getElementById('visualization');
            if (currentMapKey) {
                drawSingleMap(data, mapGroup, viz.clientWidth / 2, viz.clientHeight / 2);
            } else {
                drawAllMaps(data);
            }
            svg.transition().duration(750).call(zoom.transform, d3.zoomIdentity);
            window.hideInspector();
        } catch (error) {
            console.error('Map trace error:', error);
            window.hideInspector();
        }
    }

    // --- UI and Drawing Functions ---
    
    // MODIFIED: showInspector to match LLDP map panel
    window.showInspector = function(nodeData) { // Make this a window global function
        const inspectorOverlay = document.getElementById('inspector-overlay'); // Re-declare locally for use in this function

        if (inspectorPanel) {
            inspectorPanel.classList.add('inspector-open');
        }
        if (inspectorOverlay) {
            inspectorOverlay.classList.remove('hidden');
        }
        
        window.activeInspectorNode = nodeData; 

        const titleElement = document.getElementById('inspector-title');
        const content = document.getElementById('inspector-content');
        content.innerHTML = ''; 

        const detailsList = document.createElement('ul');
        detailsList.className = 'inspector-details-list';
        let detailsHtml = '';

        // Add NGFW Name and VR Name at the top for clarity (always present for map nodes)
        const ngfwName = nodeData.ngfw_name || 'N/A';
        const vrName = nodeData.virtual_router_name || 'N/A';
        const model = nodeData.model || 'N/A'; // Get model for icon

        const iconPath = getIconPath('ngfw', model);
        titleElement.innerHTML = `<img src="${iconPath}" class="device-icon inspector-title-icon" alt="${model} Icon"> ${ngfwName}`;

        detailsHtml += `<li><span class="detail-label">NGFW:</span><span class="detail-value">${ngfwName}</span></li>`;
        detailsHtml += `<li><span class="detail-label">Virtual Router:</span><span class="detail-value">${vrName}</span></li>`;
        detailsHtml += `<li><span class="detail-label">Model:</span><span class="detail-value">${model}</span></li>`;
        detailsHtml += `<hr class="section-divider">`;

        if (nodeData.type === 'zone') {
            detailsHtml += `<li><span class="detail-label">Type:</span><span class="detail-value">Zone</span></li>`;
            detailsHtml += `<li><span class="detail-label">Name:</span><span class="detail-value">${nodeData.name}</span></li>`;
            
            if (nodeData.interfaces && nodeData.interfaces.length > 0) {
                detailsHtml += `<h5>Interfaces:</h5>`;
                detailsHtml += `<table><thead><tr><th>Name</th><th>IP</th><th>Tag</th><th>IPv6</th></tr></thead><tbody>`;
                nodeData.interfaces.forEach(iface => {
                    const ipv6Addrs = (iface.ipv6_addresses && iface.ipv6_addresses.length > 0) ? iface.ipv6_addresses.join('<br>') : 'N/A';
                    detailsHtml += `<tr><td>${iface.name}</td><td>${iface.ip || 'N/A'}</td><td>${iface.tag || 'N/A'}</td><td>${ipv6Addrs}</td></tr>`;
                });
                detailsHtml += `</tbody></table>`;
            } else {
                detailsHtml += `<li><span class="detail-value">No interfaces in this zone.</span></li>`;
            }

            const allZoneFibs = (nodeData.interfaces || []).flatMap(iface => iface.fibs || []);
            if (allZoneFibs.length > 0) {
                detailsHtml += `<h5 class="inspector-fibs-header">FIB Entries in Zone:</h5>`;
                detailsHtml += `<ul class="inspector-fibs-list">`;
                allZoneFibs.forEach(f => detailsHtml += `<li>${f}</li>`);
                detailsHtml += `</ul>`;
            }


        } else if (nodeData.type === 'drop') {
            detailsHtml += `<li><span class="detail-label">Type:</span><span class="detail-value">Drop Route</span></li>`;
            detailsHtml += `<li><span class="detail-label">Name:</span><span class="detail-value">${nodeData.name}</span></li>`;
            if (nodeData.fibs && nodeData.fibs.length > 0) {
                detailsHtml += `<h5>Dropped Destinations:</h5>`;
                detailsHtml += `<ul class="inspector-fibs-list">`;
                nodeData.fibs.forEach(f => detailsHtml += `<li>${f}</li>`);
                detailsHtml += `</ul>`;
            }

        } else if (nodeData.type === 'next-vr') {
            detailsHtml += `<li><span class="detail-label">Type:</span><span class="detail-value">Next Virtual Router</span></li>`;
            detailsHtml += `<li><span class="detail-label">Next VR:</span><span class="detail-value">${nodeData.name}</span></li>`;
            if (nodeData.fibs && nodeData.fibs.length > 0) {
                detailsHtml += `<h5>Destinations Routed to Next VR:</h5>`;
                detailsHtml += `<ul class="inspector-fibs-list">`;
                nodeData.fibs.forEach(f => detailsHtml += `<li>${f}</li>`);
                detailsHtml += `</ul>`;
            }
        }
        if (nodeData.trace_type) {
            detailsHtml += `<hr class="section-divider">`;
            detailsHtml += `<li><span class="detail-label">Trace Type:</span><span class="detail-value">${nodeData.trace_type.toUpperCase()}</span></li>`;
            if (nodeData.interface_name) {
                detailsHtml += `<li><span class="detail-label">Interface:</span><span class="detail-value">${nodeData.interface_name}</span></li>`;
            }
            if (nodeData.destination) {
                detailsHtml += `<li><span class="detail-label">Destination:</span><span class="detail-value">${nodeData.destination}</span></li>`;
            }
            if (nodeData.nexthop) {
                detailsHtml += `<li><span class="detail-label">Next-Hop:</span><span class="detail-value">${nodeData.nexthop}</span></li>`;
            }
            if (nodeData.flags) {
                detailsHtml += `<li><span class="detail-label">Flags:</span><span class="detail-value">${nodeData.flags}</span></li>`;
            }
        }


        detailsList.innerHTML = detailsHtml;
        content.appendChild(detailsList);
        content.style.maxHeight = 'calc(100vh - 150px)';
        content.style.overflowY = 'auto';
    }

    // MODIFIED: hideInspector to match LLDP map panel
    window.hideInspector = function() { // Make this a window global function
        const inspectorOverlay = document.getElementById('inspector-overlay'); // Re-declare locally for use in this function

        if (inspectorPanel) inspectorPanel.classList.remove('inspector-open');
        if (inspectorOverlay) {
            inspectorOverlay.classList.add('hidden');
        }
    }
    
    function drawAllMaps(allMapsData) {
        const mapKeys = Object.keys(allMapsData);
        const numMaps = mapKeys.length;
        const cols = Math.ceil(Math.sqrt(numMaps));
        const mapWidth = 1200, mapHeight = 900, padding = 200;
        mapKeys.forEach((key, i) => {
            const mapData = allMapsData[key];
            if (!mapData) return;
            const col = i % cols, row = Math.floor(i / cols);
            const centerX = col * (mapWidth + padding) + (mapWidth / 2);
            const centerY = row * (mapHeight + padding) + (mapHeight / 2);
            const container = mapGroup.append("g");
            
            // Extract NGFW and VR names from the mapData
            const ngfwName = mapData.ngfw?.name || 'Unknown NGFW';
            const vrName = mapData.ngfw?.children?.[0]?.name || 'Unknown VR';
            const model = mapData.ngfw?.model || 'Unknown'; // Assuming model is available at mapData.ngfw.model
            
            // Add NGFW/VR info to each node's datum so showInspector can access it
            // This is crucial for adding NGFW/VR context to the inspector panel
            const nodesWithContext = mapData.ngfw.children[0].children.map(node => ({
                ...node,
                ngfw_name: ngfwName,
                virtual_router_name: vrName,
                model: model // Pass model from the NGFW data
            }));

            container.append("text").attr("class", "map-title").attr("x", centerX).attr("y", centerY - 400).text(key);
            // Pass the modified nodesWithContext to drawSingleMapInternal
            drawSingleMapInternal(ngfwName, vrName, nodesWithContext, container, centerX, centerY);
        });
    }

    // Helper function for drawing a single map's nodes and links, now takes nodes directly
    // and also the NGFW and VR names to pass to the inspector.
    function drawSingleMapInternal(ngfwDisplayName, vrDisplayName, nodes, parentGroup, centerX, centerY) {
        const nodesPerRing = 20, ringPadding = 180, nodeWidth = 140, nodePadding = 40, minBaseRadius = 250;
        const numRings = Math.ceil(nodes.length / nodesPerRing) || 1;
        const ringRadii = [];
        for (let i = 0; i < numRings; i++) {
            const nodesOnThisRing = (i === numRings - 1) ? (nodes.length % nodesPerRing || nodesPerRing) : nodesPerRing;
            const requiredCircumference = nodesOnThisRing * (nodeWidth + nodePadding);
            let calculatedRadius = requiredCircumference / (2 * Math.PI);
            if (i === 0) ringRadii.push(Math.max(minBaseRadius, calculatedRadius));
            else ringRadii.push(Math.max(ringRadii[i - 1] + ringPadding, calculatedRadius));
        }
        const linkGroup = parentGroup.append("g"), nodeGroup = parentGroup.append("g"), centerGroup = parentGroup.append("g");
        
        nodes.forEach((node, i) => {
            const ringIndex = Math.floor(i / nodesPerRing), indexInRing = i % nodesPerRing;
            const nodesInThisRing = (ringIndex === numRings - 1) ? (nodes.length % nodesPerRing || nodesPerRing) : nodesPerRing;
            const nodeRadius = ringRadii[ringIndex];
            const angle = (indexInRing / nodesInThisRing) * 2 * Math.PI - (Math.PI / 2);
            const boxX = centerX + nodeRadius * Math.cos(angle), boxY = centerY + nodeRadius * Math.sin(angle);
            
            // Only draw links if a trace is present AND if it's not a drop node (which won't have a direct link)
            if (node.trace_type && node.type !== 'drop') {
                 linkGroup.append("line").attr("class", `link trace-link trace-${node.trace_type}`).attr("x1", centerX).attr("y1", centerY).attr("x2", boxX).attr("y2", boxY);
            }
            else if (!node.trace_type) { // Draw regular links if no trace is active
                 linkGroup.append("line").attr("class", "link").attr("x1", centerX).attr("y1", centerY).attr("x2", boxX).attr("y2", boxY);
            }

            // Draw trace nodes
            if (node.trace_type) {
                const traceGroup = nodeGroup.append("g")
                    .attr("class", `trace-node trace-${node.trace_type}`)
                    .attr("transform", `translate(${boxX}, ${boxY})`);
                
                if (node.type === 'drop') {
                    traceGroup.attr("class", `trace-node trace-drop`);
                    const size = 50;
                    const octagonPoints = [
                        {x: -size*0.4, y: -size}, {x: size*0.4, y: -size},
                        {x: size, y: -size*0.4}, {x: size, y: size*0.4},
                        {x: size*0.4, y: size}, {x: -size*0.4, y: size},
                        {x: -size, y: size*0.4}, {x: -size, y: -size*0.4}
                    ].map(p => `${p.x},${p.y}`).join(' ');
                    traceGroup.append('polygon').attr('points', octagonPoints);
                } else {
                    const size = 1800; // Size for the star symbol
                    const star = d3.symbol().type(d3.symbolStar).size(size);
                    if (node.trace_type === 'ingress') {
                        traceGroup.append('path').attr('class', 'trace-symbol').attr('d', star);
                    }
                    else if (node.trace_type === 'egress') {
                        traceGroup.append('circle').attr('class', 'target-outer trace-symbol').attr('r', 45);
                        traceGroup.append('circle').attr('class', 'target-middle trace-symbol').attr('r', 30);
                        traceGroup.append('circle').attr('class', 'target-inner trace-symbol').attr('r', 15);
                    } else if (node.trace_type === 'ingress-egress') {
                        traceGroup.append('circle').attr("class", 'target-outer trace-symbol').attr('r', 45);
                        traceGroup.append('circle').attr("class", 'target-middle trace-symbol').attr('r', 30);
                        traceGroup.append('path').attr("class", 'star-overlay trace-symbol').attr('d', d3.symbol().type(d3.symbolStar).size(size * 0.8));
                    }
                }

                if (node.type === 'drop') {
                    traceGroup.append("text").attr("text-anchor", "middle").attr("dy", "0.3em").text(node.name);
                } else {
                    const label = traceGroup.append("text")
                        .attr("text-anchor", "start")
                        .attr("x", 60)
                        .attr("y", 0);
                    
                    label.append("tspan")
                        .attr("class", "zone-label")
                        .attr("x", 60)
                        .attr("dy", "-0.3em")
                        .text(node.name);

                    label.append("tspan")
                        .attr("x", 60)
                        .attr("dy", "1.1em")
                        .text(node.interface_name);
                }
            } else { // Draw regular nodes
                // Each node already has ngfw_name, virtual_router_name, and model from drawAllMaps
                const dataGroup = nodeGroup.append("g").attr("class", "data-group").datum(node).attr("transform", `translate(${boxX}, ${boxY})`);
                dataGroup.on("click", (event, d) => window.showInspector(d)); // Call global showInspector
                const rect = dataGroup.append("rect").attr("rx", 5);
                const label = dataGroup.append("text").attr("text-anchor", "middle");
                if (node.type === 'zone') {
                    let hasDefaultRoute = (node.interfaces || []).some(iface => (iface.fibs || []).some(fib => fib === '0.0.0.0/0' || fib === '::/0'));
                    rect.attr("class", hasDefaultRoute ? "data-box data-box-default" : "data-box");
                    label.attr("class", hasDefaultRoute ? "data-label data-label-default" : "data-label");
                    label.append("tspan").attr("x", 0).style("font-weight", "bold").style("font-size", "14px").text(node.name);
                    const maxInterfacesToShow = 4;
                    if (node.interfaces && node.interfaces.length > 0) {
                        node.interfaces.slice(0, maxInterfacesToShow).forEach(iface => label.append("tspan").attr("x", 0).attr("dy", "1.2em").text(iface.name));
                        if (node.interfaces.length > maxInterfacesToShow) label.append("tspan").attr("x", 0).attr("dy", "1.2em").text("(...)");
                    }
                    const padding = 10, bbox = label.node().getBBox();
                    rect.attr("x", bbox.x - padding).attr("y", bbox.y - padding).attr("width", bbox.width + 2 * padding).attr("height", bbox.height + 2 * padding);
                } else {
                    rect.attr("class", `data-box data-box-${node.type === 'drop' ? 'drop' : 'nextvr'}`).attr("width", 120).attr("height", 60).attr("x", -60).attr("y", -30);
                    label.attr("class", "data-label-special").attr("dy", "0.3em").text(node.name);
                }
            }
        });
        const ngfwGroup = centerGroup.append("g").attr("transform", `translate(${centerX}, ${centerY})`);
        ngfwGroup.append("rect").attr("class", "ngfw-container").attr("width", 300).attr("height", 200).attr("x", -150).attr("y", -100).attr("rx", 10);
        ngfwGroup.append("text").attr("class", "ngfw-label").text(ngfwDisplayName).attr("text-anchor", "middle").attr("dy", -80);
        const vrGroup = ngfwGroup.append("g");
        vrGroup.append("circle").attr("class", "vr-circle").attr("r", 50);
        vrGroup.append("text").attr("class", "vr-label").text(vrDisplayName).attr("text-anchor", "middle").attr("dy", "0.3em");
    }

    // New wrapper for drawSingleMap (called by loadAndDrawSingleMap directly)
    // This extracts necessary info and calls drawSingleMapInternal
    function drawSingleMap(mapData, parentGroup, centerX, centerY) {
        if (!mapData || !mapData.ngfw || !mapData.ngfw.children || !mapData.ngfw.children[0]) return;
        const ngfwName = mapData.ngfw.name || 'Unknown NGFW';
        const vrName = mapData.ngfw.children[0].name || 'Unknown VR';
        const model = mapData.ngfw.model || 'Unknown'; // Assuming model is available here

        // Add NGFW/VR/Model context to each node
        const nodesWithContext = mapData.ngfw.children[0].children.map(node => ({
            ...node,
            ngfw_name: ngfwName,
            virtual_router_name: vrName,
            model: model // Pass model from mapData
        }));
        drawSingleMapInternal(ngfwName, vrName, nodesWithContext, parentGroup, centerX, centerY);
    }

    function handleSearch(event) {
        const searchTerm = event.target.value.trim().toLowerCase();
        const allGroups = d3.selectAll(".data-group, .map-title, .trace-node");
        if (!searchTerm) {
            allGroups.classed("faded", false).classed("highlight", false);
            return;
        }
        allGroups.classed("faded", true).classed("highlight", false);
        d3.selectAll(".data-group, .trace-node").each(function(d) {
            if (!d) return;
            let searchableContent = [d.name, d.interface_name, d.ngfw_name, d.virtual_router_name]; // Add NGFW/VR to search
            if (d.type === 'zone') {
                (d.interfaces || []).forEach(iface => {
                    searchableContent.push(iface.name, iface.ip, String(iface.tag));
                    if (iface.fibs) searchableContent = searchableContent.concat(iface.fibs);
                    if (iface.ipv6_addresses) searchableContent = searchableContent.concat(iface.ipv6_addresses);
                });
            } else if (d.fibs) {
                searchableContent = searchableContent.concat(d.fibs);
            }
            if (searchableContent.some(c => c && String(c).toLowerCase().includes(searchTerm))) {
                d3.select(this).classed("faded", false).classed("highlight", true);
                // Also highlight the map title (VR) if any of its nodes match
                d3.select(this.parentNode).selectAll('.map-title').classed("faded", false);
            }
        });
    }

    // --- Attach Event Listeners ---
    // controlsHeader.addEventListener is now handled by global.js

    resetViewBtn.addEventListener('click', () => {
        document.getElementById('map-trace-form').reset();
        loadAndDrawAllMaps();
    });
    loadAllBtn.addEventListener('click', () => {
        document.getElementById('map-trace-form').reset();
        loadAndDrawAllMaps();
    });
    inspectorCloseBtn.addEventListener('click', window.hideInspector);
    searchInput.addEventListener('input', handleSearch);
    vrSelector.addEventListener('change', (event) => {
        document.getElementById('map-trace-form').reset();
        window.hideInspector();
        loadAndDrawSingleMap(event.target.value);
    });
    // closeLogBtn listener is now handled by global.js
    mapTraceForm.addEventListener('submit', handleMapPathTrace);
    
    // MODIFIED: exportSvgBtn to call the global function
    exportSvgBtn.addEventListener('click', () => {
        const currentMapKey = vrSelector.value;
        let filename = 'mapper-map';
        if (currentMapKey) {
            filename = currentMapKey.replace(/[^a-zA-Z0-9-]/g, '_'); // Sanitize key for filename
        }
        window.exportSvg(svg, mapGroup, filename); // Pass svg, mapGroup, and desired filename prefix
    });

    // --- Initial Load ---
    setupSvgSize();
    svg.call(zoom);
    window.addEventListener('resize', setupSvgSize);
    populateDropdown();

    // Attach inspector overlay listener globally
    const inspectorOverlay = document.getElementById('inspector-overlay'); // Re-declare locally for use in this event listener
    if (inspectorOverlay) {
        inspectorOverlay.addEventListener('click', window.hideInspector);
    }
});