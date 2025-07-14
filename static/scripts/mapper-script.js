// static/scripts/mapper-script.js

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
    // controlsHeader event listener is now handled by global.js
    // const controls = document.querySelector('.controls'); 
    // const controlsHeader = document.getElementById('controls-header');
    const logModal = document.getElementById('task-log-modal');
    const logOutput = document.getElementById('log-output');
    const closeLogBtn = document.getElementById('close-log-btn');
    const inspectorCloseBtn = document.getElementById('inspector-close-btn');
    const mapTraceForm = document.getElementById('map-trace-form');

    let eventSource = null;

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
            alert("Could not load map list from server.");
        }
    }

    async function loadAndDrawSingleMap(key) {
        if (!key) {
            mapGroup.selectAll("*").remove();
            return;
        }
        console.log(`Fetching single map: ${key}`);
        try {
            const response = await fetch(`/api/maps/single/${encodeURIComponent(key)}`);
            if (!response.ok) throw new Error(`API Error: ${response.statusText}`);
            const mapData = await response.json();
            if (!mapData) {
                alert(`Map data for ${key} is empty or not found.`);
                return;
            }
            mapGroup.selectAll("*").remove();
            const viz = document.getElementById('visualization');
            drawSingleMap(mapData, mapGroup, viz.clientWidth / 2, viz.clientHeight / 2);
            svg.transition().duration(750).call(zoom.transform, d3.zoomIdentity);
        } catch (error) {
            console.error("Failed to load single map:", error);
            alert(`Could not load map for ${key}.`);
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
                alert("No saved maps found to display.");
                return;
            }
            drawAllMaps(allMapsData);
            svg.transition().duration(750).call(zoom.transform, d3.zoomIdentity);
        } catch (error) {
            console.error("Failed to load all maps:", error);
            alert("Could not load all maps from server.");
        }
    }
    
    // --- Task Management and Log Modal Logic ---
    function showLogModal() {
        logOutput.textContent = 'Initializing task...';
        logModal.style.display = 'flex';
    }

    function closeLogModal() {
        logModal.style.display = 'none';
        if (eventSource) {
            eventSource.close();
            eventSource = null;
        }
    }

    async function startTask(startUrl) {
        showLogModal();
        try {
            const startResponse = await fetch(startUrl, { method: 'POST' });
            if (!startResponse.ok) throw new Error(`Failed to start task: ${startResponse.statusText}`);
            const data = await startResponse.json();
            logOutput.textContent = `Task started with ID: ${data.task_id}\nConnecting to log stream...\n\n`;
            connectToStream(data.task_id);
        } catch (error) {
            logOutput.textContent += `\n\nERROR: Could not start task.\n${error.message}`;
        }
    }

    function connectToStream(taskId) {
        if (eventSource) eventSource.close();
        eventSource = new EventSource(`/api/tasks/stream/${taskId}`);
        eventSource.onopen = () => logOutput.textContent += 'Connection to log stream established.\n----------------------------------------\n';
        eventSource.onmessage = (event) => {
            logOutput.textContent += event.data + '\n';
            logOutput.parentElement.scrollTop = logOutput.parentElement.scrollHeight;
            if (event.data.includes('--- TASK')) {
                eventSource.close();
                eventSource = null;
                populateDropdown();
            }
        };
        eventSource.onerror = () => {
            logOutput.textContent += '\n----------------------------------------\nConnection to log stream lost.';
            eventSource.close();
            eventSource = null;
        };
    }

    // --- Map-based Path Trace handler ---
    async function handleMapPathTrace(event) {
        event.preventDefault();
        const srcIp = document.getElementById('map-src-ip-input').value;
        const dstIp = document.getElementById('map-dst-ip-input').value;
        if (!srcIp || !dstIp) {
            alert('Please enter both a source and destination IP address.');
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
            if (!response.ok) throw new Error(data.error || 'Path trace failed.');
            
            mapGroup.selectAll("*").remove();
            if (currentMapKey) {
                drawSingleMap(data, mapGroup, svg.clientWidth / 2, svg.clientHeight / 2); // Pass actual svg dimensions
            } else {
                drawAllMaps(data);
            }
            svg.transition().duration(750).call(zoom.transform, d3.zoomIdentity);
        } catch (error) {
            alert(`Error tracing path: ${error.message}`);
            console.error('Map trace error:', error);
        }
    }

    // --- UI and Drawing Functions ---
    // These drawing functions remain in mapper-script.js as they are specific to this page's map structure
    
    function showInspector(nodeData) {
        document.getElementById('main-controls').style.display = 'none';
        const panel = document.getElementById('inspector-panel');
        panel.style.display = 'block';
        const title = document.getElementById('inspector-title');
        const content = document.getElementById('inspector-content');
        content.innerHTML = ''; // Clear previous content

        if (nodeData.type === 'zone') {
            title.textContent = `Zone: ${nodeData.name}`;
            (nodeData.interfaces || []).forEach(iface => {
                const item = document.createElement('div');
                item.className = 'inspector-item';

                // Interface Name Sub-header
                const ifaceHeader = document.createElement('h5');
                ifaceHeader.textContent = iface.name;
                item.appendChild(ifaceHeader);

                // Details List for IP, Tag, etc.
                const detailsList = document.createElement('ul');
                detailsList.className = 'inspector-details-list';
                
                let detailsHtml = '';
                if (iface.ip) {
                    detailsHtml += `<li><span class="detail-label">IP Address:</span><span class="detail-value">${iface.ip}</span></li>`;
                }
                if (iface.tag) {
                    detailsHtml += `<li><span class="detail-label">Tag:</span><span class="detail-value">${iface.tag}</span></li>`;
                }
                if (iface.ipv6_addresses && iface.ipv6_addresses.length > 0) {
                    const ipv6Html = iface.ipv6_addresses.join('<br>');
                    detailsHtml += `<li><span class="detail-label">IPv6:</span><span class="detail-value">${ipv6Html}</span></li>`;
                }
                detailsList.innerHTML = detailsHtml;
                item.appendChild(detailsList);

                // FIBs List (if any)
                if (iface.fibs && iface.fibs.length > 0) {
                    const fibsHeader = document.createElement('h6');
                    fibsHeader.className = 'inspector-fibs-header';
                    fibsHeader.textContent = 'FIB Entries';
                    item.appendChild(fibsHeader);

                    const fibsList = document.createElement('ul');
                    fibsList.className = 'inspector-fibs-list';
                    fibsList.innerHTML = iface.fibs.map(f => `<li>${f}</li>`).join('');
                    item.appendChild(fibsList);
                }
                content.appendChild(item);
            });
        } else { // Fallback for other node types like 'drop' or 'nextvr'
            title.textContent = nodeData.name;
            if (nodeData.fibs && nodeData.fibs.length > 0) {
                const fibsList = document.createElement('ul');
                fibsList.className = 'inspector-fibs-list'; // Re-use class
                fibsList.innerHTML = nodeData.fibs.map(f => `<li>${f}</li>`).join('');
                content.appendChild(fibsList);
            }
        }
    }

    function hideInspector() {
        document.getElementById('inspector-panel').style.display = 'none';
        document.getElementById('main-controls').style.display = 'block';
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
            container.append("text").attr("class", "map-title").attr("x", centerX).attr("y", centerY - 400).text(key);
            drawSingleMap(mapData, container, centerX, centerY);
        });
    }

    function drawSingleMap(data, parentGroup, centerX, centerY) {
        if (!data || !data.ngfw || !data.ngfw.children || !data.ngfw.children[0]) return;
        const nodes = data.ngfw.children[0].children || [];
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
            linkGroup.append("line").attr("class", "link").attr("x1", centerX).attr("y1", centerY).attr("x2", boxX).attr("y2", boxY);
            
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
                    const size = 1800;
                    const star = d3.symbol().type(d3.symbolStar).size(size);
                    if (node.trace_type === 'ingress') traceGroup.append('path').attr('d', star);
                    else if (node.trace_type === 'egress') {
                        traceGroup.append('circle').attr('class', 'target-outer').attr('r', 45);
                        traceGroup.append('circle').attr('class', 'target-middle').attr('r', 30);
                        traceGroup.append('circle').attr('class', 'target-inner').attr('r', 15);
                    } else if (node.trace_type === 'ingress-egress') {
                        traceGroup.append('circle').attr("class", 'target-outer').attr('r', 45);
                        traceGroup.append('circle').attr("class", 'target-middle').attr('r', 30);
                        traceGroup.append('path').attr("class", 'star-overlay').attr('d', d3.symbol().type(d3.symbolStar).size(size * 0.8));
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
            } else {
                const dataGroup = nodeGroup.append("g").attr("class", "data-group").datum(node).attr("transform", `translate(${boxX}, ${boxY})`);
                dataGroup.on("click", (event, d) => showInspector(d));
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
        ngfwGroup.append("text").attr("class", "ngfw-label").text(data.ngfw.name).attr("text-anchor", "middle").attr("dy", -80);
        const vrGroup = ngfwGroup.append("g");
        vrGroup.append("circle").attr("class", "vr-circle").attr("r", 50);
        vrGroup.append("text").attr("class", "vr-label").text(data.ngfw.children[0].name).attr("text-anchor", "middle").attr("dy", "0.3em");
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
            let searchableContent = [d.name, d.interface_name];
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
                d3.select(this.parentNode).selectAll('.map-title').classed("faded", false);
            }
        });
    }

    // --- Attach Event Listeners ---
    // controlsHeader.addEventListener is now handled by global.js
    // controlsHeader.addEventListener('click', () => { ... });

    resetViewBtn.addEventListener('click', () => {
        document.getElementById('map-trace-form').reset();
        loadAndDrawAllMaps();
    });
    loadAllBtn.addEventListener('click', () => {
        document.getElementById('map-trace-form').reset();
        loadAndDrawAllMaps();
    });
    inspectorCloseBtn.addEventListener('click', hideInspector);
    searchInput.addEventListener('input', handleSearch);
    vrSelector.addEventListener('change', (event) => {
        document.getElementById('map-trace-form').reset();
        hideInspector();
        loadAndDrawSingleMap(event.target.value);
    });
    closeLogBtn.addEventListener('click', closeLogModal);
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
});