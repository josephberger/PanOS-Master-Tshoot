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
    const controlsHeader = document.getElementById('controls-header'); // Sidebar toggle is now handled by global.js
    const loadAllLldpBtn = document.getElementById('loadAllLldpBtn');
    const toggleAllNodesLockBtn = document.getElementById('toggleAllNodesLockBtn');

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
            ngfwSelector.innerHTML = '<option value="">-- Select an NGFW --</option>';
            ngfws.forEach(ngfw => {
                const option = document.createElement('option');
                option.value = ngfw.hostname;
                option.textContent = ngfw.hostname || ngfw.serial_number;
                option.dataset.serial = ngfw.serial_number; 
                ngfwSelector.appendChild(option);
            });
            console.log("NGFW dropdown populated.");
        } catch (error) {
            console.error("Failed to populate NGFW dropdown:", error);
            alert("Could not load NGFW list from server.");
        }
    }

    window.loadAndDrawLldpMap = async function(ngfwHostname) {
        currentMapMode = 'single';
        const selectedOption = ngfwSelector.options[ngfwSelector.selectedIndex];
        currentNgfwSerial = selectedOption ? selectedOption.dataset.serial || selectedOption.value : null;

        toggleAllNodesLockBtn.style.display = 'none';
        window.hideTooltip(); 

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

            drawSingleLldpMap(mapGroup, tooltip, mapData.unique_neighbors, mapData.ngfw_hostname, svg.attr("width") / 2, svg.attr("height") / 2);
            
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
    
    // REMOVED: Local exportSvg. Now calls the global one.
    // window.exportSvg = async function() { ... } 

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
    // controlsHeader listener moved to global.js
    controlsHeader.addEventListener('click', () => {
        // This specific click listener is already handled by global.js
        // However, if you need any *additional* behavior specific to main-lldp-app.js
        // when controlsHeader is clicked, you would add it here.
        // For now, it's safe to remove this listener as global.js manages it.
    });

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
    
    // MODIFIED: exportSvgBtn to call the global function
    exportSvgBtn.addEventListener('click', () => {
        let filename = `lldp-map-${currentMapMode}`;
        if (currentMapMode === 'single' && currentNgfwSerial) {
            filename += `-${currentNgfwSerial}`;
        }
        window.exportSvg(svg, mapGroup, filename); // Pass svg, mapGroup, and desired filename prefix
    });

    // --- Initial Load ---
    window.setupSvgSize(); 
    svg.call(zoom);
    window.addEventListener('resize', window.setupSvgSize); 
    populateNgfwDropdown();

    // Initially hide the "Lock All Nodes" button as we start in single mode
    toggleAllNodesLockBtn.style.display = 'none';

    // Global click listener to hide locked tooltip
    document.body.addEventListener('click', (event) => {
        if (tooltipLocked && !tooltip.node().contains(event.target)) {
            // Check if the click was also not on a node (to avoid immediate re-show)
            if (!event.target.closest('.node') && !event.target.closest('.lldp-neighbor-group')) { 
                window.hideTooltip();
            }
        }
    });
});