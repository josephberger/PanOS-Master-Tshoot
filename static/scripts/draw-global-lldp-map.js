// static/scripts/draw-global-lldp-map.js

function drawGlobalLldpMap(mapGroup, tooltip, simulation, nodes, links) {
    console.log("drawGlobalLldpMap: Starting with nodes:", nodes, "and links:", links);

    const nodeRectWidth = 180;
    const nodeRectHeight = 70;

    mapGroup.selectAll("*").remove();

    const viz = document.getElementById('visualization');
    simulation.force("center", d3.forceCenter(viz.clientWidth / 2, viz.clientHeight / 2));

    simulation.nodes(nodes);
    simulation.force("link").links(links);

    link = mapGroup.append("g")
        .attr("class", "links")
        .selectAll("line")
        .data(links)
        .enter().append("line")
        .attr("class", "link");

    node = mapGroup.append("g")
        .attr("class", "nodes")
        .selectAll("g")
        .data(nodes)
        .enter().append("g")
        .attr("class", d => `node ${d.type === 'ngfw' ? 'ngfw-node' : 'remote-node'}`)
        .classed("locked-node", d => d.locked);

    node.append("rect")
        .attr("rx", 5)
        .attr("width", nodeRectWidth)
        .attr("height", nodeRectHeight)
        .attr("x", -nodeRectWidth / 2)
        .attr("y", -nodeRectHeight / 2)
        .attr("class", d => d.type === 'ngfw' ? 'ngfw-container' : 'lldp-box');

    node.append("text")
        .attr("dy", "0.3em")
        .attr("text-anchor", "middle")
        .attr("class", d => d.type === 'ngfw' ? 'ngfw-label' : 'lldp-label')
        .text(d => d.label);

    // --- REVISED EVENT HANDLERS ---
    node
        .on("click", function(event, d) {
            event.stopPropagation();
            window.hideTooltip(); // Hide any active preview tooltip on click

            // Retrieve the full list of links from the simulation's force link, as 'links' variable
            // might be a copy or not reflect ongoing simulation state if it was paused etc.
            const allCurrentLinks = simulation.force("link").links();

            let connectionsForInspector = [];

            if (d.type === 'ngfw') {
                // For NGFW nodes, filter links where the NGFW is either source or target
                const relevantLinks = allCurrentLinks.filter(l => l.source.id === d.id || l.target.id === d.id);
                relevantLinks.forEach(l => {
                    const isSourceNode = (l.source.id === d.id);
                    const connectedNode = isSourceNode ? l.target : l.source; // Get the other node in the link

                    connectionsForInspector.push({
                        ngfw_hostname: l.ngfw_hostname,
                        local_interface: l.local_interface,
                        remote_interface_id: l.remote_interface_id,
                        remote_interface_description: l.remote_interface_description,
                        connected_device_name: connectedNode.name, // The name of the connected neighbor/NGFW
                        connected_device_type: connectedNode.type
                    });
                });
            } else if (d.type === 'remote_device') { // Changed 'lldp_neighbor' to 'remote_device' based on Python backend
                // For LLDP Neighbor nodes, filter links where this neighbor is either source or target
                // Each link represents a connection *to* an NGFW, and contains the NGFW's info.
                const relevantLinks = allCurrentLinks.filter(l => l.source.id === d.id || l.target.id === d.id);
                relevantLinks.forEach(l => {
                    // Determine which end of the link is the NGFW and which is the neighbor
                    const ngfwNode = (l.source.type === 'ngfw') ? l.source : l.target;
                    const neighborNode = (l.source.type === 'remote_device') ? l.source : l.target; // Use 'remote_device'

                    // Ensure this link actually involves the clicked neighbor and an NGFW
                    // This condition also ensures we're only looking at links directly connected to the clicked 'd' node
                    if ((ngfwNode.id === l.source.id && neighborNode.id === l.target.id && neighborNode.id === d.id) ||
                        (ngfwNode.id === l.target.id && neighborNode.id === l.source.id && neighborNode.id === d.id)) {

                        connectionsForInspector.push({
                            // The NGFW's hostname for this specific connection
                            ngfw_hostname: l.ngfw_hostname,
                            // The NGFW's interface from this connection
                            local_interface: l.local_interface,
                            // The neighbor's interface from this connection
                            remote_interface_id: l.remote_interface_id,
                            // The neighbor's interface description from this connection
                            remote_interface_description: l.remote_interface_description
                        });
                    }
                });
            }

            // Construct nodeData to pass to the inspector
            let nodeDataForInspector = {
                name: d.name, // Use 'name' for title
                type: d.type, // 'ngfw' or 'remote_device'
                locked: d.locked,
                connections: connectionsForInspector // Pass the connections array directly
            };

            if (d.type === 'ngfw') {
                nodeDataForInspector.serial_number = d.serial_number;
                nodeDataForInspector.model = d.model;
            } else if (d.type === 'remote_device') {
                // For remote_device, map 'name' to 'remote_hostname' as expected by showInspector
                nodeDataForInspector.remote_hostname = d.name;
            }

            // Call the global showInspector function
            window.showInspector(nodeDataForInspector);
        })
        .on("mouseover", function(event, d) {
            // Only show preview tooltip if inspector is NOT open
            const inspectorPanel = document.getElementById('inspector-panel');
            if (inspectorPanel && inspectorPanel.classList.contains('inspector-open')) {
                return; // Do not show preview tooltip if inspector is already open
            }

            tooltip.transition().duration(50).style("opacity", .7); // Brief fade-in
            let tooltipHtml = `<strong>${d.name}</strong><br>`;

            // Brief details for tooltip preview
            if (d.type === 'ngfw') {
                tooltipHtml += `Type: NGFW<br>`;
                tooltipHtml += `Serial: ${d.serial_number || 'N/A'}`;
            } else { // remote_device
                tooltipHtml += `Type: LLDP Neighbor<br>`;
            }
            tooltipHtml += `<br>Status: ${d.locked ? 'Locked' : 'Unlocked'} (Double-click to ${d.locked ? 'unlock' : 'lock'})`;

            tooltip.html(tooltipHtml);

            // Positioning logic for tooltip (copied from previous version)
            const mouseX = event.pageX;
            const mouseY = event.pageY;
            const tooltipWidth = tooltip.node().offsetWidth;
            const tooltipHeight = tooltip.node().offsetHeight;

            let left = mouseX + 10;
            let top = mouseY - 28;
            if (left + tooltipWidth > window.innerWidth - 20) left = mouseX - tooltipWidth - 10;
            if (top + tooltipHeight > window.innerHeight - 20) top = mouseY - tooltipHeight - 10;

            tooltip.style("left", left + "px")
                   .style("top", top + "px");
        })
        .on("mouseout", function(event, d) {
            // Only hide preview tooltip if inspector is NOT open
            const inspectorPanel = document.getElementById('inspector-panel');
            if (inspectorPanel && inspectorPanel.classList.contains('inspector-open')) {
                return; // Keep tooltip if inspector is open (to avoid flicker when moving mouse over inspector)
            }
            window.hideTooltip(); // Calls the global hideTooltip which checks window.tooltipLocked
        })
        .on("dblclick", function(event, d) {
            event.stopPropagation(); // Prevent zoom on double click

            d.locked = !d.locked; // Toggle locked state
            d3.select(this).classed("locked-node", d.locked); // Toggle CSS class

            if (d.locked) {
                d.fx = d.x; // Fix position
                d.fy = d.y;
                console.log(`Locked node: ${d.name} at (${d.fx}, ${d.fy})`);
            } else {
                d.fx = null; // Release position
                d.fy = null;
                console.log(`Unlocked node: ${d.name}`);
            }
            simulation.alpha(0.3).restart(); // Restart simulation to react to fixed nodes

            // Update inspector if it's open for this node to reflect new lock status
            const inspectorPanel = document.getElementById('inspector-panel');
            if (inspectorPanel && inspectorPanel.classList.contains('inspector-open') && window.activeInspectorNode && window.activeInspectorNode.id === d.id) {
                // Re-show inspector with updated data
                // Re-prepare connections data as locked status might affect it in some hypothetical future logic
                const allCurrentLinks = simulation.force("link").links();
                const relevantLinks = allCurrentLinks.filter(l => l.source.id === d.id || l.target.id === d.id);
                
                let updatedConnections = [];
                if (d.type === 'ngfw') {
                    relevantLinks.forEach(l => {
                        const isSourceNode = (l.source.id === d.id);
                        const connectedNode = isSourceNode ? l.target : l.source;
                        updatedConnections.push({
                            ngfw_hostname: l.ngfw_hostname,
                            local_interface: l.local_interface,
                            remote_interface_id: l.remote_interface_id,
                            remote_interface_description: l.remote_interface_description,
                            connected_device_name: connectedNode.name,
                            connected_device_type: connectedNode.type
                        });
                    });
                } else if (d.type === 'remote_device') { // Use 'remote_device' here too
                    relevantLinks.forEach(l => {
                        const ngfwNode = (l.source.type === 'ngfw') ? l.source : l.target;
                        const neighborNode = (l.source.type === 'remote_device') ? l.source : l.target; // Use 'remote_device'

                        if ((ngfwNode.id === l.source.id && neighborNode.id === l.target.id && neighborNode.id === d.id) ||
                            (ngfwNode.id === l.target.id && neighborNode.id === l.source.id && neighborNode.id === d.id)) {
                            updatedConnections.push({
                                ngfw_hostname: l.ngfw_hostname,
                                local_interface: l.local_interface,
                                remote_interface_id: l.remote_interface_id,
                                remote_interface_description: l.remote_interface_description
                            });
                        }
                    });
                }

                // Prepare the updated node data for the inspector
                let updatedNodeDataForInspector = {
                    name: d.name,
                    type: d.type,
                    locked: d.locked, // Pass the updated locked status
                    connections: updatedConnections // Pass the re-prepared connections
                };

                if (d.type === 'ngfw') {
                    updatedNodeDataForInspector.serial_number = d.serial_number;
                    updatedNodeDataForInspector.model = d.model;
                } else if (d.type === 'remote_device') {
                    updatedNodeDataForInspector.remote_hostname = d.name; // Map 'name' to 'remote_hostname'
                }
                
                window.showInspector(updatedNodeDataForInspector);
            }
        });

    node.call(d3.drag()
        .on("start", window.dragstarted)
        .on("drag", window.dragged)
        .on("end", window.dragended));

    simulation.alpha(1).restart();
    console.log("drawGlobalLldpMap: Completed, simulation started.");
}