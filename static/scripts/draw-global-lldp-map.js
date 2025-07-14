// static/scripts/draw-global-lldp-map.js

// drawGlobalLldpMap now takes hideTooltip as an argument
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

    // Add tooltips to nodes (for global map) - REVISED FOR CLICK ACTIVATION AND PREVIEW BEHAVIOR
    node
        .on("click", function(event, d) {
            event.stopPropagation();

            // If this tooltip is already locked for THIS node, unlock it
            if (window.tooltipLocked && window.activeTooltipNode === d) {
                window.hideTooltip();
                return;
            }

            // Hide any currently locked tooltip (if it belongs to a different node)
            if (window.tooltipLocked && window.activeTooltipNode !== d) {
                window.hideTooltip();
            }

            // Show and lock the tooltip for this node
            tooltip.transition().duration(200).style("opacity", .9);
            tooltip.classed("locked", true);
            window.tooltipLocked = true;
            window.activeTooltipNode = d;

            let tooltipHtml = `<strong>${d.name}</strong><br>`;
            if (d.type === 'ngfw') {
                tooltipHtml += `Serial: ${d.serial_number}<br>Type: NGFW`;
            } else {
                tooltipHtml += `Type: LLDP Neighbor`;
            }
            if (d.locked) {
                tooltipHtml += `<br>Status: Locked (Double-click to unlock)`;
            } else {
                tooltipHtml += `<br>Status: Unlocked (Double-click to lock)`;
            }

            const allCurrentLinks = simulation.force("link").links();
            const relevantLinks = allCurrentLinks.filter(l => l.source.id === d.id || l.target.id === d.id);

            if (relevantLinks.length > 0) {
                tooltipHtml += "<br><br>Connections:<br>";
                relevantLinks.forEach(l => {
                    const bullet = '&#x25CF; ';
                    tooltipHtml += `${bullet} `;

                    const isSourceNode = (l.source.id === d.id);
                    const connectedDeviceName = isSourceNode ? l.target.name : l.source.name;
                    const connectedNgfwHostname = l.ngfw_hostname;

                    // Removed "To " prefix and adjusted "via NGFW"
                    if (d.type === 'ngfw' && l.target.type === 'ngfw' && l.target.name === connectedNgfwHostname) {
                         tooltipHtml += `${connectedDeviceName}<br>`;
                    } else if (d.type === 'remote_device' && l.source.type === 'ngfw' && l.source.name === connectedNgfwHostname) {
                         tooltipHtml += `NGFW ${connectedNgfwHostname}<br>`;
                    } else {
                        tooltipHtml += `${connectedDeviceName} (via NGFW ${connectedNgfwHostname})<br>`;
                    }

                    tooltipHtml += `&nbsp;&nbsp;NGFW Interface: ${l.local_interface}<br>`;
                    tooltipHtml += `&nbsp;&nbsp;Interface: ${l.remote_interface_id}`;
                    if (l.remote_interface_description) {
                        tooltipHtml += `<br>&nbsp;&nbsp;Description: ${l.remote_interface_description}`;
                    }
                    tooltipHtml += `<br>`;
                });
            }

            tooltip.html(tooltipHtml);

            const mouseX = event.pageX;
            const mouseY = event.pageY;
            const tooltipWidth = tooltip.node().offsetWidth;
            const tooltipHeight = tooltip.node().offsetHeight;

            const viewportWidth = window.innerWidth;
            const viewportHeight = window.innerHeight;

            let left = mouseX + 10;
            let top = mouseY - 28;

            if (left + tooltipWidth > viewportWidth - 20) {
                left = mouseX - tooltipWidth - 10;
            }

            if (top + tooltipHeight > viewportHeight - 20) {
                top = viewportHeight - tooltipHeight - 20;
                if (top < 0) top = 0;
            }

            tooltip.style("left", left + "px")
                   .style("top", top + "px");
        })
        .on("mouseover", function(event, d) {
            // Show preview only if NO tooltip is currently locked (anywhere)
            if (window.tooltipLocked) return;

            tooltip.transition().duration(50).style("opacity", .7);
            let tooltipHtml = `<strong>${d.name}</strong><br>`;
            if (d.type === 'ngfw') {
                tooltipHtml += `Serial: ${d.serial_number}<br>Type: NGFW`;
            } else {
                tooltipHtml += `Type: LLDP Neighbor`;
            }
            // Only add a few connections for preview to keep it light
            const allCurrentLinks = simulation.force("link").links();
            const relevantLinks = allCurrentLinks.filter(l => l.source.id === d.id || l.target.id === d.id);
            if (relevantLinks.length > 0) {
                tooltipHtml += "<br><br>Connections:<br>";
                // Show first 2 connections in preview
                relevantLinks.slice(0,2).forEach(l => {
                    const bullet = '&#x25CF; ';
                    tooltipHtml += `${bullet} `;
                    const isSourceNode = (l.source.id === d.id);
                    const connectedDeviceName = isSourceNode ? l.target.name : l.source.name;
                    tooltipHtml += `${connectedDeviceName}<br>`;
                });
                if (relevantLinks.length > 2) tooltipHtml += `<br>...(${relevantLinks.length - 2} more)`;
            }

            tooltip.html(tooltipHtml);

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
        .on("mouseout", function(d) {
            // Hide preview tooltip unconditionally on mouseout
            if (!window.tooltipLocked) {
                window.hideTooltip();
            }
        })
        .on("dblclick", function(event, d) { // <<< ADDED event.stopPropagation()
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
        });

    node.call(d3.drag()
        .on("start", window.dragstarted)
        .on("drag", window.dragged)
        .on("end", window.dragended));

    simulation.alpha(1).restart();
    console.log("drawGlobalLldpMap: Completed, simulation started.");
}