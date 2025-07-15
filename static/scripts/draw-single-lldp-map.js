// static/scripts/draw-single-lldp-map.js

// drawSingleLldpMap now takes mapGroup, tooltip, uniqueNeighborNodes, etc.
// Add ngfwSerial and ngfwModel as parameters
function drawSingleLldpMap(mapGroup, tooltip, uniqueNeighborNodes, ngfwName, ngfwSerial, ngfwModel, centerX, centerY) { // ADDED ngfwModel
    console.log("drawSingleLldpMap: Starting with ngfwName:", ngfwName, "ngfwSerial:", ngfwSerial, "ngfwModel:", ngfwModel, "and uniqueNeighborNodes:", uniqueNeighborNodes); // LOG ngfwModel

    if (!uniqueNeighborNodes || uniqueNeighborNodes.length === 0) {
        mapGroup.append("text")
            .attr("x", centerX)
            .attr("y", centerY)
            .attr("text-anchor", "middle")
            .style("font-size", "20px")
            .style("fill", "#555")
            .text(`No LLDP neighbors found for ${ngfwName}.`);
        console.log("drawSingleLldpMap: No uniqueNeighborNodes, returning.");
        return;
    }

    // Layout parameters
    const nodeHeight = 80;
    const nodePadding = 80;
    const linkFanAngle = Math.PI / 6;

    const maxCharPerLine = 20;
    const baseNodeWidth = 200;
    const charWidthFactor = 8;

    const calculateNodeWidth = (hostname) => {
        const hostnameLength = hostname.length;
        if (hostnameLength > maxCharPerLine) {
            return baseNodeWidth + (hostnameLength - maxCharPerLine) * charWidthFactor;
        }
        return baseNodeWidth;
    };

    let maxNodeWidth = calculateNodeWidth(ngfwName);
    uniqueNeighborNodes.forEach(node => {
        maxNodeWidth = Math.max(maxNodeWidth, calculateNodeWidth(node.remote_hostname));
    });
    const finalNodeWidth = maxNodeWidth;

    const baseMinRadius = 450;
    const calculatedCircumference = uniqueNeighborNodes.length * (finalNodeWidth + nodePadding);
    const autoRadius = calculatedCircumference / (2 * Math.PI);
    const actualOuterRadius = Math.max(baseMinRadius, autoRadius);

    const ringRadii = [actualOuterRadius];

    const linkGroup = mapGroup.append("g");
    const nodeGroup = mapGroup.append("g");
    const centerGroup = mapGroup.append("g"); // Group for the central NGFW

    // --- getRectIntersectionPoint function ---
    function getRectIntersectionPoint(rectCenterX, rectCenterY, rectWidth, rectHeight, angle) {
        const dx = Math.cos(angle);
        const dy = Math.sin(angle);

        const hw = rectWidth / 2;
        const hh = rectHeight / 2;

        let x, y;

        if (Math.abs(dx) < 1e-9) {
            x = rectCenterX;
            y = rectCenterY + Math.sign(dy) * hh;
        } else if (Math.abs(dy) < 1e-9) {
            x = rectCenterX + Math.sign(dx) * hw;
            y = rectCenterY;
        } else {
            const tx = hw / dx;
            const ty = hh / dy;

            let t;
            if (Math.abs(tx) < Math.abs(ty)) {
                t = tx;
            } else {
                t = ty;
            }

            x = rectCenterX + dx * t;
            y = rectCenterY + dy * t;

            x = Math.max(rectCenterX - hw, Math.min(rectCenterX + hw, x));
            y = Math.max(rectCenterY - hh, Math.min(rectCenterY + hh, y));
        }

        if (isNaN(x) || isNaN(y)) {
            console.error(`getRectIntersectionPoint: Calculated NaN for angle ${angle * 180 / Math.PI}. dx=${dx}, dy=${dy}. Falling back to center.`);
            return { x: rectCenterX, y: rectCenterY };
        }
        return { x, y };
    }
    // --- END getRectIntersectionPoint function ---


    // Draw Neighbor Nodes and their Links
    const neighborGroups = nodeGroup.selectAll(".lldp-neighbor-group")
        .data(uniqueNeighborNodes)
        .enter().append("g")
        .attr("class", "lldp-neighbor-group")
        .attr("transform", (d, i) => {
            const ringIndex = 0;
            const nodesInThisRing = uniqueNeighborNodes.length;
            const nodeRadius = ringRadii[ringIndex];
            const baseAngle = (i / nodesInThisRing) * 2 * Math.PI - (Math.PI / 2);
            const boxX = centerX + nodeRadius * Math.cos(baseAngle);
            const boxY = centerY + nodeRadius * Math.sin(baseAngle);
            return `translate(${boxX}, ${boxY})`;
        });

    neighborGroups.append("rect")
        .attr("class", "lldp-box")
        .attr("rx", 5)
        .attr("width", finalNodeWidth)
        .attr("height", nodeHeight)
        .attr("x", -finalNodeWidth / 2)
        .attr("y", -nodeHeight / 2);

    neighborGroups.append("text")
        .attr("class", "lldp-label")
        .attr("text-anchor", "middle")
        .attr("dy", "0.3em")
        .text(d => d.remote_hostname);

    // Draw links for neighbors
    uniqueNeighborNodes.forEach((uniqueNeighbor, i) => {
        const ringIndex = 0;
        const nodesInThisRing = uniqueNeighborNodes.length;
        const nodeRadius = ringRadii[ringIndex];
        const baseAngle = (i / nodesInThisRing) * 2 * Math.PI - (Math.PI / 2);
        const boxX = centerX + nodeRadius * Math.cos(baseAngle);
        const boxY = centerY + nodeRadius * Math.sin(baseAngle);

        const numConnections = uniqueNeighbor.connections.length;
        uniqueNeighbor.connections.forEach((conn, connIndex) => {
            const angleOffset = numConnections > 1
                                ? (connIndex - (numConnections - 1) / 2) * (linkFanAngle / (numConnections - 1))
                                : 0;
            const currentLinkAngle = baseAngle + angleOffset;

            const ngfwBoxWidth = finalNodeWidth;
            const ngfwBoxHeight = nodeHeight;

            const lineStartPoint = getRectIntersectionPoint(centerX, centerY, ngfwBoxWidth, ngfwBoxHeight, currentLinkAngle);
            const lineEndPoint = getRectIntersectionPoint(boxX, boxY, finalNodeWidth, nodeHeight, currentLinkAngle + Math.PI);

            if (isNaN(lineStartPoint.x) || isNaN(lineStartPoint.y) || isNaN(lineEndPoint.x) || isNaN(lineEndPoint.y)) {
                console.error("Invalid coordinate detected for line (after getRectIntersectionPoint):", lineStartPoint, lineEndPoint, "Connection:", conn);
                return;
            }

            const midX = (lineStartPoint.x + lineEndPoint.x) / 2;
            const midY = (lineStartPoint.y + lineEndPoint.y) / 2;

            const isMoreHorizontal = Math.abs(lineEndPoint.x - lineStartPoint.x) > Math.abs(lineEndPoint.y - lineStartPoint.y);

            let pathData;
            if (isMoreHorizontal) {
                pathData = `M ${lineStartPoint.x} ${lineStartPoint.y} L ${midX} ${lineStartPoint.y} L ${midX} ${lineEndPoint.y} L ${lineEndPoint.x} ${lineEndPoint.y}`;
            } else {
                pathData = `M ${lineStartPoint.x} ${lineStartPoint.y} L ${lineStartPoint.x} ${midY} L ${lineEndPoint.x} ${midY} L ${lineEndPoint.x} ${lineEndPoint.y}`;
            }

            linkGroup.append("path")
                .attr("class", "link")
                .attr("d", pathData);
        });
    });


    // Tooltip events (for the neighbor box itself) - PURE HOVER/NO CLICK LOCKING
    neighborGroups
        .on("mouseover", function(event, d) {
            tooltip.transition().duration(200).style("opacity", .9);
            tooltip.classed("locked", false); // Ensure NOT locked class

            let tooltipHtml = `<strong>${d.remote_hostname}</strong><br>`;
            tooltipHtml += `NGFW: ${ngfwName}<br><br>`;
            tooltipHtml += `Connections:<br>`;
            d.connections.forEach(conn => {
                const bullet = '&#x25CF; ';

                tooltipHtml += `${bullet} `;

                // conn.connected_device_name and conn.connected_device_type are now available from Python!
                tooltipHtml += `${conn.connected_device_name || conn.remote_hostname}`; // Use connected_device_name if available
                if (conn.connected_device_type === 'ngfw') {
                    tooltipHtml += ` (NGFW)`;
                } else if (conn.connected_device_type === 'remote_device') {
                    tooltipHtml += ` (Neighbor)`;
                }
                tooltipHtml += `<br>`;
                tooltipHtml += `&nbsp;&nbsp;NGFW Interface: ${conn.local_interface}<br>`;
                tooltipHtml += `&nbsp;&nbsp;Interface: ${conn.remote_interface_id || 'N/A'}<br>`;
                if (conn.remote_interface_description) {
                    tooltipHtml += `&nbsp;&nbsp;Description: ${conn.remote_interface_description}<br>`;
                }
                tooltipHtml += `<br>`;
            });
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
        .on("mouseout", function(d) {
            tooltip.transition().duration(500).style("opacity", 0);
            tooltip.classed("locked", false); // Ensure locked class is removed
        })
        .on("click", function(event, d) { // Click to open Inspector Panel
            event.stopPropagation(); // Prevents global click from closing inspector

            // Pass the node data to the inspector
            // 'd' (the uniqueNeighbor object) already has `remote_hostname` as its 'name' for the inspector
            // and its `connections` array is already formatted correctly by the Python backend.
            window.showInspector({
                type: 'remote_device', // Use 'remote_device' for consistency with global map
                name: d.remote_hostname, // 'name' for inspector title/hostname field
                connections: d.connections // These are the connections to the central NGFW
            });
        });

    // Draw NGFW in the center - Make it a clickable node too
    console.log("Drawing NGFW in center:", ngfwName);
    const ngfwGroup = centerGroup.append("g")
        .attr("class", "ngfw-node-group") // Add a class for consistent selection
        .datum({ name: ngfwName, type: 'ngfw' }) // Changed type to 'ngfw'
        .attr("transform", `translate(${centerX}, ${centerY})`);

    ngfwGroup.append("rect")
        .attr("class", "ngfw-container")
        .attr("width", finalNodeWidth)
        .attr("height", nodeHeight)
        .attr("x", -finalNodeWidth / 2)
        .attr("y", -nodeHeight / 2)
        .attr("rx", 10);

    ngfwGroup.append("text")
        .attr("class", "ngfw-label")
        .text(ngfwName)
        .attr("text-anchor", "middle")
        .attr("dy", "0.3em"); // Centered vertically

    // Add tooltip and click events to the NGFW group - PURE HOVER/CLICK FOR INSPECTOR
    ngfwGroup
        .on("mouseover", function(event, d) {
            tooltip.transition().duration(200).style("opacity", .9);
            tooltip.classed("locked", false); // Ensure NOT locked class
            let tooltipHtml = `<strong>${ngfwName}</strong><br>Type: NGFW`;
            tooltipHtml += `<br><br>Neighbors (${uniqueNeighborNodes.length}):<br>`;
            uniqueNeighborNodes.slice(0, 3).forEach(neighbor => { // Show max 3 for preview
                tooltipHtml += `&#x25CF; ${neighbor.remote_hostname}<br>`;
            });
            if (uniqueNeighborNodes.length > 3) tooltipHtml += `...`; // Ellipsis if more
            tooltip.html(tooltipHtml)
                .style("left", (event.pageX + 10) + "px")
                .style("top", (event.pageY - 28) + "px");
        })
        .on("mouseout", function(d) {
            tooltip.transition().duration(500).style("opacity", 0);
            tooltip.classed("locked", false); // Ensure locked class is removed
        })
        .on("click", function(event, d) { // Click to open Inspector Panel for NGFW
            event.stopPropagation(); // Prevents global click from closing inspector

            // Prepare NGFW's connections array in the format expected by showInspector
            const ngfwConnections = [];
            uniqueNeighborNodes.forEach(neighbor => {
                neighbor.connections.forEach(conn => {
                    // Each connection from the NGFW's perspective is to a remote_device
                    ngfwConnections.push({
                        ngfw_hostname: conn.ngfw_hostname, // This is `ngfwName`
                        local_interface: conn.local_interface,
                        remote_interface_id: conn.remote_interface_id,
                        remote_interface_description: conn.remote_interface_description,
                        connected_device_name: conn.connected_device_name, // This is the neighbor's hostname
                        connected_device_type: conn.connected_device_type // This should be 'remote_device'
                    });
                });
            });

            window.showInspector({
                type: 'ngfw',
                name: ngfwName,
                serial_number: ngfwSerial,
                model: ngfwModel, // Pass the model here
                connections: ngfwConnections // Pass the re-formatted connections
            });
        });

    console.log("drawSingleLldpMap: Completed.");
}