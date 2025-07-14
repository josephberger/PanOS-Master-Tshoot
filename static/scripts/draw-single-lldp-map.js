// static/scripts/draw-single-lldp-map.js

// drawSingleLldpMap now takes hideTooltip as an argument
function drawSingleLldpMap(mapGroup, tooltip, uniqueNeighborNodes, ngfwName, centerX, centerY) {
    console.log("drawSingleLldpMap: Starting with ngfwName:", ngfwName, "and uniqueNeighborNodes:", uniqueNeighborNodes);

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
    uniqueNeighborNodes.forEach((uniqueNeighbor, i) => {
        console.log("Processing uniqueNeighbor:", uniqueNeighbor.remote_hostname, "Connections:", uniqueNeighbor.connections.length);

        const ringIndex = 0;
        const nodesInThisRing = uniqueNeighborNodes.length;

        const nodeRadius = ringRadii[ringIndex];
        const baseAngle = (i / nodesInThisRing) * 2 * Math.PI - (Math.PI / 2);

        const boxX = centerX + nodeRadius * Math.cos(baseAngle);
        const boxY = centerY + nodeRadius * Math.sin(baseAngle);

        const neighborGroup = nodeGroup.append("g")
            .attr("class", "lldp-neighbor-group")
            .datum(uniqueNeighbor) // Attach node data
            .attr("transform", `translate(${boxX}, ${boxY})`);

        neighborGroup.append("rect")
            .attr("class", "lldp-box")
            .attr("rx", 5)
            .attr("width", finalNodeWidth)
            .attr("height", nodeHeight)
            .attr("x", -finalNodeWidth / 2)
            .attr("y", -nodeHeight / 2);

        neighborGroup.append("text")
            .attr("class", "lldp-label")
            .attr("text-anchor", "middle")
            .attr("dy", "0.3em")
            .text(uniqueNeighbor.remote_hostname);

        const numConnections = uniqueNeighbor.connections.length;

        uniqueNeighbor.connections.forEach((conn, connIndex) => {
            console.log("  Drawing connection for:", conn.local_interface, "-", conn.remote_interface_id);

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


        // Tooltip events (for the neighbor box itself) - REVERTED TO PREVIOUS BEHAVIOR
        neighborGroup
            .on("mouseover", function(event, d) {
                tooltip.transition().duration(200).style("opacity", .9);
                let tooltipHtml = `<strong>${d.remote_hostname}</strong><br>`;
                tooltipHtml += `NGFW: ${ngfwName}<br><br>`;
                tooltipHtml += `Connections:<br>`;
                d.connections.forEach(conn => {
                    const bullet = '&#x25CF; ';

                    tooltipHtml += `${bullet} `;

                    const connectedDeviceName = (conn.remote_hostname === ngfwName) ? d.name : conn.remote_hostname;
                    const viaNgfwPart = (connectedDeviceName === ngfwName) ? "" : ` (via NGFW ${conn.ngfw_hostname})`;

                    tooltipHtml += `${connectedDeviceName}${viaNgfwPart}<br>`;
                    tooltipHtml += `&nbsp;&nbsp;NGFW Interface: ${conn.local_interface}<br>`;
                    tooltipHtml += `&nbsp;&nbsp;Interface: ${conn.remote_interface_id}<br>`;
                    if (conn.remote_interface_description) {
                        tooltipHtml += `&nbsp;&nbsp;Description: ${conn.remote_interface_description}<br>`;
                    }
                    tooltipHtml += `<br>`;
                });
                tooltip.html(tooltipHtml)
                    .style("left", (event.pageX + 10) + "px")
                    .style("top", (event.pageY - 28) + "px");
            })
            .on("mouseout", function(d) {
                tooltip.transition().duration(500).style("opacity", 0);
            })
            .on("click", function(event, d) { // Click to lock/unlock tooltip
                event.stopPropagation(); // Prevent global click from affecting this

                if (window.tooltipLocked && window.activeTooltipNode === d) {
                    // Clicking on the currently locked node -> unlock and hide
                    window.hideTooltip();
                } else {
                    // Click on a new node or an unlocked node -> lock this one
                    if (window.tooltipLocked) { // If another tooltip is locked, hide it first
                        window.hideTooltip();
                    }
                    tooltip.transition().duration(200).style("opacity", .9);
                    tooltip.classed("locked", true);
                    window.tooltipLocked = true;
                    window.activeTooltipNode = d;

                    let tooltipHtml = `<strong>${d.remote_hostname}</strong><br>`;
                    tooltipHtml += `NGFW: ${ngfwName}<br><br>`;
                    tooltipHtml += `Connections:<br>`;
                    d.connections.forEach(conn => {
                        const bullet = '&#x25CF; ';
                        tooltipHtml += `${bullet} `;
                        const connectedDeviceName = (conn.remote_hostname === ngfwName) ? d.name : conn.remote_hostname;
                        const viaNgfwPart = (connectedDeviceName === ngfwName) ? "" : ` (via NGFW ${conn.ngfw_hostname})`;
                        tooltipHtml += `${connectedDeviceName}${viaNgfwPart}<br>`;
                        tooltipHtml += `&nbsp;&nbsp;NGFW Interface: ${conn.local_interface}<br>`;
                        tooltipHtml += `&nbsp;&nbsp;Interface: ${conn.remote_interface_id}<br>`;
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
                }
            });
    });

    // Draw NGFW in the center - Make it a clickable node too
    console.log("Drawing NGFW in center:", ngfwName);
    const ngfwGroup = centerGroup.append("g")
        .attr("class", "ngfw-node-group") // NEW: Add a class for consistent selection
        .datum({ name: ngfwName, type: 'ngfw' }) // Attach data for tooltip
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

    // Add tooltip events to the NGFW group
    ngfwGroup
        .on("mouseover", function(event, d) {
            tooltip.transition().duration(200).style("opacity", .9);
            let tooltipHtml = `<strong>${ngfwName}</strong><br>Type: NGFW`;
            // You could potentially add more NGFW specific details here if available in ngfwName context
            tooltip.html(tooltipHtml)
                .style("left", (event.pageX + 10) + "px")
                .style("top", (event.pageY - 28) + "px");
        })
        .on("mouseout", function(d) {
            tooltip.transition().duration(500).style("opacity", 0);
        })
        .on("click", function(event, d) { // Click to lock/unlock tooltip for NGFW
            event.stopPropagation(); 

            // If clicking the currently active/locked node, hide it
            if (window.activeTooltipNode === d) {
                window.hideTooltip();
                return;
            }

            // Hide any currently locked tooltip (if it belongs to a different node)
            if (window.tooltipLocked && window.activeTooltipNode !== d) {
                window.hideTooltip();
            }

            // Show and lock the tooltip for this NGFW node
            tooltip.transition().duration(200).style("opacity", .9);
            tooltip.classed("locked", true);
            window.tooltipLocked = true;
            window.activeTooltipNode = d;

            let tooltipHtml = `<strong>${ngfwName}</strong><br>Type: NGFW<br><br>`;
            // Add NGFW-specific details, e.g., its serial, its managed devices, etc.
            // This would require fetching more data about the NGFW, or having it passed into drawSingleLldpMap
            // For now, it's basic, but expandable.
            tooltipHtml += `Serial: (Not available in this context)<br>`; // Placeholder
            tooltipHtml += `Managed Devices: (Not available in this context)<br>`; // Placeholder

            // Show its connections (LLDP neighbors it discovered)
            if (uniqueNeighborNodes.length > 0) {
                 tooltipHtml += "<br>Discovered Neighbors:<br>";
                 uniqueNeighborNodes.forEach(neighbor => {
                     tooltipHtml += `&#x25CF; ${neighbor.remote_hostname} (via ${neighbor.connections.map(c=>c.local_interface).join(', ')})<br>`;
                 });
            } else {
                 tooltipHtml += "<br>No LLDP neighbors discovered by this NGFW.";
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
        });

    console.log("drawSingleLldpMap: Completed.");
}