// static/scripts/device-manager.js

document.addEventListener('DOMContentLoaded', () => {
    // --- DOM Element References ---
    const deviceInventoryList = document.getElementById('device-inventory-list');
    const addPanForm = document.getElementById('add-pan-form');
    const addNgfwForm = document.getElementById('add-ngfw-form');
    // Removed controls and controlsHeader as they are handled by global.js
    // const controls = document.querySelector('.controls');
    // const controlsHeader = document.getElementById('controls-header');
    
    // Global Action Buttons
    const importBtn = document.getElementById('importBtn');
    const refreshBtn = document.getElementById('refreshBtn');
    const updateHaBtn = document.getElementById('updateHaBtn');
    const updateRoutesBtn = document.getElementById('updateRoutesBtn');
    const updateArpsBtn = document.getElementById('updateArpsBtn');
    const updateBgpBtn = document.getElementById('updateBgpBtn');
    const updateLldpBtn = document.getElementById('updateLldpBtn');

    // Modal Elements (these are specific to this page's task log modal)
    const logModal = document.getElementById('task-log-modal');
    const logOutput = document.getElementById('log-output');
    const closeLogBtn = document.getElementById('close-log-btn');

    // --- Global Variables ---
    let eventSource = null;

    // --- Core Functions ---
    // showAppModal remains here as it's a specific type of modal for this page's interactions
    function showAppModal(message, isConfirm = false, onConfirm = null) {
        const existingModal = document.querySelector('.app-modal-backdrop');
        if (existingModal) existingModal.remove();

        const modalBackdrop = document.createElement('div');
        modalBackdrop.className = 'modal-backdrop app-modal-backdrop';

        const modalContent = document.createElement('div');
        modalContent.className = 'modal-content';
        modalContent.style.maxWidth = '450px';

        const modalBody = document.createElement('div');
        modalBody.className = 'modal-body';
        modalBody.style.padding = '25px';
        modalBody.style.fontSize = '16px';
        modalBody.style.textAlign = 'center';
        modalBody.textContent = message;

        const modalFooter = document.createElement('div');
        modalFooter.style.cssText = 'padding: 15px; display: flex; justify-content: flex-end; border-top: 1px solid #eee; gap: 10px;';

        modalContent.appendChild(modalBody);
        modalContent.appendChild(modalFooter);
        modalBackdrop.appendChild(modalContent);
        document.body.appendChild(modalBackdrop);

        const close = () => modalBackdrop.remove();

        if (isConfirm) {
            const confirmBtn = document.createElement('button');
            confirmBtn.textContent = 'Confirm';
            confirmBtn.className = 'button-primary';
            confirmBtn.onclick = () => {
                if (onConfirm) onConfirm();
                close();
            };
            modalFooter.appendChild(confirmBtn);

            const cancelBtn = document.createElement('button');
            cancelBtn.textContent = 'Cancel';
            cancelBtn.className = 'button-secondary';
            cancelBtn.onclick = close;
            modalFooter.appendChild(cancelBtn);
        } else {
            const okBtn = document.createElement('button');
            okBtn.textContent = 'OK';
            okBtn.className = 'button-primary';
            okBtn.onclick = close;
            modalFooter.appendChild(okBtn);
        }
    }

    async function fetchAndDisplayInventory() {
        console.log("Fetching device inventory...");
        if (!deviceInventoryList) return;

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
            if (platform === 'panorama') {
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
                return '/static/images/ngfw.svg';
            }
            return '/static/images/ngfw.svg';
        };

        try {
            const response = await fetch('/api/devices');
            if (!response.ok) throw new Error('Failed to fetch inventory');
            const devices = await response.json();
            deviceInventoryList.innerHTML = '';
            if (!devices || (!devices.panoramas?.length && !devices.ngfws?.length)) {
                deviceInventoryList.innerHTML = '<p>No devices found in database.</p>';
                return;
            }
            const trashIconSvg = `
                <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="trash-icon">
                    <polyline points="3 6 5 6 21 6"></polyline>
                    <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path>
                    <line x1="10" y1="11" x2="10" y2="17"></line>
                    <line x1="14" y1="11" x2="14" y2="17"></line>
                </svg>`;

            (devices.panoramas || []).forEach(pan => {
                const item = document.createElement('div');
                item.className = 'device-item';
                item.dataset.serial = pan.serial_number;
                item.dataset.platform = 'panorama';
                const iconPath = getIconPath('panorama', null);
                item.innerHTML = `
                    <div class="device-item-header">
                        <div class="device-identity">
                            <img src="${iconPath}" class="device-icon" alt="Panorama Icon">
                            <span>${pan.hostname} (Panorama)</span>
                        </div>
                        <button class="delete-btn" title="Delete ${pan.hostname}">${trashIconSvg}</button>
                    </div>
                    <div class="device-item-details">SN: ${pan.serial_number} | IP: ${pan.ip_address}</div>`;
                deviceInventoryList.appendChild(item);
            });

            // Process NGFWs
            (devices.ngfws || []).forEach(ngfw => {
                const item = document.createElement('div');
                item.className = 'device-item';
                item.dataset.serial = ngfw.serial_number;
                item.dataset.platform = 'ngfw';
                const iconPath = getIconPath('ngfw', ngfw.model);

                // --- START: NEW INDICATOR LOGIC ---
                let indicatorsHtml = '';
                // Check for HA status
                if (ngfw.alt_ip || ngfw.alt_serial) {
                    indicatorsHtml += `<span class="indicator-icon" title="HA Configured">🔗</span>`;
                }
                // Check for never refreshed status
                if (ngfw.last_update === 'Never') {
                    indicatorsHtml += `<span class="indicator-icon" title="Never Refreshed">❌</span>`;
                }
                // --- END: NEW INDICATOR LOGIC ---

                item.innerHTML = `
                    <div class="device-item-header">
                        <div class="device-identity">
                            <img src="${iconPath}" class="device-icon" alt="NGFW Icon">
                            <span>${ngfw.hostname}</span>
                            ${indicatorsHtml}
                        </div>
                        <button class="delete-btn" title="Delete ${ngfw.hostname}">${trashIconSvg}</button>
                    </div>
                    <div class="device-item-details">SN: ${ngfw.serial_number} | Model: ${ngfw.model}</div>`;
                deviceInventoryList.appendChild(item);
            });
        } catch (error) {
            console.error("Inventory fetch error:", error);
            deviceInventoryList.innerHTML = '<p class="error-text">Error loading inventory.</p>';
        }
    }

    async function handleAddDevice(event, platform) {
        event.preventDefault();
        const host = document.getElementById(`${platform}-host`).value;
        const user = document.getElementById(`${platform}-user`).value;
        const pass = document.getElementById(`${platform}-pass`).value;
        if (!host || !user || !pass) {
            showAppModal("Please fill out all fields to add a device.");
            return;
        }
        try {
            const response = await fetch('/api/devices/add', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ platform, host, username: user, password: pass })
            });
            const result = await response.json();
            if (!response.ok) throw new Error(result.error || 'Failed to add device');
            showAppModal(result.message);
            event.target.closest('form').reset();
            fetchAndDisplayInventory();
        } catch (error) {
            showAppModal(`Error: ${error.message}`);
        }
    }

    function handleDeleteDevice(button) {
        const item = button.closest('.device-item');
        const platform = item.dataset.platform;
        const serial = item.dataset.serial;
        const hostname = item.querySelector('.device-item-header span').textContent;
        const message = `Are you sure you want to delete ${platform.toUpperCase()} ${hostname} (${serial})?\nThis action cannot be undone.`;
        
        showAppModal(message, true, async () => {
            try {
                const response = await fetch('/api/devices/delete', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ platform, serial })
                });
                const result = await response.json();
                if (!response.ok) throw new Error(result.error || 'Failed to delete device');
                showAppModal(result.message);
                fetchAndDisplayInventory();
            } catch (error) {
                showAppModal(`Error: ${error.message}`);
            }
        });
    }

    async function showNgfwDetails(serial, targetElement) {
        const detailContainer = document.createElement('div');
        detailContainer.className = 'device-detail-container';
        detailContainer.innerHTML = '<p class="placeholder-text">Loading details...</p>';
        targetElement.after(detailContainer);

        const actionsHtml = `
            <div class="detail-actions">
                <button class="button-action" data-platform="ngfw" data-task-type="refresh" data-filter="${serial}">Refresh Device</button>
                <button class="button-action" data-platform="ngfw" data-task-type="update_ha" data-filter="${serial}">Update HA Status</button>
                <button class="button-action" data-platform="ngfw" data-task-type="update_routes" data-filter="${serial}">Update Routes</button>
                <button class="button-action" data-platform="ngfw" data-task-type="update_arps" data-filter="${serial}">Update ARPs</button>
                <button class="button-action" data-platform="ngfw" data-task-type="update_lldp" data-filter="${serial}">Update LLDP</button>
                <button class="button-action" data-platform="ngfw" data-task-type="update_bgp" data-filter="${serial}">Update BGP</button>
            </div>
        `;

        setTimeout(() => detailContainer.classList.add('expanded'), 10);
        try {
            const response = await fetch(`/api/devices/ngfw/${serial}`);
            if (!response.ok) {
                const err = await response.json();
                throw new Error(err.error || 'Failed to fetch device details');
            }
            const details = await response.json();
            const detailLabels = { hostname: 'Hostname', serial_number: 'Serial Number', ip_address: 'IP Address', ipv6_address: 'IPv6 Address', mac_address: 'MAC Address', model: 'Model', sw_version: 'Software Version', uptime: 'Uptime', panorama: 'Panorama', active: 'HA Active', alt_serial: 'HA Peer Serial', alt_ip: 'HA Peer IP', advanced_routing_enabled: 'Advanced Routing', app_version: 'App Version', threat_version: 'Threat Version', av_version: 'AV Version', wildfire_version: 'WildFire Version', url_filtering_version: 'URL Filtering', device_cert_present: 'Device Certificate', device_cert_expiry_date: 'Cert Expiry', last_update: 'Last Refresh' };
            const generalInfo = ['hostname', 'serial_number', 'ip_address', 'ipv6_address', 'mac_address', 'model', 'sw_version', 'uptime', 'panorama'];
            const haInfo = ['active', 'alt_serial', 'alt_ip'];
            const versionInfo = ['app_version', 'threat_version', 'av_version', 'wildfire_version', 'url_filtering_version'];
            const certInfo = ['device_cert_present', 'device_cert_expiry_date', 'last_update'];
            const renderSection = (title, keys) => {
                let sectionHtml = `<h3>${title}</h3>`;
                keys.forEach(key => {
                    if (details[key] !== null && details[key] !== undefined) {
                        sectionHtml += `<div class="detail-item"><span class="label">${detailLabels[key] || key}</span><span class="value">${details[key] || '-'}</span></div>`;
                    }
                });
                return sectionHtml;
            };

            detailContainer.innerHTML = actionsHtml + `
                <div class="detail-header"><h1>${details.hostname}</h1><div class="detail-sub-header">${details.model} | ${details.serial_number}</div></div>
                <div class="detail-grid">
                    <div class="detail-section">${renderSection('General Information', generalInfo)}</div>
                    <div class="detail-section">${renderSection('High Availability', haInfo)}</div>
                    <div class="detail-section">${renderSection('Content Versions', versionInfo)}</div>
                    <div class="detail-section">${renderSection('Certificates & Misc', certInfo)}</div>
                </div>`;
        } catch (error) {
            console.error("Error fetching details:", error);
            detailContainer.innerHTML = `<p class="error-text">Could not load details: ${error.message}</p>`;
        }
    }

    async function showPanoramaDetails(serial, targetElement) {
        const detailContainer = document.createElement('div');
        detailContainer.className = 'device-detail-container';
        detailContainer.innerHTML = '<p class="placeholder-text">Loading details...</p>';
        targetElement.after(detailContainer);
        
        setTimeout(() => detailContainer.classList.add('expanded'), 10);
        try {
            const response = await fetch(`/api/devices/panorama/${serial}`);
            if (!response.ok) {
                const err = await response.json();
                throw new Error(err.error || 'Failed to fetch Panorama details');
            }
            const details = await response.json();

            const actionsHtml = `
                <div class="detail-actions">
                    <button class="button-action" data-platform="panorama" data-task-type="import" data-filter="${details.hostname}">Import from Panorama</button>
                    <button class="button-action" data-platform="panorama" data-task-type="update_ha" data-filter="${details.hostname}">Update HA Status</button>
                </div>
            `;

            const detailLabels = { hostname: 'Hostname', serial_number: 'Serial Number', ip_address: 'IP Address', ipv6_address: 'IPv6 Address', mac_address: 'MAC Address', model: 'Model', sw_version: 'Software Version', uptime: 'Uptime', active: 'HA Active', alt_ip: 'HA Peer IP', ngfws: 'Managed NGFWs', licensed_device_capacity: 'Device Capacity', system_mode: 'System Mode', device_certificate_status: 'Device Certificate', last_system_info_refresh: 'Last Refresh', app_version: 'App Version', av_version: 'AV Version', wildfire_version: 'WildFire Version', logdb_version: 'Log DB Version'};
            const generalInfo = ['hostname', 'serial_number', 'ip_address', 'ipv6_address', 'mac_address', 'model', 'sw_version', 'uptime'];
            const haInfo = ['active', 'alt_ip'];
            const capacityInfo = ['system_mode', 'ngfws', 'licensed_device_capacity'];
            const versionInfo = ['app_version', 'av_version', 'wildfire_version', 'logdb_version'];
            const miscInfo = ['device_certificate_status', 'last_system_info_refresh'];

            const renderSection = (title, keys) => {
                let sectionHtml = `<h3>${title}</h3>`;
                keys.forEach(key => {
                    if (details[key] !== null && details[key] !== undefined) {
                        sectionHtml += `<div class="detail-item"><span class="label">${detailLabels[key] || key}</span><span class="value">${details[key] || '-'}</span></div>`;
                    }
                });
                return sectionHtml;
            };

            detailContainer.innerHTML = actionsHtml + `
                <div class="detail-header"><h1>${details.hostname}</h1><div class="detail-sub-header">${details.model || 'Panorama'} | ${details.serial_number}</div></div>
                <div class="detail-grid">
                    <div class="detail-section">${renderSection('General Information', generalInfo)}</div>
                    <div class="detail-section">${renderSection('Capacity & Management', capacityInfo)}</div>
                    <div class="detail-section">${renderSection('High Availability', haInfo)}</div>
                    <div class="detail-section">${renderSection('Content Versions', versionInfo)}</div>
                    <div class="detail-section">${renderSection('Misc', miscInfo)}</div>
                </div>`;
        } catch (error) {
            console.error("Error fetching Panorama details:", error);
            detailContainer.innerHTML = `<p class="error-text">Could not load details: ${error.message}</p>`;
        }
    }

    function showLogModal() {
        if (logModal) {
            logOutput.textContent = 'Initializing task...';
            logModal.style.display = 'flex';
        }
    }

    function closeLogModal() {
        if (logModal) logModal.style.display = 'none';
        if (eventSource) {
            eventSource.close();
            eventSource = null;
        }
    }
    
    async function startTask(startUrl) {
        showLogModal();
        try {
            const startResponse = await fetch(startUrl, { method: 'POST' });
            if (!startResponse.ok) {
                const err = await startResponse.json();
                throw new Error(err.error || `Failed to start task: ${startResponse.statusText}`);
            }
            const data = await startResponse.json();
            logOutput.textContent = `Task started with ID: ${data.task_id}\nConnecting to log stream...\n\n`;
            connectToStream(data.task_id);
        } catch (error) {
            logOutput.textContent += `\n\nERROR: Could not start task.\n${error.message}`;
        }
    }

    async function startDeviceActionTask(platform, taskType, filterValue) {
        showLogModal();
        try {
            const startResponse = await fetch('/api/tasks/device-action/start', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    platform: platform,
                    task_type: taskType,
                    filter_value: filterValue
                })
            });
            if (!startResponse.ok) {
                const err = await startResponse.json();
                throw new Error(err.error || `Failed to start task: ${startResponse.statusText}`);
            }
            const data = await startResponse.json();
            logOutput.textContent = `Task '${taskType}' started for ${platform} ${filterValue}\n(ID: ${data.task_id})\nConnecting to log stream...\n\n`;
            connectToStream(data.task_id);
        } catch (error) {
            logOutput.textContent += `\n\nERROR: Could not start task.\n${error.message}`;
        }
    }

    async function handleGlobalUpdate(taskName, taskStartUrl) {
        try {
            const countResponse = await fetch('/api/inventory/count');
            if (!countResponse.ok) throw new Error('Could not get device count.');
            const data = await countResponse.json();
            const ngfwCount = data.ngfw_count;

            if (ngfwCount === 0) {
                showAppModal('There are no NGFWs to update.');
                return;
            }

            const message = `This will start a task to ${taskName} for all ${ngfwCount} NGFW(s). Are you sure?`;
            showAppModal(message, true, () => {
                startTask(taskStartUrl);
            });

        } catch (error) {
            showAppModal(`Error: ${error.message}`);
        }
    }

    function connectToStream(taskId) {
        if (eventSource) eventSource.close();
        eventSource = new EventSource(`/api/tasks/stream/${taskId}`);
        eventSource.onopen = () => { logOutput.textContent += 'Connection to log stream established.\n----------------------------------------\n'; };
        eventSource.onmessage = (event) => {
            logOutput.textContent += event.data + '\n';
            if (logOutput.parentElement) logOutput.parentElement.scrollTop = logOutput.parentElement.scrollHeight;
            if (event.data.includes('--- TASK')) {
                eventSource.close();
                eventSource = null;
                fetchAndDisplayInventory();
            }
        };
        eventSource.onerror = () => {
            logOutput.textContent += '\n----------------------------------------\nConnection to log stream lost.';
            if (eventSource) eventSource.close();
            eventSource = null;
        };
    }

    // --- Attach Event Listeners ---
    if (addPanForm) addPanForm.addEventListener('submit', (e) => handleAddDevice(e, 'panorama'));
    if (addNgfwForm) addNgfwForm.addEventListener('submit', (e) => handleAddDevice(e, 'ngfw'));
    if (importBtn) importBtn.addEventListener('click', () => startTask('/api/tasks/import/start'));
    if (refreshBtn) refreshBtn.addEventListener('click', () => startTask('/api/tasks/refresh/start'));
    if (updateHaBtn) updateHaBtn.addEventListener('click', () => startTask('/api/tasks/update-ha/start'));
    if (updateRoutesBtn) updateRoutesBtn.addEventListener('click', () => handleGlobalUpdate('update all routes', '/api/tasks/update-routes/start'));
    if (updateArpsBtn) updateArpsBtn.addEventListener('click', () => handleGlobalUpdate('update all ARPs', '/api/tasks/update-arps/start'));
    if (updateBgpBtn) updateBgpBtn.addEventListener('click', () => handleGlobalUpdate('update all BGP peers', '/api/tasks/update-bgp/start'));
    if (updateLldpBtn) updateLldpBtn.addEventListener('click', () => handleGlobalUpdate('update all LLDP neighbors', '/api/tasks/update-lldp/start'));

    if (deviceInventoryList) {
        deviceInventoryList.addEventListener('click', (event) => {
            if (event.target.matches('.button-action')) {
                const platform = event.target.dataset.platform;
                const taskType = event.target.dataset.taskType; 
                const filterValue = event.target.dataset.filter;
                startDeviceActionTask(platform, taskType, filterValue);
                return;
            }

            const item = event.target.closest('.device-item');
            if (!item) return;

            if (event.target.closest('.delete-btn')) { 
                handleDeleteDevice(event.target.closest('.delete-btn'));
                return;
            }

            const platform = item.dataset.platform;
            const serial = item.dataset.serial;
            const isAlreadyActive = item.classList.contains('active');
            
            const existingDetailView = deviceInventoryList.querySelector('.device-detail-container');
            if (existingDetailView) {
                existingDetailView.classList.remove('expanded');
                setTimeout(() => existingDetailView.remove(), 500);
            }
            const activeItem = deviceInventoryList.querySelector('.device-item.active');
            if (activeItem) activeItem.classList.remove('active');
            
            if (!isAlreadyActive) {
                item.classList.add('active');
                if (platform === 'ngfw') {
                    showNgfwDetails(serial, item);
                } else if (platform === 'panorama') {
                    showPanoramaDetails(serial, item);
                }
            }
        });
    }
    // Removed controlsHeader event listener - now handled by global.js
    // if (controlsHeader) { ... }

    // --- Initial Load ---
    fetchAndDisplayInventory();
});