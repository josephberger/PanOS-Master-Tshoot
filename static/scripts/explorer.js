document.addEventListener('DOMContentLoaded', () => {
    // --- DOM Element References ---
    const explorerForm = document.getElementById('explorer-form');
    const fibLookupForm = document.getElementById('fib-lookup-form');
    const ngfwSelect = document.getElementById('ngfw-select');
    const vrSelect = document.getElementById('vr-select');
    const dataTypeSelect = document.getElementById('data-type-select');
    const resultsContainer = document.getElementById('results-container');
    const messageContainer = document.getElementById('message-container');
    const controls = document.querySelector('.controls');
    const controlsHeader = document.getElementById('controls-header');
    const contextualFiltersContainer = document.getElementById('contextual-filters-container');
    const resultsHeader = document.getElementById('results-header');
    const exportCsvBtn = document.getElementById('export-csv-btn');
    // NEW: References for filter controls
    const filterControls = document.getElementById('filter-controls');
    const filterInput = document.getElementById('filter-input');


    // --- Column Order Mapping ---
    const columnOrders = {
        'routes': ['ngfw', 'virtual_router', 'destination', 'nexthop', 'metric', 'flags', 'interface', 'route_table', 'age', 'zone'],
        'fibs': ['ngfw', 'virtual_router', 'destination', 'nexthop', 'nh_type', 'flags', 'interface', 'mtu', 'zone'],
        'fib-lookup': ['ngfw', 'virtual_router', 'nexthop', 'interface', 'zone'],
        'arps': ['ngfw', 'interface', 'ip', 'mac', 'port', 'status', 'ttl', 'zone'],
        'bgp-peers': ['ngfw', 'virtual_router', 'peer_name', 'peer_group', 'peer_router_id', 'remote_as', 'status', 'status_duration', 'peer_address', 'local_address'],
        'lldp-neighbors': ['ngfw', 'local_interface', 'remote_interface_id', 'remote_interface_description', 'remote_hostname'],
        'interfaces': ['ngfw', 'virtual_router', 'name', 'tag', 'ip', 'ipv6_present', 'zone'],
        'interfacesv6': ['ngfw', 'virtual_router', 'name', 'tag', 'ipv6_address_list', 'zone']
    };

    // --- Core Functions ---

    async function populateSelectors() {
        try {
            const response = await fetch('/api/devices');
            if (!response.ok) throw new Error('Failed to fetch devices for selectors');
            const devices = await response.json();

            (devices.ngfws || []).forEach(ngfw => {
                const option = document.createElement('option');
                option.value = ngfw.hostname;
                option.textContent = ngfw.hostname;
                ngfwSelect.appendChild(option);
            });

            const keysResponse = await fetch('/api/maps/keys');
            if (!keysResponse.ok) throw new Error('Failed to fetch VR keys');
            const keys = await keysResponse.json();
            const vrNames = new Set();
            keys.forEach(key => {
                const vrName = key.split(' - ')[1];
                if (vrName) vrNames.add(vrName);
            });
            
            Array.from(vrNames).sort().forEach(vr => {
                const option = document.createElement('option');
                option.value = vr;
                option.textContent = vr;
                vrSelect.appendChild(option);
            });

        } catch (error) {
            console.error("Error populating selectors:", error);
            messageContainer.textContent = `Error: Could not load filter options. ${error.message}`;
        }
    }

    function updateContextualFilters() {
        const selectedType = dataTypeSelect.value;
        contextualFiltersContainer.querySelectorAll('.context-filter').forEach(el => {
            el.style.display = 'none';
        });

        if (selectedType === 'routes' || selectedType === 'fibs') {
            document.getElementById('filter-for-dst').style.display = 'block';
            document.getElementById('filter-for-flag').style.display = 'block';
            document.getElementById('filter-for-afi').style.display = 'block';
        } else if (selectedType === 'arps') {
            document.getElementById('filter-for-int').style.display = 'block';
        }
    }

    async function handleDataFetch(event) {
        event.preventDefault();
        resultsContainer.innerHTML = '<p class="placeholder-text">Fetching data...</p>';
        messageContainer.innerHTML = '';
        resultsHeader.style.display = 'none';
        // NEW: Hide filter controls and clear input
        filterControls.style.display = 'none';
        filterInput.value = '';

        const formData = new FormData(explorerForm);
        const params = new URLSearchParams();

        for (const [key, value] of formData.entries()) {
            if (value) {
                if (key === 'on_demand' && value === 'on') {
                    params.append(key, 'true');
                } else {
                    params.append(key, value);
                }
            }
        }

        try {
            const response = await fetch(`/api/data/query?${params.toString()}`);
            const data = await response.json();
            if (!response.ok) throw new Error(data.error || 'An unknown error occurred.');
            
            renderResults(data.results, formData.get('type'));
            renderMessages(data.message);

        } catch (error) {
            console.error("Data fetch error:", error);
            resultsContainer.innerHTML = `<p class="error-text">Failed to fetch data: ${error.message}</p>`;
        }
    }

    function renderResults(results, dataType) {
        // Hide controls by default
        resultsHeader.style.display = 'none';
        filterControls.style.display = 'none';
        filterInput.value = '';

        if (!results || results.length === 0) {
            resultsContainer.innerHTML = '<p class="placeholder-text">No results found for the selected criteria.</p>';
            return;
        }

        const table = document.createElement('table');
        table.className = 'results-table';
        const headers = columnOrders[dataType] || Object.keys(results[0]);

        const thead = table.createTHead();
        const headerRow = thead.insertRow();
        headers.forEach(headerKey => {
            const th = document.createElement('th');
            th.textContent = headerKey.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
            headerRow.appendChild(th);
        });

        const tbody = table.createTBody();
        results.forEach(rowData => {
            const row = tbody.insertRow();
            headers.forEach(headerKey => {
                const cell = row.insertCell();
                let cellData = rowData[headerKey];
                if (Array.isArray(cellData)) {
                    cell.innerHTML = cellData.join('<br>');
                } else {
                    cell.textContent = cellData !== undefined ? cellData : 'N/A';
                }
            });
        });

        resultsContainer.innerHTML = '';
        resultsContainer.appendChild(table);
        
        // NEW: Make table sortable and show relevant controls
        makeTableSortable(table);
        resultsHeader.style.display = 'flex';
        filterControls.style.display = 'block';
    }
    
    function renderMessages(messages) {
        if (!messages || messages.length === 0) {
            messageContainer.innerHTML = '';
            return;
        }
        messageContainer.innerHTML = `<h5>Info:</h5><pre>${messages.join('\n')}</pre>`;
    }

    async function handleFibLookup(event) {
        event.preventDefault();
        resultsContainer.innerHTML = '<p class="placeholder-text">Performing FIB lookup...</p>';
        messageContainer.innerHTML = '';
        resultsHeader.style.display = 'none';
        // NEW: Hide filter controls and clear input
        filterControls.style.display = 'none';
        filterInput.value = '';

        const ip = document.getElementById('fib-ip-input').value;
        const ngfw = document.getElementById('ngfw-select').value;
        const vr = document.getElementById('vr-select').value;
        const onDemand = document.getElementById('on-demand-checkbox').checked;

        const params = new URLSearchParams({ ip });
        if (ngfw) params.append('ngfw', ngfw);
        if (vr) params.append('vr', vr);
        if (onDemand) params.append('on_demand', 'true');

        try {
            const response = await fetch(`/api/data/fib-lookup?${params.toString()}`);
            const data = await response.json();
            if (!response.ok) throw new Error(data.error || 'FIB lookup failed');
            
            renderResults(data.results, 'fib-lookup');
            renderMessages(data.message);

        } catch (error) {
            console.error("FIB lookup error:", error);
            resultsContainer.innerHTML = `<p class="error-text">Failed to perform lookup: ${error.message}</p>`;
        }
    }

    function exportTableToCSV(filename) {
        const table = resultsContainer.querySelector('.results-table');
        if (!table) return;

        const csv = [];
        const rows = table.querySelectorAll('tr');
        
        for (const row of rows) {
            const rowData = [];
            // Filter out rows that are currently hidden by the text filter
            if (row.style.display === 'none') continue;
            
            const cols = row.querySelectorAll('th, td');
            
            for (const col of cols) {
                let data = col.innerHTML.replace(/<br\s*\/?>/ig, '\n').trim();
                data = data.replace(/"/g, '""');
                rowData.push(`"${data}"`);
            }
            csv.push(rowData.join(','));
        }

        const csvFile = new Blob([csv.join('\n')], { type: 'text/csv' });
        const downloadLink = document.createElement('a');
        downloadLink.download = filename;
        downloadLink.href = window.URL.createObjectURL(csvFile);
        downloadLink.style.display = 'none';
        document.body.appendChild(downloadLink);
        downloadLink.click();
        document.body.removeChild(downloadLink);
    }

    // --- NEW: Table Sorting & Filtering Functions ---

    /**
     * Makes an HTML table sortable by clicking its headers.
     * @param {HTMLTableElement} table The table element to make sortable.
     */
    function makeTableSortable(table) {
        const headers = Array.from(table.querySelectorAll('thead th'));

        headers.forEach((header, colIndex) => {
            header.addEventListener('click', () => {
                const tbody = table.querySelector('tbody');
                const rows = Array.from(tbody.rows);
                const currentDirection = header.getAttribute('data-sort-direction');
                const newDirection = currentDirection === 'asc' ? 'desc' : 'asc';

                // Sort the rows
                rows.sort((a, b) => {
                    const aText = a.cells[colIndex].textContent.trim();
                    const bText = b.cells[colIndex].textContent.trim();
                    
                    // Check if data is numeric. Handles integers, floats, and IP addresses partially.
                    const aIsNumeric = !isNaN(parseFloat(aText)) && isFinite(aText);
                    const bIsNumeric = !isNaN(parseFloat(bText)) && isFinite(bText);

                    let comparison = 0;
                    if (aIsNumeric && bIsNumeric) {
                        comparison = parseFloat(aText) - parseFloat(bText);
                    } else {
                        comparison = aText.localeCompare(bText, undefined, { numeric: true });
                    }
                    
                    return newDirection === 'asc' ? comparison : -comparison;
                });

                // Clear and re-add sorted rows
                tbody.innerHTML = '';
                tbody.append(...rows);

                // Update header attributes and visual indicators
                headers.forEach(h => {
                    h.removeAttribute('data-sort-direction');
                    h.textContent = h.textContent.replace(/ (↑|↓)$/, '');
                });
                header.setAttribute('data-sort-direction', newDirection);
                header.textContent += newDirection === 'asc' ? ' ↑' : ' ↓';
            });
        });
    }

    // --- Attach Event Listeners ---
    explorerForm.addEventListener('submit', handleDataFetch);
    fibLookupForm.addEventListener('submit', handleFibLookup);
    dataTypeSelect.addEventListener('change', updateContextualFilters);
    
    controlsHeader.addEventListener('click', () => {
        controls.classList.toggle('collapsed');
        const headerStrong = controlsHeader.querySelector('strong');
        headerStrong.innerHTML = controls.classList.contains('collapsed') ? `<span id="menu-toggle-icon">«</span>` : `<span id="menu-toggle-icon">«</span> Menu`;
    });

    exportCsvBtn.addEventListener('click', () => {
        const dataType = dataTypeSelect.value || 'data';
        const date = new Date().toISOString().slice(0, 10);
        const filename = `${dataType}_export_${date}.csv`;
        exportTableToCSV(filename);
    });

    // NEW: Real-time filtering listener
    filterInput.addEventListener('input', () => {
        const searchTerm = filterInput.value.toLowerCase();
        const table = resultsContainer.querySelector('.results-table');
        if (!table) return;

        const rows = table.querySelectorAll('tbody tr');
        rows.forEach(row => {
            const rowText = row.textContent.toLowerCase();
            row.style.display = rowText.includes(searchTerm) ? '' : 'none';
        });
    });

    // --- Initial Load ---
    populateSelectors();
    updateContextualFilters();
});