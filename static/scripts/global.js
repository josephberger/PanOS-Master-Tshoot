// static/scripts/global.js

// Theme toggle logic
(function() {
    const theme = localStorage.getItem('theme');
    if (theme === 'dark') {
        document.documentElement.classList.add('dark-mode');
    }

    document.addEventListener('DOMContentLoaded', () => {
        const themeCheckbox = document.getElementById('theme-checkbox');
        if (themeCheckbox) {
            if (localStorage.getItem('theme') === 'dark') {
                themeCheckbox.checked = true;
            }
            themeCheckbox.addEventListener('change', () => {
                if (themeCheckbox.checked) {
                    document.documentElement.classList.add('dark-mode');
                    localStorage.setItem('theme', 'dark');
                } else {
                    document.documentElement.classList.remove('dark-mode');
                    localStorage.setItem('theme', 'light');
                }
            });
        }
    });
})();

// Universal sidebar collapse/expand logic
document.addEventListener('DOMContentLoaded', () => {
    const controlsHeader = document.getElementById('controls-header');
    const controls = document.querySelector('.controls');

    if (controlsHeader && controls) {
        controlsHeader.addEventListener('click', () => {
            controls.classList.toggle('collapsed');
            const headerStrong = controlsHeader.querySelector('strong');
            const menuToggleIcon = headerStrong.querySelector('#menu-toggle-icon');
            if (menuToggleIcon) {
                if (controls.classList.contains('collapsed')) {
                    menuToggleIcon.style.transform = 'scaleX(-1)';
                } else {
                    menuToggleIcon.style.transform = 'scaleX(1)';
                }
            }
            headerStrong.innerHTML = controls.classList.contains('collapsed') 
                ? `<span id="menu-toggle-icon" style="transform: scaleX(-1);">«</span>` 
                : `<span id="menu-toggle-icon">«</span> Menu`;
        });
    }
});

// Global SVG Export Function
window.exportSvg = async function(svgElement, mapGroupElement, filenamePrefix = 'map') {
    if (!mapGroupElement || !mapGroupElement.node() || !mapGroupElement.node().hasChildNodes()) {
        alert("The map is empty. There is nothing to export.");
        return;
    }
    const svgClone = svgElement.node().cloneNode(true);

    let cssPathsToInclude = [];
    if (filenamePrefix.includes('lldp-map')) {
        cssPathsToInclude = ['/static/styles/main-styles.css', '/static/styles/lldp-styles.css'];
    } else {
        cssPathsToInclude = ['/static/styles/main-styles.css', '/static/styles/mapper-styles.css'];
    }

    let allCss = '';
    for (const path of cssPathsToInclude) {
        try {
            const response = await fetch(path);
            if (response.ok) {
                allCss += await response.text();
            }
        } catch (error) {
            console.error('Could not fetch stylesheet for export:', path, error);
        }
    }
    const styleElement = document.createElement('style');
    styleElement.innerHTML = allCss;
    const defsElement = document.createElement('defs');
    defsElement.appendChild(styleElement);
    svgClone.insertBefore(defsElement, svgClone.firstChild);
    if (document.documentElement.classList.contains('dark-mode')) {
        svgClone.classList.add('dark-mode');
    }
    const svgString = new XMLSerializer().serializeToString(svgClone);
    const blob = new Blob([svgString], { type: 'image/svg+xml;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `${filenamePrefix}.svg`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
};

// NEW: Global Task Log Modal Functions
let globalEventSource = null; // Use a distinct name to avoid conflicts if other scripts have 'eventSource'

window.showLogModal = function() {
    const logModal = document.getElementById('task-log-modal');
    const logOutput = document.getElementById('log-output');
    if (logModal && logOutput) {
        logOutput.textContent = 'Initializing task...';
        logModal.style.display = 'flex';
    } else {
        console.warn("Task log modal elements not found.");
    }
}

window.closeLogModal = function() {
    const logModal = document.getElementById('task-log-modal');
    if (logModal) logModal.style.display = 'none';
    if (globalEventSource) { // Use globalEventSource
        globalEventSource.close();
        globalEventSource = null;
    }
}

// Attach the close listener globally to the button that exists on all pages with the modal
document.addEventListener('DOMContentLoaded', () => {
    const closeLogBtn = document.getElementById('close-log-btn');
    if (closeLogBtn) {
        closeLogBtn.addEventListener('click', window.closeLogModal);
    }
});