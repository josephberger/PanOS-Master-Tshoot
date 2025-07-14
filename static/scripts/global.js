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

// NEW: Global SVG Export Function
window.exportSvg = async function(svgElement, mapGroupElement, filenamePrefix = 'map') {
    if (!mapGroupElement || !mapGroupElement.node() || !mapGroupElement.node().hasChildNodes()) {
        alert("The map is empty. There is nothing to export.");
        return;
    }
    const svgClone = svgElement.node().cloneNode(true);
    // You might need to dynamically determine which CSS file is relevant for the *current* page's styles
    // For now, let's assume a common set or pass an array of CSS paths.
    // For the original mapper, it uses mapper-styles.css. For LLDP, it uses lldp-styles.css.
    // This function can take a parameter for relevant CSS files, or try to infer.
    // For simplicity, let's try to include both and let the browser handle duplicates.
    // A more robust solution might pass active CSS paths from the calling page.

    // A better way might be to pass an array of relevant CSS files from the calling script
    let cssPathsToInclude = [];
    if (filenamePrefix.includes('lldp-map')) { // Heuristic: if filename suggests LLDP map
        cssPathsToInclude = ['/static/styles/main-styles.css', '/static/styles/lldp-styles.css'];
    } else { // Assume default mapper styles
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