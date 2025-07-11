document.addEventListener('DOMContentLoaded', () => {
    const themeToggleCheckbox = document.getElementById('theme-checkbox');

    if (themeToggleCheckbox) {
        // On page load, set the toggle's position to match the current theme
        themeToggleCheckbox.checked = document.documentElement.classList.contains('dark-mode');

        // Add an event listener for when the switch is clicked
        themeToggleCheckbox.addEventListener('change', () => {
            if (themeToggleCheckbox.checked) {
                // If checked, add dark mode class and save preference
                document.documentElement.classList.add('dark-mode');
                localStorage.setItem('theme', 'dark');
            } else {
                // If unchecked, remove dark mode class and save preference
                document.documentElement.classList.remove('dark-mode');
                localStorage.setItem('theme', 'light');
            }
        });
    }
});