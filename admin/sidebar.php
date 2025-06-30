<!-- admin_sidebar.php -->
<div id="sidebar" class="hidden md:flex flex-col w-64 bg-white shadow-lg transition-all duration-300 ease-in-out">
    <!-- Logo Section -->
    <div class="p-4 border-b border-gray-200 hover:bg-gray-50 transition-colors">
        <div class="flex items-center space-x-2 cursor-pointer">
            <i class="fas fa-leaf text-white-500 transform hover:scale-110 transition-transform"></i>
            <span class="text-xl font-semibold bg-gradient-to-r from-green-500 to-blue-700 bg-clip-text text-transparent">Admin Panel</span>
        </div>
    </div>

    <!-- Navigation -->
    <nav class="flex-1 p-4 overflow-y-auto">
        <div class="space-y-1">
            <!-- Dashboard -->
            <a href="/CholoSave-CS/admin/admin_dashboard.php"
                class="sidebar-item group flex items-center p-3 text-gray-700 rounded-lg hover:bg-white-50 transition-all duration-200">
                <i class="fas fa-chart-line w-6 text-white-600 group-hover:scale-110 transition-transform"></i>
                <span class="ml-2 group-hover:translate-x-1 transition-transform">Dashboard</span>
            </a>

            <!-- Expert Team Dropdown -->
            <div class="space-y-1">
                <div class="sidebar-item group flex items-center p-3 text-gray-600 rounded-lg hover:bg-white-50 transition-all duration-200 cursor-pointer"
                    id="expertTeamToggle">
                    <i class="fas fa-users w-6 text-white-600 group-hover:scale-110 transition-transform"></i>
                    <span class="ml-2 group-hover:translate-x-1 transition-transform">Expert Team</span>
                    <i class="fas fa-chevron-down ml-auto transition-transform" id="expertTeamChevron"></i>
                </div>
                <div class="hidden pl-8 space-y-1" id="expertTeamSubmenu">
                    <a href="/CholoSave-CS/admin/add_expert.php"
                        class="flex items-center p-2 text-gray-600 rounded-lg hover:bg-white-50 transition-all duration-200">
                        <span class="text-sm">Add Expert</span>
                    </a>
                    <a href="/CholoSave-CS/admin/edit_expert.php"
                        class="flex items-center p-2 text-gray-600 rounded-lg hover:bg-white-50 transition-all duration-200">
                        <span class="text-sm">Edit Expert</span>
                    </a>
                </div>
            </div>

            <!-- Contact Us -->
            <a href="/CholoSave-CS/admin/contact_us.php"
                class="sidebar-item group flex items-center p-3 text-gray-600 rounded-lg hover:bg-white-50 transition-all duration-200">
                <i class="fas fa-envelope w-6 text-white-600 group-hover:scale-110 transition-transform"></i>
                <span class="ml-2 group-hover:translate-x-1 transition-transform">Contact Us</span>
            </a>

            <!-- Logout -->
            <a href="/CholoSave-CS/admin/logout.php"
                class="sidebar-item group flex items-center p-3 text-gray-600 rounded-lg hover:bg-red-50 transition-all duration-200">
                <i class="fas fa-sign-out-alt w-6 text-red-600 group-hover:scale-110 transition-transform"></i>
                <span class="ml-2 group-hover:translate-x-1 transition-transform">Log Out</span>
            </a>
        </div>
    </nav>

    <!-- Theme Toggle -->
    <div class="p-4 border-t border-gray-200">
        <button id="theme-toggle"
            class="flex items-center justify-center w-full p-2 rounded-lg hover:bg-gray-100 transition-all duration-200">
            <i class="fas fa-moon mr-2 text-gray-600"></i>
            <span class="text-gray-600">Dark Mode</span>
        </button>
    </div>
</div>

<style>
    /* Custom scrollbar for the navigation */
    nav::-webkit-scrollbar {
        width: 4px;
    }

    nav::-webkit-scrollbar-track {
        background: transparent;
    }

    nav::-webkit-scrollbar-thumb {
        background: #e2e8f0;
        border-radius: 2px;
    }

    nav::-webkit-scrollbar-thumb:hover {
        background: #cbd5e0;
    }

    /* Dark mode styles */
    .dark-mode {
        background-color: #1a1a1a;
        color: #ffffff;
    }

    .dark-mode .sidebar-item {
        color: #e2e8f0;
    }

    .dark-mode .sidebar-item:hover {
        background-color: #2d3748;
    }

    .dark-mode .border-t,
    .dark-mode .border-b {
        border-color: #2d3748;
    }

    /* Animation for menu item hover */
    @keyframes slideRight {
        0% {
            transform: translateX(0);
        }

        100% {
            transform: translateX(4px);
        }
    }

    .sidebar-item:hover i {
        color: #059669;
    }
</style>

<script>
    document.addEventListener('DOMContentLoaded', function () {
        // Theme toggle functionality
        const themeToggle = document.getElementById('theme-toggle');
        const sidebar = document.getElementById('sidebar');
        const themeIcon = themeToggle.querySelector('i');
        const themeText = themeToggle.querySelector('span');

        let isDarkMode = localStorage.getItem('darkMode') === 'true';
        updateTheme();

        themeToggle.addEventListener('click', () => {
            isDarkMode = !isDarkMode;
            localStorage.setItem('darkMode', isDarkMode);
            updateTheme();
        });

        function updateTheme() {
            if (isDarkMode) {
                sidebar.classList.add('dark-mode');
                themeIcon.classList.replace('fa-moon', 'fa-sun');
                themeText.textContent = 'Light Mode';
            } else {
                sidebar.classList.remove('dark-mode');
                themeIcon.classList.replace('fa-sun', 'fa-moon');
                themeText.textContent = 'Dark Mode';
            }
        }

        // Expert Team submenu toggle
        const expertTeamToggle = document.getElementById('expertTeamToggle');
        const expertTeamSubmenu = document.getElementById('expertTeamSubmenu');
        const expertTeamChevron = document.getElementById('expertTeamChevron');

        expertTeamToggle.addEventListener('click', () => {
            expertTeamSubmenu.classList.toggle('hidden');
            expertTeamChevron.style.transform = expertTeamSubmenu.classList.contains('hidden')
                ? 'rotate(0deg)'
                : 'rotate(180deg)';
        });
    });
</script>