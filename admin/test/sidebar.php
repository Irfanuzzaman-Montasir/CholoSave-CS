<!-- admin_sidebar.php -->
<div id="sidebar" class="hidden md:flex flex-col w-64 bg-white shadow-lg dark:bg-gray-800 dark:text-white transition-all duration-300 ease-in-out">
    <!-- Brand Logo -->
    <div class="p-4 border-b border-gray-200 dark:border-gray-700">
        <div class="flex items-center space-x-2 transform hover:scale-105 transition-transform duration-200">
            <i class="fas fa-leaf text-green-500 text-xl transition-transform hover:rotate-12"></i>
            <span class="text-xl font-semibold">Admin Panel</span>
        </div>
    </div>

    <!-- Navigation Links -->
    <nav class="flex-1 p-4">
        <ul class="space-y-2">
            <!-- Dashboard -->
            <li class="group">
                <a href="/admin/dashboard.php" 
                   class="sidebar-item flex items-center p-3 rounded-lg text-gray-700 dark:text-gray-300 
                          hover:bg-gray-100 dark:hover:bg-gray-700 transition-all duration-200 
                          transform hover:translate-x-2 hover:shadow-md">
                    <i class="fas fa-chart-line w-6 transition-transform group-hover:rotate-12"></i>
                    <span class="transition-colors duration-200">Dashboard</span>
                </a>
            </li>

            <!-- Expert Team -->
            <li class="group">
                <a href="/admin/expert_team.php" 
                   class="sidebar-item flex items-center p-3 rounded-lg text-gray-700 dark:text-gray-300 
                          hover:bg-gray-100 dark:hover:bg-gray-700 transition-all duration-200 
                          transform hover:translate-x-2 hover:shadow-md">
                    <i class="fas fa-users w-6 transition-transform group-hover:rotate-12"></i>
                    <span class="transition-colors duration-200">Expert Team</span>
                </a>
            </li>

            <!-- Add Expert -->
            <li class="group">
                <a href="/admin/add_expert.php" 
                   class="sidebar-item flex items-center p-3 rounded-lg text-gray-700 dark:text-gray-300 
                          hover:bg-gray-100 dark:hover:bg-gray-700 transition-all duration-200 
                          transform hover:translate-x-2 hover:shadow-md">
                    <i class="fas fa-user-plus w-6 transition-transform group-hover:rotate-12"></i>
                    <span class="transition-colors duration-200">Add Expert</span>
                </a>
            </li>

            <!-- Edit Expert -->
            <li class="group">
                <a href="/admin/edit_expert.php" 
                   class="sidebar-item flex items-center p-3 rounded-lg text-gray-700 dark:text-gray-300 
                          hover:bg-gray-100 dark:hover:bg-gray-700 transition-all duration-200 
                          transform hover:translate-x-2 hover:shadow-md">
                    <i class="fas fa-user-edit w-6 transition-transform group-hover:rotate-12"></i>
                    <span class="transition-colors duration-200">Edit Expert</span>
                </a>
            </li>

            <!-- Contact Us -->
            <li class="group">
                <a href="/admin/contact_us.php" 
                   class="sidebar-item flex items-center p-3 rounded-lg text-gray-700 dark:text-gray-300 
                          hover:bg-gray-100 dark:hover:bg-gray-700 transition-all duration-200 
                          transform hover:translate-x-2 hover:shadow-md">
                    <i class="fas fa-envelope w-6 transition-transform group-hover:rotate-12"></i>
                    <span class="transition-colors duration-200">Contact Us</span>
                </a>
            </li>

            <!-- Logout -->
            <li class="group">
                <a href="/admin/logout.php" 
                   class="sidebar-item flex items-center p-3 rounded-lg text-gray-700 dark:text-gray-300 
                          hover:bg-gray-100 dark:hover:bg-gray-700 transition-all duration-200 
                          transform hover:translate-x-2 hover:shadow-md">
                    <i class="fas fa-sign-out-alt w-6 transition-transform group-hover:rotate-12"></i>
                    <span class="transition-colors duration-200">Log Out</span>
                </a>
            </li>
        </ul>
    </nav>

    <!-- Theme Toggle -->
    <div class="p-4 border-t border-gray-200 dark:border-gray-700">
        <button id="theme-toggle" 
                class="flex items-center justify-center w-full p-2 rounded-lg
                       hover:bg-gray-100 dark:hover:bg-gray-700 transition-all duration-200
                       hover:shadow-md group">
            <i class="fas fa-moon mr-2 transition-transform group-hover:rotate-45"></i>
            <span class="transition-colors duration-200">Dark Mode</span>
        </button>
    </div>
</div>

<script>
    // Theme Toggle Functionality with enhanced transitions
    const themeToggle = document.getElementById('theme-toggle');
    const icon = themeToggle.querySelector('i');
    const text = themeToggle.querySelector('span');

    themeToggle.addEventListener('click', () => {
        document.body.classList.toggle('dark');
        
        // Toggle icon and text
        if (document.body.classList.contains('dark')) {
            icon.classList.replace('fa-moon', 'fa-sun');
            text.textContent = 'Light Mode';
        } else {
            icon.classList.replace('fa-sun', 'fa-moon');
            text.textContent = 'Dark Mode';
        }
    });

    // Optional: Add active state to current page
    document.addEventListener('DOMContentLoaded', () => {
        const currentPath = window.location.pathname;
        const sidebarItems = document.querySelectorAll('.sidebar-item');
        
        sidebarItems.forEach(item => {
            if (item.getAttribute('href') === currentPath) {
                item.classList.add('bg-gray-100', 'dark:bg-gray-700');
            }
        });
    });
</script>