<?php
// filepath: /c:/xampp/htdocs/test_project/admin/sidebar.php
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="/test_project/assets/css/style.css">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap" rel="stylesheet">
    <title>CholoSave</title>
</head>
<div class="h-screen w-64 bg-gray-100 fixed shadow-md hidden md:block">
    <div class="p-6">
        <!-- Logo -->
        <img src="../assets/logo.png" alt="Logo" class="w-24 mx-auto">
    </div>
    <nav class="mt-10">
        <!-- Dashboard Link -->
        <a href="admin_dashboard.php" 
           class="block py-2 px-4 rounded-lg text-left bg-gray-200 font-medium text-gray-800 hover:bg-gray-300 <?= basename($_SERVER['PHP_SELF']) == 'admin_dashboard.php' ? 'bg-indigo-500 text-white' : ''; ?>">
            Dashboard
        </a>

        <!-- Expert Team Dropdown -->
        <div class="relative group">
            <a href="#" 
               class="block py-2 px-4 rounded-lg font-medium text-gray-800 hover:bg-gray-200 flex items-center">
                Expert Team
                <svg xmlns="http://www.w3.org/2000/svg" 
                     class="h-4 w-4 ml-auto group-hover:rotate-180 transform transition-transform" 
                     fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7" />
                </svg>
            </a>
            <div class="hidden group-hover:block pl-4">
                <a href="add_expert.php" 
                   class="block py-2 px-4 rounded-lg text-gray-700 hover:bg-gray-200">Add Expert</a>
                <a href="edit_expert.php" 
                   class="block py-2 px-4 rounded-lg text-gray-700 hover:bg-gray-200">Edit Expert</a>
            </div>
        </div>

        <!-- Contact Us Link -->
        <a href="contact_us.php" 
           class="block py-2 px-4 rounded-lg font-medium text-gray-800 hover:bg-gray-200 <?= basename($_SERVER['PHP_SELF']) == 'contact_us.php' ? 'bg-indigo-500 text-white' : ''; ?>">
            Contact Us
        </a>

        <!-- Logout Link -->
        <a href="../logout.php" 
           class="block py-2 px-4 rounded-lg font-medium text-gray-800 hover:bg-gray-200">
            Logout
        </a>
    </nav>
</div>

<!-- Mobile Sidebar (hidden by default) -->
<div class="md:hidden bg-gray-100 w-full shadow-md">
    <div class="p-4 flex justify-between items-center">
        <img src="../assets/logo.png" alt="Logo" class="w-24">
        <button id="mobile-menu-toggle" class="text-gray-600 focus:outline-none">
            <svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16m-7 6h7" />
            </svg>
        </button>
    </div>
    <div id="mobile-menu" class="hidden">
        <nav class="mt-4">
            <a href="admin_dashboard.php" class="block py-2 px-4 font-medium text-gray-800 hover:bg-gray-200">Dashboard</a>
            <a href="add_expert.php" class="block py-2 px-4 font-medium text-gray-800 hover:bg-gray-200">Add Expert</a>
            <a href="edit_expert.php" class="block py-2 px-4 font-medium text-gray-800 hover:bg-gray-200">Edit Expert</a>
            <a href="contact_us.php" class="block py-2 px-4 font-medium text-gray-800 hover:bg-gray-200">Contact Us</a>
            <a href="/test_project/logout.php" class="block py-2 px-4 font-medium text-gray-800 hover:bg-gray-200">Logout</a>
        </nav>
    </div>
</div>

<script>
    // Mobile menu toggle functionality
    document.getElementById('mobile-menu-toggle').addEventListener('click', function() {
        const mobileMenu = document.getElementById('mobile-menu');
        if (mobileMenu.classList.contains('hidden')) {
            mobileMenu.classList.remove('hidden');
        } else {
            mobileMenu.classList.add('hidden');
        }
    });
</script>