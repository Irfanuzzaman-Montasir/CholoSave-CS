<?php
session_start();

if (!isset($_SESSION['group_id'])) {
    header("Location: error_page.php"); // Redirect if group_id is not set
    exit;
}

$group_id = $_SESSION['group_id'];
$user_id = $_SESSION['user_id'];

if (isset($_SESSION['group_id']) && isset($_SESSION['user_id'])) {
    $group_id = $_SESSION['group_id'];
    $user_id = $_SESSION['user_id'];
    echo 'This is group id: ' . htmlspecialchars($group_id, ENT_QUOTES, 'UTF-8');
    echo 'This is user id: ' . htmlspecialchars($user_id, ENT_QUOTES, 'UTF-8');
} else {
    echo 'Group ID is not set in the session.';
}
?>


<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Enhanced CholoSave Dashboard</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>

    <style>
        .sidebar-item {
            transition: all 0.3s ease;
        }

        .sidebar-item:hover {
            transform: translateX(10px);
        }

        .stats-card {
            transition: all 0.3s ease;
        }

        .stats-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.1);
        }

        .contribution-bar {
            transition: height 1s ease-out;
        }

        @keyframes slideIn {
            from {
                transform: translateX(-100%);
                opacity: 0;
            }

            to {
                transform: translateX(0);
                opacity: 1;
            }
        }

        .slide-in {
            animation: slideIn 0.5s ease-out;
        }

        /* Dark mode transitions */
        .dark-mode-transition {
            transition: background-color 0.3s ease, color 0.3s ease;
        }

        /* Custom scrollbar */
        ::-webkit-scrollbar {
            width: 8px;
        }

        ::-webkit-scrollbar-track {
            background: #f1f1f1;
        }

        ::-webkit-scrollbar-thumb {
            background: #888;
            border-radius: 4px;
        }

        ::-webkit-scrollbar-thumb:hover {
            background: #555;
        }

        body.dark-mode {
            background-color: #1a1a1a;
            color: #ffffff;
        }

        body.dark-mode #sidebar,
        body.dark-mode .stats-card,
        body.dark-mode header,
        body.dark-mode .bg-white {
            background-color: #2d2d2d;
            color: #ffffff;
        }

        body.dark-mode .text-gray-500,
        body.dark-mode .text-gray-600,
        body.dark-mode .text-gray-700 {
            color: #a0aec0;
        }

        body.dark-mode .hover\:bg-gray-100:hover {
            background-color: #3d3d3d;
        }

        body.dark-mode .bg-gray-200 {
            background-color: #4a4a4a;
        }

        body.dark-mode .shadow {
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.3);
        }

        body.dark-mode ::-webkit-scrollbar-track {
            background: #2d2d2d;
        }

        body.dark-mode ::-webkit-scrollbar-thumb {
            background: #666;
        }

        body.dark-mode ::-webkit-scrollbar-thumb:hover {
            background: #888;
        }

        #contributionChart {
            height: 300px !important;
        }
    </style>
    </style>
</head>

<body class="bg-gray-100 dark-mode-transition">
    <div class="flex h-screen">
        <!-- Sidebar -->
        <div id="sidebar" class="hidden md:flex flex-col w-64 bg-white shadow-lg dark-mode-transition">
            <div class="p-4 border-b">
                <div class="flex items-center space-x-2">
                    <i class="fas fa-leaf text-green-500"></i>
                    <span class="text-xl font-semibold">CholoSave</span>
                </div>
            </div>

            <nav class="flex-1 p-4">
                <div class="space-y-2">
                    <a href="#" class="sidebar-item flex items-center p-3 text-gray-700 bg-gray-100 rounded-lg">
                        <i class="fas fa-chart-line w-6"></i>
                        <span>Dashboard</span>
                    </a>
                    <a href="#" class="sidebar-item flex items-center p-3 text-gray-600 hover:bg-gray-100 rounded-lg">
                        <i class="fas fa-hand-holding-dollar w-6"></i>
                        <span>Emergency Loan Request</span>
                    </a>
                    <a href="#" class="sidebar-item flex items-center p-3 text-gray-600 hover:bg-gray-100 rounded-lg">
                        <i class="fas fa-comments w-6"></i>
                        <span>Chats</span>
                    </a>
                    <a href="#" class="sidebar-item flex items-center p-3 text-gray-600 hover:bg-gray-100 rounded-lg">
                        <i class="fas fa-users w-6"></i>
                        <span>Members</span>
                    </a>
                    <a href="#" class="sidebar-item flex items-center p-3 text-gray-600 hover:bg-gray-100 rounded-lg">
                        <i class="fas fa-credit-card w-6"></i>
                        <span>Payment</span>
                    </a>
                    <a href="#" class="sidebar-item flex items-center p-3 text-gray-600 hover:bg-gray-100 rounded-lg">
                        <i class="fas fa-calendar-day w-6"></i>
                        <span>Leave Request</span>
                    </a>
                    <a href="#" class="sidebar-item flex items-center p-3 text-gray-600 hover:bg-gray-100 rounded-lg">
                        <i class="fas fa-history w-6"></i>
                        <span>Loan History</span>
                    </a>
                    <a href="#" class="sidebar-item flex items-center p-3 text-gray-600 hover:bg-gray-100 rounded-lg">
                        <i class="fas fa-history w-6"></i>
                        <span>Payment History</span>
                    </a>
                    <a href="#" class="sidebar-item flex items-center p-3 text-gray-600 hover:bg-gray-100 rounded-lg">
                        <i class="fas fa-wallet w-6"></i>
                        <span>Withdraw Request</span>
                    </a>
                    <a href="#" class="sidebar-item flex items-center p-3 text-gray-600 hover:bg-gray-100 rounded-lg">
                        <i class="fas fa-sign-out-alt w-6"></i>
                        <span>Exit</span>
                    </a>
                </div>
            </nav>

            <!-- Theme Toggle -->
            <div class="p-4 border-t">
                <button id="theme-toggle"
                    class="flex items-center justify-center w-full p-2 rounded-lg hover:bg-gray-100">
                    <i class="fas fa-moon mr-2"></i>
                    <span>Dark Mode</span>
                </button>
            </div>
        </div>

        <!-- Main Content -->
        <div class="flex-1 flex flex-col overflow-hidden">
            <!-- Top Bar -->
            <header class="flex items-center justify-between p-4 bg-white shadow dark-mode-transition">
                <div class="flex items-center">
                    <button id="menu-button"
                        class="md:hidden p-2 hover:bg-gray-100 rounded-lg transition-colors duration-200">
                        <i class="fas fa-bars"></i>
                    </button>
                    
                    <div><h1 class="text-5xl font-semibold ml-96 ">Dashboard</h1></div>
                    
                </div>
                <div class="flex items-center space-x-4">
                    <button class="p-2 hover:bg-gray-100 rounded-full transition-colors duration-200">
                        <i class="fas fa-bell"></i>
                    </button>
                    <button class="p-2 hover:bg-gray-100 rounded-full transition-colors duration-200">
                        <i class="fas fa-user-circle"></i>
                    </button>
                </div>
            </header>

            <!-- Main Content Area -->
            <main class="flex-1 overflow-y-auto p-4">
                <!-- Stats Grid -->
                <div class="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
                    <div class="stats-card bg-white p-6 rounded-lg shadow cursor-pointer">
                        <div class="flex justify-between items-center">
                            <div>
                                <h3 class="text-gray-500">Total Savings</h3>
                                <p class="text-2xl font-bold" id="savings-counter">$0</p>
                                <p class="text-green-500 text-sm">+12.5% this month</p>
                            </div>
                            <div class="text-2xl text-gray-400">
                                <i class="fas fa-dollar-sign"></i>
                            </div>
                        </div>
                    </div>

                    <div class="stats-card bg-white p-6 rounded-lg shadow cursor-pointer">
                        <div class="flex justify-between items-center">
                            <div>
                                <h3 class="text-gray-500">Members</h3>
                                <p class="text-2xl font-bold" id="members-counter">0</p>
                                <p class="text-green-500 text-sm">+2 new this month</p>
                            </div>
                            <div class="text-2xl text-gray-400">
                                <i class="fas fa-users"></i>
                            </div>
                        </div>
                    </div>

                    <div class="stats-card bg-white p-6 rounded-lg shadow cursor-pointer">
                        <div class="flex justify-between items-center">
                            <div>
                                <h3 class="text-gray-500">Emergency Fund</h3>
                                <p class="text-2xl font-bold" id="fund-counter">$0</p>
                            </div>
                            <div class="text-2xl text-gray-400">
                                <i class="fas fa-piggy-bank"></i>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="h-96">

                </div>


                <!-- Contribution Section -->
                <!-- <div class="bg-white p-6 rounded-lg shadow mb-6">
                    <h2 class="text-xl font-semibold mb-4">Contribution</h2>
                    <canvas id="contributionChart"></canvas>
                </div> -->


                <!-- Polls Section -->
                <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div class="bg-white p-6 rounded-lg shadow">
                        <h3 class="font-semibold mb-4">New member 'Afnan' wants to join</h3>
                        <div class="space-y-4">
                            <div class="poll-option">
                                <div class="flex justify-between mb-1">
                                    <span>Yes</span>
                                    <span class="text-sm text-gray-500">75%</span>
                                </div>
                                <div class="w-full bg-gray-200 rounded-full h-2">
                                    <div class="bg-blue-500 h-2 rounded-full transition-all duration-500"
                                        style="width: 0%"></div>
                                </div>
                            </div>
                            <div class="poll-option">
                                <div class="flex justify-between mb-1">
                                    <span>No</span>
                                    <span class="text-sm text-gray-500">25%</span>
                                </div>
                                <div class="w-full bg-gray-200 rounded-full h-2">
                                    <div class="bg-blue-500 h-2 rounded-full transition-all duration-500"
                                        style="width: 0%"></div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <div class="bg-white p-6 rounded-lg shadow">
                        <h3 class="font-semibold mb-4">Member 1 wants to Take Loan of $3000</h3>
                        <div class="space-y-4">
                            <div class="poll-option">
                                <div class="flex justify-between mb-1">
                                    <span>Yes</span>
                                    <span class="text-sm text-gray-500">50%</span>
                                </div>
                                <div class="w-full bg-gray-200 rounded-full h-2">
                                    <div class="bg-blue-500 h-2 rounded-full transition-all duration-500"
                                        style="width: 0%"></div>
                                </div>
                            </div>
                            <div class="poll-option">
                                <div class="flex justify-between mb-1">
                                    <span>No</span>
                                    <span class="text-sm text-gray-500">50%</span>
                                </div>
                                <div class="w-full bg-gray-200 rounded-full h-2">
                                    <div class="bg-blue-500 h-2 rounded-full transition-all duration-500"
                                        style="width: 0%"></div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </main>
        </div>
    </div>



    <script>
        // Counter animation function
        function animateCounter(element, target, duration = 2000, prefix = '') {
            let start = 0;
            const increment = target / (duration / 16);
            const animate = () => {
                start += increment;
                if (start < target) {
                    element.textContent = prefix + Math.floor(start).toLocaleString();
                    requestAnimationFrame(animate);
                } else {
                    element.textContent = prefix + target.toLocaleString();
                }
            };
            animate();
        }

        // Initialize animations
        document.addEventListener('DOMContentLoaded', () => {
            // Animate counters
            animateCounter(document.getElementById('savings-counter'), 45850, 2000, '$');
            animateCounter(document.getElementById('members-counter'), 24);
            animateCounter(document.getElementById('fund-counter'), 10000, 2000, '$');

            // // Initialize contribution chart
            // const ctx = document.getElementById('contributionChart').getContext('2d');
            // new Chart(ctx, {
            //     type: 'bar',
            //     data: {
            //         labels: ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul'],
            //         datasets: [{
            //             label: 'Monthly Contribution',
            //             data: [1200, 1500, 1000, 1800, 1300, 2000, 1600],
            //             backgroundColor: '#EC4899',
            //             borderColor: '#EC4899',
            //             borderWidth: 1
            //         }]
            //     },
            //     options: {
            //         responsive: true,
            //         maintainAspectRatio: false,
            //         scales: {
            //             y: {
            //                 beginAtZero: true,
            //                 grid: {
            //                     color: '#f0f0f0'
            //                 }
            //             },
            //             x: {
            //                 grid: {
            //                     display: false
            //                 }
            //             }
            //         },
            //         plugins: {
            //             legend: {
            //                 display: true,
            //                 position: 'top'
            //             }
            //         }
            //     }
            // });

            // Animate poll bars
            document.querySelectorAll('.poll-option').forEach(option => {
                const bar = option.querySelector('.bg-blue-500');
                const percentage = option.querySelector('.text-gray-500').textContent;
                setTimeout(() => {
                    bar.style.width = percentage;
                }, 500);
            });
        });

        // // Mobile menu toggle with animation
        // document.getElementById('menu-button').addEventListener('click', () => {
        //     const sidebar = document.getElementById('sidebar');
        //     sidebar.classList.toggle('hidden');
        //     if (!sidebar.classList.contains('hidden')) {
        //         sidebar.classList.add('slide-in');
        //         sidebar.classList.add('absolute');
        //         sidebar.classList.add('z-50');
        //         sidebar.classList.add('h-screen');
        //         sidebar.classList.add('w-64');
        //         sidebar.classList.add('bg-white');
        //     } else {
        //         sidebar.classList.remove('slide-in');
        //         sidebar.classList.remove('absolute');
        //     }
        // });

        // Dark mode functionality
        let isDarkMode = localStorage.getItem('darkMode') === 'true';
        const body = document.body;
        const themeToggle = document.getElementById('theme-toggle');
        const themeIcon = themeToggle.querySelector('i');
        const themeText = themeToggle.querySelector('span');

        function updateTheme() {
            if (isDarkMode) {
                body.classList.add('dark-mode');
                themeIcon.classList.remove('fa-moon');
                themeIcon.classList.add('fa-sun');
                themeText.textContent = 'Light Mode';
            } else {
                body.classList.remove('dark-mode');
                themeIcon.classList.remove('fa-sun');
                themeIcon.classList.add('fa-moon');
                themeText.textContent = 'Dark Mode';
            }
        }

        // Initialize theme
        updateTheme();

        themeToggle.addEventListener('click', () => {
            isDarkMode = !isDarkMode;
            localStorage.setItem('darkMode', isDarkMode);
            updateTheme();
        });

        // // Enhanced mobile responsiveness
        // const handleResize = () => {
        //     const sidebar = document.getElementById('sidebar');
        //     if (window.innerWidth >= 768) {
        //         sidebar.classList.remove('hidden', 'absolute', 'z-50');
        //     } else {
        //         sidebar.classList.add('hidden');
        //         sidebar.classList.remove('absolute', 'z-50');
        //     }
        // };

        window.addEventListener('resize', handleResize);
        handleResize();

        // Add smooth scroll behavior
        document.querySelectorAll('a[href^="#"]').forEach(anchor => {
            anchor.addEventListener('click', function (e) {
                e.preventDefault();
                document.querySelector(this.getAttribute('href')).scrollIntoView({
                    behavior: 'smooth'
                });
            });
        });
    </script>
</body>

</html>