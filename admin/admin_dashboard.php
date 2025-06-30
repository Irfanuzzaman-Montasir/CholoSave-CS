<?php
include 'db.php';
session_start();

if (!isset($_SESSION['user_id']) || $_SESSION['role'] !== 'admin') {
    header("Location: /CholoSave-CS/admin/login.php");
    exit;
}

// Enhanced stats query
$query = "SELECT 
    (SELECT IFNULL(SUM(amount), 0) FROM savings) AS totalSavings,
    (SELECT IFNULL(SUM(amount), 0) FROM savings WHERE MONTH(created_at) = MONTH(CURRENT_DATE)) AS thisMonthSavings,
    (SELECT COUNT(*) FROM users) AS totalMembers,
    (SELECT COUNT(*) FROM users WHERE MONTH(created_at) = MONTH(CURRENT_DATE)) AS newMembers,
    (SELECT COUNT(*) FROM my_group) AS totalGroups,
    (SELECT COUNT(*) FROM contact_us) AS totalReports,
    (SELECT IFNULL(SUM(amount), 0) FROM investments) AS totalInvestments";
$result = mysqli_query($conn, $query);
$stats = mysqli_fetch_assoc($result);
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Dashboard - CholoSave</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;600&display=swap" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>
    <style>
        .custom-font {
            font-family: 'Poppins', sans-serif;
        }
        .stats-card {
            transition: transform 0.2s ease-in-out;
        }
        .stats-card:hover {
            transform: translateY(-5px);
        }
    </style>
</head>

<body class="bg-gray-100 custom-font">
    <div class="flex h-screen">
        <!-- Sidebar -->
        <?php include 'sidebar.php'; ?>

        <!-- Main Content -->
        <div class="flex-1 flex flex-col overflow-hidden">
            <!-- Top Bar -->
            <header class="flex items-center justify-between p-4 bg-white shadow">
                <div class="flex items-center justify-center w-full">
                    <button id="menu-button" class="md:hidden p-2 hover:bg-gray-100 rounded-lg transition-colors duration-200 absolute left-2">
                        <i class="fa-solid fa-bars text-xl"></i>
                    </button>
                    <h1 class="text-4xl font-semibold custom-font text-gray-800">
                        <i class="fa-solid fa-chart-line mr-3"></i>
                        Admin Dashboard
                    </h1>
                </div>

                <!-- Header Controls -->
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
            <main class="flex-1 overflow-y-auto p-6">
                <!-- Welcome Message -->
                <div class="mb-6">
                    <h2 class="text-2xl font-semibold text-gray-800">Welcome back, Admin!</h2>
                    <p class="text-sm text-gray-500">Here's what's happening with your platform today.</p>
                </div>

                <!-- Stats Grid -->
                <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
                    <!-- Total Savings Card -->
                    <div class="stats-card bg-white p-6 rounded-lg shadow-lg cursor-pointer">
                        <div class="flex justify-between items-center">
                            <div>
                                <h3 class="text-gray-500">Total Savings</h3>
                                <p class="text-2xl font-bold" id="savings-counter">
                                    $<?php echo number_format($stats['totalSavings'], 2); ?>
                                </p>
                                <p class="text-green-500 text-sm">
                                    +$<?php echo number_format($stats['thisMonthSavings'], 2); ?> this month
                                </p>
                            </div>
                            <div class="text-3xl text-green-500">
                                <i class="fas fa-wallet"></i>
                            </div>
                        </div>
                    </div>

                    <!-- Total Members Card -->
                    <div class="stats-card bg-white p-6 rounded-lg shadow-lg cursor-pointer">
                        <div class="flex justify-between items-center">
                            <div>
                                <h3 class="text-gray-500">Total Members</h3>
                                <p class="text-2xl font-bold" id="members-counter">
                                    <?php echo number_format($stats['totalMembers']); ?>
                                </p>
                                <p class="text-blue-500 text-sm">
                                    +<?php echo $stats['newMembers']; ?> new this month
                                </p>
                            </div>
                            <div class="text-3xl text-blue-500">
                                <i class="fas fa-users"></i>
                            </div>
                        </div>
                    </div>

                    <!-- Total Groups Card -->
                    <div class="stats-card bg-white p-6 rounded-lg shadow-lg cursor-pointer">
                        <div class="flex justify-between items-center">
                            <div>
                                <h3 class="text-gray-500">Total Groups</h3>
                                <p class="text-2xl font-bold" id="groups-counter">
                                    <?php echo number_format($stats['totalGroups']); ?>
                                </p>
                                <p class="text-purple-500 text-sm">Active Groups</p>
                            </div>
                            <div class="text-3xl text-purple-500">
                                <i class="fas fa-users-rectangle"></i>
                            </div>
                        </div>
                    </div>

                    <!-- Total Investments Card -->
                    <div class="stats-card bg-white p-6 rounded-lg shadow-lg cursor-pointer">
                        <div class="flex justify-between items-center">
                            <div>
                                <h3 class="text-gray-500">Total Investments</h3>
                                <p class="text-2xl font-bold" id="investments-counter">
                                    $<?php echo number_format($stats['totalInvestments'], 2); ?>
                                </p>
                                <p class="text-orange-500 text-sm">Current Period</p>
                            </div>
                            <div class="text-3xl text-orange-500">
                                <i class="fas fa-chart-line"></i>
                            </div>
                        </div>
                    </div>

                    <!-- Total Reports Card -->
                    <div class="stats-card bg-white p-6 rounded-lg shadow-lg cursor-pointer">
                        <div class="flex justify-between items-center">
                            <div>
                                <h3 class="text-gray-500">Total Reports</h3>
                                <p class="text-2xl font-bold" id="reports-counter">
                                    <?php echo number_format($stats['totalReports']); ?>
                                </p>
                                <p class="text-red-500 text-sm">User Reports</p>
                            </div>
                            <div class="text-3xl text-red-500">
                                <i class="fas fa-flag"></i>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Charts Section -->
                <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
                    <!-- Graph Section -->
                    <div class="bg-white shadow-lg rounded-lg p-6">
                        <h3 class="text-xl font-semibold mb-4">Savings Overview</h3>
                        <?php include 'dashboard_graph.php'; ?>
                    </div>
                </div>
            </main>
        </div>
    </div>

    <script>
        // Mobile menu toggle
        const menuButton = document.getElementById('menu-button');
        const sidebar = document.querySelector('#sidebar');
        
        menuButton.addEventListener('click', () => {
            sidebar.classList.toggle('hidden');
        });

        // Counter animation
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
            const stats = {
                savings: <?php echo $stats['totalSavings']; ?>,
                members: <?php echo $stats['totalMembers']; ?>,
                groups: <?php echo $stats['totalGroups']; ?>,
                investments: <?php echo $stats['totalInvestments']; ?>,
                reports: <?php echo $stats['totalReports']; ?>
            };

            animateCounter(document.getElementById('savings-counter'), stats.savings, 2000, '$');
            animateCounter(document.getElementById('members-counter'), stats.members);
            animateCounter(document.getElementById('groups-counter'), stats.groups);
            animateCounter(document.getElementById('investments-counter'), stats.investments, 2000, '$');
            animateCounter(document.getElementById('reports-counter'), stats.reports);
        });
    </script>
</body>
</html>