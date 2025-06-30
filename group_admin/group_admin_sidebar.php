<?php
// session_start();

if (!isset($_SESSION['group_id'])) {
    header('Location: login.php');
    exit();
}

include 'db.php'; // Your database connection file

$group_id = $_SESSION['group_id'];
$query = "SELECT group_name FROM my_group WHERE group_id = ?";
$stmt = $conn->prepare($query);
$stmt->bind_param("i", $group_id);
$stmt->execute();
$result = $stmt->get_result();

$group_name = ($row = $result->fetch_assoc()) ? $row['group_name'] : 'My Group';
$stmt->close();

// echo'groupname is '.$group_name;
?>




<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;600&display=swap" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>
</head>

<body>
    <!-- Enhanced Sidebar -->
    <div id="sidebar" class="hidden md:flex flex-col w-64 bg-white shadow-lg transition-all duration-300 ease-in-out">
        <!-- Logo Section -->
        <!-- <div class="p-4 border-b border-gray-200 hover:bg-gray-50 transition-colors">
            <div class="flex items-center space-x-2 cursor-pointer">
                <i class="fas fa-leaf text-green-500 transform hover:scale-110 transition-transform"></i>
                <span
                    class="text-xl font-semibold bg-gradient-to-r from-green-500 to-blue-700 bg-clip-text text-transparent">CholoSave</span>
            </div>
        </div> -->

        <!-- Profile Section -->
        <div class="p-4 border-b border-gray-200 flex items-center space-x-4">
            <div
                class="w-12 h-12 bg-gradient-to-r from-green-400 to-blue-500 rounded-full flex items-center justify-center">
                <i class="fas fa-user text-white text-2xl"></i>
            </div>
            <div>
                <span class="font-semibold text-black-800"><?php echo htmlspecialchars($group_name); ?></span>
                <p class="text-xs text-gray-500">Group Admin</p>
            </div>
        </div>

        <!-- Navigation -->
        <nav class="flex-1 p-4 overflow-y-auto">
            <div class="space-y-1">
                <!-- Dashboard -->
                <a href="/CholoSave-CS/group_admin/group_admin_dashboard.php"
                    class="sidebar-item group flex items-center p-3 text-gray-700 rounded-lg hover:bg-white-50 transition-all duration-200">
                    <i class="fas fa-chart-line w-6 text-gray-600 group-hover:scale-110 transition-transform"></i>
                    <span class="ml-2 group-hover:translate-x-1 transition-transform">Dashboard</span>
                </a>


                <!-- Notifications -->
                <div class="relative">
                    <a href="/CholoSave-CS/group_admin/group_notifications.php"
                        class="sidebar-item group flex items-center p-3 text-gray-600 rounded-lg hover:bg-gray-50 transition-all duration-200">
                        <div class="relative">
                            <i class="fas fa-bell w-6 text-gray-600 group-hover:scale-110 transition-transform"></i>
                            <span id="notification-badge" class="absolute -top-2 -right-2 inline-flex items-center justify-center w-5 h-5 
                                       text-xs font-bold text-white bg-blue-500 rounded-full border-2 border-white
                                       opacity-0 transition-all duration-300 ease-in-out">
                                0
                            </span>
                        </div>
                        <span class="ml-3 group-hover:translate-x-1 transition-transform">Activity alert</span>
                    </a>
                </div>

                <!-- Financial Management Section -->
                <div class="pt-4">
                    <div class="px-3 text-xs font-semibold text-gray-500 uppercase tracking-wider">
                        Financial Management
                    </div>

                    <!-- Loans -->
                    <div class="mt-2">
                        <button
                            class="sidebar-item group flex items-center w-full p-3 text-gray-600 rounded-lg hover:bg-white-50 transition-all duration-200"
                            onclick="toggleSubMenu('loan-menu')">
                            <i
                                class="fas fa-hand-holding-dollar w-6 text-gray-600 group-hover:scale-110 transition-transform"></i>
                            <span class="ml-2 group-hover:translate-x-1 transition-transform">Loans</span>
                            <i class="fas fa-chevron-down ml-auto transition-transform"></i>
                        </button>
                        <div id="loan-menu" class="hidden pl-8 space-y-1">
                            <a href="/CholoSave-CS/group_admin/group_admin_loan_request.php"
                                class="flex items-center p-2 text-gray-600 rounded-lg hover:bg-white-50 transition-all duration-200">
                                <span class="text-sm">Request Loan</span>
                            </a>
                            <a href="/CholoSave-CS/group_admin/group_admin_loan_history.php"
                                class="flex items-center p-2 text-gray-600 rounded-lg hover:bg-white-50 transition-all duration-200">
                                <span class="text-sm">My Loans</span>
                            </a>
                            <a href="/CholoSave-CS/group_admin/group_members_loan_history.php"
                                class="flex items-center p-2 text-gray-600 rounded-lg hover:bg-white-50 transition-all duration-200">
                                <span class="text-sm">Member Loans</span>
                            </a>
                        </div>
                    </div>

                    <!-- Payments -->
                    <div class="mt-2">
                        <button
                            class="sidebar-item group flex items-center w-full p-3 text-gray-600 rounded-lg hover:bg-white-50 transition-all duration-200"
                            onclick="toggleSubMenu('payment-menu')">
                            <i
                                class="fas fa-credit-card w-6 text-gray-600 group-hover:scale-110 transition-transform"></i>
                            <span class="ml-2 group-hover:translate-x-1 transition-transform">Payments</span>
                            <i class="fas fa-chevron-down ml-auto transition-transform"></i>
                        </button>
                        <div id="payment-menu" class="hidden pl-8 space-y-1">
                            <a href="/CholoSave-CS/group_admin/payment-page.php"
                                class="flex items-center p-2 text-gray-600 rounded-lg hover:bg-white-50 transition-all duration-200">
                                <span class="text-sm">Make Payment</span>
                            </a>
                            <a href="/CholoSave-CS/group_admin/group_admin_payment_history.php"
                                class="flex items-center p-2 text-gray-600 rounded-lg hover:bg-white-50 transition-all duration-200">
                                <span class="text-sm">My Payment History</span>
                            </a>
                            <a href="/CholoSave-CS/group_admin/group_members_payments.php"
                                class="flex items-center p-2 text-gray-600 rounded-lg hover:bg-white-50 transition-all duration-200">
                                <span class="text-sm">Member Payments</span>
                            </a>
                        </div>
                    </div>

                    <!-- Investments -->
                    <div class="mt-2">
                        <button
                            class="sidebar-item group flex items-center w-full p-3 text-gray-600 rounded-lg hover:bg-white-50 transition-all duration-200"
                            onclick="toggleSubMenu('investments-menu')">
                            <i
                                class="fas fa-piggy-bank w-6 text-gray-600 group-hover:scale-110 transition-transform"></i>
                            <span class="ml-2 group-hover:translate-x-1 transition-transform">Investments</span>
                            <i class="fas fa-chevron-down ml-auto transition-transform"></i>
                        </button>
                        <div id="investments-menu" class="hidden pl-8 space-y-1">
                            <a href="/CholoSave-CS/group_admin/group_admin_investment.php"
                                class="flex items-center p-2 text-gray-600 rounded-lg hover:bg-white-50 transition-all duration-200">
                                <span class="text-sm">New Investment</span>
                            </a>
                            <a href="/CholoSave-CS/group_admin/investment_returns.php"
                                class="flex items-center p-2 text-gray-600 rounded-lg hover:bg-white-50 transition-all duration-200">
                                <span class="text-sm">Record Returns</span>
                            </a>
                            <a href="/CholoSave-CS/group_admin/investment_history.php"
                                class="flex items-center p-2 text-gray-600 rounded-lg hover:bg-white-50 transition-all duration-200">
                                <span class="text-sm">Investment History</span>
                            </a>
                        </div>
                    </div>
                </div>

                <!-- Group Management Section -->
                <div class="pt-4">
                    <div class="px-3 text-xs font-semibold text-gray-500 uppercase tracking-wider">
                        Group Management
                    </div>

                    <a href="/CholoSave-CS/group_admin/group_members.php"
                        class="sidebar-item group flex items-center p-3 text-gray-600 rounded-lg hover:bg-white-50 transition-all duration-200">
                        <i class="fas fa-users w-6 text-gray-600 group-hover:scale-110 transition-transform"></i>
                        <span class="ml-2 group-hover:translate-x-1 transition-transform">Members</span>
                    </a>

                    <!-- Leave Requests -->
                    <div class="mt-2">
                        <button
                            class="sidebar-item group flex items-center w-full p-3 text-gray-600 rounded-lg hover:bg-white-50 transition-all duration-200"
                            onclick="toggleSubMenu('leave-menu')">
                            <i
                                class="fas fa-calendar-day w-6 text-gray-600 group-hover:scale-110 transition-transform"></i>
                            <span class="ml-2 group-hover:translate-x-1 transition-transform">Leave</span>
                            <i class="fas fa-chevron-down ml-auto transition-transform"></i>
                        </button>
                        <div id="leave-menu" class="hidden pl-8 space-y-1">
                            <a href="/CholoSave-CS/group_admin/request_for_me.php" id="leaveRequestBtn"
                                class="flex items-center p-2 text-gray-600 rounded-lg hover:bg-white-50 transition-all duration-200">
                                <span class="text-sm">Request For Me</span>
                            </a>
                            <a href="/CholoSave-CS/group_admin/member_leave_request.php"
                                class="flex items-center p-2 text-gray-600 rounded-lg hover:bg-white-50 transition-all duration-200">
                                <span class="text-sm">Member Requests</span>
                            </a>
                        </div>
                    </div>

                    <!-- Withdraw -->
                    <div class="mt-2">
                        <button
                            class="sidebar-item group flex items-center w-full p-3 text-gray-600 rounded-lg hover:bg-white-50 transition-all duration-200"
                            onclick="toggleSubMenu('withdraw-menu')">
                            <i class="fas fa-wallet w-6 text-gray-600 group-hover:scale-110 transition-transform"></i>
                            <span class="ml-2 group-hover:translate-x-1 transition-transform">Withdraw</span>
                            <i class="fas fa-chevron-down ml-auto transition-transform"></i>
                        </button>
                        <div id="withdraw-menu" class="hidden pl-8 space-y-1">
                            <a href="/CholoSave-CS/group_admin/group_admin_withdraw_request.php"
                                class="flex items-center p-2 text-gray-600 rounded-lg hover:bg-white-50 transition-all duration-200">
                                <span class="text-sm">Request For Me</span>
                            </a>
                            <a href="/CholoSave-CS/group_admin/member_withdraw_request.php"
                                class="flex items-center p-2 text-gray-600 rounded-lg hover:bg-white-50 transition-all duration-200">
                                <span class="text-sm">Member Requests</span>
                            </a>
                        </div>
                    </div>

                    <!-- Chats -->
                    <a href="/CholoSave-CS/group_chat.php"
                        class="sidebar-item group flex items-center p-3 text-gray-600 rounded-lg hover:bg-white-50 transition-all duration-200">
                        <i class="fas fa-comments w-6 text-gray-600 group-hover:scale-110 transition-transform"></i>
                        <span class="ml-2 group-hover:translate-x-1 transition-transform">Chats</span>
                    </a>

                    <!-- Polls -->
                    <div class="mt-2">
                        <button
                            class="sidebar-item group flex items-center w-full p-3 text-gray-600 rounded-lg hover:bg-white-50 transition-all duration-200"
                            onclick="toggleSubMenu('polls-menu')">
                            <i class="fas fa-poll w-6 text-gray-600 group-hover:scale-110 transition-transform"></i>
                            <span class="ml-2 group-hover:translate-x-1 transition-transform">Polls</span>
                            <i class="fas fa-chevron-down ml-auto transition-transform"></i>
                        </button>
                        <div id="polls-menu" class="hidden pl-8 space-y-1">
                            <a href="/CholoSave-CS/group_admin/admin_create_poll.php"
                                class="flex items-center p-2 text-gray-600 rounded-lg hover:bg-white-50 transition-all duration-200">
                                <span class="text-sm">Create Poll</span>
                            </a>
                            <a href="/CholoSave-CS/group_admin/admin_poll_history.php"
                                class="flex items-center p-2 text-gray-600 rounded-lg hover:bg-white-50 transition-all duration-200">
                                <span class="text-sm">View Polls</span>
                            </a>
                        </div>
                    </div>

                    <!-- Join Requests -->
                    <a href="/CholoSave-CS/group_admin/member_join_request.php"
                        class="sidebar-item group flex items-center p-3 text-gray-600 rounded-lg hover:bg-white-50 transition-all duration-200">
                        <i class="fas fa-user-plus w-6 text-gray-600 group-hover:scale-110 transition-transform"></i>
                        <span class="ml-2 group-hover:translate-x-1 transition-transform">Join Request</span>
                    </a>

                    <!-- Settings -->
                    <a href="/CholoSave-CS/group_admin/settings.php"
                        class="sidebar-item group flex items-center p-3 text-gray-600 rounded-lg hover:bg-white-50 transition-all duration-200">
                        <i class="fas fa-cogs w-6 text-gray-600 group-hover:scale-110 transition-transform"></i>
                        <span class="ml-2 group-hover:translate-x-1 transition-transform">Settings</span>
                    </a>

                    <a href="/CholoSave-CS/group_admin/group_generate_report.php"
                        class="sidebar-item group flex items-center p-3 text-gray-600 rounded-lg hover:bg-white-50 transition-all duration-200">
                        <i
                            class="fa-solid fa-file-lines w-6 text-gray-600 group-hover:scale-110 transition-transform"></i>
                        <span class="ml-2 group-hover:translate-x-1 transition-transform">Generate Report</span>
                    </a>

                    <!-- Exit -->
                    <a href="/CholoSave-CS/group_exit.php"
                        class="sidebar-item group flex items-center p-3 text-gray-600 rounded-lg hover:bg-red-50 transition-all duration-200">
                        <i class="fas fa-sign-out-alt w-6 text-red-600 group-hover:scale-110 transition-transform"></i>
                        <span class="ml-2 group-hover:translate-x-1 transition-transform">Exit</span>
                    </a>
                </div>
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
        /* Custom scrollbar */
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

            // Submenu toggle functionality
            function toggleSubMenu(menuId) {
                const menu = document.getElementById(menuId);
                const chevron = menu.previousElementSibling.querySelector('.fa-chevron-down');
                menu.classList.toggle('hidden');
                if (!menu.classList.contains('hidden')) {
                    chevron.style.transform = 'rotate(180deg)';
                } else {
                    chevron.style.transform = 'rotate(0deg)';
                }
            }

            // Make toggleSubMenu available globally
            window.toggleSubMenu = toggleSubMenu;

            // Enhanced leave request functionality
            document.getElementById('leaveRequestBtn').addEventListener('click', function (e) {
                e.preventDefault();

                Swal.fire({
                    title: 'Leave Group',
                    text: 'Are you sure you want to leave this group?',
                    icon: 'warning',
                    showCancelButton: true,
                    confirmButtonColor: '#d33',
                    cancelButtonColor: '#3085d6',
                    confirmButtonText: 'Yes, leave group',
                    cancelButtonText: 'Cancel',
                    backdrop: `rgba(0,0,0,0.4)`,
                    showClass: {
                        popup: 'animate__animated animate__fadeInDown'
                    },
                    hideClass: {
                        popup: 'animate__animated animate__fadeOutUp'
                    }
                }).then((result) => {
                    if (result.isConfirmed) {
                        // Show loading state
                        Swal.fire({
                            title: 'Processing...',
                            html: 'Please wait while we process your request',
                            allowOutsideClick: false,
                            didOpen: () => {
                                Swal.showLoading();
                            }
                        });





                        // Send leave request to server
                        fetch('/CholoSave-CS/group_admin/process_admin_leave_request.php', {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/json'
                            }
                        })
                            .then(response => response.json())
                            .then(data => {
                                if (data.status === 'success') {
                                    Swal.fire({
                                        icon: 'success',
                                        title: 'Request Submitted',
                                        text: data.message,
                                        showConfirmButton: true,
                                        timer: 2000
                                    });
                                } else {
                                    throw new Error(data.message);
                                }
                            })
                            .catch(error => {
                                Swal.fire({
                                    icon: 'error',
                                    title: 'Error',
                                    text: error.message || 'There was an error processing your request. Please try again.',
                                    showConfirmButton: true
                                });
                            });
                    }
                });
            });
        });
    </script>
</body>

</html>