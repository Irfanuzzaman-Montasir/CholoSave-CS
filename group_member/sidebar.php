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

<!-- Enhanced Sidebar -->
<div id="sidebar" class="hidden md:flex flex-col w-64 bg-white shadow-lg transition-all duration-300 ease-in-out">
 


    <!-- Profile Section -->
    <div class="p-4 border-b border-gray-200 flex items-center space-x-4">
        <div
            class="w-12 h-12 bg-gradient-to-r from-green-400 to-blue-500 rounded-full flex items-center justify-center">
            <i class="fas fa-user text-white text-2xl"></i>
        </div>
        <div>
            <span class="font-semibold text-black-800"><?php echo htmlspecialchars($group_name); ?></span>
            <p class="text-xs text-gray-500">Group Member</p>
        </div>
    </div>

    <!-- Navigation -->
    <nav class="flex-1 p-4 overflow-y-auto">
        <div class="space-y-1">
            <!-- Navigation Items -->
            <a href="/CholoSave-CS/group_member/group_member_dashboard.php"
                class="sidebar-item group flex items-center p-3 text-gray-700 rounded-lg hover:bg-white-50 transition-all duration-200">
                <i class="fas fa-chart-line w-6 text-white-600 group-hover:scale-110 transition-transform"></i>
                <span class="ml-2 group-hover:translate-x-1 transition-transform">Dashboard</span>
            </a>

            <a href="/CholoSave-CS/group_member/group_notifications.php"
                class="sidebar-item group flex items-center p-3 text-gray-600 rounded-lg hover:bg-white-50 transition-all duration-200">
                <i class="fas fa-bell w-6 text-white-600 group-hover:scale-110 transition-transform"></i>
                <span class="ml-2 group-hover:translate-x-1 transition-transform">Activity alert</span>
            </a>


            <a href="/CholoSave-CS/group_member/group_member_emergency_loan_req.php"
                class="sidebar-item group flex items-center p-3 text-gray-600 rounded-lg hover:bg-white-50 transition-all duration-200">
                <i class="fas fa-hand-holding-dollar w-6 text-white-600 group-hover:scale-110 transition-transform"></i>
                <span class="ml-2 group-hover:translate-x-1 transition-transform">Loan Request</span>
            </a>

            <a href="/CholoSave-CS/group_chat.php"
                class="sidebar-item group flex items-center p-3 text-gray-600 rounded-lg hover:bg-white-50 transition-all duration-200">
                <i class="fas fa-comments w-6 text-white-600 group-hover:scale-110 transition-transform"></i>
                <span class="ml-2 group-hover:translate-x-1 transition-transform">Chats</span>
                <span class="ml-auto bg-white-100 text-white-800 text-xs font-medium px-2 py-0.5 rounded-full hidden"
                    id="unreadCount">0</span>
            </a>


            <a href="/CholoSave-CS/group_member/group_member_list.php"
                class="sidebar-item group flex items-center p-3 text-gray-600 rounded-lg hover:bg-white-50 transition-all duration-200">
                <i class="fas fa-users w-6 text-white-600 group-hover:scale-110 transition-transform"></i>
                <span class="ml-2 group-hover:translate-x-1 transition-transform">Members</span>
            </a>

            <a href="/CholoSave-CS/group_member/payment-page.php"
                class="sidebar-item group flex items-center p-3 text-gray-600 rounded-lg hover:bg-white-50 transition-all duration-200">
                <i class="fas fa-credit-card w-6 text-white-600 group-hover:scale-110 transition-transform"></i>
                <span class="ml-2 group-hover:translate-x-1 transition-transform">Payment</span>
            </a>

            <a href="#" id="leaveRequestBtn"
                class="sidebar-item group flex items-center p-3 text-gray-600 rounded-lg hover:bg-white-50 transition-all duration-200">
                <i class="fas fa-calendar-day w-6 text-white-600 group-hover:scale-110 transition-transform"></i>
                <span class="ml-2 group-hover:translate-x-1 transition-transform">Leave Request</span>
            </a>

            <!-- History Section with Collapsible Submenu -->
            <div class="space-y-1">
                <div class="sidebar-item group flex items-center p-3 text-gray-600 rounded-lg hover:bg-white-50 transition-all duration-200 cursor-pointer"
                    id="historyToggle">
                    <i class="fas fa-history w-6 text-white-600"></i>
                    <span class="ml-2">History</span>
                    <i class="fas fa-chevron-down ml-auto transition-transform" id="historyChevron"></i>
                </div>
                <div class="hidden pl-8 space-y-1" id="historySubmenu">
                    <a href="/CholoSave-CS/group_member/group_member_loan_history.php"
                        class="flex items-center p-2 text-gray-600 rounded-lg hover:bg-white-50 transition-all duration-200">
                        <span class="text-sm">Loan History</span>
                    </a>
                    <a href="/CholoSave-CS/group_member/group_member_payment_history.php"
                        class="flex items-center p-2 text-gray-600 rounded-lg hover:bg-white-50 transition-all duration-200">
                        <span class="text-sm">Payment History</span>
                    </a>
                    <a href="/CholoSave-CS/group_member/group_members_withdraw_history.php"
                        class="flex items-center p-2 text-gray-600 rounded-lg hover:bg-white-50 transition-all duration-200">
                        <span class="text-sm">Withdraw History</span>
                    </a>
                </div>
            </div>

            <a href="/CholoSave-CS/group_member/group_member_withdraw_request.php"
                class="sidebar-item group flex items-center p-3 text-gray-600 rounded-lg hover:bg-white-50 transition-all duration-200">
                <i class="fas fa-wallet w-6 text-white-600 group-hover:scale-110 transition-transform"></i>
                <span class="ml-2 group-hover:translate-x-1 transition-transform">Withdraw Request</span>
            </a>

            <a href="/CholoSave-CS/group_member/group_investment_details.php"
                class="sidebar-item group flex items-center p-3 text-gray-600 rounded-lg hover:bg-white-50 transition-all duration-200">
                <i class="fas fa-piggy-bank w-6 text-white-600 group-hover:scale-110 transition-transform"></i>
                <span class="ml-2 group-hover:translate-x-1 transition-transform">Investment Details</span>
            </a>


            <a href="/CholoSave-CS/group_member/group_generate_report.php"
                class="sidebar-item group flex items-center p-3 text-gray-600 rounded-lg hover:bg-white-50 transition-all duration-200">
                <i class="fa-solid fa-file-lines w-6 text-white-600 group-hover:scale-110 transition-transform"></i>
                <span class="ml-2 group-hover:translate-x-1 transition-transform">Generate Report</span>
            </a>

            <a href="/CholoSave-CS/group_exit.php"
                class="sidebar-item group flex items-center p-3 text-gray-600 rounded-lg hover:bg-red-50 transition-all duration-200">
                <i class="fas fa-sign-out-alt w-6 text-red-600 group-hover:scale-110 transition-transform"></i>
                <span class="ml-2 group-hover:translate-x-1 transition-transform">Exit</span>
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

        // History submenu toggle
        const historyToggle = document.getElementById('historyToggle');
        const historySubmenu = document.getElementById('historySubmenu');
        const historyChevron = document.getElementById('historyChevron');

        historyToggle.addEventListener('click', () => {
            historySubmenu.classList.toggle('hidden');
            historyChevron.style.transform = historySubmenu.classList.contains('hidden')
                ? 'rotate(0deg)'
                : 'rotate(180deg)';
        });

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
                    fetch('process_leave_request.php', {
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

        // Check for unread messages periodically
        function checkUnreadMessages() {
            fetch('check_unread_messages.php')
                .then(response => response.json())
                .then(data => {
                    const unreadCount = document.getElementById('unreadCount');
                    if (data.count > 0) {
                        unreadCount.textContent = data.count;
                        unreadCount.classList.remove('hidden');
                    } else {
                        unreadCount.classList.add('hidden');
                    }
                });
        }

        // Check for unread messages every 30 seconds
        setInterval(checkUnreadMessages, 30000);
        checkUnreadMessages(); // Initial check
    });
</script>