<?php
session_start();
include 'db.php';
// Check if user is logged in and part of a group
if (!isset($_SESSION['user_id']) || !isset($_SESSION['group_id'])) {
    header('Location: login.php');
    exit();
}

$user_id = $_SESSION['user_id'];
$group_id = $_SESSION['group_id'];

// Fetch group notifications
$query = "SELECT * FROM notifications WHERE target_group_id = ? and status ='unread' ORDER BY created_at DESC";

try {
    $stmt = $conn->prepare($query);
    $stmt->bind_param("i", $group_id);
    $stmt->execute();
    $notifications = $stmt->get_result()->fetch_all(MYSQLI_ASSOC);
} catch (Exception $e) {
    die("Error: " . $e->getMessage());
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Group Notifications</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        html, body {
            height: 100%;
            margin: 0;
        }

        .wrapper {
            min-height: 100%;
            display: flex;
            flex-direction: column;
        }

        .content {
            flex: 1;
        }

        .notification-card {
            transition: all 0.3s ease;
            animation: slideIn 0.5s ease-out;
        }
        
        .notification-card:hover {
            transform: translateY(-2px);
        }
        
        @keyframes slideIn {
            from {
                opacity: 0;
                transform: translateY(20px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }
        
        .icon-container {
            transition: all 0.3s ease;
        }
        
        .notification-card:hover .icon-container {
            transform: scale(1.1);
        }
    </style>
</head>
<body class="bg-gradient-to-br from-blue-50 via-gray-50 to-purple-50">
    <div class="flex h-screen">
        <?php include 'sidebar.php'; ?>

        <div class="flex-1 overflow-hidden">
            <header class="bg-white shadow-sm border-b border-gray-200 px-6 py-4">
                <div class="flex items-center justify-center w-full">
                    <div class="flex items-center">
                        <button id="menu-button" class="md:hidden mr-4 text-gray-600 hover:text-gray-900">
                            <i class="fa-solid fa-bars text-xl"></i>
                        </button>
                        <h1 class="text-2xl font-semibold text-gray-800">
                            <i class="fas fa-bell mr-2 text-blue-600"></i>
                            Group Notifications
                        </h1>
                    </div>
                </div>
            </header>

            <div class="content p-6 overflow-auto h-[calc(100vh-4rem)]">
                <div class="container mx-auto">
                    <!-- Header Section -->
                    <div class="text-center mb-12">
                        <!-- <h1 class="text-4xl font-bold text-gray-800 mb-3">Group Notifications</h1> -->
                     
                            <p class="text-gray-600 text-lg">
                                <span class="inline-flex items-center justify-center px-4 py-1 bg-blue-100 text-blue-800 rounded-full font-semibold">
                                    <?= count($notifications) ?> notification<?= count($notifications) !== 1 ? 's' : '' ?>
                                </span>
                            </p>

                       
                    </div>

                    <!-- Notifications List -->
                    <div class="max-w-4xl mx-auto mb-12">
                        <?php if (empty($notifications)): ?>
                            <div class="bg-white rounded-2xl shadow-lg p-12 text-center">
                                <div class="icon-container mb-6">
                                    <i class="fas fa-bell-slash text-6xl text-gray-300"></i>
                                </div>
                                <h3 class="text-xl font-semibold text-gray-700 mb-2">No Notifications</h3>
                                <p class="text-gray-500">Your group notification center is empty at the moment</p>
                            </div>
                        <?php else: ?>
                            <div class="space-y-6">
                                <?php foreach ($notifications as $index => $notification): ?>
                                    <?php
                                        $icon = match($notification['type']) {
                                            'loan_approval' => 'fa-hand-holding-dollar',
                                            'withdrawal' => 'fa-money-bill-transfer',
                                            'join_request' => 'fa-user-plus',
                                            'payment_reminder' => 'fa-clock',
                                            'group_loan_request' => 'fa-money-bill',
                                            'leave_request' => 'fa-user-minus',
                                            'group_withdraw_request' => 'fa-arrow-right-from-bracket',
                                            default => 'fa-bell'
                                        };
                                        
                                        $bgColor = 'bg-white';
                                        
                                        $iconColor = match($notification['type']) {
                                            'loan_approval' => 'text-green-600',
                                            'withdrawal' => 'text-blue-600',
                                            'join_request' => 'text-purple-600',
                                            'payment_reminder' => 'text-orange-600',
                                            'group_loan_request' => 'text-indigo-600',
                                            'leave_request' => 'text-red-600',
                                            'group_withdraw_request' => 'text-yellow-600',
                                            default => 'text-blue-600'
                                        };
                                    ?>
                                    <div class="notification-card <?= $bgColor ?> rounded-2xl shadow-md p-6" 
                                         style="animation-delay: <?= $index * 0.1 ?>s">
                                        <div class="flex items-start gap-4">
                                            <div class="flex-shrink-0">
                                                <div class="icon-container w-14 h-14 bg-white rounded-xl shadow-sm flex items-center justify-center">
                                                    <i class="fas <?= $icon ?> <?= $iconColor ?> text-2xl"></i>
                                                </div>
                                            </div>
                                            <div class="flex-grow">
                                                <div class="flex items-center justify-between mb-2">
                                                    <h3 class="text-lg font-semibold text-gray-800">
                                                        <?= htmlspecialchars($notification['title']) ?>
                                                    </h3>
                                                    <span class="text-sm font-medium text-gray-500">
                                                        <?= date('M j, Y g:i A', strtotime($notification['created_at'])) ?>
                                                    </span>
                                                </div>
                                                <p class="text-gray-600 leading-relaxed">
                                                    <?= htmlspecialchars($notification['message']) ?>
                                                </p>
                                            </div>
                                        </div>
                                    </div>
                                <?php endforeach; ?>
                            </div>
                        <?php endif; ?>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        // Menu toggle for mobile
        const menuButton = document.getElementById('menu-button');
        const sidebar = document.querySelector('.sidebar');

        menuButton?.addEventListener('click', () => {
            sidebar?.classList.toggle('hidden');
        });

        // Handle window resize
        window.addEventListener('resize', () => {
            if (window.innerWidth >= 768) {
                sidebar?.classList.remove('hidden');
            }
        });
    </script>
</body>
</html>