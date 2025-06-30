<?php
ob_start();
session_start();
include 'db.php';
include 'includes/header2.php';

// Check if user is logged in
if (!isset($_SESSION['user_id'])) {
    header('Location: login.php');
    exit();
}

$user_id = $_SESSION['user_id'];

// delete all
if (isset($_POST['delete_all_notifications'])) {
    $delete_query = "DELETE FROM notifications WHERE target_user_id = ?";
    $stmt = $conn->prepare($delete_query);
    $stmt->bind_param("i", $user_id);
    $stmt->execute();

    header('Location: notification.php');
    exit();
}

// Mark notification as read when clicked
if (isset($_POST['mark_read']) && isset($_POST['notification_id'])) {
    $notification_id = $_POST['notification_id'];
    $update_query = "UPDATE notifications SET status = 'read' WHERE notification_id = ? AND target_user_id = ?";
    $stmt = $conn->prepare($update_query);
    $stmt->bind_param("ii", $notification_id, $user_id);
    $stmt->execute();
}

// Fetch notifications for the user
$query = "SELECT * FROM notifications WHERE target_user_id = ? ORDER BY created_at DESC";

try {
    $stmt = $conn->prepare($query);
    $stmt->bind_param("i", $user_id);
    $stmt->execute();
    $notifications = $stmt->get_result()->fetch_all(MYSQLI_ASSOC);

    // Count unread notifications
    $unread_count = array_reduce($notifications, function ($carry, $item) {
        return $carry + ($item['status'] === 'unread' ? 1 : 0);
    }, 0);
} catch (Exception $e) {
    die("Error: " . $e->getMessage());
}



?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Notifications Center</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        /* Ensure the page takes at least full viewport height */
        html,
        body {
            height: 100%;
            margin: 0;
        }

        /* Main wrapper to create a sticky footer */
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

        .mark-read-btn {
            transition: all 0.2s ease;
        }

        .mark-read-btn:hover {
            transform: translateX(5px);
        }

        .badge {
            animation: pulse 2s infinite;
        }

        @keyframes pulse {
            0% {
                transform: scale(1);
            }

            50% {
                transform: scale(1.05);
            }

            100% {
                transform: scale(1);
            }
        }
    </style>
</head>

<body class="bg-gradient-to-br from-blue-50 via-gray-50 to-purple-50">
    <div class="wrapper">
        <div class="content">
            <div class="container mx-auto p-6">
                <!-- Header Section -->
                <div class="text-center mb-12">
                    <h1 class="text-4xl font-bold text-gray-800 mb-3">Notifications Center</h1>
                    <p class="text-gray-600 text-lg">
                        <?php if ($unread_count > 0): ?>
                            <span
                                class="badge inline-flex items-center justify-center px-4 py-1 bg-blue-100 text-blue-800 rounded-full font-semibold">
                                <?= $unread_count ?> unread notification<?= $unread_count !== 1 ? 's' : '' ?>
                            </span>
                        <?php else: ?>
                            You're all caught up!
                        <?php endif; ?>
                    </p>

                    <?php if (!empty($notifications)): ?>
                        <form method="POST" class="mt-4">
                            <button type="submit" name="delete_all_notifications"
                                class="inline-flex items-center px-6 py-3 bg-red-500 text-white rounded-lg shadow-md hover:bg-red-600 transition-colors">
                                <i class="fas fa-trash mr-2"></i>
                                Delete All Notifications
                            </button>
                        </form>
                    <?php endif; ?>
                </div>

                <!-- Notifications List -->
                <div class="max-w-4xl mx-auto mb-12">
                    <?php if (empty($notifications)): ?>
                        <div class="bg-white rounded-2xl shadow-lg p-12 text-center">
                            <div class="icon-container mb-6">
                                <i class="fas fa-bell-slash text-6xl text-gray-300"></i>
                            </div>
                            <h3 class="text-xl font-semibold text-gray-700 mb-2">No Notifications</h3>
                            <p class="text-gray-500">Your notification center is empty at the moment</p>
                        </div>
                    <?php else: ?>
                        <div class="space-y-6">
                            <?php foreach ($notifications as $index => $notification): ?>
                                <?php
                                $icon = match ($notification['type']) {
                                    'loan_approval' => 'fa-hand-holding-dollar',
                                    'withdrawal' => 'fa-money-bill-transfer',
                                    'join_request' => 'fa-user-plus',
                                    'payment_reminder' => 'fa-clock',
                                    'group_loan_request' => 'fa-money-bill',
                                    'leave_request' => 'fa-user-minus',
                                    'group_withdraw_request' => 'fa-arrow-right-from-bracket',
                                    default => 'fa-bell'
                                };

                                $bgColor = $notification['status'] === 'unread'
                                    ? 'bg-gradient-to-r from-blue-50 to-blue-100'
                                    : 'bg-white';

                                $iconColor = match ($notification['type']) {
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
                                            <div
                                                class="icon-container w-14 h-14 bg-white rounded-xl shadow-sm flex items-center justify-center">
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

                                            <?php if ($notification['status'] === 'unread'): ?>
                                                <form method="POST" class="mt-4">
                                                    <input type="hidden" name="notification_id"
                                                        value="<?= $notification['notification_id'] ?>">
                                                    <button type="submit" name="mark_read"
                                                        class="mark-read-btn inline-flex items-center px-4 py-2 bg-white rounded-lg shadow-sm text-sm font-medium text-blue-600 hover:bg-blue-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500">
                                                        <i class="fas fa-check mr-2"></i>
                                                        Mark as read
                                                    </button>
                                                </form>
                                            <?php endif; ?>
                                        </div>
                                    </div>
                                </div>
                            <?php endforeach; ?>
                        </div>
                    <?php endif; ?>
                </div>
            </div>
        </div>

        <footer class="mt-auto">
            <?php include 'includes/new_footer.php'; ?>
        </footer>
    </div>
</body>

</html>