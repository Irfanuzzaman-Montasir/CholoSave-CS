<?php
session_start();

$group_id = $_SESSION['group_id'];
$user_id = $_SESSION['user_id'];

if (isset($_SESSION['group_id']) && isset($_SESSION['user_id'])) {
    $group_id = $_SESSION['group_id'];
    $user_id = $_SESSION['user_id'];
} else {
    header("Location: /test_project/error_page.php");
    exit;
}

if (!isset($conn)) {
    include 'db.php';
}

// Check if the user is an admin for the group
$is_admin = false;
$checkAdminQuery = "SELECT group_admin_id, group_name FROM my_group WHERE group_id = ?";
if ($stmt = $conn->prepare($checkAdminQuery)) {
    $stmt->bind_param('i', $group_id);
    $stmt->execute();
    $stmt->bind_result($group_admin_id, $group_name);
    $stmt->fetch();
    $stmt->close();

    if ($group_admin_id === $user_id) {
        $is_admin = true;
    }
}

if (!$is_admin) {
    header("Location: /test_project/error_page.php");
    exit;
}

$joinRequestsQuery = "
    SELECT 
        gm.user_id, 
        gm.group_id, 
        gm.status, 
        gm.join_request_date, 
        u.name AS username
    FROM 
        group_membership gm
    LEFT JOIN 
        users u ON gm.user_id = u.id
    WHERE 
        gm.status = 'pending' 
        AND gm.group_id = ?
";

$joinRequests = [];
if ($stmt = $conn->prepare($joinRequestsQuery)) {
    $stmt->bind_param('i', $group_id);
    $stmt->execute();
    $result = $stmt->get_result();
    while ($row = $result->fetch_assoc()) {
        $joinRequests[] = $row;
    }
    $stmt->close();
}

if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['action'])) {
    $user_id_to_update = $_POST['user_id'];
    $action = $_POST['action'];
    $current_date = date('Y-m-d');

    // Start transaction
    $conn->begin_transaction();

    try {
        if ($action == 'approve') {
            // Get group time period
            $getTimePeriodQuery = "SELECT time_period FROM my_group WHERE group_id = ?";
            if ($stmt = $conn->prepare($getTimePeriodQuery)) {
                $stmt->bind_param('i', $group_id);
                $stmt->execute();
                $stmt->bind_result($time_period);
                $stmt->fetch();
                $stmt->close();
            }

            // Update membership status
            $updateQuery = "
                UPDATE group_membership 
                SET status = 'approved', join_date = ?, time_period_remaining = ? 
                WHERE user_id = ? AND group_id = ?
            ";
            if ($stmt = $conn->prepare($updateQuery)) {
                $stmt->bind_param('siii', $current_date, $time_period, $user_id_to_update, $group_id);
                $stmt->execute();
                $stmt->close();
            }

            // Add 5 points to the leaderboard
            $updateLeaderboardQuery = "UPDATE leaderboard SET points = points + 5 WHERE group_id = ?";
            if ($stmt = $conn->prepare($updateLeaderboardQuery)) {
                $stmt->bind_param('i', $group_id);
                $stmt->execute();
                $stmt->close();
            }


            // Create approval notification for the user
            $notificationTitleUser = "Join Request Approved";
            $notificationMessageUser = "Your request to join the group '$group_name' has been approved. Welcome to the group!";

            $insertNotificationQuery = "
                INSERT INTO notifications (
                    target_user_id,
                    target_group_id,
                    type,
                    title,
                    message,
                    status
                ) VALUES (?, NULL, 'join_request', ?, ?, 'unread')
            ";

            if ($stmt = $conn->prepare($insertNotificationQuery)) {
                $stmt->bind_param(
                    'iss',
                    $user_id_to_update,
                    $notificationTitleUser,
                    $notificationMessageUser
                );
                $stmt->execute();
                $stmt->close();
            }

            // Create approval notification for the group
            $notificationTitleGroup = "New Member Joined";
            $notificationMessageGroup = "A new member has joined your group '$group_name'.";

            $insertGroupNotificationQuery = "
                INSERT INTO notifications (
                    target_user_id,
                    target_group_id,
                    type,
                    title,
                    message,
                    status
                ) VALUES (NULL, ?, 'join_request', ?, ?, 'unread')
            ";

            if ($stmt = $conn->prepare($insertGroupNotificationQuery)) {
                $stmt->bind_param(
                    'iss',
                    $group_id,
                    $notificationTitleGroup,
                    $notificationMessageGroup
                );
                $stmt->execute();
                $stmt->close();
            }

        } elseif ($action == 'reject') {
            // Update membership status
            $updateQuery = "UPDATE group_membership SET status = 'declined' WHERE user_id = ? AND group_id = ?";
            if ($stmt = $conn->prepare($updateQuery)) {
                $stmt->bind_param('ii', $user_id_to_update, $group_id);
                $stmt->execute();
                $stmt->close();
            }

            // Create rejection notification for the user
            $notificationTitleRejection = "Join Request Declined";
            $notificationMessageRejection = "Your request to join the group '$group_name' has been declined.";

            $insertNotificationQuery = "
                INSERT INTO notifications (
                    target_user_id,
                    target_group_id,
                    type,
                    title,
                    message,
                    status
                ) VALUES (?, NULL, 'join_request', ?, ?, 'unread')
            ";

            if ($stmt = $conn->prepare($insertNotificationQuery)) {
                $stmt->bind_param(
                    'iss',
                    $user_id_to_update,
                    $notificationTitleRejection,
                    $notificationMessageRejection
                );
                $stmt->execute();
                $stmt->close();
            }
        }

        // Commit transaction
        $conn->commit();

        echo "<script>
                window.location.href = 'member_join_request.php';
              </script>";
    } catch (Exception $e) {
        // Rollback transaction on error
        $conn->rollback();
        error_log("Error processing join request: " . $e->getMessage());
        echo "<script>
                alert('An error occurred. Please try again.');
                window.location.href = 'member_join_request.php';
              </script>";
    }
}
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Manage Join Requests</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        body {
            font-family: 'Inter', sans-serif;
        }

        .glass-effect {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            -webkit-backdrop-filter: blur(10px);
        }
    </style>
</head>

<body class="bg-gradient-to-br from-white-50 to-blue-100 min-h-screen">
    <div class="flex h-screen">
        <!-- Sidebar -->
        <?php include 'group_admin_sidebar.php'; ?>

        <!-- Main Content -->
        <div class="flex-1 flex flex-col overflow-hidden">
            <!-- Top Bar -->
            <header class="glass-effect shadow-sm border-b border-gray-200">
                <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6 flex justify-center">
                    <div class="flex items-center justify-center">
                        <button id="menu-button" class="md:hidden p-2 rounded-lg text-gray-600 hover:bg-gray-100">
                            <i class="fa-solid fa-bars text-xl"></i>
                        </button>
                        <h1 class="text-2xl font-semibold text-gray-800 ml-4">
                            <i class="fa-solid fa-user-plus text-blue-600 mr-3"></i>
                            Member Join Requests
                        </h1>
                    </div>
                </div>
            </header>

            <!-- Main Content Area -->
            <div class="flex-1 overflow-y-auto p-6">
                <div class="max-w-7xl mx-auto">
                    <div class="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
                        <!-- Stats Overview -->
                        <div class="grid grid-cols-1 md:grid-cols-3 gap-4 p-6 bg-gradient-to-r from-blue-50 to-blue-50">
                            <div class="bg-white p-4 rounded-lg shadow-sm border border-gray-100">
                                <div class="text-sm font-medium text-gray-500">Pending Requests</div>
                                <div class="mt-2 text-3xl font-semibold text-blue-600">
                                    <?php echo count($joinRequests); ?></div>
                            </div>
                            <!-- Add more stats cards as needed -->
                        </div>

                        <!-- Table Section -->
                        <div class="p-6">
                            <div class="overflow-x-auto">
                                <table class="min-w-full divide-y divide-gray-200">
                                    <thead>
                                        <tr class="bg-gray-50">
                                            <th
                                                class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                                Serial</th>
                                            <th
                                                class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                                Username</th>
                                            <th
                                                class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                                Join Request Date</th>
                                            <th
                                                class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                                Actions</th>
                                        </tr>
                                    </thead>
                                    <tbody class="bg-white divide-y divide-gray-200">
                                        <?php
                                        $serial = 1;
                                        foreach ($joinRequests as $request):
                                            ?>
                                            <tr class="hover:bg-gray-50 transition-colors duration-200">
                                                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                                                    <?php echo $serial++; ?></td>
                                                <td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">
                                                    <?php echo htmlspecialchars($request['username']); ?>
                                                </td>
                                                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                                                    <?php echo date('d M Y', strtotime($request['join_request_date'])); ?>
                                                </td>
                                                <td class="px-6 py-4 whitespace-nowrap text-sm font-medium">
                                                    <form method="POST" class="flex space-x-2">
                                                        <input type="hidden" name="user_id"
                                                            value="<?php echo $request['user_id']; ?>">
                                                        <button type="submit" name="action" value="approve"
                                                            class="inline-flex items-center px-3 py-2 border border-transparent text-sm leading-4 font-medium rounded-md text-white bg-green-600 hover:bg-green-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-green-500 transition-colors duration-200">
                                                            <i class="fas fa-check mr-2"></i> Approve
                                                        </button>
                                                        <button type="submit" name="action" value="reject"
                                                            class="inline-flex items-center px-3 py-2 border border-transparent text-sm leading-4 font-medium rounded-md text-white bg-red-600 hover:bg-red-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-red-500 transition-colors duration-200">
                                                            <i class="fas fa-times mr-2"></i> Reject
                                                        </button>
                                                    </form>
                                                </td>
                                            </tr>
                                        <?php endforeach; ?>
                                        <?php if (empty($joinRequests)): ?>
                                            <tr>
                                                <td colspan="4" class="px-6 py-10 text-center text-gray-500">
                                                    <i class="fas fa-inbox text-4xl mb-4"></i>
                                                    <p>No pending join requests</p>
                                                </td>
                                            </tr>
                                        <?php endif; ?>
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        // Menu toggle for mobile
        document.getElementById('menu-button').addEventListener('click', function () {
            const sidebar = document.querySelector('.sidebar');
            sidebar.classList.toggle('-translate-x-full');
        });
    </script>
</body>

</html>
<?php include 'new_footer.php'; ?>