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
$checkAdminQuery = "SELECT group_admin_id FROM my_group WHERE group_id = ?";
if ($stmt = $conn->prepare($checkAdminQuery)) {
    $stmt->bind_param('i', $group_id);
    $stmt->execute();
    $stmt->bind_result($group_admin_id);
    $stmt->fetch();
    $stmt->close();

    // If the user is the admin of the group, proceed; otherwise, redirect to an error page
    if ($group_admin_id === $user_id) {
        $is_admin = true;
    }
}

if (!$is_admin) {
    // Redirect to error page if the user is not an admin
    header("Location: /test_project/error_page.php");
    exit;
}

$leaveRequestsQuery = "
  SELECT 
    gm.user_id, 
    gm.group_id, 
    gm.leave_request, 
    gm.join_date, 
    gm.time_period_remaining, 
    u.name AS username,
    SUM(s.amount) AS total_contribution,
    (
      SELECT COALESCE(SUM(w.amount), 0)
      FROM withdrawal w
      WHERE w.user_id = gm.user_id 
      AND w.group_id = gm.group_id 
      AND w.status = 'approved'
    ) AS total_withdrawn
FROM 
    group_membership gm
LEFT JOIN 
    savings s ON gm.user_id = s.user_id AND gm.group_id = s.group_id
LEFT JOIN 
    users u ON gm.user_id = u.id
WHERE 
    gm.leave_request = 'pending' 
    AND gm.group_id = ? 
GROUP BY 
    gm.user_id, gm.group_id, gm.leave_request, gm.join_date, gm.time_period_remaining, u.name;
";

$leaveRequests = [];
if ($stmt = $conn->prepare($leaveRequestsQuery)) {
    $stmt->bind_param('i', $group_id);
    $stmt->execute();
    $result = $stmt->get_result();
    while ($row = $result->fetch_assoc()) {
        $leaveRequests[] = $row;
    }
    $stmt->close();
}

if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['action'])) {
    $user_id_to_update = $_POST['user_id'];
    $action = $_POST['action'];

    if ($action == 'approve') {
        // Start transaction
        $conn->begin_transaction();

        try {
            // Get user and group information for notifications
            $getUserInfo = "SELECT u.name, mg.group_name 
                          FROM users u 
                          JOIN my_group mg ON mg.group_id = ? 
                          WHERE u.id = ?";
            $stmt = $conn->prepare($getUserInfo);
            $stmt->bind_param('ii', $group_id, $user_id_to_update);
            $stmt->execute();
            $result = $stmt->get_result();
            $info = $result->fetch_assoc();
            $username = $info['name'];
            $groupname = $info['group_name'];
            $stmt->close();

            // 1. Delete from group_membership
            $deleteGroupMembership = "DELETE FROM group_membership WHERE user_id = ? AND group_id = ?";
            $stmt = $conn->prepare($deleteGroupMembership);
            $stmt->bind_param('ii', $user_id_to_update, $group_id);
            $stmt->execute();
            $stmt->close();

            // 2. Delete from savings
            $deleteSavings = "DELETE FROM savings WHERE user_id = ? AND group_id = ?";
            $stmt = $conn->prepare($deleteSavings);
            $stmt->bind_param('ii', $user_id_to_update, $group_id);
            $stmt->execute();
            $stmt->close();

            // 3. Delete from loan_requests
            $deleteLoanRequests = "DELETE FROM loan_request WHERE user_id = ? AND group_id = ?";
            $stmt = $conn->prepare($deleteLoanRequests);
            $stmt->bind_param('ii', $user_id_to_update, $group_id);
            $stmt->execute();
            $stmt->close();

            // 4. Delete from transaction_info
            $deleteTransactions = "DELETE FROM transaction_info WHERE user_id = ? AND group_id = ?";
            $stmt = $conn->prepare($deleteTransactions);
            $stmt->bind_param('ii', $user_id_to_update, $group_id);
            $stmt->execute();
            $stmt->close();

            // 5. Delete from withdrawal
            $deleteWithdrawals = "DELETE FROM withdrawal WHERE user_id = ? AND group_id = ?";
            $stmt = $conn->prepare($deleteWithdrawals);
            $stmt->bind_param('ii', $user_id_to_update, $group_id);
            $stmt->execute();
            $stmt->close();


            // Deduct 10 points to the leaderboard
            $updateLeaderboardQuery = "UPDATE leaderboard SET points = points - 10 WHERE group_id = ?";
            if ($stmt = $conn->prepare($updateLeaderboardQuery)) {
                $stmt->bind_param('i', $group_id);
                $stmt->execute();
                $stmt->close();
            }

            // 6. Create notification for user
            $userNotificationTitle = "Leave Request Approved";
            $userNotificationMessage = "Your request to leave the group '$groupname' has been approved.";
            $insertUserNotification = "INSERT INTO notifications (target_user_id, type, title, message) 
                                    VALUES (?, 'leave_request', ?, ?)";
            $stmt = $conn->prepare($insertUserNotification);
            $stmt->bind_param('iss', $user_id_to_update, $userNotificationTitle, $userNotificationMessage);
            $stmt->execute();
            $stmt->close();

            // 7. Create notification for group
            $groupNotificationTitle = "Member Left Group";
            $groupNotificationMessage = "Member '$username' has left the group.";
            $insertGroupNotification = "INSERT INTO notifications (target_group_id, type, title, message) 
                                     VALUES (?, 'leave_request', ?, ?)";
            $stmt = $conn->prepare($insertGroupNotification);
            $stmt->bind_param('iss', $group_id, $groupNotificationTitle, $groupNotificationMessage);
            $stmt->execute();
            $stmt->close();

            // If all operations are successful, commit the transaction
            $conn->commit();

            // Redirect with success message
            echo "<script>
                    alert('Member removed successfully');
                    window.location.href = 'member_leave_request.php';
                  </script>";

        } catch (Exception $e) {
            // If any operation fails, rollback all changes
            $conn->rollback();

            // Redirect with error message
            echo "<script>
                    alert('Error processing leave request. Please try again.');
                    window.location.href = 'member_leave_request.php';
                  </script>";
        }
    } elseif ($action == 'reject') {
        $updateQuery = "UPDATE group_membership SET leave_request = 'no' WHERE user_id = ? AND group_id = ?";
        if ($stmt = $conn->prepare($updateQuery)) {
            $stmt->bind_param('ii', $user_id_to_update, $group_id);
            if ($stmt->execute()) {
                echo "<script>
                        alert('Leave request rejected');
                        window.location.href = 'member_leave_request.php';
                      </script>";
            }
            $stmt->close();
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Manage Leave Requests</title>
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
                        <h1 class="text-2xl font-semibold text-gray-800 ml-4">
                            <i class="fa-solid fa-user-times text-blue-600 mr-3"></i>
                            Member Leave Requests
                        </h1>
                    </div>
                </div>
            </header>

            <!-- Main Content Area -->
            <div class="flex-1 overflow-y-auto p-6">
                <div class="max-w-7xl mx-auto">
                    <div class="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
                        <div class="p-6">
                            <div class="overflow-x-auto">
                                <table class="min-w-full divide-y divide-gray-200">
                                    <thead>
                                        <tr class="bg-gray-50">
                                            <th
                                                class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                                Serial
                                            </th>
                                            <th
                                                class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                                Name
                                            </th>
                                            <th
                                                class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                                Join Date
                                            </th>
                                            <th
                                                class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                                Installment Remaining
                                            </th>
                                            <th
                                                class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                                Total Contribution
                                            </th>
                                            <th
                                                class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                                Withdraw Amount
                                            </th>
                                            <th
                                                class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                                Actions
                                            </th>
                                        </tr>
                                    </thead>
                                    <tbody class="bg-white divide-y divide-gray-200">
                                        <?php
                                        $serial = 1;
                                        foreach ($leaveRequests as $request):
                                            ?>
                                            <tr class="hover:bg-gray-50 transition-colors duration-200">
                                                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                                                    <?php echo $serial++; ?>
                                                </td>
                                                <td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">
                                                    <?php echo htmlspecialchars($request['username']); ?>
                                                </td>
                                                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                                                    <?php echo date('Y-m-d', strtotime($request['join_date'])); ?>
                                                </td>
                                                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                                                    <?php echo $request['time_period_remaining']; ?> months
                                                </td>
                                                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                                                    ৳<?php echo number_format($request['total_contribution'], 2); ?>
                                                </td>
                                                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                                                    ৳<?php echo number_format($request['total_withdrawn'], 2); ?>
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
                                        <?php if (empty($leaveRequests)): ?>
                                            <tr>
                                                <td colspan="7" class="px-6 py-10 text-center text-gray-500">
                                                    <i class="fas fa-inbox text-4xl mb-4"></i>
                                                    <p>No pending leave requests</p>
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
        document.getElementById('menu-button')?.addEventListener('click', function () {
            const sidebar = document.querySelector('.sidebar');
            sidebar.classList.toggle('-translate-x-full');
        });
    </script>
</body>

</html>

<?php include 'new_footer.php'; ?>