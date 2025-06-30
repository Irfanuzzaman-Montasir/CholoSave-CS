<?php
session_start();

$group_id = $_SESSION['group_id'];
$user_id = $_SESSION['user_id'];

// Check if user is logged in and belongs to a group
if (!isset($group_id) || !isset($user_id)) {
    header("Location: /CholoSave-CS/error_page.php");
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

    if ($group_admin_id === $user_id) {
        $is_admin = true;
    }
}

if (!$is_admin) {
    header("Location: /CholoSave-CS/error_page.php");
    exit;
}

// Fetch group members' details
$membersQuery = "
    SELECT 
        um.user_id, 
        u.name, 
        u.email, 
        um.join_date, 
        um.is_admin, 
        COALESCE(SUM(s.amount), 0) AS contribution
    FROM 
        group_membership um
    JOIN 
        users u ON um.user_id = u.id
    LEFT JOIN 
        savings s ON um.user_id = s.user_id AND um.group_id = s.group_id
    WHERE 
        um.group_id = ? AND um.status = 'approved'
    GROUP BY 
        um.user_id
";

$members = [];
if ($stmt = $conn->prepare($membersQuery)) {
    $stmt->bind_param('i', $group_id);
    $stmt->execute();
    $result = $stmt->get_result();
    while ($row = $result->fetch_assoc()) {
        $row['role'] = $row['is_admin'] == 1 ? 'Admin' : 'Member';
        $members[] = $row;
    }
    $stmt->close();
}

// Update member role to admin
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['make_admin'])) {
    $target_user_id = $_POST['user_id'];

    // Start transaction
    $conn->begin_transaction();

    try {
        // Update my_group table to set new admin
        $updateGroupAdminQuery = "UPDATE my_group SET group_admin_id = ? WHERE group_id = ?";
        $stmt = $conn->prepare($updateGroupAdminQuery);
        $stmt->bind_param('ii', $target_user_id, $group_id);
        $stmt->execute();
        $stmt->close();

        // Update group_membership for old admin (current user)
        $updateOldAdminQuery = "UPDATE group_membership SET is_admin = 0 WHERE user_id = ? AND group_id = ?";
        $stmt = $conn->prepare($updateOldAdminQuery);
        $stmt->bind_param('ii', $user_id, $group_id);
        $stmt->execute();
        $stmt->close();

        // Update group_membership for new admin
        $updateNewAdminQuery = "UPDATE group_membership SET is_admin = 1 WHERE user_id = ? AND group_id = ?";
        $stmt = $conn->prepare($updateNewAdminQuery);
        $stmt->bind_param('ii', $target_user_id, $group_id);
        $stmt->execute();
        $stmt->close();

        // Fetch group name
        $groupNameQuery = "SELECT group_name FROM my_group WHERE group_id = ?";
        $stmt = $conn->prepare($groupNameQuery);
        $stmt->bind_param('i', $group_id);
        $stmt->execute();
        $stmt->bind_result($group_name);
        $stmt->fetch();
        $stmt->close();

        // Notification for user
        $message = "You have been promoted to admin of the group '{$group_name}'.";
        $messageTitle = "Group Admin Promotion";
        $userNotificationQuery = "INSERT INTO notifications (target_user_id, target_group_id, message, title, type, created_at) VALUES (?, NULL, ?, ?, 'admin_promotion', NOW())";
        $stmt = $conn->prepare($userNotificationQuery);
        $stmt->bind_param('iss', $target_user_id, $message, $messageTitle);
        $stmt->execute();
        $stmt->close();

        // Notification for group
        $groupMessage = "A new admin has been assigned to the group.";
        $groupMessageTitle = "Group Admin Change";
        $groupNotificationQuery = "INSERT INTO notifications (target_user_id, target_group_id, message, title, type, created_at) VALUES (NULL, ?, ?, ?, 'admin_promotion', NOW())";
        $stmt = $conn->prepare($groupNotificationQuery);
        $stmt->bind_param('iss', $group_id, $groupMessage, $groupMessageTitle);
        $stmt->execute();
        $stmt->close();

        // Commit transaction
        $conn->commit();

        // Clear session and redirect to login
        session_destroy();
        echo json_encode(['success' => true]);
        exit;

    } catch (Exception $e) {
        // Rollback transaction on error
        $conn->rollback();
        echo json_encode(['success' => false, 'message' => 'An error occurred']);
        exit;
    }
}
?>
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Group Members</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>
    <style>
        body {
            font-family: 'Inter', sans-serif;
        }

        .glass-effect {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            -webkit-backdrop-filter: blur(10px);
        }

        .editable {
            background-color: #f9fafb;
            border: 1px solid #d1d5db;
            padding: 0.25rem;
            border-radius: 0.25rem;
        }
    </style>
</head>

<body class="bg-gradient-to-br from-white-50 to-blue-100 min-h-screen">
    <div class="flex h-screen">
        <?php include 'group_admin_sidebar.php'; ?>

        <div class="flex-1 flex flex-col overflow-hidden">
            <header class="glass-effect shadow-sm border-b border-gray-200">
                <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6 flex justify-center">
                    <div class="flex items-center justify-center">
                        <h1 class="text-2xl font-semibold text-gray-800 ml-4">
                            <i class="fa-solid fa-users text-blue-600 mr-3"></i>
                            Group Members
                        </h1>
                    </div>
                </div>
            </header>

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
                                                Serial</th>
                                            <th
                                                class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                                Name</th>
                                            <th
                                                class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                                Email</th>
                                            <th
                                                class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                                Join Date</th>
                                            <th
                                                class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                                Role</th>
                                            <th
                                                class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                                Contribution</th>
                                            <th
                                                class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                                Actions</th>
                                        </tr>
                                    </thead>
                                    <tbody class="bg-white divide-y divide-gray-200">
                                        <?php
                                        $serial = 1;
                                        foreach ($members as $member):
                                            ?>
                                            <tr class="hover:bg-gray-50 transition-colors duration-200">
                                                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                                                    <?php echo $serial++; ?>
                                                </td>
                                                <td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">
                                                    <?php echo htmlspecialchars($member['name']); ?>
                                                </td>
                                                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                                                    <?php echo htmlspecialchars($member['email']); ?>
                                                </td>
                                                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                                                    <?php echo date('Y-m-d', strtotime($member['join_date'])); ?>
                                                </td>
                                                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                                                    <?php echo $member['role']; ?>
                                                </td>
                                                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                                                    <?php echo $member['contribution']; ?>
                                                </td>
                                                <td class="px-6 py-4 whitespace-nowrap text-sm font-medium">
                                                    <?php if ($member['role'] === 'Member'): ?>
                                                        <button onclick="confirmMakeAdmin(<?php echo $member['user_id']; ?>)"
                                                            class="inline-flex items-center px-3 py-2 border border-transparent text-sm leading-4 font-medium rounded-md text-white bg-green-600 hover:bg-green-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-green-500 transition-colors duration-200">
                                                            <i class="fas fa-user-shield mr-2"></i> Make Admin
                                                        </button>
                                                    <?php endif; ?>
                                                </td>
                                            </tr>
                                        <?php endforeach; ?>
                                        <?php if (empty($members)): ?>
                                            <tr>
                                                <td colspan="7" class="px-6 py-10 text-center text-gray-500">
                                                    <i class="fas fa-inbox text-4xl mb-4"></i>
                                                    <p>No members found</p>
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
        function confirmMakeAdmin(userId) {
            Swal.fire({
                title: 'Make Member Admin?',
                text: "You will be logged out and this member will become the new admin. This action cannot be undone!",
                icon: 'warning',
                showCancelButton: true,
                confirmButtonColor: '#3085d6',
                cancelButtonColor: '#d33',
                confirmButtonText: 'Yes, make admin!'
            }).then((result) => {
                if (result.isConfirmed) {
                    const formData = new FormData();
                    formData.append('make_admin', true);
                    formData.append('user_id', userId);

                    fetch(window.location.href, {
                        method: 'POST',
                        body: formData
                    })
                        .then(response => response.json())
                        .then(data => {
                            if (data.success) {
                                Swal.fire(
                                    'Admin Changed!',
                                    'You will be logged out now.',
                                    'success'
                                ).then(() => {
                                    window.location.href = '/CholoSave-CS/logout.php';
                                });
                            } else {
                                Swal.fire(
                                    'Error!',
                                    'Something went wrong.',
                                    'error'
                                );
                            }
                        });
                }
            });
        }
    </script>
</body>

</html>

<?php include 'new_footer.php'; ?>