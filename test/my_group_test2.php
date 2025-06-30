<?php
// Include session, database connection, and header
include 'session.php';
include 'db.php';
include 'includes/header2.php';

// Check if the user is logged in
if (!isLoggedIn()) {
    echo json_encode(["status" => "error", "message" => "User not logged in."]);
    exit();
}

$user_id = getUserId();

// Handle join request
if (isset($_POST['join_group'])) {
    $group_id = $_POST['group_id'];

    // Check if already a member
    $checkMemberQuery = "SELECT status FROM group_membership WHERE user_id = ? AND group_id = ?";
    $stmt = $conn->prepare($checkMemberQuery);
    $stmt->bind_param("ii", $user_id, $group_id);
    $stmt->execute();

    // Check if there was an error executing the query
    if ($stmt->error) {
        echo "Error executing query: " . $stmt->error;
        exit();
    }

    $result = $stmt->get_result();
    
    if ($result->num_rows > 0) {
        $membership = $result->fetch_assoc();
        if ($membership['status'] == 'approved') {
            $_SESSION['message'] = "You are already a member of this group.";
            $_SESSION['message_type'] = "warning";
        } else {
            $_SESSION['message'] = "Your join request is pending approval.";
            $_SESSION['message_type'] = "info";
        }
    } else {
        // Insert join request
        $joinQuery = "INSERT INTO group_membership (user_id, group_id, status, join_request_date) VALUES (?, ?, 'pending', NOW())";
        $stmt = $conn->prepare($joinQuery);
        $stmt->bind_param("ii", $user_id, $group_id);

        if ($stmt->execute()) {
            $_SESSION['message'] = "Join request sent successfully! Please wait for approval.";
            $_SESSION['message_type'] = "success";
        } else {
            echo "Error inserting join request: " . $stmt->error;
        }
    }
}

// Query to get all group details and member count
$allGroupsQuery = "
    SELECT 
        g.group_id, 
        g.group_name, 
        g.dps_type, 
        g.amount AS installment, 
        COUNT(gm.user_id) AS members_count,
        EXISTS (
            SELECT 1 FROM group_membership 
            WHERE group_id = g.group_id 
            AND user_id = ? 
            AND status IN ('approved', 'pending')
        ) as is_member,
        (
            SELECT status FROM group_membership 
            WHERE group_id = g.group_id 
            AND user_id = ?
        ) as membership_status
    FROM 
        my_group g
    LEFT JOIN 
        group_membership gm 
    ON 
        g.group_id = gm.group_id AND gm.status = 'approved'
    GROUP BY 
        g.group_id
";

$stmt = $conn->prepare($allGroupsQuery);
$stmt->bind_param("ii", $user_id, $user_id);
$stmt->execute();
$allGroupsResult = $stmt->get_result();
$allGroups = [];
if ($allGroupsResult) {
    while ($row = $allGroupsResult->fetch_assoc()) {
        $allGroups[] = $row;
    }
}

// Query to get the user's joined groups
$joinedGroupsQuery = "
    SELECT 
        g.group_id, 
        g.group_name, 
        g.dps_type, 
        g.amount AS installment, 
        COUNT(gm2.user_id) AS members_count,
        CASE WHEN g.group_admin_id = ? THEN 1 ELSE 0 END AS is_admin
    FROM 
        group_membership gm
    INNER JOIN 
        my_group g 
    ON 
        gm.group_id = g.group_id
    LEFT JOIN 
        group_membership gm2 
    ON 
        g.group_id = gm2.group_id AND gm2.status = 'approved'
    WHERE 
        gm.user_id = ? AND gm.status = 'approved'
    GROUP BY 
        g.group_id
";

$stmt = $conn->prepare($joinedGroupsQuery);
$stmt->bind_param("ii", $user_id, $user_id);
$stmt->execute();
$joinedGroupsResult = $stmt->get_result();
$joinedGroups = [];
if ($joinedGroupsResult) {
    while ($row = $joinedGroupsResult->fetch_assoc()) {
        $joinedGroups[] = $row;
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Groups</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        body {
            font-family: 'Inter', sans-serif;
            background: linear-gradient(135deg, #f6f8fd 0%, #f1f4f9 100%);
            min-height: 100vh;
        }
        .group-card {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(229, 231, 235, 1);
            transition: all 0.3s ease;
        }
        .group-card:hover {
            transform: translateY(-4px);
            box-shadow: 0 12px 24px rgba(0, 0, 0, 0.1);
        }
    </style>
</head>
<body>
    <div class="container mx-auto px-4 py-12">
        <!-- Message Display -->
        <?php if (isset($_SESSION['message'])): ?>
            <div class="mb-6 p-4 rounded-lg <?php 
                echo $_SESSION['message_type'] === 'success' ? 'bg-green-100 text-green-700' : 
                    ($_SESSION['message_type'] === 'warning' ? 'bg-yellow-100 text-yellow-700' : 
                    'bg-blue-100 text-blue-700'); 
                ?>">
                <?php 
                echo $_SESSION['message']; 
                unset($_SESSION['message']);
                unset($_SESSION['message_type']);
                ?>
            </div>
        <?php endif; ?>

        <!-- Header Section -->
        <div class="text-center mb-12">
            <h1 class="text-4xl font-bold text-gray-800 mb-6">Groups</h1>
            <div class="inline-flex rounded-lg bg-gray-100 p-1 space-x-1">
                <button onclick="showGroups('all')" 
                        class="px-6 py-2.5 rounded-md text-sm font-medium transition-all duration-200 focus:outline-none active-tab"
                        id="all-tab">
                    All Groups
                </button>
                <button onclick="showGroups('joined')" 
                        class="px-6 py-2.5 rounded-md text-sm font-medium transition-all duration-200 focus:outline-none"
                        id="joined-tab">
                    My Groups
                </button>
            </div>
        </div>

        <!-- All Groups Section -->
        <div id="all-groups" class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            <?php foreach ($allGroups as $group): ?>
                <div class="group-card rounded-xl p-6 flex flex-col">
                    <div class="flex justify-between items-start mb-4">
                        <h3 class="text-xl font-bold text-gray-800"><?php echo htmlspecialchars($group['group_name']); ?></h3>
                        <span class="px-3 py-1 bg-blue-100 text-blue-800 rounded-full text-sm">
                            <?php echo htmlspecialchars($group['dps_type']); ?>
                        </span>
                    </div>
                    <div class="space-y-2 mb-6">
                        <p class="text-gray-600">
                            <span class="font-medium">Installment:</span> 
                            $<?php echo htmlspecialchars($group['installment']); ?>
                        </p>
                        <p class="text-gray-600">
                            <span class="font-medium">Members:</span> 
                            <?php echo htmlspecialchars($group['members_count']); ?>
                        </p>
                    </div>
                    <div class="mt-auto space-y-2">
                        <?php if ($group['is_member']): ?>
                            <?php if ($group['membership_status'] === 'approved'): ?>
                                <button class="w-full px-4 py-2 bg-green-500 text-white rounded-lg opacity-75 cursor-not-allowed">
                                    Already Joined
                                </button>
                            <?php else: ?>
                                <button class="w-full px-4 py-2 bg-yellow-500 text-white rounded-lg opacity-75 cursor-not-allowed">
                                    Request Pending
                                </button>
                            <?php endif; ?>
                        <?php else: ?>
                            <a href="group-details.php?group_id=<?php echo $group['group_id']; ?>&preview=true" 
                               class="block w-full px-4 py-2 bg-gray-600 text-white text-center rounded-lg hover:bg-gray-700 transition-colors duration-200">
                                Show Details
                            </a>
                            <form method="POST" class="w-full">
                                <input type="hidden" name="group_id" value="<?php echo $group['group_id']; ?>">
                                <button type="submit" name="join_group" 
                                        class="w-full px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors duration-200">
                                    Join Group
                                </button>
                            </form>
                        <?php endif; ?>
                    </div>
                </div>
            <?php endforeach; ?>
        </div>

        <!-- My Groups Section -->
        <div id="joined-groups" class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6" style="display: none;">
            <?php foreach ($joinedGroups as $group): ?>
                <div class="group-card rounded-xl p-6 flex flex-col">
                    <div class="flex justify-between items-start mb-4">
                        <h3 class="text-xl font-bold text-gray-800"><?php echo htmlspecialchars($group['group_name']); ?></h3>
                        <span class="px-3 py-1 bg-blue-100 text-blue-800 rounded-full text-sm">
                            <?php echo htmlspecialchars($group['dps_type']); ?>
                        </span>
                    </div>
                    <div class="space-y-2 mb-6">
                        <p class="text-gray-600">
                            <span class="font-medium">Installment:</span> 
                            $<?php echo htmlspecialchars($group['installment']); ?>
                        </p>
                        <p class="text-gray-600">
                            <span class="font-medium">Members:</span> 
                            <?php echo htmlspecialchars($group['members_count']); ?>
                        </p>
                        <p class="text-gray-600">
                            <span class="font-medium">Role:</span> 
                            <?php echo $group['is_admin'] ? 'Admin' : 'Member'; ?>
                        </p>
                    </div>
                    <div class="mt-auto space-y-2">
                        <a href="group-details.php?group_id=<?php echo $group['group_id']; ?>&preview=true" 
                           class="block w-full px-4 py-2 bg-gray-600 text-white text-center rounded-lg hover:bg-gray-700 transition-colors duration-200">
                            Show Details
                        </a>
                        <a href="group-details.php?group_id=<?php echo $group['group_id']; ?>&user_id=<?php echo $user_id; ?>" 
                           class="block w-full px-4 py-2 bg-indigo-600 text-white text-center rounded-lg hover:bg-indigo-700 transition-colors duration-200">
                            Enter Group
                        </a>
                    </div>
                </div>
            <?php endforeach; ?>
            <?php if (empty($joinedGroups)): ?>
                <div class="col-span-full text-center py-12">
                    <p class="text-gray-600 text-lg">You haven't joined any groups yet.</p>
                </div>
            <?php endif; ?>
        </div>
    </div>

    <script>
        function showGroups(type) {
            const allGroups = document.getElementById('all-groups');
            const joinedGroups = document.getElementById('joined-groups');
            const allTab = document.getElementById('all-tab');
            const joinedTab = document.getElementById('joined-tab');

            if (type === 'all') {
                allGroups.style.display = 'grid';
                joinedGroups.style.display = 'none';
                allTab.classList.add('bg-white', 'shadow-sm');
                joinedTab.classList.remove('bg-white', 'shadow-sm');
            } else {
                allGroups.style.display = 'none';
                joinedGroups.style.display = 'grid';
                joinedTab.classList.add('bg-white', 'shadow-sm');
                allTab.classList.remove('bg-white', 'shadow-sm');
            }
        }

        // Initialize the tabs
        document.addEventListener('DOMContentLoaded', function() {
            document.getElementById('all-tab').classList.add('bg-white', 'shadow-sm');
        });
    </script>
</body>
</html>
