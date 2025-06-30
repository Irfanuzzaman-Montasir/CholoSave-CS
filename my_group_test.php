<?php
// Include session, database connection, and header
include 'session.php';
include 'db.php';
include 'includes/header2.php';

// Check if the user is logged in
if (!isLoggedIn()) {
    header('Location: login.php');
    exit();
}

$user_id = getUserId();

// Handle join request
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['join_group'])) {
    // Validate input
    $group_id = filter_input(INPUT_POST, 'group_id', FILTER_VALIDATE_INT);
    $response = ['status' => 'error', 'message' => ''];
    
    if ($group_id === false || $group_id === null) {
        $response['message'] = "Invalid group ID.";
    } else {
        try {
            // Start transaction
            $conn->begin_transaction();
            
            // Check if already a member
            $checkMemberQuery = "SELECT status FROM group_membership WHERE user_id = ? AND group_id = ?";
            $stmt = $conn->prepare($checkMemberQuery);
            
            if (!$stmt) {
                throw new Exception("Failed to prepare member check query: " . $conn->error);
            }
            
            $stmt->bind_param("ii", $user_id, $group_id);
            
            if (!$stmt->execute()) {
                throw new Exception("Failed to execute member check query: " . $stmt->error);
            }
            
            $result = $stmt->get_result();
            
            if ($result->num_rows > 0) {
                $membership = $result->fetch_assoc();
                if ($membership['status'] == 'approved') {
                    throw new Exception("You are already a member of this group.");
                } else {
                    throw new Exception("Your join request is pending approval.");
                }
            }
            
            // Insert join request
            $joinQuery = "INSERT INTO group_membership (user_id, group_id, status, join_request_date) VALUES (?, ?, 'pending', NOW())";
            $stmt = $conn->prepare($joinQuery);
            
            if (!$stmt) {
                throw new Exception("Failed to prepare join request query: " . $conn->error);
            }
            
            $stmt->bind_param("ii", $user_id, $group_id);
            
            if (!$stmt->execute()) {
                throw new Exception("Failed to execute join request query: " . $stmt->error);
            }
            
            // Commit transaction
            $conn->commit();
            
            $response['status'] = 'success';
            $response['message'] = "Join request sent successfully! Please wait for approval.";
            
        } catch (Exception $e) {
            // Rollback transaction on error
            $conn->rollback();
            $response['message'] = $e->getMessage();
        }
    }
    
    // Set session message for non-AJAX requests
    $_SESSION['message'] = $response['message'];
    $_SESSION['message_type'] = $response['status'];
    
    // Return JSON for AJAX requests
    if (isset($_SERVER['HTTP_X_REQUESTED_WITH']) && $_SERVER['HTTP_X_REQUESTED_WITH'] === 'XMLHttpRequest') {
        header('Content-Type: application/json');
        echo json_encode($response);
        exit();
    }
    
    // Redirect for non-AJAX requests
    header('Location: ' . $_SERVER['PHP_SELF']);
    exit();
}

// Query to get all group details
$allGroupsQuery = "
    SELECT 
        g.group_id, 
        g.group_name, 
        g.dps_type, 
        g.amount AS installment,
        g.description,
        g.members AS members_required,
        g.goal_amount,
        g.emergency_fund,
        g.time_period,
        g.start_date,
        u.name AS admin_name,
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
        ) as membership_status,
        CASE WHEN g.group_admin_id = ? THEN 1 ELSE 0 END AS is_admin
    FROM 
        my_group g
    LEFT JOIN 
        group_membership gm 
    ON 
        g.group_id = gm.group_id AND gm.status = 'approved'
    LEFT JOIN
        users u
    ON
        g.group_admin_id = u.id
    GROUP BY 
        g.group_id
";

$stmt = $conn->prepare($allGroupsQuery);
$stmt->bind_param("iii", $user_id, $user_id, $user_id);
$stmt->execute();
$allGroupsResult = $stmt->get_result();
$allGroups = [];
while ($row = $allGroupsResult->fetch_assoc()) {
    $allGroups[] = $row;
}

// Query to get user's joined groups
$joinedGroupsQuery = "
    SELECT 
        g.group_id, 
        g.group_name, 
        g.dps_type, 
        g.amount AS installment,
        g.description,
        g.members AS members_required,
        g.goal_amount,
        g.emergency_fund,
        g.time_period,
        g.start_date,
        u.name AS admin_name,
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
    LEFT JOIN
        users u
    ON
        g.group_admin_id = u.id
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
while ($row = $joinedGroupsResult->fetch_assoc()) {
    $joinedGroups[] = $row;
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Groups</title>
    <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
    <style>
        body {
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
        .active-tab {
            background-color: white;
            color: #1a56db;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        }
        .modal-overlay {
            transition: opacity 0.3s ease-in-out;
            opacity: 0;
        }
        .modal-overlay.show {
            opacity: 1;
        }
        .modal-container {
            transform: translateY(-50px);
            transition: transform 0.3s ease-in-out;
        }
        .modal-container.show {
            transform: translateY(0);
        }
        .loading-spinner {
            border: 3px solid #f3f3f3;
            border-radius: 50%;
            border-top: 3px solid #3498db;
            width: 20px;
            height: 20px;
            animation: spin 1s linear infinite;
        }
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
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
                    ($_SESSION['message_type'] === 'error' ? 'bg-red-100 text-red-700' :
                    'bg-blue-100 text-blue-700')); 
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
            
            <!-- Search Bar -->
            <div class="max-w-md mx-auto mb-8">
                <div class="relative">
                    <input 
                        type="text" 
                        id="searchInput" 
                        placeholder="Search groups..." 
                        class="w-full px-4 py-2 pl-10 rounded-lg border border-gray-300 focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                    >
                    <svg class="w-5 h-5 text-gray-400 absolute left-3 top-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/>
                    </svg>
                </div>
            </div>

            <!-- Tabs -->
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

        <!-- Group Details Modal -->
        <div id="groupDetailsModal" class="fixed inset-0 hidden z-50">
            <!-- Modal Overlay -->
            <div class="modal-overlay absolute inset-0 bg-black bg-opacity-50"></div>
            
            <!-- Modal Content -->
            <div class="modal-container absolute inset-x-0 top-[10%] mx-auto p-4 max-w-xl">
                <div class="relative bg-white rounded-xl shadow-2xl">
                    <!-- Loading Spinner -->
                    <div id="modalLoading" class="absolute inset-0 flex items-center justify-center bg-white bg-opacity-90 rounded-xl z-10 hidden">
                        <div class="loading-spinner"></div>
                    </div>

                    <!-- Modal Header -->
                    <div class="p-6 border-b border-gray-200">
                        <h3 class="text-2xl font-bold text-gray-900" id="modalGroupName"></h3>
                        <button onclick="closeGroupDetails()" class="absolute top-4 right-4 text-gray-400 hover:text-gray-600">
                            <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
                            </svg>
                        </button>
                    </div>

                    <!-- Modal Body -->
                    <div class="p-6">
                        <div class="grid grid-cols-2 gap-4 mb-6">
                            <div class="bg-blue-50 p-4 rounded-lg">
                                <p class="text-sm text-blue-600 font-medium">Type</p>
                                <p class="text-lg text-blue-900" id="modalDpsType"></p>
                            </div>
                            <div class="bg-green-50 p-4 rounded-lg">
                                <p class="text-sm text-green-600 font-medium">Installment</p>
                                <p class="text-lg text-green-900">$<span id="modalInstallment"></span></p>
                            </div>
                        </div>

                        <div class="space-y-4">
                            <div class="bg-gray-50 p-4 rounded-lg">
                                <h4 class="font-medium text-gray-700 mb-2">Group Details</h4>
                                <div class="space-y-2 text-sm">
                                    <p><span class="text-gray-500">Members:</span> <span id="modalMembers" class="text-gray-900"></span></p>
                                    <p><span class="text-gray-500">Goal Amount:</span> $<span id="modalGoalAmount" class="text-gray-900"></span></p>
                                    <p><span class="text-gray-500">Emergency Fund:</span> $<span id="modalEmergencyFund" class="text-gray-900"></span></p>
                                    <p><span class="text-gray-500">Time Period:</span> <span id="modalTimePeriod" class="text-gray-900"></span></p>
                                    <p><span class="text-gray-500">Start Date:</span> <span id="modalStartDate" class="text-gray-900"></span></p>
                                    <p><span class="text-gray-500">Admin:</span> <span id="modalAdminName" class="text-gray-900"></span></p>
                                </div>
                            </div>

                            <div class="bg-gray-50 p-4 rounded-lg">
                                <h4 class="font-medium text-gray-700 mb-2">Description</h4>
                                <p id="modalDescription" class="text-gray-600 text-sm"></p>
                            </div>
                        </div>
                    </div>

                    <!-- Modal Footer -->
                    <div class="p-6 border-t border-gray-200">
                        <button onclick="closeGroupDetails()" class="w-full px-4 py-2 bg-blue-500 text-white rounded-lg hover:bg-blue-600 transition-all focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2">
                            Close
                        </button>
                    </div>
                </div>
            </div>
        </div>

        <!-- All Groups Section -->
        <div id="all-groups" class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            <?php foreach ($allGroups as $group): ?>
                <div class="group-card rounded-xl p-6 flex flex-col" data-group-name="<?php echo strtolower(htmlspecialchars($group['group_name'])); ?>">
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
                            <?php echo htmlspecialchars($group['members_count']); ?>/<?php echo htmlspecialchars($group['members_required']); ?>
                        </p>
                    </div>
                    
                    <!-- Group Details Button -->
                    <button 
                        onclick='showGroupDetails(<?php echo json_encode($group); ?>)'
                        class="w-full px-4 py-2 bg-gray-100 text-gray-700 rounded-lg hover:bg-gray-200 transition-colors duration-200 mb-3">
                        View Details
                    </button>

                    <div class="mt-auto" id="join-button-container-<?php echo $group['group_id']; ?>">
                        <?php if ($group['is_member']): ?>
                            <?php if ($group['membership_status'] === 'approved'): ?>
                                <button 
                                    onclick="enterGroup(<?php echo $group['group_id']; ?>, <?php echo $user_id; ?>, <?php echo $group['is_admin']; ?>)"
                                    class="w-full px-4 py-2 bg-green-500 text-white rounded-lg hover:bg-green-600 transition-all">
                                    Enter Group
                                </button>
                            <?php else: ?>
                                <button class="w-full px-4 py-2 bg-yellow-500 text-white rounded-lg cursor-not-allowed opacity-75" disabled>
                                    Pending Approval
                                </button>
                            <?php endif; ?>
                        <?php else: ?>
                            <form action="" method="POST" class="join-group-form" onsubmit="return handleJoinSubmit(this, <?php echo $group['group_id']; ?>)">
                                <input type="hidden" name="group_id" value="<?php echo $group['group_id']; ?>">
                                <button type="submit" name="join_group" 
                                        class="w-full px-4 py-2 bg-blue-500 text-white rounded-lg hover:bg-blue-600 transition-all">
                                    Request to Join
                                </button>
                            </form>
                        <?php endif; ?>
                    </div>
                </div>
            <?php endforeach; ?>
            <?php if (empty($allGroups)): ?>
                <div class="col-span-full text-center py-12">
                    <p class="text-gray-600 text-lg">No groups available to join.</p>
                </div>
            <?php endif; ?>
        </div>

        <!-- My Groups Section -->
        <div id="joined-groups" class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6" style="display: none;">
            <?php foreach ($joinedGroups as $group): ?>
                <div class="group-card rounded-xl p-6 flex flex-col" data-group-name="<?php echo strtolower(htmlspecialchars($group['group_name'])); ?>">
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
                            <?php echo htmlspecialchars($group['members_count']); ?>/<?php echo htmlspecialchars($group['members_required']); ?>
                        </p>
                    </div>

                    <!-- Group Details Button -->
                    <button 
                        onclick="enterGroup(<?php echo $group['group_id']; ?>, <?php echo $user_id; ?>, <?php echo $group['is_admin']; ?>)"
                        class="w-full px-4 py-2 bg-green-500 text-white rounded-lg hover:bg-green-600 transition-all">
                        Enter Group
                    </button>
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
        function showGroupDetails(group) {
            const modal = document.getElementById('groupDetailsModal');
            const overlay = modal.querySelector('.modal-overlay');
            const container = modal.querySelector('.modal-container');
            const loading = document.getElementById('modalLoading');

            // Show modal
            modal.classList.remove('hidden');
            setTimeout(() => {
                overlay.classList.add('show');
                container.classList.add('show');
            }, 10);

            // Show loading
            loading.classList.remove('hidden');

            // Update modal content
            setTimeout(() => {
                document.getElementById('modalGroupName').textContent = group.group_name;
                document.getElementById('modalDpsType').textContent = group.dps_type;
                document.getElementById('modalInstallment').textContent = group.installment;
                document.getElementById('modalMembers').textContent = `${group.members_count}/${group.members_required}`;
                document.getElementById('modalGoalAmount').textContent = group.goal_amount;
                document.getElementById('modalEmergencyFund').textContent = group.emergency_fund;
                document.getElementById('modalTimePeriod').textContent = group.time_period;
                document.getElementById('modalStartDate').textContent = new Date(group.start_date).toLocaleDateString();
                document.getElementById('modalAdminName').textContent = group.admin_name;
                document.getElementById('modalDescription').textContent = group.description;

                // Hide loading
                loading.classList.add('hidden');
            }, 500);

            // Prevent body scrolling
            document.body.style.overflow = 'hidden';
        }

        function handleJoinSubmit(form, groupId) {
    // Submit the form
    fetch(form.action, {
        method: 'POST',
        body: new FormData(form),
        headers: {
            'X-Requested-With': 'XMLHttpRequest'
        }
    })
    .then(response => response.json())
    .then(data => {
        const container = document.getElementById(`join-button-container-${groupId}`);
        
        if (data.status === 'success') {
            container.innerHTML = `
                <button class="w-full px-4 py-2 bg-yellow-500 text-white rounded-lg cursor-not-allowed opacity-75" disabled>
                    Pending Approval
                </button>
            `;
            
            // Show success message
            showMessage(data.message, 'success');
        } else {
            // Show error message
            showMessage(data.message, 'error');
        }
    })
    .catch(error => {
        console.error('Error:', error);
        showMessage('An error occurred while processing your request.', 'error');
    });

    // Prevent default form submission
    return false;
}

// Function to show messages
function showMessage(message, type) {
    const container = document.querySelector('.container');
    const messageDiv = document.createElement('div');
    messageDiv.className = `mb-6 p-4 rounded-lg ${
        type === 'success' ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-700'
    }`;
    messageDiv.textContent = message;
    
    // Insert message at the top of the container
    container.insertBefore(messageDiv, container.firstChild);
    
    // Remove message after 5 seconds
    setTimeout(() => {
        messageDiv.remove();
    }, 5000);
}
        // Close group details
        function closeGroupDetails() {
            const modal = document.getElementById('groupDetailsModal');
            const overlay = modal.querySelector('.modal-overlay');
            const container = modal.querySelector('.modal-container');

            overlay.classList.remove('show');
            container.classList.remove('show');

            setTimeout(() => {
                modal.classList.add('hidden');
                document.body.style.overflow = 'auto';
            }, 300);
        }

        // Close modal when clicking overlay
        document.querySelector('.modal-overlay').addEventListener('click', closeGroupDetails);

        // Function to show groups (All/My Groups tabs)
        function showGroups(type) {
            const allGroups = document.getElementById('all-groups');
            const joinedGroups = document.getElementById('joined-groups');
            const allTab = document.getElementById('all-tab');
            const joinedTab = document.getElementById('joined-tab');
            
            if (type === 'all') {
                allGroups.style.display = 'grid';
                joinedGroups.style.display = 'none';
                allTab.classList.add('active-tab');
                joinedTab.classList.remove('active-tab');
            } else {
                allGroups.style.display = 'none';
                joinedGroups.style.display = 'grid';
                allTab.classList.remove('active-tab');
                joinedTab.classList.add('active-tab');
            }
        }

        // Search functionality
        document.getElementById('searchInput').addEventListener('input', function() {
            const filter = this.value.toLowerCase();
            const groups = document.querySelectorAll('.group-card');
            
            groups.forEach(group => {
                const groupName = group.dataset.groupName;
                const isVisible = groupName.includes(filter);
                group.style.display = isVisible ? '' : 'none';
            });
        });

        // Function to enter group
        function enterGroup(groupId, userId, isAdmin) {
            if (isAdmin) {
                window.location.href = "group_admin_dashboard.php?group_id=" + groupId + "&user_id=" + userId;
            } else {
                window.location.href = "member_dashboard.php?group_id=" + groupId + "&user_id=" + userId;
            }
        }
    </script>
</body>
</html>


