<?php
session_start();

// Check if group_id and user_id are set in session
if (!isset($_SESSION['group_id']) || !isset($_SESSION['user_id'])) {
    echo json_encode(['status' => 'error', 'message' => 'Session expired']);
    exit;
}

// Ensure database connection
if (!isset($conn)) {
    include 'db.php';
}

$group_id = $_SESSION['group_id'];
$user_id = $_SESSION['user_id'];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Check if the user has any outstanding loans
    $loanCheckQuery = "SELECT COUNT(*) FROM loan_request WHERE group_id = ? AND user_id = ? AND status = 'approved'";
    $stmt = $conn->prepare($loanCheckQuery);
    if (!$stmt) {
        echo json_encode(['status' => 'error', 'message' => 'Database error: Cannot prepare statement']);
        exit;
    }

    $stmt->bind_param("ii", $group_id, $user_id);
    $stmt->execute();
    $stmt->bind_result($outstanding_loans);
    $stmt->fetch();
    $stmt->close();

    if ($outstanding_loans > 0) {
        // SweetAlert message for outstanding loans
        echo json_encode([
            'status' => 'error',
            'message' => 'You cannot leave the group as you have outstanding loans.'
        ]);
        exit;
    }

    // Check if the user is the only admin in the group
    $adminCheckQuery = "SELECT group_admin_id FROM my_group WHERE group_id = ?";
    $stmt = $conn->prepare($adminCheckQuery);
    if (!$stmt) {
        echo json_encode(['status' => 'error', 'message' => 'Database error: Cannot prepare statement']);
        exit;
    }

    $stmt->bind_param("i", $group_id);
    $stmt->execute();
    $stmt->bind_result($group_admin_id);
    $stmt->fetch();
    $stmt->close();

    if ($group_admin_id == $user_id) {
        // SweetAlert message to assign another admin
        echo json_encode([
            'status' => 'error',
            'message' => 'You are the admin. Please assign another admin before leaving the group.'
        ]);
        exit;
    }

    // Success case - Admin can leave after becoming a member
    echo json_encode([
        'status' => 'success',
        'message' => 'You are allowed to leave the group after assigning another admin.'
    ]);
    exit;
}
?>
