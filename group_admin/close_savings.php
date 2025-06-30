<?php
session_start();
include 'db.php';

// Ensure only group admin can close savings
if (!isset($_SESSION['user_id']) || !isset($_SESSION['group_id'])) {
    die(json_encode(['success' => false, 'message' => 'Unauthorized access']));
}

$user_id = $_SESSION['user_id'];
$group_id = $_SESSION['group_id'];

// Verify admin status
$checkAdminQuery = "SELECT group_admin_id, group_name FROM my_group WHERE group_id = ? AND group_admin_id = ?";
$stmt = $conn->prepare($checkAdminQuery);
$stmt->bind_param('ii', $group_id, $user_id);
$stmt->execute();
$result = $stmt->get_result();

if ($result->num_rows === 0) {
    die(json_encode(['success' => false, 'message' => 'Only group admin can close savings']));
}

// Fetch group name and admin details
$row = $result->fetch_assoc();
$group_name = $row['group_name'];

// Start transaction for data integrity
$conn->begin_transaction();

try {
    // 1. Fetch approved group members
    $membersQuery = "SELECT user_id FROM group_membership WHERE group_id = ? AND status = 'approved'";
    $memberStmt = $conn->prepare($membersQuery);
    $memberStmt->bind_param('i', $group_id);
    $memberStmt->execute();
    $memberResult = $memberStmt->get_result();

    // 2. Prepare notification details
    $messageTitle = "Group Closing";
    $messageDesc = "Your savings group " . $group_name . " has been closed.";
    $notification_type = 'close_savings';

    // 3. Insert notifications for each member
    if ($memberResult->num_rows > 0) {
        $notificationQuery = "INSERT INTO notifications (target_user_id, title, message, type) VALUES (?, ?, ?, ?)";
        $notifStmt = $conn->prepare($notificationQuery);

        while ($memberRow = $memberResult->fetch_assoc()) {
            $notifStmt->bind_param('isss', $memberRow['user_id'], $messageTitle, $messageDesc, $notification_type);
            $notifStmt->execute();
        }
    }

    // 4. Delete related tables with group_id
    $tablesToDelete = [
        'investment_returns' => "DELETE ir FROM investment_returns ir 
        JOIN investments i ON ir.investment_id = i.investment_id 
        WHERE i.group_id = ?",
        'investments' => "DELETE FROM investments WHERE group_id = ?",
        'polls_vote' => "DELETE pv FROM polls_vote pv 
                         JOIN polls p ON pv.poll_id = p.poll_id 
                         WHERE p.group_id = ?",
        'polls' => "DELETE FROM polls WHERE group_id = ?",
        'group_membership' => "DELETE FROM group_membership WHERE group_id = ?",
        'leaderboard' => "DELETE FROM leaderboard WHERE group_id = ?",
        'loan_request' => "DELETE FROM loan_request WHERE group_id = ?",
        'savings' => "DELETE FROM savings WHERE group_id = ?",
        'withdrawal' => "DELETE FROM withdrawal WHERE group_id = ?",
        'transaction_info' => "DELETE FROM transaction_info WHERE group_id = ?",
        'messages' => "DELETE FROM messages WHERE group_id = ?",
        'notifications' => "DELETE FROM notifications WHERE target_group_id = ?"
    ];

    foreach ($tablesToDelete as $table => $deleteQuery) {
        $deleteStmt = $conn->prepare($deleteQuery);
        $deleteStmt->bind_param('i', $group_id);
        $deleteStmt->execute();
    }

    // 5. Finally delete the group itself
    $deleteGroupQuery = "DELETE FROM my_group WHERE group_id = ?";
    $deleteGroupStmt = $conn->prepare($deleteGroupQuery);
    $deleteGroupStmt->bind_param('i', $group_id);
    $deleteGroupStmt->execute();

    // Commit transaction
    $conn->commit();

    // Clear session
    unset($_SESSION['group_id']);

    echo json_encode(['success' => true, 'message' => 'Group successfully closed']);
} catch (Exception $e) {
    // Rollback transaction
    $conn->rollback();
    echo json_encode(['success' => false, 'message' => 'Closure failed: ' . $e->getMessage()]);
}