<?php
session_start();

if (!isset($_SESSION['user_id']) || !isset($_SESSION['group_id'])) {
    echo json_encode(['error' => 'Unauthorized']);
    exit;
}

include 'db.php'; // Database connection

$group_id = $_SESSION['group_id'];

// Calculate total savings
$total_savings_query = "SELECT SUM(amount) as total_savings FROM savings WHERE group_id = ?";
$stmt = $conn->prepare($total_savings_query);
$stmt->bind_param('i', $group_id);
$stmt->execute();
$result = $stmt->get_result();
$total_savings = $result->fetch_assoc()['total_savings'];
$stmt->close();

// Calculate total approved withdrawals
$total_withdrawals_query = "SELECT SUM(amount) as total_withdrawals FROM withdrawal WHERE group_id = ? AND status = 'approved'";
$stmt = $conn->prepare($total_withdrawals_query);
$stmt->bind_param('i', $group_id);
$stmt->execute();
$result = $stmt->get_result();
$total_withdrawals = $result->fetch_assoc()['total_withdrawals'];
$stmt->close();

// Check if total savings minus total withdrawals is zero (or very close to zero)
$is_balanced = (abs($total_savings - $total_withdrawals) < 0.01);

echo json_encode([
    'is_balanced' => $is_balanced,
    'total_savings' => $total_savings,
    'total_withdrawals' => $total_withdrawals
]);
?>