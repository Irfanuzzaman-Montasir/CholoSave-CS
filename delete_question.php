<?php
session_start();
include 'db.php';

// Check if user is logged in and question_id is provided
if (!isset($_SESSION['user_id']) || !isset($_POST['question_id'])) {
    echo json_encode(['success' => false, 'error' => 'Unauthorized']);
    exit();
}

if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
$user_id = $_SESSION['user_id'];
$question_id = $_POST['question_id'];

// Start transaction
mysqli_begin_transaction($conn);

try {
    // Verify user owns the question
    $stmt = $conn->prepare("SELECT user_id FROM questions WHERE id = ?");
    $stmt->bind_param('i', $question_id);
    $stmt->execute();
    $result = $stmt->get_result();
    $question = $result->fetch_assoc();
    $stmt->close();

    if (!$question || $question['user_id'] != $user_id) {
        throw new Exception('Unauthorized');
    }

    // Delete all reactions to replies of this question
    $delete_reply_reactions = "DELETE reactions FROM reactions 
                             INNER JOIN replies ON reactions.reply_id = replies.id 
                             WHERE replies.question_id = ?";
    $stmt = $conn->prepare($delete_reply_reactions);
    $stmt->bind_param('i', $question_id);
    $stmt->execute();
    $stmt->close();

    // Delete all reactions to the question
    $stmt = $conn->prepare("DELETE FROM reactions WHERE question_id = ?");
    $stmt->bind_param('i', $question_id);
    $stmt->execute();
    $stmt->close();

    // Delete all replies to the question
    $stmt = $conn->prepare("DELETE FROM replies WHERE question_id = ?");
    $stmt->bind_param('i', $question_id);
    $stmt->execute();
    $stmt->close();

    // Finally, delete the question
    $stmt = $conn->prepare("DELETE FROM questions WHERE id = ? AND user_id = ?");
    $stmt->bind_param('ii', $question_id, $user_id);
    $result = $stmt->execute();
    $stmt->close();

    if (!$result) {
        throw new Exception('Failed to delete question');
    }

    // If everything is successful, commit the transaction
    mysqli_commit($conn);
    echo json_encode(['success' => true]);

} catch (Exception $e) {
    // If there's an error, rollback the changes
    mysqli_rollback($conn);
    echo json_encode(['success' => false, 'error' => $e->getMessage()]);
}

mysqli_close($conn);
?>