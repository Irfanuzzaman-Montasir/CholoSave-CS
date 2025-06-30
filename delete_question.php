<?php
session_start();
include 'db.php';

// Check if user is logged in and question_id is provided
if (!isset($_SESSION['user_id']) || !isset($_POST['question_id'])) {
    echo json_encode(['success' => false, 'error' => 'Unauthorized']);
    exit();
}

$user_id = mysqli_real_escape_string($conn, $_SESSION['user_id']);
$question_id = mysqli_real_escape_string($conn, $_POST['question_id']);

// Start transaction
mysqli_begin_transaction($conn);

try {
    // Verify user owns the question
    $check_query = "SELECT user_id FROM questions WHERE id = '$question_id'";
    $result = mysqli_query($conn, $check_query);
    $question = mysqli_fetch_assoc($result);

    if (!$question || $question['user_id'] != $user_id) {
        throw new Exception('Unauthorized');
    }

    // Delete all reactions to replies of this question
    $delete_reply_reactions = "DELETE reactions FROM reactions 
                             INNER JOIN replies ON reactions.reply_id = replies.id 
                             WHERE replies.question_id = '$question_id'";
    mysqli_query($conn, $delete_reply_reactions);

    // Delete all reactions to the question
    $delete_question_reactions = "DELETE FROM reactions WHERE question_id = '$question_id'";
    mysqli_query($conn, $delete_question_reactions);

    // Delete all replies to the question
    $delete_replies = "DELETE FROM replies WHERE question_id = '$question_id'";
    mysqli_query($conn, $delete_replies);

    // Finally, delete the question
    $delete_question = "DELETE FROM questions WHERE id = '$question_id' AND user_id = '$user_id'";
    $result = mysqli_query($conn, $delete_question);

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