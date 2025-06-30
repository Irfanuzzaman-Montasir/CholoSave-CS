<?php
// vote.php
session_start();
include 'db.php';

if (!isset($_SESSION['user_id']) || !isset($_POST['type']) || !isset($_POST['id']) || !isset($_POST['vote_type'])) {
    echo json_encode(['success' => false]);
    exit();
}

$user_id = mysqli_real_escape_string($conn, $_SESSION['user_id']);
$id = mysqli_real_escape_string($conn, $_POST['id']);
$vote_type = mysqli_real_escape_string($conn, $_POST['vote_type']);
$type = mysqli_real_escape_string($conn, $_POST['type']);

// Start transaction
mysqli_begin_transaction($conn);

try {
    // Remove any existing votes by this user
    if ($type === 'question') {
        $delete_query = "DELETE FROM reactions WHERE user_id = '$user_id' AND question_id = '$id'";
        $success = mysqli_query($conn, $delete_query);

        if ($success) {
            // Insert new vote
            $insert_query = "INSERT INTO reactions (user_id, question_id, reaction_type) 
                           VALUES ('$user_id', '$id', '$vote_type')";
            $success = mysqli_query($conn, $insert_query);
        }
    } else {
        $delete_query = "DELETE FROM reactions WHERE user_id = '$user_id' AND reply_id = '$id'";
        $success = mysqli_query($conn, $delete_query);

        if ($success) {
            // Insert new vote
            $insert_query = "INSERT INTO reactions (user_id, reply_id, reaction_type) 
                           VALUES ('$user_id', '$id', '$vote_type')";
            $success = mysqli_query($conn, $insert_query);
        }
    }

    if ($success) {
        mysqli_commit($conn);
        echo json_encode(['success' => true]);
    } else {
        throw new Exception('Query failed');
    }
} catch (Exception $e) {
    mysqli_rollback($conn);
    echo json_encode(['success' => false]);
}

mysqli_close($conn);
?>