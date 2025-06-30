<?php
// submit_reply.php
session_start();
include 'db.php';

if (!isset($_SESSION['user_id']) || !isset($_POST['question_id']) || !isset($_POST['content'])) {
    header('Location: forum.php');
    exit();
}

$question_id = mysqli_real_escape_string($conn, $_POST['question_id']);
$user_id = mysqli_real_escape_string($conn, $_SESSION['user_id']);
$content = mysqli_real_escape_string($conn, $_POST['content']);

$query = "INSERT INTO replies (question_id, user_id, content) VALUES ('$question_id', '$user_id', '$content')";

if (mysqli_query($conn, $query)) {
    header('Location: question.php?id=' . $question_id);
} else {
    header('Location: question.php?id=' . $question_id . '&error=1');
}

mysqli_close($conn);
?>