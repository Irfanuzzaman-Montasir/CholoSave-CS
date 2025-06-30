<?php
// submit_question.php
session_start();
include 'db.php';

if (!isset($_SESSION['user_id']) || !isset($_POST['title']) || !isset($_POST['content'])) {
    header('Location: forum.php');
    exit();
}

$user_id = mysqli_real_escape_string($conn, $_SESSION['user_id']);
$title = mysqli_real_escape_string($conn, $_POST['title']);
$content = mysqli_real_escape_string($conn, $_POST['content']);

$query = "INSERT INTO questions (user_id, title, content) VALUES ('$user_id', '$title', '$content')";

if (mysqli_query($conn, $query)) {
    $new_question_id = mysqli_insert_id($conn);
    header('Location: question.php?id=' . $new_question_id);
} else {
    header('Location: forum.php?error=1');
}

mysqli_close($conn);
?>