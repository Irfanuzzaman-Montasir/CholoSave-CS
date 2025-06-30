<?php
// submit_question.php
session_start();
include 'db.php';

if (!isset($_SESSION['user_id']) || !isset($_POST['title']) || !isset($_POST['content'])) {
    header('Location: forum.php');
    exit();
}

if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
    header('Location: forum.php?error=csrf');
    exit();
}

if (isset($_SESSION['last_question_time']) && (time() - $_SESSION['last_question_time']) < 30) {
    header('Location: forum.php?error=rate_limit');
    exit();
}

$user_id = $_SESSION['user_id'];
$title = trim($_POST['title']);
$content = trim($_POST['content']);

// Input validation
if (strlen($title) < 5 || strlen($title) > 100) {
    header('Location: forum.php?error=title_length');
    exit();
}
if (strlen($content) < 10 || strlen($content) > 2000) {
    header('Location: forum.php?error=content_length');
    exit();
}
if (!preg_match('/^[\w\s\-\.,?!]+$/u', $title)) {
    header('Location: forum.php?error=title_invalid');
    exit();
}

// Prepared statement
$stmt = $conn->prepare("INSERT INTO questions (user_id, title, content) VALUES (?, ?, ?)");
$stmt->bind_param('iss', $user_id, $title, $content);
if ($stmt->execute()) {
    $new_question_id = $stmt->insert_id;
    $_SESSION['last_question_time'] = time();
    header('Location: question.php?id=' . $new_question_id);
} else {
    error_log(date('[Y-m-d H:i:s] ') . 'submit_question.php: ' . $stmt->error . "\n", 3, __DIR__ . '/logs/error.log');
    header('Location: forum.php?error=generic');
}
$stmt->close();
$conn->close();
?>