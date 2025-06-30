<?php
// submit_reply.php
session_start();
include 'db.php';

if (!isset($_SESSION['user_id']) || !isset($_POST['question_id']) || !isset($_POST['content'])) {
    header('Location: forum.php');
    exit();
}

if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
    header('Location: question.php?id=' . $_POST['question_id'] . '&error=csrf');
    exit();
}

$question_id = $_POST['question_id'];
$user_id = $_SESSION['user_id'];
$content = trim($_POST['content']);

// Input validation
if (strlen($content) < 2 || strlen($content) > 2000) {
    header('Location: question.php?id=' . $question_id . '&error=content_length');
    exit();
}
if (!preg_match('/^[\w\s\-\.,?!]+$/u', $content)) {
    header('Location: question.php?id=' . $question_id . '&error=content_invalid');
    exit();
}

if (isset($_SESSION['last_reply_time']) && (time() - $_SESSION['last_reply_time']) < 15) {
    header('Location: question.php?id=' . $question_id . '&error=rate_limit');
    exit();
}

// Prepared statement
$stmt = $conn->prepare("INSERT INTO replies (question_id, user_id, content) VALUES (?, ?, ?)");
$stmt->bind_param('iis', $question_id, $user_id, $content);
if ($stmt->execute()) {
    $_SESSION['last_reply_time'] = time();
    header('Location: question.php?id=' . $question_id);
} else {
    error_log(date('[Y-m-d H:i:s] ') . 'submit_reply.php: ' . $stmt->error . "\n", 3, __DIR__ . '/logs/error.log');
    header('Location: question.php?id=' . $question_id . '&error=generic');
}
$stmt->close();
$conn->close();
?>