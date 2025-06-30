<?php
session_start();

function isLoggedIn() {
    return isset($_SESSION['user_id']);
}

function requireLogin() {
    if (!isLoggedIn()) {
        header("Location: /CholoSave-CS/admin/login.php");
        exit();
    }
}

function requireAdmin() {
    if (!isLoggedIn() || $_SESSION['role'] !== 'admin') {
        header("Location: /CholoSave-CS/admin/login.php");
        exit();
    }
}

function getUserRole() {
    return $_SESSION['role'] ?? null;
}

function getUserId() {
    return $_SESSION['user_id'] ?? null;
}

function getUserName() {
    return $_SESSION['name'] ?? null;
}

function setUserSession($user_id, $name, $role) {
    $_SESSION['user_id'] = $user_id;
    $_SESSION['name'] = $name;
    $_SESSION['role'] = $role;
}

function clearUserSession() {
    session_unset();
    session_destroy();
}
?> 