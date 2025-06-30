<?php
include __DIR__ . '/session.php';

// Check if the user is logged in
if (!isLoggedIn()) {
    // If the user is not logged in, you may want to redirect them elsewhere or just exit
    header("Location: /CholoSave-CS/login.php");
    exit();
}

// Clear the session
clearUserSession();

// Redirect to login page
header("Location: /CholoSave-CS/login.php");
exit();
?>
