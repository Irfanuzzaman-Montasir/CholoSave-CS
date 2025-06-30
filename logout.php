<?php
include 'session.php'; // Include the session management file

// Check if the user is logged in
if (!isLoggedIn()) {
    // If the user is not logged in, you may want to redirect them elsewhere or just exit
    header("Location: /CholoSave-CS/index.php");
    exit();
}

// Start the session (it must be started before you modify session variables)
session_start(); 

// Destroy the session
session_unset();  // Remove all session variables
session_destroy();  // Destroy the session

// Redirect the user after successfully logging out
header("Location: /CholoSave-CS/index.php");
exit(); // Always call exit after a header redirect to stop further script execution
?>
