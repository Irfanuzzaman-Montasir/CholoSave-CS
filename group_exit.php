<?php
session_start(); // Start the session

// Check if group_id exists in the session
if (isset($_SESSION['group_id'])) {
    unset($_SESSION['group_id']); // Remove group_id from session
}

// Optional: Redirect to another page after exiting the group
header("Location: user_landing_page.php"); // Replace with the desired page
exit;
?>
