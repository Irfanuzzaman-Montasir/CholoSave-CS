<?php
session_start();
include('session.php');  // Assuming user session is already set (user_id)

// Include the database connection file
include('db.php'); // Correct path to db.php

// Check if group_id is passed via POST
if (isset($_POST['group_id']) && isset($_SESSION['user_id'])) {
    // Store group_id in session
    $_SESSION['group_id'] = $_POST['group_id'];

    // Get the user_id from the session
    $user_id = $_SESSION['user_id'];
    $group_id = $_SESSION['group_id'];

    // Query to check if the user is admin or member in the group
    $query = "SELECT is_admin FROM group_membership WHERE group_id = ? AND user_id = ?";
    if ($stmt = $conn->prepare($query)) {  // Use $conn instead of $mysqli
        $stmt->bind_param("ii", $group_id, $user_id);  // Bind the group_id and user_id as integers
        $stmt->execute();
        $stmt->store_result();
        
        // Check if the user is found in the group
        if ($stmt->num_rows > 0) {
            $stmt->bind_result($is_admin);
            $stmt->fetch();

            // If the user is an admin, redirect to the admin page
            if ($is_admin) {
                header("Location: /CholoSave-CS/group_admin/group_admin_dashboard.php");
            } else {
                // If the user is a member, redirect to the member page
                header("Location: /CholoSave-CS/group_member/group_member_dashboard.php");
            }
            exit;
        } else {
            // If user is not part of the group, redirect to error page
            header("Location: http://localhost/CholoSave-CS/error_page.php");
            exit;
        }

        $stmt->close();  // Close the statement
    } else {
        // If query fails to prepare
        header("Location: http://localhost/CholoSave-CS/error_page.php");
        exit;
    }
} else {
    // Redirect to error page if group_id is not set or user is not logged in
    header("Location: http://localhost/CholoSave-CS/error_page.php");
    exit;
}
