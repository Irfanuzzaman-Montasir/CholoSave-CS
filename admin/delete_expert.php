<?php
include 'db.php';
session_start();

if (!isset($_SESSION['user_id']) || $_SESSION['role'] !== 'admin') {
    header("Location: /CholoSave-CS/admin/login.php");
    exit;
}

if (isset($_GET['id'])) {
    $expert_id = $_GET['id'];
    
    // Get expert image filename before deletion
    $query = "SELECT image FROM expert_team WHERE id = ?";
    $stmt = $conn->prepare($query);
    $stmt->bind_param("i", $expert_id);
    $stmt->execute();
    $result = $stmt->get_result();
    $expert = $result->fetch_assoc();
    
    // Delete the expert
    $delete_query = "DELETE FROM expert_team WHERE id = ?";
    $stmt = $conn->prepare($delete_query);
    $stmt->bind_param("i", $expert_id);
    
    if ($stmt->execute()) {
        // Delete the expert's image file if it exists
        if ($expert['image']) {
            $image_path = "/CholoSave-CS/uploads/experts/" . $expert['image'];
            if (file_exists($image_path)) {
                unlink($image_path);
            }
        }
        header("Location: /CholoSave-CS/admin/edit_expert.php?deleted=1");
    } else {
        header("Location: /CholoSave-CS/admin/edit_expert.php?error=1");
    }
} else {
    header("Location: /CholoSave-CS/admin/edit_expert.php");
}
exit;
?>