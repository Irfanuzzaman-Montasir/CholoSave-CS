<?php
// Save loan_id to session and redirect
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['loan_id'])) {
    session_start();
    $_SESSION['loan_id'] = $_POST['loan_id'];
    header("Location: group_admin_loan_pay.php"); // Redirect to the payment page
    exit;
}
?>
