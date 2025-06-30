<?php
session_start();
include 'db.php';
include 'vendor/autoload.php';

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

// Check if user is coming from payment page
if (!isset($_SESSION['group_id'], $_SESSION['user_id'])) {
    header("Location: payment-page.php");
    exit;
}

$group_id = $_SESSION['group_id'];
$user_id = $_SESSION['user_id'];

$error_message = '';
$otp_attempts = $_SESSION['otp_attempts'] ?? 0;

// Fetch payment details from database
$fetch_stmt = $conn->prepare("SELECT * FROM payment_otps WHERE user_id = ? AND group_id = ? ORDER BY created_at DESC LIMIT 1");
$fetch_stmt->bind_param('ii', $user_id, $group_id);
$fetch_stmt->execute();
$payment_otp_result = $fetch_stmt->get_result()->fetch_assoc();

if (!$payment_otp_result) {
    header("Location: payment-page.php");
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $entered_otp = $_POST['otp'] ?? '';
    
    // Check OTP validity
    if ($entered_otp === $payment_otp_result['otp'] && 
        strtotime($payment_otp_result['otp_expiry']) > time()) {
        
        // Start transaction
        $conn->begin_transaction();

        try {
            // Insert into transaction_info
            $insert_stmt = $conn->prepare("INSERT INTO transaction_info (user_id, group_id, amount, transaction_id, payment_method) VALUES (?, ?, ?, ?, ?)");
            $insert_stmt->bind_param('iidss', $user_id, $group_id, $payment_otp_result['amount'], $payment_otp_result['transaction_id'], $payment_otp_result['payment_method']);
            $insert_stmt->execute();

            // Insert into savings
            $savings_stmt = $conn->prepare("INSERT INTO savings (user_id, group_id, amount) VALUES (?, ?, ?)");
            $savings_stmt->bind_param('iid', $user_id, $group_id, $payment_otp_result['amount']);
            $savings_stmt->execute();

            // Update time_period_remaining in group_membership
            $update_stmt = $conn->prepare("UPDATE group_membership SET time_period_remaining = time_period_remaining - 1 WHERE user_id = ? AND group_id = ?");
            $update_stmt->bind_param('ii', $user_id, $group_id);
            $update_stmt->execute();

            // Add 1% of the payment amount to the leaderboard
            $points = $payment_otp_result['amount'] * 0.01; 
            $update_leaderboard_stmt = $conn->prepare("UPDATE leaderboard SET points = points + ? WHERE group_id = ?");
            $update_leaderboard_stmt->bind_param('di', $points, $group_id);
            $update_leaderboard_stmt->execute();

            // Delete the used OTP
            $delete_otp_stmt = $conn->prepare("DELETE FROM payment_otps WHERE user_id = ? AND group_id = ?");
            $delete_otp_stmt->bind_param('ii', $user_id, $group_id);
            $delete_otp_stmt->execute();

            $conn->commit();
            
            // Store transaction details in session
            $_SESSION['transaction_id'] = $payment_otp_result['transaction_id'];
            $_SESSION['total_amount'] = $payment_otp_result['amount'];
            $_SESSION['payment_method'] = $payment_otp_result['payment_method'];
            $_SESSION['transaction_date'] = date('Y-m-d H:i:s');

            header("Location: success_payment.php");
            exit;
        } catch (Exception $e) {
            $conn->rollback();
            header("Location: failure_page.php");
            exit;
        }
    } else {
        $error_message = "Invalid or expired OTP. Please try again.";
        $otp_attempts++;
        $_SESSION['otp_attempts'] = $otp_attempts;

        // Limit OTP attempts
        if ($otp_attempts >= 3) {
            // Clear OTP and redirect to payment page
            $delete_otp_stmt = $conn->prepare("DELETE FROM payment_otps WHERE user_id = ? AND group_id = ?");
            $delete_otp_stmt->bind_param('ii', $user_id, $group_id);
            $delete_otp_stmt->execute();

            header("Location: payment-page.php");
            exit;
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OTP Verification</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-100 flex items-center justify-center min-h-screen">
    <div class="w-full max-w-md p-8 space-y-8 bg-white rounded shadow-lg">
        <h2 class="text-2xl font-bold text-center">OTP Verification</h2>
        
        <?php if ($error_message): ?>
            <div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded">
                <?php echo $error_message; ?>
            </div>
        <?php endif; ?>

        <form method="POST" class="space-y-6">
            <div>
                <label for="otp" class="block text-sm font-medium text-gray-700">Enter OTP</label>
                <input type="text" name="otp" required 
                       class="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm"
                       maxlength="6" pattern="\d{6}">
                <p class="text-sm text-gray-500 mt-2">OTP sent to your registered email. Valid for 2 minutes.</p>
            </div>
            <button type="submit" 
                    class="w-full px-4 py-2 text-white bg-blue-600 rounded-md hover:bg-blue-700">
                Verify OTP
            </button>
        </form>

        <div class="text-center">
            <a href="payment-page.php" class="text-sm text-blue-600 hover:underline">
                Cancel Payment
            </a>
        </div>
    </div>
</body>
</html>