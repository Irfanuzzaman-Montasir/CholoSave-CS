<?php
// Enforce HTTPS
if (!isset($_SERVER['HTTPS']) || $_SERVER['HTTPS'] !== 'on') {
    if ($_SERVER['HTTP_HOST'] !== 'localhost' && $_SERVER['HTTP_HOST'] !== '127.0.0.1') {
        header("Location: https://" . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI']);
        exit();
    }
}
include 'db.php';
include 'password_utils.php';

require_once __DIR__ . '/vendor/phpmailer/phpmailer/src/PHPMailer.php';
require_once __DIR__ . '/vendor/phpmailer/phpmailer/src/SMTP.php';
require_once __DIR__ . '/vendor/phpmailer/phpmailer/src/Exception.php';

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;
session_start();

// Function to sanitize input
function sanitize_input($data) {
    $data = trim($data);
    $data = stripslashes($data);
    $data = htmlspecialchars($data, ENT_QUOTES, 'UTF-8');
    return $data;
}
// Function to log security events
function log_security_event($event_type, $details, $ip_address) {
    global $conn;
    $stmt = $conn->prepare("INSERT INTO security_logs (event_type, details, ip_address, timestamp) VALUES (?, ?, ?, NOW())");
    $stmt->bind_param("sss", $event_type, $details, $_SERVER['REMOTE_ADDR']);
    $stmt->execute();
    $stmt->close();
}

if (!isset($_SESSION['reset_email']) || !isset($_SESSION['otp_verified'])) {
    header('Location: forgot_password.php');
    exit();
}

$email = $_SESSION['reset_email'];
$error_message = '';
$ip_address = $_SERVER['REMOTE_ADDR'];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $new_password = sanitize_input($_POST['new_password'] ?? '');
    $confirm_password = sanitize_input($_POST['confirm_password'] ?? '');
    if ($new_password !== $confirm_password) {
        $error_message = "Passwords do not match.";
    } else {
        // Validate password strength
        $strength = PasswordUtils::validatePasswordStrength($new_password);
        if (!$strength['valid']) {
            $error_message = "Password requirements: " . implode(" ", $strength['errors']);
        } else {
            // Hash new password
            $hashed_password = PasswordUtils::hashPassword($new_password);
            // Update password in database and clear OTP
            $query = "UPDATE users SET password = ?, otp = NULL, otp_expiry = NULL WHERE email = ?";
            $stmt = $conn->prepare($query);
            $stmt->bind_param("ss", $hashed_password, $email);
            if ($stmt->execute()) {
                // Log success
                log_security_event('FORGOT_PASSWORD_RESET_SUCCESS', 'Password reset for: ' . $email, $ip_address);
                // Send password change notification email
                $mail = new PHPMailer(true);
                try {
                    $mail->isSMTP();
                    $mail->Host = 'smtp.gmail.com';
                    $mail->SMTPAuth = true;
                    $mail->Username = 'cholosave.uiu@gmail.com';
                    $mail->Password = 'dhsq tqmy dfap ztob'; // Use App Password
                    $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
                    $mail->Port = 587;
                    $mail->setFrom('cholosave.uiu@gmail.com', 'CholoSave');
                    $mail->addAddress($email);
                    $mail->isHTML(true);
                    $mail->Subject = 'Your CholoSave Password Has Been Changed';
                    $mail->Body = "Your password was just changed. If this was not you, please <a href='https://yourdomain.com/forgot_password.php'>reset your password</a> immediately or contact support.";
                    $mail->send();
                    log_security_event('PASSWORD_RESET_NOTIFICATION_SENT', 'Password reset notification sent to: ' . $email, $ip_address);
                } catch (Exception $e) {
                    log_security_event('PASSWORD_RESET_NOTIFICATION_FAIL', 'Failed to send password reset notification to: ' . $email, $ip_address);
                }
                // Clear session data
                unset($_SESSION['reset_email']);
                unset($_SESSION['otp_verified']);
                // Redirect to login with success message
                header('Location: login.php?reset=success');
                exit();
            } else {
                $error_message = "Password reset failed. Please try again.";
                log_security_event('FORGOT_PASSWORD_RESET_FAIL', 'Password reset failed for: ' . $email, $ip_address);
            }
        }
    }
}
// Cancel logic
if (isset($_GET['cancel'])) {
    unset($_SESSION['reset_email']);
    unset($_SESSION['otp_verified']);
    header('Location: login.php');
    exit();
}
?>
<!DOCTYPE html>
<html>
<head>
    <title>Reset Password</title>
    <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
</head>
<body class="bg-gray-100 flex items-center justify-center min-h-screen">
    <div class="w-full max-w-md p-8 space-y-8 bg-white rounded shadow-lg">
        <h2 class="text-2xl font-bold text-center">Reset Password</h2>
        <?php if ($error_message): ?>
            <div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded">
                <?php echo $error_message; ?>
            </div>
        <?php endif; ?>
        <form method="POST" class="space-y-6">
            <div>
                <label for="new_password" class="block text-sm font-medium text-gray-700">New Password</label>
                <input type="password" name="new_password" required 
                       class="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm">
                <div class="text-xs text-gray-500 mt-1">
                    Password must be at least 8 characters, include uppercase, lowercase, number, and special character.
                </div>
            </div>
            <div>
                <label for="confirm_password" class="block text-sm font-medium text-gray-700">Confirm Password</label>
                <input type="password" name="confirm_password" required 
                       class="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm">
            </div>
            <button type="submit" 
                    class="w-full px-4 py-2 text-white bg-blue-600 rounded-md hover:bg-blue-700">
                Reset Password
            </button>
        </form>
        <div class="text-center mt-4">
            <a href="?cancel=1" class="text-blue-600 hover:underline">Cancel</a>
        </div>
    </div>
</body>
</html>

