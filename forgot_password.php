<?php
ob_start();
// Enforce HTTPS
if (!isset($_SERVER['HTTPS']) || $_SERVER['HTTPS'] !== 'on') {
    if ($_SERVER['HTTP_HOST'] !== 'localhost' && $_SERVER['HTTP_HOST'] !== '127.0.0.1') {
        header("Location: https://" . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI']);
        exit();
    }
}
include 'db.php';
include 'vendor/autoload.php'; 
include 'includes/new_header.php';

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

if (session_status() == PHP_SESSION_NONE) {
    session_start();
}

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

$email = '';
$error_message = '';
$success_message = '';
$ip_address = $_SERVER['REMOTE_ADDR'];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = sanitize_input($_POST['email'] ?? '');

    // Check if email exists in database
    $query = "SELECT * FROM users WHERE email = ?";
    $stmt = $conn->prepare($query);
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $result = $stmt->get_result();

    // Always show generic message
    $success_message = "If this email is registered, you will receive an OTP to reset your password.";

    if ($result->num_rows > 0) {
        // Generate OTP
        $otp = sprintf("%06d", mt_rand(1, 999999));
        date_default_timezone_set('Asia/Dhaka');
        $otp_expiry = date('Y-m-d H:i:s', strtotime('+2 minutes'));
        $otp_hash = hash('sha256', $otp);
        // Store OTP hash in database
        $update_query = "UPDATE users SET otp = ?, otp_expiry = ? WHERE email = ?";
        $update_stmt = $conn->prepare($update_query);
        $update_stmt->bind_param("sss", $otp_hash, $otp_expiry, $email);
        $update_stmt->execute();
        // Send OTP via email using PHPMailer
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
            $mail->Subject = 'Password Reset OTP';
            $mail->Body = "Your OTP for password reset is: <b>$otp</b>. This OTP will expire in 2 minutes.";
            $mail->send();
            // Store email in session for OTP verification
            $_SESSION['reset_email'] = $email;
            // Clear output buffer and redirect
            ob_end_clean();
            header('Location: /CholoSave-CS/verify_otp.php');
            exit();
        } catch (Exception $e) {
            $error_message = "OTP could not be sent. {$mail->ErrorInfo}";
        }
    }
}
?>



<!DOCTYPE html>
<html>
<head>
    <title>Forgot Password</title>
    <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
</head>
<body class="bg-gray-100 flex items-center justify-center min-h-screen">
    <div class="w-full max-w-md p-8 space-y-8 bg-white rounded shadow-lg">
        <h2 class="text-2xl font-bold text-center">Forgot Password</h2>
        
        <?php if ($error_message): ?>
            <div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded">
                <?php echo $error_message; ?>
            </div>
        <?php endif; ?>

        <form method="POST" class="space-y-6">
            <div>
                <label for="email" class="block text-sm font-medium text-gray-700">Email Address</label>
                <input type="email" name="email" required 
                       class="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm"
                       value="<?php echo htmlspecialchars($email); ?>">
            </div>
            <button type="submit" 
                    class="w-full px-4 py-2 text-white bg-blue-600 rounded-md hover:bg-blue-700">
                Get OTP
            </button>
        </form>
    </div>
</body>
</html>
