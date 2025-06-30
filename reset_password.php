<?php
include 'db.php';
session_start();


if (!isset($_SESSION['reset_email']) || !isset($_SESSION['otp_verified'])) {
    header('Location: forgot_password.php');
    exit();
}

$email = $_SESSION['reset_email'];
$error_message = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $new_password = trim($_POST['new_password']);
    $confirm_password = trim($_POST['confirm_password']);

    if ($new_password !== $confirm_password) {
        $error_message = "Passwords do not match";
    } else {
        // Hash new password
        $hashed_password = password_hash($new_password, PASSWORD_DEFAULT);

        // Update password in database and clear OTP
        $query = "UPDATE users SET password = ?, otp = NULL, otp_expiry = NULL WHERE email = ?";
        $stmt = $conn->prepare($query);
        $stmt->bind_param("ss", $hashed_password, $email);
        
        if ($stmt->execute()) {
            // Clear session data
            unset($_SESSION['reset_email']);
            unset($_SESSION['otp_verified']);

            // Redirect to login with success message
            header('Location: login.php?reset=success');
            exit();
        } else {
            $error_message = "Password reset failed. Please try again.";
        }
    }
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
                       class="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm"
                       >
            </div>
            <div>
                <label for="confirm_password" class="block text-sm font-medium text-gray-700">Confirm Password</label>
                <input type="password" name="confirm_password" required 
                       class="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm"
                       >
            </div>
            <button type="submit" 
                    class="w-full px-4 py-2 text-white bg-blue-600 rounded-md hover:bg-blue-700">
                Reset Password
            </button>
        </form>
    </div>
</body>
</html>

