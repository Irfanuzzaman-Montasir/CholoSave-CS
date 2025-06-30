<?php
include 'db.php';

session_start();

if (!isset($_SESSION['reset_email'])) {
    header('Location: forgot_password.php');
    exit();
}

$email = $_SESSION['reset_email'];
$error_message = '';


$query = "SELECT otp_expiry FROM users WHERE email = ?";
$stmt = $conn->prepare($query);
$stmt->bind_param("s", $email);
$stmt->execute();
$result = $stmt->get_result();
$row = $result->fetch_assoc();
$otp_expiry_time = $row['otp_expiry'];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $entered_otp = trim($_POST['otp']);

    date_default_timezone_set('Asia/Dhaka');

    // Check OTP in database with time-based validation
    $query = "SELECT * FROM users WHERE email = ? AND otp = ? AND otp_expiry > NOW()";
    $stmt = $conn->prepare($query);
    $stmt->bind_param("ss", $email, $entered_otp);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows > 0) {
        // Valid OTP, proceed to reset password
        $_SESSION['otp_verified'] = true;
        header('Location: reset_password.php');
        exit();
    } else {
        $error_message = "Invalid or expired OTP";
    }
}
?>
<!DOCTYPE html>
<html>
<head>
    <title>Verify OTP</title>
    <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
</head>
<body class="bg-gray-100 flex items-center justify-center min-h-screen">
    <div class="w-full max-w-md p-8 space-y-8 bg-white rounded shadow-lg">
        <h2 class="text-2xl font-bold text-center">Verify OTP</h2>
        
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
            </div>
            <div id="timer" class="text-center text-red-600 font-bold"></div>
            <button type="submit" 
                    class="w-full px-4 py-2 text-white bg-blue-600 rounded-md hover:bg-blue-700">
                Verify OTP
            </button>
        </form>
    </div>

    <script>
function formatTime(date) {
    let hours = date.getHours();
    const minutes = date.getMinutes();
    const ampm = hours >= 12 ? 'PM' : 'AM';
    
    hours = hours % 12;
    hours = hours ? hours : 12; // the hour '0' should be '12'
    const minutesStr = minutes < 10 ? '0' + minutes : minutes;

    return `${hours}:${minutesStr} ${ampm}`;
}

// Assuming you'll pass the OTP expiry time from PHP
const otpExpiryTime = new Date('<?php echo $otp_expiry_time; ?>');
const timerElement = document.getElementById('timer');

function updateOTPExpiry() {
    const now = new Date();
    
    if (now > otpExpiryTime) {
        timerElement.textContent = 'OTP Expired';
        return;
    }

    const expiryTimeFormatted = formatTime(otpExpiryTime);
    timerElement.textContent = `OTP will expire at ${expiryTimeFormatted}`;
}

// Initial call
updateOTPExpiry();
</script>
</body>
</html>