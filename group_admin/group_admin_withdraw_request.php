<?php
// --- Secure Session Settings ---
ini_set('session.cookie_httponly', 1);
ini_set('session.cookie_secure', 1);
ini_set('session.use_strict_mode', 1);
ini_set('session.cookie_samesite', 'Strict');

// --- Start Session ---
session_start();

// --- Enforce HTTPS (except localhost/127.0.0.1) ---
if (!isset($_SERVER['HTTPS']) || $_SERVER['HTTPS'] !== 'on') {
    if ($_SERVER['HTTP_HOST'] !== 'localhost' && $_SERVER['HTTP_HOST'] !== '127.0.0.1') {
        header("Location: https://" . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI']);
        exit();
    }
}

// --- Include DB Connection ---
if (!isset($conn)) {
    include 'db.php';
}

// --- Security Utility Functions ---
function sanitize_input($data) {
    $data = trim($data);
    $data = stripslashes($data);
    $data = htmlspecialchars($data, ENT_QUOTES, 'UTF-8');
    return $data;
}
function log_security_event($event_type, $details, $ip_address) {
    global $conn;
    if (!$conn) return;
    $stmt = $conn->prepare("INSERT INTO security_logs (event_type, details, ip_address, timestamp) VALUES (?, ?, ?, NOW())");
    $stmt->bind_param("sss", $event_type, $details, $ip_address);
    $stmt->execute();
    $stmt->close();
}

// --- CSRF Token Generation ---
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// --- Session & Authorization Checks ---
if (!isset($_SESSION['group_id']) || !isset($_SESSION['user_id'])) {
    header("Location: /CholoSave-CS/error_page.php");
    exit;
}
$group_id = $_SESSION['group_id'];
$user_id = $_SESSION['user_id'];
$ip_address = $_SERVER['REMOTE_ADDR'];

// --- Authorization: Ensure user is admin of the group ---
$is_admin = false;
$checkAdminQuery = "SELECT group_admin_id FROM my_group WHERE group_id = ?";
if ($stmt = $conn->prepare($checkAdminQuery)) {
    $stmt->bind_param('i', $group_id);
    $stmt->execute();
    $stmt->bind_result($group_admin_id);
    $stmt->fetch();
    $stmt->close();
    if ($group_admin_id === $user_id) {
        $is_admin = true;
    }
}
if (!$is_admin) {
    log_security_event('UNAUTHORIZED_ACCESS', 'Non-admin tried to access admin withdrawal for group', $ip_address);
    header("Location: /CholoSave-CS/error_page.php");
    exit;
}

$errors = [];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // --- CSRF Token Check ---
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        log_security_event('CSRF_ATTEMPT', 'Invalid CSRF token on admin withdrawal request', $ip_address);
        $errors['csrf'] = 'Invalid form submission. Please refresh and try again.';
    }

    // --- Sanitize and Validate Input ---
    $amount = isset($_POST['amount']) ? filter_var($_POST['amount'], FILTER_SANITIZE_NUMBER_FLOAT, FILTER_FLAG_ALLOW_FRACTION) : '';
    $payment_number = isset($_POST['payment_number']) ? sanitize_input($_POST['payment_number']) : '';
    $payment_method = isset($_POST['payment_method']) ? sanitize_input($_POST['payment_method']) : '';

    // Validate amount
    if (!is_numeric($amount) || $amount <= 0) {
        $errors['amount'] = 'Please enter a valid withdrawal amount.';
    }
    // Validate payment number
    if (empty($payment_number)) {
        $errors['payment_number'] = 'Please provide a payment number.';
    }
    // Validate payment method
    if (empty($payment_method)) {
        $errors['payment_method'] = 'Please select a payment method.';
    }

    // Check if user has sufficient savings
    if (empty($errors)) {
        $savingsQuery = "SELECT SUM(amount) AS total_savings FROM savings WHERE user_id = ? AND group_id = ?";
        if ($stmt = $conn->prepare($savingsQuery)) {
            $stmt->bind_param('ii', $user_id, $group_id);
            $stmt->execute();
            $stmt->bind_result($total_savings);
            $stmt->fetch();
            $stmt->close();
            if ($total_savings < $amount) {
                $errors['amount'] = 'Insufficient savings for the requested withdrawal.';
            }
        } else {
            $errors['query'] = 'Error verifying savings.';
        }
    }

    // --- CAPTCHA Check ---
    if (!isset($_POST['cf-turnstile-response'])) {
        $errors['captcha'] = 'Please complete the security verification.';
    } else {
        $turnstile_response = $_POST['cf-turnstile-response'];
        $turnstile_secret = "0x4AAAAAABV06DJH3sKKe6kuwz8k4tbcMBs"; // Real secret key
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, 'https://challenges.cloudflare.com/turnstile/v0/siteverify');
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query([
            'secret' => $turnstile_secret,
            'response' => $turnstile_response
        ]));
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 10);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
        $verify_response = curl_exec($ch);
        $curl_error = curl_error($ch);
        curl_close($ch);
        $response_data = json_decode($verify_response);
        if ($curl_error || $response_data === null || !isset($response_data->success) || !$response_data->success) {
            $errors['captcha'] = 'Please complete the security verification.';
        }
    }

    // If no errors, insert the withdrawal request
    if (empty($errors)) {
        $conn->begin_transaction();
        try {
            $withdrawalQuery = "INSERT INTO withdrawal (user_id, group_id, amount, payment_number, payment_method) VALUES (?, ?, ?, ?, ?)";
            $stmt = $conn->prepare($withdrawalQuery);
            $stmt->bind_param('iisss', $user_id, $group_id, $amount, $payment_number, $payment_method);
            $stmt->execute();
            $stmt->close();

            // Log activity for withdrawal request
            $log_action = 'request_withdrawal';
            $log_details = json_encode(['amount' => $amount, 'payment_number' => $payment_number, 'payment_method' => $payment_method]);
            $log_stmt = $conn->prepare("INSERT INTO activity_log (user_id, group_id, action, details) VALUES (?, ?, ?, ?)");
            if ($log_stmt) {
                $log_stmt->bind_param("iiss", $user_id, $group_id, $log_action, $log_details);
                $log_stmt->execute();
                $log_stmt->close();
            }

            // Fetch admin's email and group name for notification
            $userEmail = '';
            $groupName = '';
            $userName = '';
            $userEmailQuery = "SELECT email, name FROM users WHERE id = ?";
            $userEmailStmt = $conn->prepare($userEmailQuery);
            $userEmailStmt->bind_param('i', $user_id);
            $userEmailStmt->execute();
            $userEmailStmt->bind_result($userEmail, $userName);
            $userEmailStmt->fetch();
            $userEmailStmt->close();
            $groupNameQuery = "SELECT group_name FROM my_group WHERE group_id = ?";
            $groupNameStmt = $conn->prepare($groupNameQuery);
            $groupNameStmt->bind_param('i', $group_id);
            $groupNameStmt->execute();
            $groupNameStmt->bind_result($groupName);
            $groupNameStmt->fetch();
            $groupNameStmt->close();

            // Send email notification using PHPMailer
            require_once __DIR__ . '/../vendor/phpmailer/phpmailer/src/PHPMailer.php';
            require_once __DIR__ . '/../vendor/phpmailer/phpmailer/src/SMTP.php';
            require_once __DIR__ . '/../vendor/phpmailer/phpmailer/src/Exception.php';
            $mail = new PHPMailer\PHPMailer\PHPMailer(true);
            try {
                $mail->isSMTP();
                $mail->Host = 'smtp.gmail.com';
                $mail->SMTPAuth = true;
                $mail->Username = 'cholosave.uiu@gmail.com';
                $mail->Password = 'yayd tytg zrwt igjw'; // Use App Password
                $mail->SMTPSecure = PHPMailer\PHPMailer\PHPMailer::ENCRYPTION_STARTTLS;
                $mail->Port = 587;
                $mail->setFrom('cholosave.uiu@gmail.com', 'CholoSave');
                $mail->addAddress($userEmail);
                $mail->isHTML(true);
                $mail->Subject = 'Admin Withdrawal Request Submitted';
                $mail->Body = "Dear $userName,<br><br>Your withdrawal request of <b>BDT $amount</b> as group admin has been submitted for the group <b>$groupName</b>.<br><br>We will notify you once it is processed.<br><br>Thank you for using CholoSave.";
                $mail->send();
                log_security_event('ADMIN_WITHDRAWAL_REQUEST_EMAIL_SENT', 'Admin withdrawal request email sent to user: ' . $userEmail, $ip_address);
            } catch (Exception $e) {
                log_security_event('ADMIN_WITHDRAWAL_REQUEST_EMAIL_ERROR', 'Admin withdrawal request email error for user: ' . $userEmail . ' - ' . $mail->ErrorInfo, $ip_address);
                // Do not block the transaction for email failure
            }

            $conn->commit();
            log_security_event('ADMIN_WITHDRAWAL_REQUEST_SUCCESS', 'Admin withdrawal request submitted', $ip_address);
            echo "<script>
                    document.addEventListener('DOMContentLoaded', function() {
                        Swal.fire({
                            title: 'Success!',
                            text: 'Withdrawal request submitted successfully.',
                            icon: 'success',
                            confirmButtonText: 'OK'
                        }).then(() => {
                            window.location.href = '/CholoSave-CS/group_admin/group_admin_withdraw_request.php';
                        });
                    });
                  </script>";
        } catch (Exception $e) {
            $conn->rollback();
            log_security_event('ADMIN_WITHDRAWAL_REQUEST_ERROR', 'Error processing admin withdrawal request: ' . $e->getMessage(), $ip_address);
            $errors['submission'] = 'Error processing withdrawal request: ' . $e->getMessage();
        }
    }

    // Display any errors
    if (!empty($errors)) {
        $errorMessage = implode('\n', $errors);
        log_security_event('ADMIN_WITHDRAWAL_REQUEST_FAILED', $errorMessage, $ip_address);
        echo "<script>
                document.addEventListener('DOMContentLoaded', function() {
                    Swal.fire({
                        title: 'Error!',
                        text: '$errorMessage',
                        icon: 'error',
                        confirmButtonText: 'OK'
                    });
                });
              </script>";
    }
}
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Request Withdrawal</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;600&display=swap" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>
        <!-- for dark mode -->
    <link rel="stylesheet" type="text/css" href="group_admin_dashboard_style.css"> 

    <style>
        .custom-font {
            font-family: 'Poppins', sans-serif;
        }
    </style>
</head>

<body class="bg-gray-100">
    <div class="flex h-screen">
        <?php include 'group_admin_sidebar.php'; ?>

        <div class="flex-1 flex flex-col overflow-hidden">
        <header class="flex items-center justify-between p-4 bg-white shadow dark-mode-transition">
                <div class="flex items-center justify-center w-full">
                    <button id="menu-button" class="md:hidden p-2 hover:bg-gray-100 rounded-lg transition-colors duration-200 absolute left-2">
                        <i class="fa-solid fa-bars text-xl"></i>
                    </button>
                    <h1 class="text-2xl font-semibold custom-font">
                        <i class="fa-solid fa-money-bill-wave text-blue-600 mr-3"></i>
                        Withdrawal Request
                    </h1>
                </div>
            </header>

            <div class="flex-1 overflow-y-auto p-6 w-full max-w-4xl mx-auto">
                <div class="bg-white rounded-lg shadow-lg p-8">
                    <div class="mb-8 text-center">
                    <h2 class="text-1xl font-semibold custom-font text-red-800">
                                <i class="fa-solid fa-file-signature mr-2"></i>
                                Please fill in the details below to request a withdrawal
                            </h2>
                         
                        
                    </div>

                    <form method="POST" class="space-y-6">
                        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                        <div>
                            <label for="amount" class="block text-sm font-medium text-gray-700 mb-2">Withdrawal Amount (BDT)</label>
                            <input type="number" id="amount" name="amount" class="block w-full px-4 py-3 rounded-lg border border-gray-300" placeholder="Enter amount" required>
                            <div class="text-red-500 text-sm mt-2">
                                <?php echo $errors['amount'] ?? ''; ?>
                            </div>
                        </div>

                        <div>
                            <label for="payment_number" class="block text-sm font-medium text-gray-700 mb-2">Payment Number</label>
                            <input type="text" id="payment_number" name="payment_number" class="block w-full px-4 py-3 rounded-lg border border-gray-300" placeholder="Enter payment number" required>
                            <div class="text-red-500 text-sm mt-2">
                                <?php echo $errors['payment_number'] ?? ''; ?>
                            </div>
                        </div>

                        <div>
                            <label for="payment_method" class="block text-sm font-medium text-gray-700 mb-2">Payment Method</label>
                            <select id="payment_method" name="payment_method" class="block w-full px-4 py-3 rounded-lg border border-gray-300" required>
                                <option value="">Select a method</option>
                                <option value="Bkash">Bkash</option>
                                <option value="Nagad">Nagad</option>
                                <option value="Rocket">Rocket</option>
                            </select>
                            <div class="text-red-500 text-sm mt-2">
                                <?php echo $errors['payment_method'] ?? ''; ?>
                            </div>
                        </div>

                        <!-- CAPTCHA (Cloudflare Turnstile) -->
                        <div class="mb-6">
                            <div class="cf-turnstile" data-sitekey="0x4AAAAAABV06Eefv4-cjRt7" data-theme="light"></div>
                            <div id="captchaError" class="text-red-500 text-sm mt-2">
                                <?php echo isset($errors['captcha']) ? $errors['captcha'] : ''; ?>
                            </div>
                        </div>

                        <div class="pt-4">
                            <button type="submit" class="w-full bg-blue-600 text-white py-3 px-6 rounded-lg hover:bg-blue-700">
                                Submit Withdrawal Request
                            </button>
                        </div>
                    </form>
                </div>
            </div>
        </div>
    </div>
    <script>

// // Dark mode functionality
// let isDarkMode = localStorage.getItem('darkMode') === 'true';
// const body = document.body;
// const themeToggle = document.getElementById('theme-toggle');
// const themeIcon = themeToggle.querySelector('i');
// const themeText = themeToggle.querySelector('span');

// function updateTheme() {
//     if (isDarkMode) {
//         body.classList.add('dark-mode');
//         themeIcon.classList.remove('fa-moon');
//         themeIcon.classList.add('fa-sun');
//         themeText.textContent = 'Light Mode';
//     } else {
//         body.classList.remove('dark-mode');
//         themeIcon.classList.remove('fa-sun');
//         themeIcon.classList.add('fa-moon');
//         themeText.textContent = 'Dark Mode';
//     }
// }

// // Initialize theme
// updateTheme();

// themeToggle.addEventListener('click', () => {
//     isDarkMode = !isDarkMode;
//     localStorage.setItem('darkMode', isDarkMode);
//     updateTheme();
// });


window.addEventListener('resize', handleResize);
handleResize();

// Add smooth scroll behavior
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function (e) {
        e.preventDefault();
        document.querySelector(this.getAttribute('href')).scrollIntoView({
            behavior: 'smooth'
        });
    });
});
</script>
<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
</body>

</html>
<?php include 'new_footer.php'; ?>