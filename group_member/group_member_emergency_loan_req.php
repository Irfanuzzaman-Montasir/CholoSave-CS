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
    header("Location: /test_project/error_page.php");
    exit;
}
$group_id = $_SESSION['group_id'];
$user_id = $_SESSION['user_id'];
$ip_address = $_SERVER['REMOTE_ADDR'];

// --- Authorization: Ensure user is a member of the group ---
$authQuery = "SELECT status FROM group_membership WHERE user_id = ? AND group_id = ? AND status = 'approved'";
$authStmt = $conn->prepare($authQuery);
$authStmt->bind_param('ii', $user_id, $group_id);
$authStmt->execute();
$authStmt->store_result();
if ($authStmt->num_rows === 0) {
    log_security_event('UNAUTHORIZED_ACCESS', 'User tried to access loan request for group not a member of', $ip_address);
    $authStmt->close();
    header("Location: /test_project/error_page.php");
    exit;
}
$authStmt->close();

$errors = [];

// --- Rate Limiting (optional, simple) ---
$rate_limit = 3; // Number of requests allowed
$rate_limit_time = 300; // 5 minutes
if (!isset($_SESSION['loan_req_rate'])) {
    $_SESSION['loan_req_rate'] = [
        'count' => 0,
        'start_time' => time(),
        'ip' => $ip_address
    ];
}
if (time() - $_SESSION['loan_req_rate']['start_time'] > $rate_limit_time) {
    $_SESSION['loan_req_rate'] = [
        'count' => 0,
        'start_time' => time(),
        'ip' => $ip_address
    ];
}

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    // --- CSRF Token Check ---
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        log_security_event('CSRF_ATTEMPT', 'Invalid CSRF token on loan request', $ip_address);
        $errors['csrf'] = 'Invalid form submission. Please refresh and try again.';
    }

    // --- Rate Limit Check ---
    if ($_SESSION['loan_req_rate']['count'] >= $rate_limit) {
        log_security_event('LOAN_RATE_LIMIT', 'Loan request rate limit exceeded', $ip_address);
        $errors['rate_limit'] = 'Too many loan requests. Please try again later.';
    }

    // --- Sanitize and Validate Input ---
    $amount = isset($_POST['amount']) ? filter_var($_POST['amount'], FILTER_SANITIZE_NUMBER_FLOAT, FILTER_FLAG_ALLOW_FRACTION) : '';
    $reason = isset($_POST['reason']) ? sanitize_input($_POST['reason']) : '';
    $returnDate = isset($_POST['returnDate']) ? sanitize_input($_POST['returnDate']) : '';
    $currentDate = date('Y-m-d');

    // Validate loan amount
    if (!is_numeric($amount) || $amount <= 0) {
        $errors['amount'] = 'Please enter a valid loan amount.';
    }
    // Validate reason
    if (empty($reason)) {
        $errors['reason'] = 'Please provide a reason for the loan request.';
    }
    // Validate return date
    if ($returnDate < $currentDate) {
        $errors['returnDate'] = 'Return date must be today or later.';
    }

    // Check emergency fund sufficiency
    if (empty($errors)) {
        $fundQuery = "SELECT emergency_fund FROM my_group WHERE group_id = ?";
        if ($fundStmt = $conn->prepare($fundQuery)) {
            $fundStmt->bind_param('i', $group_id);
            $fundStmt->execute();
            $fundStmt->bind_result($emergencyFund);
            if ($fundStmt->fetch()) {
                if ($amount > $emergencyFund) {
                    $errors['emergency_fund'] = 'The requested loan amount exceeds the available emergency fund.';
                }
            } else {
                $errors['emergency_fund'] = 'Group not found or emergency fund data unavailable.';
            }
            $fundStmt->close();
        } else {
            $errors['query'] = 'Error preparing emergency fund query.';
        }
    }

    // Check for outstanding loans
    if (empty($errors)) {
        $loanCheckQuery = "SELECT * FROM loan_request WHERE user_id = ? AND group_id = ? AND status IN ('pending', 'approved')";
        if ($loanCheckStmt = $conn->prepare($loanCheckQuery)) {
            $loanCheckStmt->bind_param('ii', $user_id, $group_id);
            $loanCheckStmt->execute();
            $loanCheckStmt->store_result();
            if ($loanCheckStmt->num_rows > 0) {
                $errors['outstanding_loan'] = 'You have an outstanding loan request in this group.';
            }
            $loanCheckStmt->close();
        }
    }

    // Check for pending leave request
    if (empty($errors)) {
        $leaveCheckQuery = "SELECT leave_request FROM group_membership WHERE user_id = ? AND group_id = ?";
        if ($leaveCheckStmt = $conn->prepare($leaveCheckQuery)) {
            $leaveCheckStmt->bind_param('ii', $user_id, $group_id);
            $leaveCheckStmt->execute();
            $leaveCheckStmt->bind_result($leaveRequest);
            if ($leaveCheckStmt->fetch() && $leaveRequest == 1) {
                $errors['leave_request'] = 'Cannot request loan while having a pending leave request.';
            }
            $leaveCheckStmt->close();
        }
    }

    // Get user's name for poll creation
    $userName = '';
    if (empty($errors)) {
        $nameQuery = "SELECT name FROM users WHERE id = ?";
        if ($nameStmt = $conn->prepare($nameQuery)) {
            $nameStmt->bind_param('i', $user_id);
            $nameStmt->execute();
            $nameStmt->bind_result($userName);
            $nameStmt->fetch();
            $nameStmt->close();
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

    // If no errors, proceed with loan request and poll creation
    if (empty($errors)) {
        $conn->begin_transaction(); // Start transaction for multiple operations
        try {
            // Insert loan request
            $loanQuery = "INSERT INTO loan_request (user_id, group_id, reason, amount, return_time) VALUES (?, ?, ?, ?, ?)";
            $stmt = $conn->prepare($loanQuery);
            $stmt->bind_param('iisis', $user_id, $group_id, $reason, $amount, $returnDate);
            $stmt->execute();
            $loanId = $stmt->insert_id;
            $stmt->close();

            // Create poll
            $pollQuestion = "$userName has requested a loan of BDT $amount. Do you approve?";
            $pollQuery = "INSERT INTO polls (group_id, poll_question) VALUES (?, ?)";
            $pollStmt = $conn->prepare($pollQuery);
            $pollStmt->bind_param('is', $group_id, $pollQuestion);
            $pollStmt->execute();
            $pollStmt->close();

            // Fetch user's email and group name for notification
            $userEmail = '';
            $groupName = '';
            $userEmailQuery = "SELECT email FROM users WHERE id = ?";
            $userEmailStmt = $conn->prepare($userEmailQuery);
            $userEmailStmt->bind_param('i', $user_id);
            $userEmailStmt->execute();
            $userEmailStmt->bind_result($userEmail);
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
                $mail->Subject = 'Loan Request Submitted';
                $mail->Body = "Dear $userName,<br><br>Your loan request of <b>BDT $amount</b> has been submitted for the group <b>$groupName</b>.<br><br>We will notify you once it is approved or rejected.<br><br>Thank you for using CholoSave.";
                $mail->send();
                log_security_event('LOAN_REQUEST_EMAIL_SENT', 'Loan request email sent to user: ' . $userEmail, $ip_address);
            } catch (Exception $e) {
                log_security_event('LOAN_REQUEST_EMAIL_ERROR', 'Loan request email error for user: ' . $userEmail . ' - ' . $mail->ErrorInfo, $ip_address);
                // Do not block the transaction for email failure
            }

            $conn->commit(); // Commit transaction
            $_SESSION['loan_req_rate']['count']++;
            log_security_event('LOAN_REQUEST_SUCCESS', 'Loan request submitted and poll created', $ip_address);
            // Show success message
            echo "<script>
                    document.addEventListener('DOMContentLoaded', function() {
                        Swal.fire({
                            title: 'Success!',
                            text: 'Loan request submitted successfully and poll created.',
                            icon: 'success',
                            confirmButtonText: 'OK'
                        }).then(() => {
                            window.location.href = '/CholoSave-CS/group_member/group_member_emergency_loan_req.php';
                        });
                    });
                  </script>";
        } catch (Exception $e) {
            $conn->rollback(); // Rollback on error
            log_security_event('LOAN_REQUEST_ERROR', 'Error processing loan request: ' . $e->getMessage(), $ip_address);
            $errors['submission'] = 'Error processing loan request: ' . $e->getMessage();
        }
    }

    // Display any errors
    if (!empty($errors)) {
        $errorMessage = implode('\n', $errors);
        log_security_event('LOAN_REQUEST_FAILED', $errorMessage, $ip_address);
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
    <title>Enhanced CholoSave Dashboard</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;600&display=swap" rel="stylesheet">
    <link rel="stylesheet" type="text/css" href="group_member_dashboard_style.css">
    <script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>
    <style>
        .custom-font {
            font-family: 'Poppins', sans-serif;
        }

        .dark-mode {
            background-color: #1a1a1a;
            color: #ffffff;
        }

        .dark-mode .bg-white {
            background-color: #2d2d2d;
            color: #ffffff;
        }

        .dark-mode .text-gray-700 {
            color: #e0e0e0;
        }

        .dark-mode .text-gray-600 {
            color: #cccccc;
        }

        .dark-mode input,
        .dark-mode textarea {
            background-color: #3d3d3d;
            border-color: #4d4d4d;
            color: #ffffff;
        }

        .dark-mode-transition {
            transition: background-color 0.3s, color 0.3s;
        }

        .dark-mode .quick-amount-wrapper label {
            background-color: #3d3d3d;
            color: #e0e0e0;
        }

        .dark-mode .quick-amount-wrapper label:hover {
            background-color: #4d4d4d;
        }

        .dark-mode .quick-amount-wrapper .peer:checked+label {
            background-color: #3b82f6;
            color: white;
        }
    </style>
</head>

<body class="bg-gray-100 dark-mode-transition">
    <div class="flex h-screen">
        <!-- Sidebar -->
        <?php include 'sidebar.php'; ?>

        <!-- Main Content -->
        <div class="flex-1 flex flex-col overflow-hidden">
            <!-- Top Bar -->
            <header class="flex items-center justify-between p-4 bg-white shadow dark-mode-transition">
                <div class="flex items-center justify-center w-full">
                    <button id="menu-button"
                        class="md:hidden p-2 hover:bg-gray-100 rounded-lg transition-colors duration-200 absolute left-2">
                        <i class="fa-solid fa-bars text-xl"></i>
                    </button>
                    <h1 class="text-2xl font-semibold custom-font">
                        <i class="fa-solid fa-hand-holding-usd mr-2 text-blue-600"></i>
                        Loan Request
                    </h1>
                </div>
            </header>

            <!-- Main Content Area -->
            <div class="flex-1 overflow-y-auto">
                <div class="p-6 w-full max-w-4xl mx-auto">
                    <div class="bg-white rounded-lg shadow-lg p-8">
                        <!-- Form Header -->
                        <div class="mb-8 text-center">
                            <h2 class="text-1xl font-semibold custom-font text-red-800">
                                <i class="fa-solid fa-file-signature mr-2"></i>
                                Please fill in the details below to submit your loan request
                            </h2>

                        </div>

                        <!-- Loan Request Form -->
                        <form method="POST" class="space-y-6">
                            <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                            <div class="space-y-6">
                                <!-- Amount Field -->
                                <div>
                                    <label for="amount" class="block text-sm font-medium font-semibold mb-2">
                                        Loan Amount (BDT)
                                    </label>
                                    <div class="relative">
                                        <span
                                            class="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-500">$</span>
                                        <input type="number" id="amount" name="amount"
                                            class="block w-full pl-8 pr-4 py-3 rounded-lg border border-gray-300 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition duration-150 ease-in-out"
                                            placeholder="Enter amount" required
                                            value="<?php echo isset($amount) ? htmlspecialchars($amount) : ''; ?>">
                                    </div>
                                    <!-- Error message for amount -->
                                    <div id="amountError" class="text-red-500 text-sm mt-2">
                                        <?php
                                        echo isset($errors['amount']) ? $errors['amount'] : '';
                                        echo isset($errors['emergency_fund']) ? $errors['emergency_fund'] : '';
                                        ?>
                                    </div>

                                </div>

                                <!-- Quick Amount Selection -->
                                <div class="mt-3 flex flex-wrap gap-2">
                                    <!-- Hidden radio buttons with styled labels -->
                                    <div class="quick-amount-wrapper">
                                        <input type="radio" name="quick_amount" id="amount500" value="500"
                                            class="hidden peer"
                                            onclick="document.getElementById('amount').value=this.value">
                                        <label for="amount500"
                                            class="px-4 py-2 bg-gray-200 hover:bg-gray-300 rounded-lg text-gray-700 transition-colors duration-200 cursor-pointer peer-checked:bg-blue-500 peer-checked:text-white">
                                            BDT 500
                                        </label>
                                    </div>

                                    <div class="quick-amount-wrapper">
                                        <input type="radio" name="quick_amount" id="amount1000" value="1000"
                                            class="hidden peer"
                                            onclick="document.getElementById('amount').value=this.value">
                                        <label for="amount1000"
                                            class="px-4 py-2 bg-gray-200 hover:bg-gray-300 rounded-lg text-gray-700 transition-colors duration-200 cursor-pointer peer-checked:bg-blue-500 peer-checked:text-white">
                                            BDT 1,000
                                        </label>
                                    </div>

                                    <div class="quick-amount-wrapper">
                                        <input type="radio" name="quick_amount" id="amount1500" value="1500"
                                            class="hidden peer"
                                            onclick="document.getElementById('amount').value=this.value">
                                        <label for="amount1500"
                                            class="px-4 py-2 bg-gray-200 hover:bg-gray-300 rounded-lg text-gray-700 transition-colors duration-200 cursor-pointer peer-checked:bg-blue-500 peer-checked:text-white">
                                            BDT 1,500
                                        </label>
                                    </div>

                                    <div class="quick-amount-wrapper">
                                        <input type="radio" name="quick_amount" id="amount2000" value="2000"
                                            class="hidden peer"
                                            onclick="document.getElementById('amount').value=this.value">
                                        <label for="amount2000"
                                            class="px-4 py-2 bg-gray-200 hover:bg-gray-300 rounded-lg text-gray-700 transition-colors duration-200 cursor-pointer peer-checked:bg-blue-500 peer-checked:text-white">
                                            BDT 2,000
                                        </label>
                                    </div>
                                </div>
                            </div>

                            <!-- Reason Field -->
                            <div>
                                <label for="reason" class="block text-sm font-medium  mb-2">
                                    Reason for Loan
                                </label>
                                <textarea id="reason" name="reason" rows="4"
                                    class="block w-full px-4 py-3 rounded-lg border border-gray-300 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition duration-150 ease-in-out"
                                    placeholder="Please explain your reason for requesting a loan"
                                    required><?php echo isset($reason) ? htmlspecialchars($reason) : ''; ?></textarea>
                                <!-- Error message for reason -->
                                <div id="reasonError" class="text-red-500 text-sm mt-2">
                                    <?php echo isset($errors['reason']) ? $errors['reason'] : ''; ?>
                                </div>
                            </div>
                            <!-- Return Date Field -->
                            <div>
                                <label for="returnDate" class="block text-sm font-medium text-gray-700 mb-2">
                                    Expected Return Date
                                </label>
                                <input type="date" id="returnDate" name="returnDate"
                                    class="block w-full px-4 py-3 rounded-lg border border-gray-300 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition duration-150 ease-in-out"
                                    required
                                    value="<?php echo isset($returnDate) ? htmlspecialchars($returnDate) : ''; ?>">
                                <!-- Error message for return date -->
                                <div id="returnDateError" class="text-red-500 text-sm mt-2">
                                    <?php echo isset($errors['returnDate']) ? $errors['returnDate'] : ''; ?>
                                </div>
                            </div>
                            <!-- Terms and Conditions Acceptance -->
                            <div class="mb-6">
                                <div class="flex items-center">
                                    <input type="checkbox" id="terms" name="terms"
                                        class="w-4 h-4 text-blue-600 border-gray-300 rounded focus:ring-blue-500"
                                        required>
                                    <label for="terms" class="ml-2 block text-sm text-gray-700">
                                        I agree to the <a href="terms_and_condition.php" target="_blank"
                                            class="text-blue-600 hover:text-blue-800 underline">Terms and Conditions</a>
                                    </label>
                                </div>
                                <!-- Error message for terms -->
                                <div id="termsError" class="text-red-500 text-sm mt-2">
                                    <?php echo isset($errors['terms']) ? $errors['terms'] : ''; ?>
                                </div>
                            </div>

                            <!-- CAPTCHA (Cloudflare Turnstile) -->
                            <div class="mb-6">
                                <div class="cf-turnstile" data-sitekey="0x4AAAAAABV06Eefv4-cjRt7" data-theme="light"></div>
                                <div id="captchaError" class="text-red-500 text-sm mt-2">
                                    <?php echo isset($errors['captcha']) ? $errors['captcha'] : ''; ?>
                                </div>
                            </div>
                        </div>

                        <!-- Submit Button -->
                        <div class="pt-4">
                            <button type="submit"
                                class="w-full bg-blue-600 text-white py-3 px-6 rounded-lg hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 transition duration-150 ease-in-out font-medium">
                                <i class="fas fa-paper-plane mr-2"></i> Submit Loan Request
                            </button>
                        </div>
                        </form>
                    </div>
                </div>
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
    <!-- Cloudflare Turnstile JS -->
    <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
</body>

</html>
<?php include 'new_footer.php'; ?>