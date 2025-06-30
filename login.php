<?php
// Set secure session parameters BEFORE starting the session
ini_set('session.cookie_httponly', 1);
ini_set('session.cookie_secure', 1);
ini_set('session.use_strict_mode', 1);
ini_set('session.cookie_samesite', 'Strict');

// Start secure session
session_start();

// If this is a GET request, clear any pending 2FA session
if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_SESSION['pending_2fa_user_id'])) {
    unset($_SESSION['pending_2fa_user_id']);
}

// Force HTTPS (if not in development)
if (!isset($_SERVER['HTTPS']) || $_SERVER['HTTPS'] !== 'on') {
    if ($_SERVER['HTTP_HOST'] !== 'localhost' && $_SERVER['HTTP_HOST'] !== '127.0.0.1') {
        header("Location: https://" . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI']);
        exit();
    }
}

// Include the database connection, password utilities, and session management
include 'db.php';
include 'password_utils.php';
include 'session.php';

// Rate limiting configuration
$rate_limit = 5; // Number of login attempts allowed
$rate_limit_time = 300; // Time window in seconds (5 minutes)
$ip_address = $_SERVER['REMOTE_ADDR'];

// Initialize rate limit tracking if not exists
if (!isset($_SESSION['login_rate_limit'])) {
    $_SESSION['login_rate_limit'] = [
        'count' => 0,
        'start_time' => time(),
        'ip' => $ip_address
    ];
}
// Check if rate limit has expired
if (time() - $_SESSION['login_rate_limit']['start_time'] > $rate_limit_time) {
    $_SESSION['login_rate_limit'] = [
        'count' => 0,
        'start_time' => time(),
        'ip' => $ip_address
    ];
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
    $stmt->bind_param("sss", $event_type, $details, $ip_address);
    $stmt->execute();
    $stmt->close();
}

// Initialize variables
$email = '';
$password = '';
$error_message = '';
$success_message = '';

// Handle form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    try {
        // Check rate limit
        if ($_SESSION['login_rate_limit']['count'] >= $rate_limit) {
            log_security_event('LOGIN_RATE_LIMIT_EXCEEDED', 'Login rate limit exceeded', $ip_address);
            throw new Exception("Too many login attempts. Please try again in " . ceil(($rate_limit_time - (time() - $_SESSION['login_rate_limit']['start_time'])) / 60) . " minutes.");
        }

        // Only require CAPTCHA if not in OTP stage
        if (!isset($_POST['otp_stage'])) {
            if (!isset($_POST['cf-turnstile-response'])) {
                throw new Exception("Please complete the security verification.");
            }
            $turnstile_response = $_POST['cf-turnstile-response'];
            $turnstile_secret = "0x4AAAAAABV06DJH3sKKe6kuwz8k4tbcMBs"; // Replace with your actual secret key
            // Verify with Cloudflare
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
            if ($curl_error) {
                throw new Exception("Network error during verification. Please try again.");
            }
            $response_data = json_decode($verify_response);
            if ($response_data === null || !isset($response_data->success) || !$response_data->success) {
                log_security_event('LOGIN_CAPTCHA_FAILED', 'Turnstile verification failed', $ip_address);
                throw new Exception("Please complete the security verification.");
            }
        }

        // Get and sanitize form data
        $email = sanitize_input($_POST['email'] ?? '');
        $password = $_POST['password'] ?? '';
        $otp_input = $_POST['otp'] ?? null;
        $otp_stage = isset($_POST['otp_stage']);

        // If OTP is being submitted (second step)
        if ($otp_stage && isset($_SESSION['pending_2fa_user_id'])) {
            $user_id = $_SESSION['pending_2fa_user_id'];
            $query = "SELECT * FROM users WHERE id = ?";
            $stmt = $conn->prepare($query);
            $stmt->bind_param("i", $user_id);
            $stmt->execute();
            $result = $stmt->get_result();
            $user = $result->fetch_assoc();
            $stmt->close();
            if (!$user) {
                throw new Exception("Session expired. Please login again.");
            }
            if (empty($otp_input) || !preg_match('/^[0-9]{6}$/', $otp_input)) {
                throw new Exception("Please enter a valid 6-digit OTP.");
            }
            $otp_hash = hash('sha256', $otp_input);
            if ($otp_hash !== $user['otp'] || strtotime($user['otp_expiry']) < time()) {
                log_security_event('LOGIN_2FA_FAILED', 'Invalid or expired OTP for user: ' . $user['email'], $ip_address);
                throw new Exception("Invalid or expired OTP.");
            }
            // OTP is valid, clear OTP fields
            $stmt = $conn->prepare("UPDATE users SET otp = NULL, otp_expiry = NULL WHERE id = ?");
            $stmt->bind_param("i", $user_id);
            $stmt->execute();
            $stmt->close();
            // Complete login
            session_regenerate_id(true);
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['role'] = $user['role'];
            unset($_SESSION['pending_2fa_user_id']);
            log_security_event('LOGIN_2FA_SUCCESS', '2FA success for user: ' . $user['email'], $ip_address);
            if ($user['role'] === 'admin') {
                header('Location: /CholoSave-CS/admin/admin_dashboard.php');
            } else {
                header('Location: /CholoSave-CS/user_landing_page.php');
            }
            exit();
        }

        // First step: password check
        // Validate input
        if (empty($email) || empty($password)) {
            throw new Exception("Email and password are required.");
        }
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            throw new Exception("Invalid email format.");
        }
        if (strlen($password) < 8) {
            throw new Exception("Password must be at least 8 characters long.");
        }

        // Prepare SQL query to check if the user exists
        $query = "SELECT * FROM users WHERE email = ?";
        $stmt = $conn->prepare($query);
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $result = $stmt->get_result();

        // Check if user exists and password is correct
        if ($result->num_rows === 0) {
            $_SESSION['login_rate_limit']['count']++;
            log_security_event('LOGIN_FAILED', 'Invalid email', $ip_address);
            throw new Exception("Invalid email or password.");
        }
        $user = $result->fetch_assoc();
        // Verify the password using PasswordUtils
        if (!PasswordUtils::verifyPassword($password, $user['password'])) {
            $_SESSION['login_rate_limit']['count']++;
            log_security_event('LOGIN_FAILED', 'Invalid password for email: ' . $email, $ip_address);
            throw new Exception("Invalid email or password.");
        }
        // Password correct, generate OTP and send email
        $otp = random_int(100000, 999999);
        $otp_hash = hash('sha256', $otp);
        $otp_expiry = date('Y-m-d H:i:s', time() + 300); // 5 minutes
        $stmt = $conn->prepare("UPDATE users SET otp = ?, otp_expiry = ? WHERE id = ?");
        $stmt->bind_param("ssi", $otp_hash, $otp_expiry, $user['id']);
        $stmt->execute();
        $stmt->close();
        // Send OTP via PHPMailer
        require_once __DIR__ . '/vendor/phpmailer/phpmailer/src/PHPMailer.php';
        require_once __DIR__ . '/vendor/phpmailer/phpmailer/src/SMTP.php';
        require_once __DIR__ . '/vendor/phpmailer/phpmailer/src/Exception.php';
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
            $mail->addAddress($user['email']);
            $mail->isHTML(true);
            $mail->Subject = 'Your CholoSave Login OTP';
            $mail->Body = "Your OTP for login is: <b>$otp</b>. This OTP will expire in 5 minutes.";
            $mail->send();
            log_security_event('LOGIN_2FA_OTP_SENT', 'OTP sent to user: ' . $user['email'], $ip_address);
        } catch (Exception $e) {
            log_security_event('LOGIN_2FA_OTP_ERROR', 'OTP email error for user: ' . $user['email'] . ' - ' . $mail->ErrorInfo, $ip_address);
            throw new Exception("OTP could not be sent. Please try again later.");
        }
        // Store user ID in session for OTP step
        $_SESSION['pending_2fa_user_id'] = $user['id'];
        // Show OTP form/modal (handled in HTML below)
        $success_message = "An OTP has been sent to your email. Please enter it below.";
    } catch (Exception $e) {
        $error_message = $e->getMessage();
        log_security_event('LOGIN_ERROR', $error_message, $ip_address);
    }
}
?>
<script src="https://cdn.tailwindcss.com"></script>
<?php include 'includes/new_header.php'; ?>

<style>
    .login-container {
        font-family: 'Poppins', sans-serif;
        min-height: calc(100vh - 5rem);
        background-color: rgb(255, 255, 255);
        padding: 2rem 1rem;
    }
    .login-card {
        max-width: 1000px;
        margin: 0 auto;
        background: rgb(255, 255, 255);
        border-radius: 1rem;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
        overflow: hidden;
        display: flex;
    }
    .login-image {
        width: 50%;
        background: linear-gradient(135deg, #003366 0%, #004080 100%);
        padding: 2rem;
        display: flex;
        flex-direction: column;
        justify-content: center;
        align-items: center;
        color: white;
    }
    .login-image img {
        max-width: 80%;
        height: auto;
        margin-bottom: 2rem;
    }
    .login-form {
        width: 50%;
        padding: 3rem 2rem;
    }
    .login-title {
        font-size: 2rem;
        font-weight: 700;
        text-align: center;
        margin-bottom: 2rem;
    }
    .login-title span {
        background: linear-gradient(135deg, #22C55E 0%, #16A34A 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
    }
    .form-group {
        margin-bottom: 1.5rem;
    }
    .form-label {
        display: block;
        font-size: 0.875rem;
        font-weight: 500;
        color: #4B5563;
        margin-bottom: 0.5rem;
    }
    .form-input {
        width: 100%;
        padding: 0.75rem 1rem;
        border: 1px solid #E5E7EB;
        border-radius: 0.5rem;
        font-family: 'Poppins', sans-serif;
        transition: all 0.3s ease;
    }
    .form-input:focus {
        outline: none;
        border-color: #1E40AF;
        box-shadow: 0 0 0 3px rgba(30, 64, 175, 0.1);
    }
    .login-button {
        width: 100%;
        padding: 0.875rem;
        background: linear-gradient(135deg, #1E40AF 0%, #1E3A8A 100%);
        color: white;
        border: none;
        border-radius: 0.5rem;
        font-weight: 600;
        cursor: pointer;
        transition: all 0.3s ease;
    }
    .login-button:hover {
        transform: translateY(-2px);
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
    }
    .register-link {
        text-align: center;
        margin-top: 1.5rem;
        color: #4B5563;
        font-size: 0.875rem;
    }
    .register-link a {
        color: #1E40AF;
        text-decoration: none;
        font-weight: 500;
    }
    .register-link a:hover {
        text-decoration: underline;
    }
    .alert {
        padding: 1rem;
        border-radius: 0.5rem;
        margin-bottom: 1.5rem;
    }
    .alert-error {
        background-color: #FEE2E2;
        color: #991B1B;
        border: 1px solid #FCA5A5;
    }
    .alert-success {
        background-color: #D1FAE5;
        color: #065F46;
        border: 1px solid #6EE7B7;
    }
    @media (max-width: 768px) {
        .login-card {
            flex-direction: column;
        }
        .login-image,
        .login-form {
            width: 100%;
        }
        .login-image {
            padding: 2rem 1rem;
        }
        .login-form {
            padding: 2rem 1.5rem;
        }
    }
</style>

<div class="login-container">
    <div class="login-card">
        <div class="login-image">
            <img src="/CholoSave-CS/assets/images/login.png" alt="Login">
            <h2>Welcome Back!</h2>
            <p>Access your account and start managing your finances</p>
        </div>
        <div class="login-form">
            <h1 class="login-title">Login to <span>CholoSave</span></h1>
            <?php if ($success_message): ?>
                <div class="alert alert-success">
                    <?php echo $success_message; ?>
                </div>
            <?php endif; ?>
            <?php if ($error_message): ?>
                <div class="alert alert-error">
                    <?php echo $error_message; ?>
                </div>
            <?php endif; ?>
            <?php if (isset($_SESSION['pending_2fa_user_id'])): ?>
                <!-- OTP Modal/Form -->
                <form method="POST">
                    <input type="hidden" name="otp_stage" value="1">
                    <div class="form-group">
                        <label class="form-label" for="otp">Enter 6-digit OTP</label>
                        <input type="text" id="otp" name="otp" class="form-input" maxlength="6" pattern="[0-9]{6}" placeholder="Enter OTP" required autofocus>
                    </div>
                    <button type="submit" class="login-button">Verify OTP</button>
                </form>
            <?php else: ?>
                <!-- Login Form -->
                <form method="POST">
                    <div class="form-group">
                        <label class="form-label" for="email">Email Address</label>
                        <input type="email" id="email" name="email" class="form-input" placeholder="Enter your email"
                            value="<?php echo htmlspecialchars($email); ?>" required>
                    </div>
                    <div class="form-group">
                        <label class="form-label" for="password">Password</label>
                        <input type="password" id="password" name="password" class="form-input"
                            placeholder="Enter your password" required>
                    </div>
                    <!-- Cloudflare Turnstile CAPTCHA -->
                    <div class="form-group">
                        <div class="cf-turnstile" data-sitekey="0x4AAAAAABV06Eefv4-cjRt7" data-theme="light"></div>
                    </div>
                    <button type="submit" class="login-button">
                        Login
                    </button>
                    <div class="forgot-password-link mt-8 ml-36 text-blue-600">
                        <a href="/CholoSave-CS/forgot_password.php">Forgot Password?</a>
                    </div>
                </form>
            <?php endif; ?>
            <div class="register-link">
                Don't have an account?
                <a href="/CholoSave-CS/register.php">Register here</a>
            </div>
        </div>
    </div>
</div>
<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
<?php include 'includes/test_footer.php'; ?>