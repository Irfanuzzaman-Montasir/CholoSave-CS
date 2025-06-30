<?php
// Set secure session parameters BEFORE starting the session
ini_set('session.cookie_httponly', 1);
ini_set('session.cookie_secure', 1);
ini_set('session.use_strict_mode', 1);
ini_set('session.cookie_samesite', 'Strict');

// Start secure session
session_start();

// Force HTTPS (if not in development)
if (!isset($_SERVER['HTTPS']) || $_SERVER['HTTPS'] !== 'on') {
    if ($_SERVER['HTTP_HOST'] !== 'localhost' && $_SERVER['HTTP_HOST'] !== '127.0.0.1') {
        header("Location: https://" . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI']);
        exit();
    }
}

// Include the database connection and password utilities
include 'db.php';
include 'password_utils.php';

// Initialize variables
$name = $email = $phone_number = $password = $retype_password = '';
$error_message = '';
$success_message = '';

// Generate CSRF token if not exists
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Rate limiting configuration
$rate_limit = 3; // Number of submissions allowed
$rate_limit_time = 300; // Time window in seconds (5 minutes)
$ip_address = $_SERVER['REMOTE_ADDR'];

// Initialize rate limit tracking if not exists
if (!isset($_SESSION['rate_limit'])) {
    $_SESSION['rate_limit'] = [
        'count' => 0,
        'start_time' => time(),
        'ip' => $ip_address
    ];
}

// Check if rate limit has expired
if (time() - $_SESSION['rate_limit']['start_time'] > $rate_limit_time) {
    $_SESSION['rate_limit'] = [
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

// Function to validate email
function validate_email($email) {
    return filter_var($email, FILTER_VALIDATE_EMAIL) && 
           preg_match('/^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/', $email);
}

// Function to validate phone number
function validate_phone($phone) {
    // Remove all non-digit characters
    $phone = preg_replace('/[^0-9]/', '', $phone);
    
    // Check if it's a valid length (10-15 digits)
    if (strlen($phone) < 10 || strlen($phone) > 15) {
        return false;
    }
    
    return true;
}

// Function to log security events
function log_security_event($event_type, $details, $ip_address) {
    global $conn;
    
    $stmt = $conn->prepare("INSERT INTO security_logs (event_type, details, ip_address, timestamp) VALUES (?, ?, ?, NOW())");
    $stmt->bind_param("sss", $event_type, $details, $ip_address);
    $stmt->execute();
    $stmt->close();
}

// Handle form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    try {
        // Check rate limit
        if ($_SESSION['rate_limit']['count'] >= $rate_limit) {
            log_security_event('RATE_LIMIT_EXCEEDED', 'Registration rate limit exceeded', $ip_address);
            throw new Exception("Too many registration attempts. Please try again in " . ceil(($rate_limit_time - (time() - $_SESSION['rate_limit']['start_time'])) / 60) . " minutes.");
        }

        // Verify CSRF token
        if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
            log_security_event('CSRF_ATTEMPT', 'Invalid CSRF token', $ip_address);
            throw new Exception("Invalid form submission. Please try again.");
        }

        // Verify Turnstile (Cloudflare CAPTCHA)
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
            log_security_event('CAPTCHA_FAILED', 'Turnstile verification failed', $ip_address);
            throw new Exception("Please complete the security verification.");
        }

        // Get and validate form data
        $name = sanitize_input($_POST['name']);
        $email = sanitize_input($_POST['email']);
        $phone_number = sanitize_input($_POST['phone']);
        $password = $_POST['password'];
        $retype_password = $_POST['retype-password'];

        // Input validation
        if (empty($name) || empty($email) || empty($phone_number) || empty($password) || empty($retype_password)) {
            throw new Exception("All fields are required.");
        }

        // Length validation
        if (strlen($name) > 100) {
            throw new Exception("Name is too long. Maximum 100 characters allowed.");
        }

        if (strlen($email) > 255) {
            throw new Exception("Email is too long.");
        }

        if (strlen($phone_number) > 20) {
            throw new Exception("Phone number is too long.");
        }

        // Email validation
        if (!validate_email($email)) {
            throw new Exception("Please enter a valid email address.");
        }

        // Phone validation
        if (!validate_phone($phone_number)) {
            throw new Exception("Please enter a valid phone number.");
        }

        // Enhanced password validation using PasswordUtils
        $password_validation = PasswordUtils::validatePasswordStrength($password);
        if (!$password_validation['valid']) {
            throw new Exception("Password requirements: " . implode(" ", $password_validation['errors']));
        }

        if ($password !== $retype_password) {
            throw new Exception("Passwords do not match.");
        }

        // Check if email already exists
        $check_email_query = "SELECT * FROM users WHERE email = ?";
        $stmt = $conn->prepare($check_email_query);
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($result->num_rows > 0) {
            throw new Exception("Email is already registered.");
        }
        $stmt->close();

        // Enhanced password hashing with automatic salt generation and best algorithm selection
        try {
            $hashed_password = PasswordUtils::hashPassword($password);
            
            // Log the hashing algorithm used for security monitoring
            $hash_info = PasswordUtils::getHashInfo($hashed_password);
            $algorithm_name = PasswordUtils::getAlgorithmName($hash_info['algo']);
            log_security_event('PASSWORD_HASHED', "Password hashed using $algorithm_name algorithm", $ip_address);
            
        } catch (Exception $e) {
            log_security_event('PASSWORD_HASH_ERROR', $e->getMessage(), $ip_address);
            throw new Exception("Password processing error. Please try again.");
        }

        // Insert user data into the database
        $insert_query = "INSERT INTO users (name, email, phone_number, password, created_at) VALUES (?, ?, ?, ?, NOW())";
        $stmt = $conn->prepare($insert_query);
        $stmt->bind_param("ssss", $name, $email, $phone_number, $hashed_password);

        if ($stmt->execute()) {
            // Increment rate limit counter
            $_SESSION['rate_limit']['count']++;
            
            // Log successful registration with enhanced details
            log_security_event('REGISTRATION_SUCCESS', "User registered: $email with $algorithm_name hashing", $ip_address);
            
            // Regenerate session ID for security
            session_regenerate_id(true);
            
            $success_message = "User registered successfully! Please check your email for verification.";
            
            // Reset form by generating new CSRF token
            $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
            
            // TODO: Send email verification
            // send_verification_email($email, $name);
            
            // Redirect to dashboard after successful registration
            header('Location: /CholoSave-CS/user_landing_page.php');
            exit();
        } else {
            throw new Exception("Failed to register user. Please try again.");
        }
        $stmt->close();
        
    } catch (Exception $e) {
        $error_message = $e->getMessage();
        log_security_event('REGISTRATION_ERROR', $error_message, $ip_address);
    }
}
?>

<?php include 'includes/new_header.php'; ?>

<style>
.login-container {
    font-family: 'Poppins', sans-serif;
    min-height: calc(100vh - 5rem);
    background-color: #f4f7f9;
    padding: 2rem 1rem;
}

.login-card {
    max-width: 1000px;
    margin: 0 auto;
    background: #ffffff;
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

.password-requirements {
    font-size: 0.75rem;
    color: #6B7280;
    margin-top: 0.5rem;
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
            <img src="/CholoSave-CS/assets/images/register.png" alt="Register">
            <h2>Join CholoSave Today!</h2>
            <p>Create your account and start your financial journey</p>
        </div>
        
        <div class="login-form">
            <h1 class="login-title">Register with <span>CholoSave</span></h1>
            
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
            
            <form method="POST">
                <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                
                <div class="form-group">
                    <label class="form-label" for="name">Full Name</label>
                    <input 
                        type="text" 
                        id="name" 
                        name="name" 
                        class="form-input"
                        placeholder="Enter your full name"
                        value="<?php echo htmlspecialchars($name); ?>"
                        maxlength="100"
                        required
                    >
                </div>

                <div class="form-group">
                    <label class="form-label" for="email">Email Address</label>
                    <input 
                        type="email" 
                        id="email" 
                        name="email" 
                        class="form-input"
                        placeholder="Enter your email"
                        value="<?php echo htmlspecialchars($email); ?>"
                        maxlength="255"
                        required
                    >
                </div>

                <div class="form-group">
                    <label class="form-label" for="phone">Phone Number</label>
                    <input 
                        type="tel" 
                        id="phone" 
                        name="phone" 
                        class="form-input"
                        placeholder="Enter your phone number"
                        value="<?php echo htmlspecialchars($phone_number); ?>"
                        maxlength="20"
                        required
                    >
                </div>
                
                <div class="form-group">
                    <label class="form-label" for="password">Password</label>
                    <input 
                        type="password" 
                        id="password" 
                        name="password" 
                        class="form-input"
                        placeholder="Create your password"
                        minlength="8"
                        required
                    >
                    <div class="password-requirements">
                        Password must be at least 8 characters with uppercase, lowercase, number, and special character.
                    </div>
                </div>

                <div class="form-group">
                    <label class="form-label" for="retype-password">Confirm Password</label>
                    <input 
                        type="password" 
                        id="retype-password" 
                        name="retype-password" 
                        class="form-input"
                        placeholder="Confirm your password"
                        required
                    >
                </div>

                <!-- Cloudflare Turnstile CAPTCHA -->
                <div class="form-group">
                    <div class="cf-turnstile" data-sitekey="0x4AAAAAABV06Eefv4-cjRt7" data-theme="light"></div>
                </div>
                
                <button type="submit" class="login-button">
                    Create Account
                </button>
            </form>
            
            <div class="register-link">
                Already have an account? 
                <a href="/CholoSave-CS/login.php">Login here</a>
            </div>
        </div>
    </div>
</div>

<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>

<?php include 'includes/test_footer.php'; ?> 