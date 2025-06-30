<?php
// Include the database connection file and session management
include 'db.php'; // This will handle database connection
include 'session.php'; // This will handle session start and checks

// Initialize variables
$email = '';
$password = '';
$error_message = '';
$success_message = '';

// Check if the form is submitted
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    try {
        // Get form data
        $email = filter_var(trim($_POST['email']), FILTER_SANITIZE_EMAIL);
        $password = trim($_POST['password']);

        // Validate input
        if (empty($email) || empty($password)) {
            throw new Exception("Email and password are required.");
        }

        // Prepare SQL query to check if the user exists
        $query = "SELECT * FROM users WHERE email = ?";
        $stmt = $conn->prepare($query);
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $result = $stmt->get_result();

        // Check if user exists and password is correct
        if ($result->num_rows === 0) {
            throw new Exception("Invalid email or password.");
        }

        $user = $result->fetch_assoc();

        // Verify the password
        if (!password_verify($password, $user['password'])) {
            throw new Exception("Invalid email or password.");
        }

        // Start session and store user data
        session_start();
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['role'] = $user['role']; // Assuming role column exists to differentiate between admin and users

        // Redirect based on user role
        if ($user['role'] === 'admin') {
            // Redirect admin to the admin dashboard
            header('Location: /CholoSave-CS/admin/admin_dashboard.php');
        } else {
            // Redirect regular users to their landing page
            header('Location: /CholoSave-CS/user_landing_page.php');
        }
        exit();

    } catch (Exception $e) {
        // Set error message
        $error_message = $e->getMessage();
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

                <button type="submit" class="login-button">
                    Login
                </button>
                <!-- Add this inside the login form -->
                <div class="forgot-password-link mt-8 ml-36 text-blue-600">
                    <a href="/CholoSave-CS/forgot_password.php">Forgot Password?</a>
                </div>
            </form>

            <div class="register-link">
                Don't have an account?
                <a href="/CholoSave-CS/register.php">Register here</a>
            </div>

        </div>
    </div>
</div>

<?php include 'includes/test_footer.php'; ?>