<?php
// Include the database connection
include 'db.php';

// Initialize variables
$name = $email = $phone_number = $password = $retype_password = '';
$error_message = '';
$success_message = '';

// Check if the form is submitted
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    try {
        // Get the form data and sanitize
        $name = htmlspecialchars(trim($_POST['name']));
        $email = htmlspecialchars(trim($_POST['email']));
        $phone_number = htmlspecialchars(trim($_POST['phone']));
        $password = htmlspecialchars(trim($_POST['password']));
        $retype_password = htmlspecialchars(trim($_POST['retype-password']));

        // Validate the inputs
        if (empty($name) || empty($email) || empty($phone_number) || empty($password) || empty($retype_password)) {
            throw new Exception("All fields are required.");
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

        // Hash the password
        $hashed_password = password_hash($password, PASSWORD_BCRYPT);

        // Insert user data into the database
        $insert_query = "INSERT INTO users (name, email, phone_number, password) VALUES (?, ?, ?, ?)";
        $stmt = $conn->prepare($insert_query);
        $stmt->bind_param("ssss", $name, $email, $phone_number, $hashed_password);

        if ($stmt->execute()) {
            $success_message = "User registered successfully.";
            // Redirect to dashboard after successful login
            header('Location: /CholoSave-CS/user_landing_page.php');
            exit();
        } else {
            throw new Exception("Failed to register user. Please try again.");
        }
    } catch (Exception $e) {
        $error_message = $e->getMessage();
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
                <div class="form-group">
                    <label class="form-label" for="name">Full Name</label>
                    <input 
                        type="text" 
                        id="name" 
                        name="name" 
                        class="form-input"
                        placeholder="Enter your full name"
                        value="<?php echo htmlspecialchars($name); ?>"
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
                        required
                    >
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
<?php include 'includes/test_footer.php'; ?>
