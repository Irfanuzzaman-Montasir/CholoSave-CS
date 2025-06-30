<?php 
session_start();
include 'includes/new_header.php'; 
include 'db.php'; 

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

// Handle form submission
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    // Check rate limit
    if ($_SESSION['rate_limit']['count'] >= $rate_limit) {
        $error_message = "Too many submissions. Please try again in a few minutes.";
    } else {
        // Verify CSRF token
        if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
            $error_message = "Invalid form submission. Please try again.";
        } else {
            // Verify Turnstile
            $turnstile_response = $_POST['cf-turnstile-response'];
            $turnstile_secret = "0x4AAAAAABV06DJH3sKKe6kuwz8k4tbcMBs";
            
            // Use cURL for better error handling
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
                $error_message = "Network error during verification. Please try again.";
            } else {
                $response_data = json_decode($verify_response);
                
                // Check if json_decode was successful and response_data is not null
                if ($response_data === null) {
                    $error_message = "Verification service error. Please try again.";
                } elseif (!isset($response_data->success) || !$response_data->success) {
                    $error_message = "Please complete the security verification.";
                } else {
                    // Sanitize all input data
                    $name = sanitize_input($_POST['name']);
                    $email = filter_var(sanitize_input($_POST['email']), FILTER_SANITIZE_EMAIL);
                    $message = sanitize_input($_POST['message']);

                    // Validate inputs
                    if (!empty($name) && !empty($email) && !empty($message)) {
                        if (filter_var($email, FILTER_VALIDATE_EMAIL)) {
                            $stmt = $conn->prepare("INSERT INTO contact_us (name, email, description) VALUES (?, ?, ?)");
                            $stmt->bind_param("sss", $name, $email, $message);

                            if ($stmt->execute()) {
                                // Increment rate limit counter
                                $_SESSION['rate_limit']['count']++;
                                
                                $success_message = "Thank you for your message! We'll get back to you shortly.";
                                // Reset form by generating new CSRF token
                                $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
                            } else {
                                $error_message = "Something went wrong. Please try again.";
                            }
                            $stmt->close();
                        } else {
                            $error_message = "Please enter a valid email address.";
                        }
                    } else {
                        $error_message = "All fields are required.";
                    }
                }
            }
        }
    }
}
?>
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;500;600;700&display=swap" rel="stylesheet">
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css">
        <title>Contact Us - CholoSave</title>
        <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
        <style>
            body {
                font-family: 'Poppins', sans-serif;
                margin: 0;
                padding: 0;
                background-color: #f4f7f9;
            }

            .main-content {
                max-width: 1200px;
                margin: 2rem auto;
                padding: 0 1rem;
            }

            .page-title {
                text-align: center;
                margin-bottom: 3rem;
            }

            .page-title h1 {
                font-size: 2.5rem;
                font-weight: 700;
                background: linear-gradient(135deg, #003366 0%, #004080 100%);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                margin-bottom: 1rem;
            }

            .page-title p {
                color: #4B5563;
                font-size: 1.125rem;
                max-width: 600px;
                margin: 0 auto;
            }

            .contact-form-container {
                background: #ffffff;
                border-radius: 1rem;
                box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
                padding: 2rem;
                max-width: 800px;
                margin: 0 auto 3rem;
            }

            .form-title {
                font-size: 1.5rem;
                font-weight: 600;
                color: #1E40AF;
                text-align: center;
                margin-bottom: 2rem;
            }

            .success-message {
                background-color: #dcfce7;
                color: #16a34a;
                padding: 1rem;
                border-radius: 0.5rem;
                margin-bottom: 1rem;
                text-align: center;
                font-weight: 500;
            }

            .error-message {
                background-color: #fee2e2;
                color: #dc2626;
                padding: 1rem;
                border-radius: 0.5rem;
                margin-bottom: 1rem;
                text-align: center;
                font-weight: 500;
            }

            .form-grid {
                display: grid;
                grid-template-columns: repeat(2, 1fr);
                gap: 1.5rem;
                margin-bottom: 1.5rem;
            }

            .form-group {
                display: flex;
                flex-direction: column;
            }

            .form-group.full-width {
                grid-column: span 2;
            }

            .form-label {
                font-size: 0.875rem;
                font-weight: 500;
                color: #4B5563;
                margin-bottom: 0.5rem;
            }

            .form-input,
            .form-textarea {
                padding: 0.75rem;
                border: 1px solid #e5e7eb;
                border-radius: 0.5rem;
                font-family: 'Poppins', sans-serif;
                transition: all 0.3s ease;
            }

            .form-input:focus,
            .form-textarea:focus {
                outline: none;
                border-color: #1E40AF;
                box-shadow: 0 0 0 3px rgba(30, 64, 175, 0.1);
            }

            .form-textarea {
                resize: vertical;
                min-height: 120px;
            }

            .submit-button {
                background: linear-gradient(135deg, #1E40AF 0%, #1E3A8A 100%);
                color: white;
                padding: 0.875rem 1.5rem;
                border: none;
                border-radius: 0.5rem;
                font-weight: 600;
                font-size: 1rem;
                cursor: pointer;
                width: 100%;
                transition: all 0.3s ease;
            }

            .submit-button:hover {
                transform: translateY(-2px);
                box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            }

            .submit-button:active {
                transform: translateY(0);
            }

            @media (max-width: 768px) {
                .form-grid {
                    grid-template-columns: 1fr;
                }

                .form-group.full-width {
                    grid-column: span 1;
                }

                .page-title h1 {
                    font-size: 2rem;
                }

                .contact-form-container {
                    padding: 1.5rem;
                }
            }
        </style>
    </head>
    <body>
        <main class="main-content">
            <div class="page-title">
                <h1>Contact Us</h1>
                <p>We would love to hear from you. Get in touch for any inquiries or feedback.</p>
            </div>

            <div class="contact-form-container">
                <h2 class="form-title">Send Us a Message</h2>

                <?php if (!empty($success_message)): ?>
                    <div class="success-message"><?php echo $success_message; ?></div>
                <?php endif; ?>

                <?php if (!empty($error_message)): ?>
                    <div class="error-message"><?php echo $error_message; ?></div>
                <?php endif; ?>

                <form action="#" method="POST" id="contactForm">
                    <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                    <div class="form-grid">
                        <div class="form-group">
                            <label for="name" class="form-label">Your Name</label>
                            <input type="text" id="name" name="name" required class="form-input" />
                        </div>

                        <div class="form-group">
                            <label for="email" class="form-label">Your Email</label>
                            <input type="email" id="email" name="email" required class="form-input" />
                        </div>

                        <div class="form-group full-width">
                            <label for="message" class="form-label">Your Message</label>
                            <textarea id="message" name="message" required class="form-textarea"></textarea>
                        </div>
                    </div>

                    <div class="form-group full-width" style="margin-bottom: 1.5rem;">
                        <div class="cf-turnstile" data-sitekey="0x4AAAAAABV06Eefv4-cjRt7" data-theme="light"></div>
                    </div>

                    <button type="submit" class="submit-button">
                        Send Message
                    </button>
                </form>
            </div>

            <section class="contact-details">
                <?php include 'home_load.php'; ?>
            </section>
        </main>

    

        <script>
        document.getElementById('mobile-menu')?.addEventListener('click', function() {
            document.querySelector('.nav')?.classList.toggle('active');
        });

        // Reset form after successful submission
        <?php if (isset($success_message)): ?>
        document.getElementById('contactForm').reset();
        <?php endif; ?>
        </script>
    </body>
    </html>

    <?php include 'includes/test_footer.php'; ?>