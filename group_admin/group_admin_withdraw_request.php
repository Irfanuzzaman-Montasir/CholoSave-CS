<?php
session_start();

// Check if group_id and user_id are set in session
if (!isset($_SESSION['group_id']) || !isset($_SESSION['user_id'])) {
    header("Location: /CholoSave-CS/error_page.php"); // Redirect if session variables are missing
    exit;
}

$group_id = $_SESSION['group_id'];
$user_id = $_SESSION['user_id'];

// Ensure database connection
if (!isset($conn)) {
    include 'db.php';
}


// Check if the user is an admin for the group
$is_admin = false;
$checkAdminQuery = "SELECT group_admin_id FROM my_group WHERE group_id = ?";
if ($stmt = $conn->prepare($checkAdminQuery)) {
    $stmt->bind_param('i', $group_id);
    $stmt->execute();
    $stmt->bind_result($group_admin_id);
    $stmt->fetch();
    $stmt->close();
    
    // If the user is the admin of the group, proceed; otherwise, redirect to an error page
    if ($group_admin_id === $user_id) {
        $is_admin = true;
    }
}

if (!$is_admin) {
    // Redirect to error page if the user is not an admin
    header("Location: /CholoSave-CS/error_page.php");
    exit;
}


$errors = []; // To store validation errors

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Sanitize and validate input
    $amount = filter_var($_POST['amount'], FILTER_SANITIZE_NUMBER_FLOAT, FILTER_FLAG_ALLOW_FRACTION);
    $payment_number = htmlspecialchars(trim($_POST['payment_number']), ENT_QUOTES, 'UTF-8');
    $payment_method = htmlspecialchars(trim($_POST['payment_method']), ENT_QUOTES, 'UTF-8');

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

    // If no errors, insert the withdrawal request
    if (empty($errors)) {
        $withdrawalQuery = "INSERT INTO withdrawal (user_id, group_id, amount, payment_number, payment_method) VALUES (?, ?, ?, ?, ?)";
        if ($stmt = $conn->prepare($withdrawalQuery)) {
            $stmt->bind_param('iisss', $user_id, $group_id, $amount, $payment_number, $payment_method);
            if ($stmt->execute()) {
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
            } else {
                $errors['submission'] = 'Error submitting withdrawal request.';
            }
            $stmt->close();
        } else {
            $errors['query'] = 'Error preparing withdrawal request query.';
        }
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
</body>

</html>
<?php include 'new_footer.php'; ?>