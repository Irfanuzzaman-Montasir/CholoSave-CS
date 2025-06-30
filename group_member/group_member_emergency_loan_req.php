<?php
session_start();

$group_id = $_SESSION['group_id'];
$user_id = $_SESSION['user_id'];
if (!isset($_SESSION['group_id']) || !isset($_SESSION['user_id'])) {
    header("Location: /test_project/error_page.php");
    exit;
}

if (!isset($conn)) {
    include 'db.php';
}

$errors = [];

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    // Sanitize and validate input
    $amount = filter_var($_POST['amount'], FILTER_SANITIZE_NUMBER_FLOAT, FILTER_FLAG_ALLOW_FRACTION);
    $reason = htmlspecialchars(trim($_POST['reason']), ENT_QUOTES, 'UTF-8');
    $returnDate = $_POST['returnDate'];
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

            $conn->commit(); // Commit transaction

            // Show success message
            echo "<script>
                    document.addEventListener('DOMContentLoaded', function() {
                        Swal.fire({
                            title: 'Success!',
                            text: 'Loan request submitted successfully and poll created.',
                            icon: 'success',
                            confirmButtonText: 'OK'
                        }).then(() => {
                            window.location.href = '/test_project/group_member/group_member_emergency_loan_req.php';
                        });
                    });
                  </script>";

        } catch (Exception $e) {
            $conn->rollback(); // Rollback on error
            $errors['submission'] = 'Error processing loan request: ' . $e->getMessage();
        }
    }

    // Display any errors
    if (!empty($errors)) {
        $errorMessage = implode('\n', $errors);
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