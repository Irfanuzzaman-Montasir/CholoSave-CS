<?php
session_start();

$group_id = $_SESSION['group_id'];
$user_id = $_SESSION['user_id'];

if (isset($_SESSION['group_id']) && isset($_SESSION['user_id'])) {
    $group_id = $_SESSION['group_id'];
    $user_id = $_SESSION['user_id'];
   
    // echo 'group_id: '. $group_id; echo 'user_id: '. $user_id;
}
if (!isset($_SESSION['group_id']) || !isset($_SESSION['user_id'])) {
    header("Location: /CholoSave-CS/error_page.php"); // Redirect if session variables are missing
    exit;
}

if (!isset($conn)) {
    include 'db.php'; // Ensure database connection
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

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    // Sanitize and validate input
    $amount = filter_var($_POST['amount'], FILTER_SANITIZE_NUMBER_FLOAT, FILTER_FLAG_ALLOW_FRACTION);
    $investment_type = htmlspecialchars(trim($_POST['investment_type']), ENT_QUOTES, 'UTF-8');
    $expected_return = filter_var($_POST['expected_return'], FILTER_SANITIZE_NUMBER_FLOAT, FILTER_FLAG_ALLOW_FRACTION);
    $expected_return_date = $_POST['expected_return_date'];
    $currentDate = date('Y-m-d');

    // Validate investment amount
    if (!is_numeric($amount) || $amount <= 0) {
        $errors['amount'] = 'Please enter a valid investment amount.';
    }

    // Validate investment type
    if (empty($investment_type)) {
        $errors['investment_type'] = 'Please provide the type of investment.';
    }

    // Validate expected return
    if (!is_numeric($expected_return) || $expected_return <= 0) {
        $errors['expected_return'] = 'Please enter a valid expected return amount.';
    }

    // Validate expected return date
    if ($expected_return_date < $currentDate) {
        $errors['expected_return_date'] = 'Return date must be today or later.';
    }

    echo "Expected Return Date: " . $expected_return_date;


    // If no errors, proceed with database insertion
    if (empty($errors)) {
        $investmentQuery = "INSERT INTO investments (group_id, investment_type, amount, ex_return_date, ex_profit) VALUES (?, ?, ?, ?, ?)";
        
        if ($stmt = $conn->prepare($investmentQuery)) {
            $stmt->bind_param('isids', $group_id, $investment_type, $amount, $expected_return_date, $expected_return);
            if ($stmt->execute()) {
                // After successful investment insertion, show success message
                echo "<script>
                        document.addEventListener('DOMContentLoaded', function() {
                            Swal.fire({
                                title: 'Success!',
                                text: 'Investment details submitted successfully.',
                                icon: 'success',
                                confirmButtonText: 'OK'
                            }).then(() => {
                                window.location.href = '/CholoSave-CS/group_admin/group_admin_investment.php';
                            });
                        });
                      </script>";
            } else {
                $errors['submission'] = 'Error submitting investment details.';
            }
            $stmt->close();
        } else {
            $errors['query'] = 'Error preparing investment query.';
        }
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

    </style>
</head>

<body class="bg-gray-100 dark-mode-transition">
    <div class="flex h-screen">
        <!-- Sidebar -->
        <?php include 'group_admin_sidebar.php'; ?>

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
                        <i class="fa-solid fa-chart-line text-blue-600 mr-3"></i>
                        Investment Entry
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
                                Please fill in the details below to submit your investment details
                            </h2>
                        </div>

                        <!-- Investment Form -->
                        <form method="POST" class="space-y-6">
                            <div class="space-y-6">
                                <!-- Amount Field -->
                                <div>
                                    <label for="amount" class="block text-sm font-medium text-gray-700 mb-2">
                                        Investment Amount (BDT)
                                    </label>
                                    <div class="relative">
                                        <span class="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-500">৳</span>
                                        <input type="number" id="amount" name="amount"
                                            class="block w-full pl-8 pr-4 py-3 rounded-lg border border-gray-300 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition duration-150 ease-in-out"
                                            placeholder="Enter amount" required
                                            value="<?php echo isset($amount) ? htmlspecialchars($amount) : ''; ?>">
                                    </div>
                                    <!-- Error message for amount -->
                                    <div id="amountError" class="text-red-500 text-sm mt-2">
                                        <?php echo isset($errors['amount']) ? $errors['amount'] : ''; ?>
                                    </div>
                                </div>

                                <!-- Investment Type Field -->
                                <div>
                                    <label for="investment_type" class="block text-sm font-medium text-gray-700 mb-2">
                                        Investment Type
                                    </label>
                                    <input type="text" id="investment_type" name="investment_type"
                                        class="block w-full px-4 py-3 rounded-lg border border-gray-300 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition duration-150 ease-in-out"
                                        placeholder="Enter investment type" required
                                        value="<?php echo isset($investment_type) ? htmlspecialchars($investment_type) : ''; ?>">
                                    <!-- Error message for investment type -->
                                    <div id="investmentTypeError" class="text-red-500 text-sm mt-2">
                                        <?php echo isset($errors['investment_type']) ? $errors['investment_type'] : ''; ?>
                                    </div>
                                </div>

                                <!-- Expected Return Field -->
                                <div>
                                    <label for="expected_return" class="block text-sm font-medium text-gray-700 mb-2">
                                        Expected Return (BDT)
                                    </label>
                                    <div class="relative">
                                        <span class="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-500">৳</span>
                                        <input type="number" id="expected_return" name="expected_return"
                                            class="block w-full pl-8 pr-4 py-3 rounded-lg border border-gray-300 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition duration-150 ease-in-out"
                                            placeholder="Enter expected return" required
                                            value="<?php echo isset($expected_return) ? htmlspecialchars($expected_return) : ''; ?>">
                                    </div>
                                    <!-- Error message for expected return -->
                                    <div id="expectedReturnError" class="text-red-500 text-sm mt-2">
                                        <?php echo isset($errors['expected_return']) ? $errors['expected_return'] : ''; ?>
                                    </div>
                                </div>

                                <!-- Expected Return Date Field -->
                                <div>
                                    <label for="expected_return_date" class="block text-sm font-medium text-gray-700 mb-2">
                                        Expected Return Date
                                    </label>
                                    <input type="date" id="expected_return_date" name="expected_return_date"
                                        class="block w-full px-4 py-3 rounded-lg border border-gray-300 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition duration-150 ease-in-out"
                                        required
                                        value="<?php echo isset($expected_return_date) ? htmlspecialchars($expected_return_date) : ''; ?>">
                                    <!-- Error message for return date -->
                                    <div id="expectedReturnDateError" class="text-red-500 text-sm mt-2">
                                        <?php echo isset($errors['expected_return_date']) ? $errors['expected_return_date'] : ''; ?>
                                    </div>
                                </div>
                            </div>

                            <!-- Submit Button -->
                            <div class="pt-4">
                                <button type="submit"
                                    class="w-full bg-blue-600 text-white py-3 px-6 rounded-lg hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 transition duration-150 ease-in-out font-medium">
                                    <i class="fas fa-paper-plane mr-2"></i> Submit Investment
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
        </div>
    </div>

<script>
    // // Dark mode functionality (same as in your original code)
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
</script>
</body>
</html>
<?php include 'new_footer.php'; ?>