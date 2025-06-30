<?php
session_start();

$group_id = $_SESSION['group_id'];
$user_id = $_SESSION['user_id'];

if (isset($_SESSION['group_id']) && isset($_SESSION['user_id'])) {
    $group_id = $_SESSION['group_id'];
    $user_id = $_SESSION['user_id'];
} else {
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
$investments = []; // To store available investments

// Fetch investments for the group
$investmentQuery = "SELECT investment_id, investment_type FROM investments WHERE group_id = ? and status='pending'";
if ($stmt = $conn->prepare($investmentQuery)) {
    $stmt->bind_param('i', $group_id);
    $stmt->execute();
    $result = $stmt->get_result();
    while ($row = $result->fetch_assoc()) {
        $investments[] = $row;
    }
    $stmt->close();
}

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    // Sanitize and validate input
    $investment_id = filter_var($_POST['investment_id'], FILTER_SANITIZE_NUMBER_INT);
    $amount = filter_var($_POST['amount'], FILTER_SANITIZE_NUMBER_FLOAT, FILTER_FLAG_ALLOW_FRACTION);
    $description = htmlspecialchars(trim($_POST['description']), ENT_QUOTES, 'UTF-8');
    
    // Validate return amount
    if (!is_numeric($amount) || $amount <= 0) {
        $errors['amount'] = 'Please enter a valid return amount.';
    }

    // Validate description
    if (empty($description)) {
        $errors['description'] = 'Please provide a description.';
    }

    // If no errors, proceed with database insertion
    if (empty($errors)) {
        $returnQuery = "INSERT INTO investment_returns (investment_id, amount, description) VALUES (?, ?, ?)";
        
        if ($stmt = $conn->prepare($returnQuery)) {
            $stmt->bind_param('ids', $investment_id, $amount, $description);
            if ($stmt->execute()) {
                // Update the investment status to 'completed'
                $updateStatusQuery = "UPDATE investments SET status = 'completed' WHERE investment_id = ?";
                if ($updateStmt = $conn->prepare($updateStatusQuery)) {
                    $updateStmt->bind_param('i', $investment_id);
                    if ($updateStmt->execute()) {
                        // Success - Investment status updated
                        echo "<script>
                                document.addEventListener('DOMContentLoaded', function() {
                                    Swal.fire({
                                        title: 'Success!',
                                        text: 'Return recorded successfully and investment status updated.',
                                        icon: 'success',
                                        confirmButtonText: 'OK'
                                    }).then(() => {
                                        window.location.href = '/CholoSave-CS/group_admin/investment_returns.php';
                                    });
                                });
                              </script>";
                    } else {
                        $errors['status_update'] = 'Error updating investment status.';
                    }
                    $updateStmt->close();
                } else {
                    $errors['status_update_query'] = 'Error preparing status update query.';
                }
            } else {
                $errors['submission'] = 'Error recording the return.';
            }
            $stmt->close();
        } else {
            $errors['query'] = 'Error preparing return query.';
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Record Investment Returns</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;600&display=swap" rel="stylesheet">
    <link rel="stylesheet" type="text/css" href="group_member_dashboard_style.css">
    <script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>
</head>
<body class="bg-gray-100">
    <div class="flex h-screen">
        <!-- Sidebar -->
        <?php include 'group_admin_sidebar.php'; ?>

        <!-- Main Content -->
        <div class="flex-1 flex flex-col overflow-hidden">
            <!-- Top Bar -->
            <header class="flex items-center justify-between p-4 bg-white shadow">
                <div class="flex items-center justify-center w-full">
                    <button id="menu-button"
                        class="md:hidden p-2 hover:bg-gray-100 rounded-lg transition-colors duration-200 absolute left-2">
                        <i class="fa-solid fa-bars text-xl"></i>
                    </button>
                    <h1 class="text-2xl font-semibold">
                        <i class="fa-solid fa-money-bill-wave text-blue-600 mr-3"></i>
                        Record Investment Returns
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
                                Please fill in the details below to record the return on investment
                            </h2>
                         
                        </div>

                        <!-- Return Form -->
                        <form method="POST" class="space-y-6">
                            <div class="space-y-6">
                                <!-- Investment Selection -->
                                <div>
                                    <label for="investment_id" class="block text-sm font-medium text-gray-700 mb-2">
                                        Select Investment
                                    </label>
                                    <select id="investment_id" name="investment_id" class="block w-full px-4 py-3 rounded-lg border border-gray-300 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition duration-150 ease-in-out" required>
                                        <option value="">Select an investment</option>
                                        <?php foreach ($investments as $investment): ?>
                                            <option value="<?php echo $investment['investment_id']; ?>"><?php echo $investment['investment_type']; ?></option>
                                        <?php endforeach; ?>
                                    </select>
                                    <!-- Error message for investment selection -->
                                    <div id="investmentError" class="text-red-500 text-sm mt-2">
                                        <?php echo isset($errors['investment_id']) ? $errors['investment_id'] : ''; ?>
                                    </div>
                                </div>

                                <!-- Return Amount Field -->
                                <div>
                                    <label for="amount" class="block text-sm font-medium text-gray-700 mb-2">
                                        Return Amount (BDT)
                                    </label>
                                    <div class="relative">
                                        <span class="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-500">৳</span>
                                        <input type="number" id="amount" name="amount"
                                            class="block w-full pl-8 pr-4 py-3 rounded-lg border border-gray-300 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition duration-150 ease-in-out"
                                            placeholder="Enter return amount" required
                                            value="<?php echo isset($amount) ? htmlspecialchars($amount) : ''; ?>">
                                    </div>
                                    <!-- Error message for amount -->
                                    <div id="amountError" class="text-red-500 text-sm mt-2">
                                        <?php echo isset($errors['amount']) ? $errors['amount'] : ''; ?>
                                    </div>
                                </div>

                                <!-- Description Field -->
                                <div>
                                    <label for="description" class="block text-sm font-medium text-gray-700 mb-2">
                                        Description
                                    </label>
                                    <textarea id="description" name="description" rows="4"
                                        class="block w-full px-4 py-3 rounded-lg border border-gray-300 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition duration-150 ease-in-out"
                                        placeholder="Enter description" required><?php echo isset($description) ? htmlspecialchars($description) : ''; ?></textarea>
                                    <!-- Error message for description -->
                                    <div id="descriptionError" class="text-red-500 text-sm mt-2">
                                        <?php echo isset($errors['description']) ? $errors['description'] : ''; ?>
                                    </div>
                                </div>
                            </div>

                            <!-- Submit Button -->
                            <div class="pt-4">
                                <button type="submit"
                                    class="w-full bg-blue-600 text-white py-3 px-6 rounded-lg hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 transition duration-150 ease-in-out font-medium">
                                    <i class="fas fa-paper-plane mr-2"></i> Submit Return
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
        </div>
    </div>

<script>
</script>

</body>
</html>
<?php include 'new_footer.php'; ?>