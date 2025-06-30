<?php
session_start();

if (!isset($_SESSION['user_id']) || !isset($_SESSION['group_id'])) {
    header("Location: /test_project/error_page.php");
    exit;
}

$user_id = $_SESSION['user_id'];
$group_id = $_SESSION['group_id'];

if (!isset($conn)) {
    include 'db.php'; // Database connection
}

// Check if the user is the group admin
$is_admin = false;
$checkAdminQuery = "SELECT group_admin_id FROM my_group WHERE group_id = ?";
if ($stmt = $conn->prepare($checkAdminQuery)) {
    $stmt->bind_param('i', $group_id);
    $stmt->execute();
    $stmt->bind_result($group_admin_id);
    $stmt->fetch();
    $stmt->close();
    $is_admin = ($group_admin_id === $user_id);
}

if (!$is_admin) {
    header("Location: /test_project/error_page.php");
    exit;
}

// Fetch current settings
$groupDataQuery = "SELECT amount, start_date, goal_amount, emergency_fund, bKash, Rocket, Nagad FROM my_group WHERE group_id = ?";
if ($stmt = $conn->prepare($groupDataQuery)) {
    $stmt->bind_param('i', $group_id);
    $stmt->execute();
    $stmt->bind_result($amount, $start_date, $goal_amount, $emergency_fund, $bKash, $Rocket, $Nagad);
    $stmt->fetch();
    $stmt->close();
}

// Handle settings update
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $new_amount = $_POST['amount'];
    $new_start_date = $_POST['start_date'];
    $new_goal_amount = $_POST['goal_amount'];
    $new_emergency_fund = $_POST['emergency_fund'];
    $new_bKash = $_POST['bKash'];
    $new_Rocket = $_POST['Rocket'];
    $new_Nagad = $_POST['Nagad'];

    $updateQuery = "
        UPDATE my_group 
        SET amount = ?, start_date = ?, goal_amount = ?, emergency_fund = ?, bKash = ?, Rocket = ?, Nagad = ? 
        WHERE group_id = ?
    ";
    if ($stmt = $conn->prepare($updateQuery)) {
        $stmt->bind_param('dssssssi', $new_amount, $new_start_date, $new_goal_amount, $new_emergency_fund, $new_bKash, $new_Rocket, $new_Nagad, $group_id);
        if ($stmt->execute()) {
            $message = "Settings updated successfully!";
            // Redirect to the settings page on success
            header("Location: /test_project/group_admin/settings.php?message=success");
            exit;
        } else {
            $message = "Failed to update settings.";
        }
        $stmt->close();
    }
}
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Settings</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        .form-group {
            margin-bottom: 1rem;
        }

        .custom-font {
            font-family: 'Poppins', sans-serif;
        }


        .close-savings-btn {
    position: absolute;
    top: 1rem;
    right: 2rem;
    padding: 0.75rem 1.5rem;
    background-color: #dc2626; /* Tailwind red-600 */
    color: white;
    border: none;
    border-radius: 0.375rem;
    font-weight: 600;
    cursor: pointer;
    box-shadow: 0 2px 4px rgba(220, 38, 38, 0.2);
    transform: translateY(0);
    transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
    
    /* Subtle gradient overlay */
    background-image: linear-gradient(
        rgba(255, 255, 255, 0.1),
        rgba(0, 0, 0, 0.1)
    );
    
    /* Prevent text selection */
    user-select: none;
    -webkit-user-select: none;
    
    /* Improve text readability */
    text-shadow: 0 1px 1px rgba(0, 0, 0, 0.1);
}

/* Hover state */
.close-savings-btn:hover {
    background-color: #b91c1c; /* Tailwind red-700 */
    transform: translateY(-1px);
    box-shadow: 0 4px 6px rgba(220, 38, 38, 0.25);
}

/* Active state */
.close-savings-btn:active {
    transform: translateY(1px);
    box-shadow: 0 1px 2px rgba(220, 38, 38, 0.2);
}

/* Focus state */
.close-savings-btn:focus {
    outline: none;
    box-shadow: 0 0 0 3px rgba(220, 38, 38, 0.3);
}

/* Add danger icon */
.close-savings-btn::before {
    content: "⚠️";
    margin-right: 0.5rem;
    font-size: 1rem;
}

/* Optional: Add subtle pulse animation for extra attention */
@keyframes pulse {
    0% { transform: scale(1); }
    50% { transform: scale(1.02); }
    100% { transform: scale(1); }
}

.close-savings-btn:hover {
    animation: pulse 1s infinite;
}




    </style>
    <script>
        function enableEditing() {
            const fields = document.querySelectorAll(".editable-field");
            fields.forEach(field => field.disabled = false);
            document.getElementById("save-btn").style.display = "block";
            document.getElementById("edit-btn").style.display = "none";
        }
    </script>
</head>

<body class="bg-gray-100 dark-mode-transition">
    <div class="flex h-screen">
        <!-- Sidebar -->
        <?php include 'group_admin_sidebar.php'; ?>

        <!-- Main Content -->
        <div class="flex-1 overflow-y-auto">
            <!-- Page Header -->
            <header class="flex items-center justify-between p-4 bg-white shadow dark-mode-transition">
                <div class="flex items-center justify-center w-full">
                    <button id="menu-button"
                        class="md:hidden p-2 hover:bg-gray-100 rounded-lg transition-colors duration-200 absolute left-2">
                        <i class="fa-solid fa-bars text-xl"></i>
                    </button>
                    <h2 class="text-3xl font-semibold custom-font">
                        <i class="fas fa-cogs text-blue-600 mr-3"></i>
                        Settings
                    </h2>
                </div>

                <!-- Close Savings Button -->
                <form action="/test_project/group_admin/close_savings.php" method="POST">
                    <button type="submit" class="close-savings-btn">
                        Close Savings
                    </button>
                </form>
            </header>

            <div class="p-6 w-full max-w-full mx-auto mt-[50px]">

                <?php if (isset($message)): ?>
                    <div class="bg-green-100 text-green-700 p-4 rounded mb-4"><?php echo $message; ?></div>
                <?php endif; ?>

                <form method="POST" action="">
                    <div class="form-group">
                        <label for="amount" class="block font-medium text-gray-700">Amount</label>
                        <input type="text" id="amount" name="amount" class="editable-field p-2 border rounded w-full"
                            value="<?php echo htmlspecialchars($amount); ?>" disabled>
                    </div>
                    <div class="form-group">
                        <label for="start_date" class="block font-medium text-gray-700">Start Date</label>
                        <input type="date" id="start_date" name="start_date"
                            class="editable-field p-2 border rounded w-full"
                            value="<?php echo htmlspecialchars($start_date); ?>" disabled>
                    </div>
                    <div class="form-group">
                        <label for="goal_amount" class="block font-medium text-gray-700">Goal Amount</label>
                        <input type="text" id="goal_amount" name="goal_amount"
                            class="editable-field p-2 border rounded w-full"
                            value="<?php echo htmlspecialchars($goal_amount); ?>" disabled>
                    </div>
                    <div class="form-group">
                        <label for="emergency_fund" class="block font-medium text-gray-700">Emergency Fund</label>
                        <input type="text" id="emergency_fund" name="emergency_fund"
                            class="editable-field p-2 border rounded w-full"
                            value="<?php echo htmlspecialchars($emergency_fund); ?>" disabled>
                    </div>
                    <div class="form-group">
                        <label for="bKash" class="block font-medium text-gray-700">bKash</label>
                        <input type="text" id="bKash" name="bKash" class="editable-field p-2 border rounded w-full"
                            value="<?php echo htmlspecialchars($bKash); ?>" disabled>
                    </div>
                    <div class="form-group">
                        <label for="Rocket" class="block font-medium text-gray-700">Rocket</label>
                        <input type="text" id="Rocket" name="Rocket" class="editable-field p-2 border rounded w-full"
                            value="<?php echo htmlspecialchars($Rocket); ?>" disabled>
                    </div>
                    <div class="form-group">
                        <label for="Nagad" class="block font-medium text-gray-700">Nagad</label>
                        <input type="text" id="Nagad" name="Nagad" class="editable-field p-2 border rounded w-full"
                            value="<?php echo htmlspecialchars($Nagad); ?>" disabled>
                    </div>

                    <div class="flex space-x-4">
                        <button type="button" id="edit-btn"
                            class="px-4 py-2 bg-blue-500 text-white rounded hover:bg-blue-600"
                            onclick="enableEditing()">Edit</button>
                        <button type="submit" id="save-btn"
                            class="px-4 py-2 bg-green-500 text-white rounded hover:bg-green-600"
                            style="display: none;">Save</button>
                    </div>
                </form>
            </div>
        </div>
    </div>

<script>
   document.querySelector('.close-savings-btn').addEventListener('click', async (e) => {
    e.preventDefault();

    const questions = [
        'Have all members received their savings?',
        'Have all members received their profit?',
        'Do all members agree to close the savings group?',
        'Is the savings successfully completed?'
    ];

    let allYes = true;

    for (const question of questions) {
        const result = await Swal.fire({
            title: question,
            icon: 'question',
            showCancelButton: true,
            confirmButtonText: 'Yes',
            cancelButtonText: 'No'
        });

        if (!result.isConfirmed) {
            allYes = false;
            break;
        }
    }

    if (allYes) {
        // First, validate total savings vs withdrawals
        try {
            const response = await fetch('/test_project/group_admin/validate_savings.php', {
                method: 'POST'
            });
            const data = await response.json();

            if (data.is_balanced) {
                Swal.fire({
                    title: 'Warning',
                    text: 'Closing savings means all group data will be permanently deleted. You cannot recover this information. Are you absolutely sure?',
                    icon: 'warning',
                    showCancelButton: true,
                    confirmButtonColor: '#d33',
                    confirmButtonText: 'Yes, close savings!'
                }).then((result) => {
                    if (result.isConfirmed) {
                        fetch('/test_project/group_admin/close_savings.php', {
                            method: 'POST',
                            body: JSON.stringify({ confirm: true })
                        })
                        .then(response => response.json())
                        .then(data => {
                            if (data.success) {
                                Swal.fire('Savings Closed', 'All group data has been deleted.', 'success')
                                    .then(() => window.location.href = '/test_project/groups.php');
                            } else {
                                Swal.fire('Error', data.message || 'Could not close savings', 'error');
                            }
                        });
                    }
                });
            } else {
                Swal.fire({
                    title: 'Savings Balance Error',
                    text: 'Total savings and withdrawals do not balance. Cannot close savings group.',
                    icon: 'error',
                    confirmButtonText: 'Understood'
                });
            }
        } catch (error) {
            Swal.fire({
                title: 'Validation Error',
                text: 'Could not validate savings balance. Please try again.',
                icon: 'error',
                confirmButtonText: 'OK'
            });
        }
    } else {
        Swal.fire({
            title: 'Incomplete Process',
            text: 'Please complete all tasks before closing savings.',
            icon: 'error'
        });
    }
});
</script>
</body>
</html>

<?php include 'new_footer.php'; ?>