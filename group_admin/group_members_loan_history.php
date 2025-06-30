<?php
session_start();

if (!isset($_SESSION['user_id'])) {
    header("Location: /CholoSave-CS/error_page.php"); // Redirect if session variables are missing
    exit;
}

$user_id = $_SESSION['user_id'];
$group_id = $_SESSION['group_id'];

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

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['loan_id'], $_POST['action'])) {
    $loan_id = $_POST['loan_id'];
    $action = $_POST['action'];

    // Start transaction
    $conn->begin_transaction();

    try {
        if (in_array($action, ['approved', 'declined'])) {
            // Get loan request details
            $getLoanDetailsQuery = "
                SELECT lr.user_id, lr.amount, mg.group_name, mg.emergency_fund 
                FROM loan_request lr
                JOIN my_group mg ON lr.group_id = mg.group_id
                WHERE lr.id = ? AND lr.group_id = ?
            ";

            if ($stmt = $conn->prepare($getLoanDetailsQuery)) {
                $stmt->bind_param('ii', $loan_id, $group_id);
                $stmt->execute();
                $result = $stmt->get_result();
                $loanDetails = $result->fetch_assoc();
                $stmt->close();

                if ($action === 'approved') {
                    // Check if emergency fund is sufficient
                    if ($loanDetails['emergency_fund'] < $loanDetails['amount']) {
                        throw new Exception("Insufficient emergency fund balance.");
                    }

                    // Update emergency fund
                    $newEmergencyFund = $loanDetails['emergency_fund'] - $loanDetails['amount'];
                    $updateEmergencyFundQuery = "
                        UPDATE my_group 
                        SET emergency_fund = ? 
                        WHERE group_id = ?
                    ";

                    if ($stmt = $conn->prepare($updateEmergencyFundQuery)) {
                        $stmt->bind_param('di', $newEmergencyFund, $group_id);
                        $stmt->execute();
                        $stmt->close();
                    }

                    // Notification Handling for Approval
                    // Create approval notification for the user
                    $notificationTitle = "Loan Request Approved";
                    $notificationMessage = "Your loan request for BDT {$loanDetails['amount']} in group '{$loanDetails['group_name']}' has been approved.";

                    $insertUserNotificationQuery = "
                        INSERT INTO notifications (
                            target_user_id,
                            type,
                            title,
                            message,
                            status
                        ) VALUES (?, 'loan_approval', ?, ?, 'unread')
                    ";

                    if ($stmt = $conn->prepare($insertUserNotificationQuery)) {
                        $stmt->bind_param(
                            'iss',
                            $loanDetails['user_id'],
                            $notificationTitle,
                            $notificationMessage
                        );
                        $stmt->execute();
                        $stmt->close();
                    }

                    // Create approval notification for the group
                    $groupNotificationTitle = "New Loan Approved";
                    $groupNotificationMessage = "A loan request for BDT {$loanDetails['amount']} has been approved.";

                    $insertGroupNotificationQuery = "
                        INSERT INTO notifications (
                            target_group_id,
                            type,
                            title,
                            message,
                            status
                        ) VALUES (?, 'loan_approval', ?, ?, 'unread')
                    ";

                    if ($stmt = $conn->prepare($insertGroupNotificationQuery)) {
                        $stmt->bind_param(
                            'iss',
                            $group_id,
                            $groupNotificationTitle,
                            $groupNotificationMessage
                        );
                        $stmt->execute();
                        $stmt->close();
                    }
                } else {
                    // Notification Handling for Rejection
                    // Create rejection notification for the user
                    $notificationTitle = "Loan Request Declined";
                    $notificationMessage = "Your loan request for BDT {$loanDetails['amount']} in group '{$loanDetails['group_name']}' has been declined.";

                    $insertRejectionNotificationQuery = "
                        INSERT INTO notifications (
                            target_user_id,
                            type,
                            title,
                            message,
                            status
                        ) VALUES (?, 'loan_approval', ?, ?, 'unread')
                    ";

                    if ($stmt = $conn->prepare($insertRejectionNotificationQuery)) {
                        $stmt->bind_param(
                            'iss',
                            $loanDetails['user_id'],
                            $notificationTitle,
                            $notificationMessage
                        );
                        $stmt->execute();
                        $stmt->close();
                    }
                }
            }

            // Update loan status
            $updateLoanStatusQuery = "
                UPDATE loan_request 
                SET status = ?, approve_date = CURDATE() 
                WHERE id = ? AND group_id = ?
            ";

            if ($stmt = $conn->prepare($updateLoanStatusQuery)) {
                $stmt->bind_param('sii', $action, $loan_id, $group_id);
                $stmt->execute();
                $stmt->close();
            }
        }

        // Commit transaction
        $conn->commit();
        $message = "Loan request " . ($action === 'approved' ? 'approved' : 'declined') . " successfully.";
    } catch (Exception $e) {
        // Rollback transaction on error
        $conn->rollback();
        $errorMessage = $e->getMessage();

        // Show error message using SweetAlert
        echo "<script>
                Swal.fire({
                    title: 'Error!',
                    text: '$errorMessage',
                    icon: 'error',
                    confirmButtonText: 'OK'
                });
              </script>";
    }
}

// Fetch loan history details for the logged-in user
$loanHistoryQuery = "
    SELECT 
        lr.id AS loan_id,
        lr.user_id AS user_id,
        lr.amount AS loan_amount,
        lr.approve_date AS approve_date,
        lr.return_time AS due_date,
        lr.request_time AS request_date,
        lr.status AS loan_status,
        u.name AS user_name,
        (SELECT SUM(amount) FROM savings WHERE user_id = lr.user_id AND group_id = lr.group_id) AS group_contribution
    FROM loan_request lr
    LEFT JOIN users u ON lr.user_id = u.id
    WHERE lr.group_id = ? 
    ORDER BY lr.request_time DESC
";

if ($stmt = $conn->prepare($loanHistoryQuery)) {
    $stmt->bind_param('i', $group_id);
    $stmt->execute();
    $loanHistoryResult = $stmt->get_result();
} else {
    die("Error preparing loan history query.");
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CholoSave Loan Management</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>
    <style>
        body {
            font-family: 'Inter', sans-serif;
        }
        .table-container {
            scrollbar-width: thin;
            scrollbar-color: #CBD5E0 #EDF2F7;
        }
        .table-container::-webkit-scrollbar {
            width: 8px;
            height: 8px;
        }
        .table-container::-webkit-scrollbar-track {
            background: #EDF2F7;
        }
        .table-container::-webkit-scrollbar-thumb {
            background-color: #CBD5E0;
            border-radius: 4px;
        }
        .animate-fade-in {
            animation: fadeIn 0.5s ease-in-out;
        }
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }
    </style>
</head>
<body class="bg-gray-100">
    <div class="flex h-screen">
        <?php include 'group_admin_sidebar.php'; ?>

        <div class="flex-1 overflow-hidden">
            <!-- Header -->
            <header class="bg-white shadow-sm border-b border-gray-200 px-6 py-4">
                <div class="flex items-center justify-center w-full">
                    <div class="flex items-center">
                        <button id="menu-button" class="md:hidden mr-4 text-gray-600 hover:text-gray-900">
                            <i class="fa-solid fa-bars text-xl"></i>
                        </button>
                        <h1 class="text-2xl font-semibold text-gray-800">
                            <i class="fa-solid fa-file-invoice-dollar mr-2 text-blue-600"></i>
                            Loan Management
                        </h1>
                    </div>
                </div>
            </header>

            <!-- Main Content -->
            <main class="p-6 overflow-auto h-[calc(100vh-4rem)]">
                <div class="max-w-7xl mx-auto animate-fade-in">
                    <!-- Loan Management Table -->
                    <div class="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
                        <div class="px-6 py-4 border-b border-gray-200 bg-gray-50">
                            <div class="flex flex-col md:flex-row md:items-center md:justify-between">
                                <h2 class="text-lg font-semibold text-gray-800 mb-4 md:mb-0">Loan Requests</h2>
                                <form method="GET" action="" class="flex items-center space-x-4">
                                    <select id="filter" name="filter" class="p-2 border border-gray-300 rounded-md text-sm">
                                        <option value="">All Status</option>
                                        <option value="pending" <?php echo isset($_GET['filter']) && $_GET['filter'] === 'pending' ? 'selected' : ''; ?>>Pending</option>
                                        <option value="approved" <?php echo isset($_GET['filter']) && $_GET['filter'] === 'approved' ? 'selected' : ''; ?>>Approved</option>
                                        <option value="repaid" <?php echo isset($_GET['filter']) && $_GET['filter'] === 'repaid' ? 'selected' : ''; ?>>Repaid</option>
                                    </select>
                                    <button type="submit" class="px-4 py-2 bg-blue-500 text-white rounded-md text-sm font-medium hover:bg-blue-600 transition-colors duration-200">
                                        Apply Filter
                                    </button>
                                </form>
                            </div>
                        </div>
                        <div class="table-container overflow-x-auto">
                            <table class="min-w-full divide-y divide-gray-200">
                                <thead class="bg-gray-50">
                                    <tr>
                                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Serial</th>
                                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Name</th>
                                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Loan Amount (BDT)</th>
                                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Group Contribution (BDT)</th>
                                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Request Date</th>
                                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Due Date</th>
                                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Approve Date</th>
                                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
                                    </tr>
                                </thead>
                                <tbody class="bg-white divide-y divide-gray-200">
                                    <?php
                                    $filter = isset($_GET['filter']) ? $_GET['filter'] : '';
                                    $serial = 1;
                                    if ($loanHistoryResult->num_rows > 0) {
                                        while ($row = $loanHistoryResult->fetch_assoc()) {
                                            if ($filter && $row['loan_status'] !== $filter) {
                                                continue;
                                            }

                                            $statusClass = '';
                                            switch($row['loan_status']) {
                                                case 'approved':
                                                    $statusClass = 'bg-green-100 text-green-800';
                                                    break;
                                                case 'pending':
                                                    $statusClass = 'bg-yellow-100 text-yellow-800';
                                                    break;
                                                case 'repaid':
                                                    $statusClass = 'bg-blue-100 text-blue-800';
                                                    break;
                                            }

                                            echo "<tr class='hover:bg-gray-50 transition-colors duration-150'>";
                                            echo "<td class='px-6 py-4 whitespace-nowrap text-sm text-gray-500'>" . $serial++ . "</td>";
                                            echo "<td class='px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900'>" . htmlspecialchars($row['user_name']) . "</td>";
                                            echo "<td class='px-6 py-4 whitespace-nowrap text-sm text-gray-900'>" . number_format($row['loan_amount']) . "</td>";
                                            echo "<td class='px-6 py-4 whitespace-nowrap text-sm text-gray-900'>" . number_format($row['group_contribution']) . "</td>";
                                            echo "<td class='px-6 py-4 whitespace-nowrap text-sm text-gray-500'>" . date('M d, Y', strtotime($row['request_date'])) . "</td>";
                                            echo "<td class='px-6 py-4 whitespace-nowrap text-sm text-gray-500'>" . date('M d, Y', strtotime($row['due_date'])) . "</td>";
                                            echo "<td class='px-6 py-4 whitespace-nowrap text-sm text-gray-500'>" . ($row['approve_date'] ? date('M d, Y', strtotime($row['approve_date'])) : '-') . "</td>";
                                            echo "<td class='px-6 py-4 whitespace-nowrap'>
                                                    <span class='px-2 inline-flex text-xs leading-5 font-semibold rounded-full {$statusClass}'>
                                                        " . ucfirst($row['loan_status']) . "
                                                    </span>
                                                  </td>";
                                            
                                            if ($row['loan_status'] === 'pending') {
                                                echo "<td class='px-6 py-4 whitespace-nowrap text-sm font-medium space-x-2'>
                                                    <form action='' method='POST' class='inline-block'>
                                                        <input type='hidden' name='loan_id' value='" . $row['loan_id'] . "'>
                                                        <button type='submit' name='action' value='approved' class='bg-green-500 hover:bg-green-600 text-white px-3 py-1 rounded-md text-sm font-medium transition-colors duration-200'>Approve</button>
                                                        <button type='submit' name='action' value='declined' class='bg-red-500 hover:bg-red-600 text-white px-3 py-1 rounded-md text-sm font-medium transition-colors duration-200'>Reject</button>
                                                    </form>
                                                </td>";
                                            } else {
                                                echo "<td class='px-6 py-4 whitespace-nowrap text-sm text-gray-500'>N/A</td>";
                                            }
                                            echo "</tr>";
                                        }
                                    } else {
                                        echo '<tr><td colspan="9" class="px-6 py-4 text-center text-gray-500">No loan history found</td></tr>';
                                    }
                                    ?>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </main>
        </div>
    </div>

    <script>
        // Menu toggle for mobile
        const menuButton = document.getElementById('menu-button');
        const sidebar = document.querySelector('.sidebar');

        menuButton?.addEventListener('click', () => {
            sidebar?.classList.toggle('hidden');
        });

        // Handle window resize
        window.addEventListener('resize', () => {
            if (window.innerWidth >= 768) {
                sidebar?.classList.remove('hidden');
            }
        });

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