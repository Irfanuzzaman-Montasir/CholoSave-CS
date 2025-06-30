<?php
session_start();

if (!isset($_SESSION['user_id'])) {
    header("Location: /test_project/error_page.php"); // Redirect if session variables are missing
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
    
    if ($group_admin_id === $user_id) {
        $is_admin = true;
    }
}

if (!$is_admin) {
    header("Location: /test_project/error_page.php");
    exit;
}

// Fetch loan history details
$loanHistoryQuery = "
    SELECT 
        lr.id AS loan_id,
        lr.amount AS loan_amount,
        lr.approve_date AS approve_date,
        lr.return_time AS due_date,
        lr.status AS loan_status
    FROM loan_request lr
    WHERE lr.user_id = ? AND lr.group_id = ? AND lr.status IN ('approved', 'pending', 'repaid') 
    ORDER BY lr.request_time DESC
";

if ($stmt = $conn->prepare($loanHistoryQuery)) {
    $stmt->bind_param('ii', $user_id, $group_id);
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
    <title>CholoSave Loan History</title>
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
                            Loan History
                        </h1>
                    </div>
                </div>
            </header>

            <!-- Main Content -->
            <main class="p-6 overflow-auto h-[calc(100vh-4rem)]">
                <div class="max-w-7xl mx-auto animate-fade-in">
                    <!-- Loan History Table -->
                    <div class="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
                        <div class="px-6 py-4 border-b border-gray-200 bg-gray-50">
                            <h2 class="text-lg font-semibold text-gray-800">Loan Details</h2>
                        </div>
                        <div class="table-container overflow-x-auto">
                            <table class="min-w-full divide-y divide-gray-200">
                                <thead class="bg-gray-50">
                                    <tr>
                                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Serial</th>
                                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Loan Amount (BDT)</th>
                                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Approve Date</th>
                                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Due Date</th>
                                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
                                    </tr>
                                </thead>
                                <tbody class="bg-white divide-y divide-gray-200">
                                    <?php
                                    if ($loanHistoryResult->num_rows > 0) {
                                        $serial = 1;
                                        while ($row = $loanHistoryResult->fetch_assoc()) {
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
                                            
                                            $actionButton = '';
                                            if ($row['loan_status'] == 'approved') {
                                                $actionButton = "<form action='loan_session.php' method='POST'>
                                                    <input type='hidden' name='loan_id' value='" . $row['loan_id'] . "'>
                                                    <button type='submit' class='bg-blue-500 hover:bg-blue-600 text-white px-4 py-2 rounded-md text-sm font-medium transition-colors duration-200'>Pay</button>
                                                </form>";
                                            } else {
                                                $actionButton = '<span class="text-gray-400">N/A</span>';
                                            }
                                            
                                            echo "<tr class='hover:bg-gray-50 transition-colors duration-150'>";
                                            echo "<td class='px-6 py-4 whitespace-nowrap text-sm text-gray-500'>" . $serial++ . "</td>";
                                            echo "<td class='px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900'>" . number_format($row['loan_amount']) . "</td>";
                                            echo "<td class='px-6 py-4 whitespace-nowrap text-sm text-gray-500'>" . date('M d, Y', strtotime($row['approve_date'])) . "</td>";
                                            echo "<td class='px-6 py-4 whitespace-nowrap text-sm text-gray-500'>" . date('M d, Y', strtotime($row['due_date'])) . "</td>";
                                            echo "<td class='px-6 py-4 whitespace-nowrap'>
                                                    <span class='px-2 inline-flex text-xs leading-5 font-semibold rounded-full {$statusClass}'>
                                                        " . ucfirst($row['loan_status']) . "
                                                    </span>
                                                  </td>";
                                            echo "<td class='px-6 py-4 whitespace-nowrap text-sm text-gray-500'>" . $actionButton . "</td>";
                                            echo "</tr>";
                                        }
                                    } else {
                                        echo '<tr><td colspan="6" class="px-6 py-4 text-center text-gray-500">No loan history found</td></tr>';
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