<?php
session_start();

if (!isset($_SESSION['user_id'])) {
    header("Location: /test_project/error_page.php");
    exit;
}

$user_id = $_SESSION['user_id'];
$group_id = $_SESSION['group_id'];

if (!isset($conn)) {
    include 'db.php';
}

// Fetch withdrawal history
$withdrawalQuery = "
    SELECT 
        w.withdrawal_id,
        u.name,
        w.amount,
        w.payment_method,
        w.status,
        w.request_date,
        w.approve_date
    FROM withdrawal w
    JOIN users u ON w.user_id = u.id
    WHERE w.group_id = ?
    ORDER BY w.request_date DESC
";


// Execute queries
if ($stmt = $conn->prepare($withdrawalQuery)) {
    $stmt->bind_param('i', $group_id);
    $stmt->execute();
    $withdrawalResult = $stmt->get_result();
} else {
    die("Error preparing withdrawal query.");
}

?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CholoSave Withdrawal History</title>
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

<body class="bg-gray-50">
    <div class="flex h-screen">
        <?php include 'sidebar.php'; ?>

        <div class="flex-1 overflow-hidden">
            <!-- Header -->
            <header class="bg-white shadow-sm border-b border-gray-200 px-6 py-4">
                <div class="flex items-center justify-center">
                    <div class="flex items-center">
                        <button id="menu-button" class="md:hidden mr-4 text-gray-600 hover:text-gray-900">
                            <i class="fa-solid fa-bars text-xl"></i>
                        </button>
                        <h1 class="text-2xl font-semibold text-gray-800">
                            <i class="fa-solid fa-file-invoice-dollar mr-2 text-blue-600"></i>
                            Withdrawal History
                        </h1>
                    </div>
                </div>
            </header>

            <!-- Main Content -->
            <main class="p-6 overflow-auto h-[calc(100vh-4rem)]">
                <div class="max-w-7xl mx-auto animate-fade-in">
                    <!-- Summary Cards -->
                    <!-- Withdrawal History Table -->
                    <div class="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
                        <div class="px-6 py-4 border-b border-gray-200 bg-gray-50">
                            <h2 class="text-lg font-semibold text-gray-800">Group Withdrawal Details</h2>
                        </div>
                        <div class="table-container overflow-x-auto">
                            <table class="min-w-full divide-y divide-gray-200">
                                <thead class="bg-gray-50">
                                    <tr>
                                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Member Name</th>
                                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Amount (BDT)</th>
                                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Payment Method</th>
                                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Request Date</th>
                                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Approve Date</th>
                                    </tr>
                                </thead>
                                <tbody class="bg-white divide-y divide-gray-200">
                                    <?php
                                    if ($withdrawalResult->num_rows > 0) {
                                        while ($row = $withdrawalResult->fetch_assoc()) {
                                            $statusClass = '';
                                            switch($row['status']) {
                                                case 'approved':
                                                    $statusClass = 'bg-green-100 text-green-800';
                                                    break;
                                                case 'pending':
                                                    $statusClass = 'bg-yellow-100 text-yellow-800';
                                                    break;
                                                case 'rejected':
                                                    $statusClass = 'bg-red-100 text-red-800';
                                                    break;
                                                default:
                                                    $statusClass = 'bg-gray-100 text-gray-800';
                                            }
                                            
                                            echo "<tr class='hover:bg-gray-50 transition-colors duration-150'>";
                                            echo "<td class='px-6 py-4 whitespace-nowrap'>
                                                    <div class='flex items-center'>
                                                        <div class='flex-shrink-0 h-10 w-10'>
                                                            <div class='h-10 w-10 rounded-full bg-gray-200 flex items-center justify-center'>
                                                                <i class='fa-solid fa-user text-gray-500'></i>
                                                            </div>
                                                        </div>
                                                        <div class='ml-4'>
                                                            <div class='text-sm font-medium text-gray-900'>" . htmlspecialchars($row['name']) . "</div>
                                                        </div>
                                                    </div>
                                                  </td>";
                                            echo "<td class='px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900'>" . number_format($row['amount']) . "</td>";
                                            echo "<td class='px-6 py-4 whitespace-nowrap text-sm text-gray-500'>" . htmlspecialchars($row['payment_method']) . "</td>";
                                            echo "<td class='px-6 py-4 whitespace-nowrap text-sm text-gray-500'>" . date('M d, Y', strtotime($row['request_date'])) . "</td>";
                                            echo "<td class='px-6 py-4 whitespace-nowrap'>
                                                    <span class='px-2 inline-flex text-xs leading-5 font-semibold rounded-full {$statusClass}'>
                                                        " . ucfirst($row['status']) . "
                                                    </span>
                                                  </td>";
                                            echo "<td class='px-6 py-4 whitespace-nowrap text-sm text-gray-500'>" . 
                                                ($row['approve_date'] ? date('M d, Y', strtotime($row['approve_date'])) : '-') . "</td>";
                                            echo "</tr>";
                                        }
                                    } else {
                                        echo '<tr><td colspan="6" class="px-6 py-4 text-center text-gray-500">No withdrawal history found</td></tr>';
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
    </script>
</body>
</html>

<?php include 'new_footer.php'; ?>