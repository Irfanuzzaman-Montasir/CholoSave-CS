<?php
session_start();

if (!isset($_SESSION['user_id'])) {
    header("Location: /CholoSave-CS/error_page.php");
    exit;
}

$user_id = $_SESSION['user_id'];
$group_id = $_SESSION['group_id'];

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
    
    if ($group_admin_id === $user_id) {
        $is_admin = true;
    }
}

if (!$is_admin) {
    header("Location: /CholoSave-CS/error_page.php");
    exit;
}

$paymentMethodFilter = isset($_GET['payment_method']) ? $_GET['payment_method'] : '';

$paymentHistoryQuery = "
    SELECT 
        t.transaction_id, 
        t.amount, 
        t.payment_method, 
        t.payment_time, 
        t.user_id, 
        u.name AS member_name
    FROM transaction_info t
    JOIN users u ON t.user_id = u.id
    WHERE t.group_id = ? 
    " . ($paymentMethodFilter ? "AND t.payment_method = ?" : "") . "
    ORDER BY t.payment_time DESC
";

if ($stmt = $conn->prepare($paymentHistoryQuery)) {
    if ($paymentMethodFilter) {
        $stmt->bind_param('is', $group_id, $paymentMethodFilter);
    } else {
        $stmt->bind_param('i', $group_id);
    }
    $stmt->execute();
    $paymentHistoryResult = $stmt->get_result();
} else {
    die("Error preparing payment history query.");
}

$transactions = [];
while ($row = $paymentHistoryResult->fetch_assoc()) {
    $transactions[] = $row;
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CholoSave Payment History</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
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
                            <i class="fa-solid fa-chart-line mr-2 text-blue-600"></i>
                            Group Payment History
                        </h1>
                    </div>
                </div>
            </header>

            <!-- Main Content -->
            <main class="p-6 overflow-auto h-[calc(100vh-4rem)]">
                <div class="max-w-7xl mx-auto animate-fade-in">
                    <?php if ($is_admin): ?>
                    <div class="mb-6">
                        <div class="bg-blue-50 border border-blue-200 rounded-xl p-4 text-blue-600 flex items-center">
                            <i class="fa-solid fa-crown mr-2"></i>
                            <span class="font-medium">You are the admin of this group</span>
                        </div>
                    </div>
                    <?php endif; ?>

                    <!-- Filters Section -->
                    <div class="bg-white rounded-xl shadow-sm border border-gray-200 p-6 mb-6">
                        <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                            <!-- Payment Method Filter -->
                            <div>
                                <form method="GET" action="" class="flex items-end gap-4">
                                    <div class="flex-1">
                                        <label for="payment_method" class="block text-sm font-medium text-gray-700 mb-2">Filter by Payment Method</label>
                                        <select id="payment_method" name="payment_method" class="w-full rounded-lg border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500">
                                            <option value="">All Methods</option>
                                            <option value="bKash" <?php echo $paymentMethodFilter === 'bKash' ? 'selected' : ''; ?>>bKash</option>
                                            <option value="Rocket" <?php echo $paymentMethodFilter === 'Rocket' ? 'selected' : ''; ?>>Rocket</option>
                                            <option value="Nagad" <?php echo $paymentMethodFilter === 'Nagad' ? 'selected' : ''; ?>>Nagad</option>
                                        </select>
                                    </div>
                                    <button type="submit" class="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors">
                                        Apply Filter
                                    </button>
                                </form>
                            </div>
                            <!-- Search -->
                            <div>
                                <label for="search" class="block text-sm font-medium text-gray-700 mb-2">Search by Transaction ID</label>
                                <input id="search" type="text" class="w-full rounded-lg border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500" placeholder="Enter transaction ID...">
                            </div>
                        </div>
                    </div>

                    <!-- Payment History Table -->
                    <div class="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
                        <div class="px-6 py-4 border-b border-gray-200 bg-gray-50">
                            <h2 class="text-lg font-semibold text-gray-800">Payment History</h2>
                        </div>
                        <div class="table-container overflow-x-auto">
                            <table class="min-w-full divide-y divide-gray-200">
                                <thead class="bg-gray-50">
                                    <tr>
                                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Serial</th>
                                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Member Name</th>
                                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Transaction ID</th>
                                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Amount (BDT)</th>
                                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Payment Method</th>
                                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Payment Time</th>
                                    </tr>
                                </thead>
                                <tbody id="payment-table-body" class="bg-white divide-y divide-gray-200">
                                    <?php
                                    foreach ($transactions as $index => $row) {
                                        echo "<tr class='hover:bg-gray-50 transition-colors duration-150'>";
                                        echo "<td class='px-6 py-4 whitespace-nowrap text-sm text-gray-500'>" . ($index + 1) . "</td>";
                                        echo "<td class='px-6 py-4 whitespace-nowrap text-sm text-gray-900'>" . htmlspecialchars($row['member_name']) . "</td>";
                                        echo "<td class='px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900 transaction-id'>" . htmlspecialchars($row['transaction_id']) . "</td>";
                                        echo "<td class='px-6 py-4 whitespace-nowrap text-sm text-gray-900'>" . number_format($row['amount'], 2) . "</td>";
                                        echo "<td class='px-6 py-4 whitespace-nowrap text-sm text-gray-900'>" . htmlspecialchars($row['payment_method']) . "</td>";
                                        echo "<td class='px-6 py-4 whitespace-nowrap text-sm text-gray-500'>" . date('M d, Y H:i', strtotime($row['payment_time'])) . "</td>";
                                        echo "</tr>";
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

        // Search functionality
        const searchInput = document.getElementById('search');
        const tableBody = document.getElementById('payment-table-body');

        searchInput.addEventListener('input', function() {
            const filter = searchInput.value.toLowerCase();
            const rows = tableBody.getElementsByTagName('tr');

            Array.from(rows).forEach(row => {
                const transactionIdCell = row.querySelector('.transaction-id');
                const transactionId = transactionIdCell.textContent.toLowerCase();
                
                if (transactionId.includes(filter)) {
                    row.style.display = '';
                } else {
                    row.style.display = 'none';
                }
            });
        });

        // Add smooth scroll behavior
        document.querySelectorAll('a[href^="#"]').forEach(anchor => {
            anchor.addEventListener('click', function(e) {
                e.preventDefault();
                document.querySelector(this.getAttribute('href')).scrollIntoView({
                    behavior: 'smooth'
                });
            });
        });
    </script>
</body>
</html>