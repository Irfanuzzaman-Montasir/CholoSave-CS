<?php
// Start session
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



// Fetch investment data
$investmentHistoryQuery = "
    SELECT 
        i.amount AS 'Investment Amount', 
        i.investment_type AS Type, 
        i.status, 
        i.ex_profit AS 'Expected Profit', 
        ir.amount AS 'Actual Profit', 
        ir.return_date AS 'Return Date'
    FROM 
        investments i 
    LEFT JOIN 
        investment_returns ir 
    ON 
        i.investment_id = ir.investment_id
    WHERE 
        i.group_id = ? 
    ORDER BY i.investment_id DESC
";

$investments = [];
if ($stmt = $conn->prepare($investmentHistoryQuery)) {
    $stmt->bind_param('i', $group_id);
    $stmt->execute();
    $result = $stmt->get_result();
    while ($row = $result->fetch_assoc()) {
        $investments[] = $row;
    }
    $stmt->close();
}

// Store investments in session for PDF export
$_SESSION['investment_data'] = $investments;

?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Investment History</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        body {
            font-family: 'Inter', sans-serif;
        }

        .glass-effect {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
        }

        .hover-scale {
            transition: transform 0.2s;
        }

        .hover-scale:hover {
            transform: scale(1.02);
        }

        .status-badge {
            padding: 0.25rem 0.75rem;
            border-radius: 9999px;
            font-size: 0.875rem;
            font-weight: 500;
        }

        .gradient-bg {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        }
    </style>
</head>

<body class="bg-gradient-to-br from-gray-50 to-gray-100 min-h-screen">
    <div class="flex h-screen">
        <!-- Sidebar -->
        <?php include 'sidebar.php'; ?>

        <!-- Main Content -->
        <div class="flex-1 flex flex-col overflow-hidden">
            <!-- Top Bar -->
            <header class="glass-effect border-b border-gray-200 shadow-sm">
                <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
                    <div class="flex items-center justify-between">
                        <div class="flex items-center">
                            <button id="menu-button" class="md:hidden p-2 rounded-lg text-gray-600 hover:bg-gray-100">
                                <i class="fa-solid fa-bars text-xl"></i>
                            </button>
                            <h1 class="text-3xl font-bold text-gray-900 ml-96">
                                <i class="fa-solid fa-chart-line text-blue-600 mr-3"></i>
                                Investment History
                            </h1>
                        </div>
                        <div class="flex items-center space-x-4">
                            <a href="investment_details_export.php"
                                class="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg shadow-sm transition-colors duration-200 inline-flex items-center">
                                <i class="fas fa-download mr-2"></i> Export
                            </a>

                        </div>
                    </div>
                </div>
            </header>

            <!-- Main Content Area -->
            <div class="flex-1 overflow-y-auto bg-gray-50">
                <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
                    <!-- Stats Cards -->
                    <div class="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
                        <div class="glass-effect rounded-xl shadow-sm p-6 hover-scale">
                            <div class="flex items-center">
                                <div class="p-3 rounded-lg gradient-bg">
                                    <i class="fas fa-money-bill-wave text-white text-xl"></i>
                                </div>
                                <div class="ml-4">
                                    <p class="text-sm font-medium text-gray-600">Total Investments</p>
                                    <h3 class="text-xl font-bold text-gray-900">
                                        <?php
                                        $totalInvestment = array_sum(array_column($investments, 'Investment Amount'));
                                        echo 'BDT ' . number_format($totalInvestment, 2);
                                        ?>
                                    </h3>
                                </div>
                            </div>
                        </div>
                        <div class="glass-effect rounded-xl shadow-sm p-6 hover-scale">
                            <div class="flex items-center">
                                <div class="p-3 rounded-lg gradient-bg">
                                    <i class="fas fa-chart-pie text-white text-xl"></i>
                                </div>
                                <div class="ml-4">
                                    <p class="text-sm font-medium text-gray-600">Expected Returns</p>
                                    <h3 class="text-xl font-bold text-gray-900">
                                        <?php
                                        $totalExpected = array_sum(array_column($investments, 'Expected Profit'));
                                        echo 'BDT ' . number_format($totalExpected, 2);
                                        ?>
                                    </h3>
                                </div>
                            </div>
                        </div>
                        <div class="glass-effect rounded-xl shadow-sm p-6 hover-scale">
                            <div class="flex items-center">
                                <div class="p-3 rounded-lg gradient-bg">
                                    <i class="fas fa-hand-holding-usd text-white text-xl"></i>
                                </div>
                                <div class="ml-4">
                                    <p class="text-sm font-medium text-gray-600">Actual Returns</p>
                                    <h3 class="text-xl font-bold text-gray-900">
                                        <?php
                                        $totalActual = array_sum(array_filter(array_column($investments, 'Actual Profit')));
                                        echo 'BDT ' . number_format($totalActual, 2);
                                        ?>
                                    </h3>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- Investment History Table -->
                    <div class="glass-effect rounded-xl shadow-sm overflow-hidden">
                        <div class="px-6 py-4 border-b border-gray-200">
                            <h2 class="text-xl font-semibold text-gray-900">Investment & Return History</h2>
                            <p class="text-sm text-gray-600 mt-1">Comprehensive view of all investments and their
                                returns</p>
                        </div>
                        <div class="overflow-x-auto">
                            <table class="min-w-full divide-y divide-gray-200">
                                <thead class="bg-gray-50">
                                    <tr>
                                        <th
                                            class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                            Investment Amount</th>
                                        <th
                                            class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                            Type</th>
                                        <th
                                            class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                            Status</th>
                                        <th
                                            class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                            Expected Profit</th>
                                        <th
                                            class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                            Actual Profit</th>
                                        <th
                                            class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                            Return Date</th>
                                    </tr>
                                </thead>
                                <tbody class="bg-white divide-y divide-gray-200">
                                    <?php foreach ($investments as $investment): ?>
                                        <tr class="hover:bg-gray-50 transition-colors duration-200">
                                            <td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">
                                                BDT <?php echo number_format($investment['Investment Amount'], 2); ?>
                                            </td>
                                            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-600">
                                                <?php echo $investment['Type']; ?>
                                            </td>
                                            <td class="px-6 py-4 whitespace-nowrap">
                                                <?php
                                                $statusColor = [
                                                    'pending' => 'bg-yellow-100 text-yellow-800',
                                                    'active' => 'bg-green-100 text-green-800',
                                                    'completed' => 'bg-blue-100 text-blue-800'
                                                ][$investment['status']] ?? 'bg-gray-100 text-gray-800';
                                                ?>
                                                <span class="status-badge <?php echo $statusColor; ?>">
                                                    <?php echo ucfirst($investment['status']); ?>
                                                </span>
                                            </td>
                                            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-600">
                                                BDT <?php echo number_format($investment['Expected Profit'], 2); ?>
                                            </td>
                                            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-600">
                                                <?php echo isset($investment['Actual Profit']) ? 'BDT ' . number_format($investment['Actual Profit'], 2) : '-'; ?>
                                            </td>
                                            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-600">
                                                <?php echo isset($investment['Return Date']) ? date('d-m-Y', strtotime($investment['Return Date'])) : '-'; ?>
                                            </td>
                                        </tr>
                                    <?php endforeach; ?>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        // Menu button functionality
        const menuButton = document.getElementById('menu-button');
        const sidebar = document.querySelector('[data-sidebar]'); // Add data-sidebar attribute to your sidebar

        menuButton.addEventListener('click', () => {
            sidebar.classList.toggle('hidden');
        });

        // Responsive sidebar
        function handleResize() {
            if (window.innerWidth >= 768) {
                sidebar.classList.remove('hidden');
            } else {
                sidebar.classList.add('hidden');
            }
        }

        window.addEventListener('resize', handleResize);
        handleResize(); // Initial check
    </script>
</body>

</html>