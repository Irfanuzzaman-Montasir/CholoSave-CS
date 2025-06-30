<?php
session_start();

if (!isset($_SESSION['user_id'])) {
    header("Location: /CholoSave-CS/error_page.php");
    exit;
}

$user_id = $_SESSION['user_id'];

if (!isset($conn)) {
    include 'db.php';
}

$paymentHistoryQuery = "
    SELECT 
        transaction_id, 
        amount, 
        payment_method, 
        payment_time 
    FROM transaction_info
    WHERE user_id = ? AND group_id = ?
    ORDER BY payment_time DESC
";

if ($stmt = $conn->prepare($paymentHistoryQuery)) {
    $stmt->bind_param('ii', $user_id, $_SESSION['group_id']);
    $stmt->execute();
    $paymentHistoryResult = $stmt->get_result();
} else {
    die("Error preparing payment history query.");
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
            from {
                opacity: 0;
                transform: translateY(10px);
            }

            to {
                opacity: 1;
                transform: translateY(0);
            }
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
                        <h1 class="text-2xl font-semibold text-gray-800 ">
                            <i class="fa-solid fa-receipt mr-2 text-blue-600"></i>
                            Payment History
                        </h1>
                    </div>
                </div>
            </header>

            <!-- Main Content -->
            <main class="p-6 overflow-auto h-[calc(100vh-4rem)]">
                <div class="max-w-7xl mx-auto animate-fade-in">
                    <!-- Payment History Table -->
                    <div class="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
                        <div class="px-6 py-4 border-b border-gray-200 bg-gray-50">
                            <h2 class="text-lg font-semibold text-gray-800">Payment Details</h2>
                        </div>
                        <div class="table-container overflow-x-auto">
                            <table class="min-w-full divide-y divide-gray-200">
                                <thead class="bg-gray-50">
                                    <tr>
                                        <th
                                            class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                            Serial</th>
                                        <th
                                            class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                            Transaction ID</th>
                                        <th
                                            class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                            Amount (BDT)</th>
                                        <th
                                            class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                            Payment Method</th>
                                        <th
                                            class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                            Payment Time</th>
                                    </tr>
                                </thead>
                                <tbody class="bg-white divide-y divide-gray-200">
                                    <?php
                                    if ($paymentHistoryResult->num_rows > 0) {
                                        $serial = 1;
                                        while ($row = $paymentHistoryResult->fetch_assoc()) {
                                            echo "<tr class='hover:bg-gray-50 transition-colors duration-150'>";
                                            echo "<td class='px-6 py-4 whitespace-nowrap text-sm text-gray-500'>" . $serial++ . "</td>";
                                            echo "<td class='px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900'>" . htmlspecialchars($row['transaction_id'], ENT_QUOTES, 'UTF-8') . "</td>";
                                            echo "<td class='px-6 py-4 whitespace-nowrap text-sm text-gray-900'>" . number_format($row['amount']) . "</td>";
                                            echo "<td class='px-6 py-4 whitespace-nowrap text-sm text-gray-500'>
                                                    <span class='px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-green-100 text-green-800'>
                                                        " . htmlspecialchars($row['payment_method'], ENT_QUOTES, 'UTF-8') . "
                                                    </span>
                                                  </td>";
                                            echo "<td class='px-6 py-4 whitespace-nowrap text-sm text-gray-500'>" . date('M d, Y H:i', strtotime($row['payment_time'])) . "</td>";
                                            echo "</tr>";
                                        }
                                    } else {
                                        echo '<tr><td colspan="5" class="px-6 py-4 text-center text-gray-500">No payment history found</td></tr>';
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