<?php
session_start();

if (!isset($_SESSION['group_id']) || !isset($_SESSION['user_id'])) {
    header("Location: /CholoSave-CS/error_page.php");
    exit;
}

$group_id = $_SESSION['group_id'];
$user_id = $_SESSION['user_id'];

if (!isset($conn)) {
    include 'db.php';
}

$memberQuery = "
    SELECT u.id, u.name, u.phone_number, g.join_date, g.is_admin, SUM(s.amount) AS group_contribution, g.time_period_remaining as installment
    FROM users u
    JOIN group_membership g ON u.id = g.user_id
    LEFT JOIN savings s ON u.id = s.user_id AND s.group_id = g.group_id
    WHERE g.group_id = ? AND g.status = 'approved'
    GROUP BY u.id, u.name, u.phone_number, g.join_date, g.is_admin
";

if ($stmt = $conn->prepare($memberQuery)) {
    $stmt->bind_param('i', $group_id);
    $stmt->execute();
    $result = $stmt->get_result();
} else {
    die("Error preparing statement.");
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CholoSave Members Dashboard</title>
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
                            <i class="fa-solid fa-users mr-2 text-blue-600"></i>
                            Group Members
                        </h1>
                    </div>
                    
                </div>
            </header>

            <!-- Main Content -->
            <main class="p-6 overflow-auto h-[calc(100vh-4rem)]">
                <div class="max-w-7xl mx-auto animate-fade-in">
                    <!-- Stats Cards -->
                    

                    <!-- Members Table -->
                    <div class="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
                        <div class="px-6 py-4 border-b border-gray-200 bg-gray-50">
                            <h2 class="text-lg font-semibold text-gray-800">Member Details</h2>
                        </div>
                        <div class="table-container overflow-x-auto">
                            <table class="min-w-full divide-y divide-gray-200">
                                <thead class="bg-gray-50">
                                    <tr>
                                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Name</th>
                                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Phone Number</th>
                                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Join Date</th>
                                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Role</th>
                                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Contribution</th>
                                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Installments Left</th>
                                    </tr>
                                </thead>
                                <tbody class="bg-white divide-y divide-gray-200">
                                    <?php
                                    if ($result->num_rows > 0) {
                                        while ($row = $result->fetch_assoc()) {
                                            $role = $row['is_admin'] == 1 ? 'Admin' : 'Member';
                                            $roleClass = $row['is_admin'] == 1 ? 'bg-blue-100 text-blue-800' : 'bg-gray-100 text-gray-800';
                                            ?>
                                            <tr class="hover:bg-gray-50 transition-colors duration-150">
                                                <td class="px-6 py-4 whitespace-nowrap">
                                                    <div class="flex items-center">
                                                        <div class="flex-shrink-0 h-10 w-10">
                                                            <div class="h-10 w-10 rounded-full bg-gray-200 flex items-center justify-center">
                                                                <i class="fa-solid fa-user text-gray-500"></i>
                                                            </div>
                                                        </div>
                                                        <div class="ml-4">
                                                            <div class="text-sm font-medium text-gray-900">
                                                                <?php echo htmlspecialchars($row['name'], ENT_QUOTES, 'UTF-8'); ?>
                                                            </div>
                                                        </div>
                                                    </div>
                                                </td>
                                                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                                                    <?php echo htmlspecialchars($row['phone_number'], ENT_QUOTES, 'UTF-8'); ?>
                                                </td>
                                                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                                                    <?php echo date('M d, Y', strtotime($row['join_date'])); ?>
                                                </td>
                                                <td class="px-6 py-4 whitespace-nowrap">
                                                    <span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full <?php echo $roleClass; ?>">
                                                        <?php echo $role; ?>
                                                    </span>
                                                </td>
                                                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                                                    <?php echo number_format($row['group_contribution'] ?? 0) . ' BDT'; ?>
                                                </td>
                                                <td class="px-6 py-4 whitespace-nowrap">
                                                    <div class="flex items-center">
                                                        <span class="ml-2 text-sm text-gray-500"><?php echo $row['installment']; ?></span>
                                                    </div>
                                                </td>
                                            </tr>
                                            <?php
                                        }
                                    } else {
                                        echo '<tr><td colspan="6" class="px-6 py-4 text-center text-gray-500">No members found</td></tr>';
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