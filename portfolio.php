<?php
session_start();
include 'db.php'; // Include the database connection
include 'includes/header2.php'; // Include the header file

// Check if user is logged in
if (!isset($_SESSION['user_id'])) {
    header('Location: login.php');
    exit();
}

$user_id = $_SESSION['user_id'];

// Initialize arrays for storing portfolio data
$portfolio = [
    'total_groups' => 0,
    'total_savings' => 0.0,
    'outstanding_loans' => 0.0,
    'withdrawn_amount' => 0.0,
    'total_group_contributions' => 0.0,
    'group_investments' => []
];

// Database queries
try {
    // Get the groups the user is a member of
    $query = "
        SELECT g.group_id, g.group_name, gm.join_date
        FROM group_membership gm
        JOIN my_group g ON gm.group_id = g.group_id
        WHERE gm.user_id = ? AND gm.status = 'approved'
    ";
    $stmt = $conn->prepare($query);
    $stmt->bind_param("i", $user_id);
    $stmt->execute();
    $groups = $stmt->get_result()->fetch_all(MYSQLI_ASSOC);

    $portfolio['total_groups'] = count($groups);

    foreach ($groups as $group) {
        $group_id = $group['group_id'];

        // Get total savings for this group
        $query = "
            SELECT SUM(amount) as total_savings
            FROM savings
            WHERE user_id = ? AND group_id = ?
        ";
        $stmt = $conn->prepare($query);
        $stmt->bind_param("ii", $user_id, $group_id);
        $stmt->execute();
        $stmt->bind_result($total_savings);
        $stmt->fetch();
        $portfolio['total_savings'] += $total_savings ?: 0;
        $stmt->close();

        // Get outstanding loans for this group
        $query = "
            SELECT SUM(amount) as outstanding_loans
            FROM loan_request
            WHERE user_id = ? AND group_id = ? AND status = 'approved'
        ";
        $stmt = $conn->prepare($query);
        $stmt->bind_param("ii", $user_id, $group_id);
        $stmt->execute();
        $stmt->bind_result($outstanding_loans);
        $stmt->fetch();
        $portfolio['outstanding_loans'] += $outstanding_loans ?: 0;
        $stmt->close();

        // Get withdrawn amount for this group
        $query = "
            SELECT SUM(amount) as withdrawn_amount
            FROM withdrawal
            WHERE user_id = ? AND group_id = ? AND status = 'approved'
        ";
        $stmt = $conn->prepare($query);
        $stmt->bind_param("ii", $user_id, $group_id);
        $stmt->execute();
        $stmt->bind_result($withdrawn_amount);
        $stmt->fetch();
        $portfolio['withdrawn_amount'] += $withdrawn_amount ?: 0;
        $stmt->close();

        // Calculate total contributions for the group
        $group_contributions = $total_savings - $withdrawn_amount;
        $portfolio['total_group_contributions'] += $group_contributions;

        // Get investments made by the group
        $query = "
            SELECT investment_type, SUM(amount) as total_invested
            FROM investments
            WHERE group_id = ?
            GROUP BY investment_type
        ";
        $stmt = $conn->prepare($query);
        $stmt->bind_param("i", $group_id);
        $stmt->execute();
        $investments = $stmt->get_result()->fetch_all(MYSQLI_ASSOC);
        $portfolio['group_investments'][$group['group_name']] = $investments;
        $stmt->close();
    }
} catch (Exception $e) {
    die("Error: " . $e->getMessage());
}
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>User Portfolio Dashboard</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
</head>

<body class="bg-gradient-to-br from-gray-50 to-gray-100 min-h-screen">
    <div class="container mx-auto p-6 mt-16">
        <!-- Header Section -->
        <div class="text-center mb-8">
            <h1 class="text-3xl font-bold text-gray-800 mb-2">Welcome Back </h1>
            <p class="text-gray-600">Monitor Your Portfolio Performance & Group Analytics</p>
        </div>

        <!-- Overview Cards -->
        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 mb-8">
            <!-- Total Groups Card -->
            <div class="bg-white rounded-xl shadow-md p-6 transform transition-transform hover:scale-105">
                <div class="flex items-center justify-between">
                    <div>
                        <p class="text-sm text-gray-500 mb-1">Total Groups</p>
                        <h3 class="text-2xl font-bold text-gray-800"><?= $portfolio['total_groups'] ?></h3>
                    </div>
                    <div class="bg-blue-100 p-3 rounded-full">
                        <i class="fas fa-users text-blue-600 text-xl"></i>
                    </div>
                </div>
            </div>

            <!-- Total Savings Card -->
            <div class="bg-white rounded-xl shadow-md p-6 transform transition-transform hover:scale-105">
                <div class="flex items-center justify-between">
                    <div>
                        <p class="text-sm text-gray-500 mb-1">Total Savings</p>
                        <h3 class="text-2xl font-bold text-green-600">
                            BDT <?= number_format($portfolio['total_savings'], 2) ?></h3>
                    </div>
                    <div class="bg-green-100 p-3 rounded-full">
                        <i class="fas fa-piggy-bank text-green-600 text-xl"></i>
                    </div>
                </div>
            </div>

            <!-- Outstanding Loans Card -->
            <div class="bg-white rounded-xl shadow-md p-6 transform transition-transform hover:scale-105">
                <div class="flex items-center justify-between">
                    <div>
                        <p class="text-sm text-gray-500 mb-1">Outstanding Loans</p>
                        <h3 class="text-2xl font-bold text-red-600">
                            BDT <?= number_format($portfolio['outstanding_loans'], 2) ?></h3>
                    </div>
                    <div class="bg-red-100 p-3 rounded-full">
                        <i class="fas fa-hand-holding-dollar text-red-600 text-xl"></i>
                    </div>
                </div>
            </div>
        </div>

        <!-- Financial Summary Section -->
        <div class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
            <!-- Withdrawals & Contributions -->
            <div class="bg-white rounded-xl shadow-md p-6">
                <h2 class="text-xl font-semibold text-gray-800 mb-4">Financial Summary</h2>
                <div class="space-y-4">
                    <div class="flex justify-between items-center p-3 bg-gray-50 rounded-lg">
                        <div class="flex items-center">
                            <i class="fas fa-arrow-down text-red-500 mr-3"></i>
                            <span>Withdrawn Amount</span>
                        </div>
                        <span class="font-semibold">BDT <?= number_format($portfolio['withdrawn_amount'], 2) ?></span>
                    </div>
                    <div class="flex justify-between items-center p-3 bg-gray-50 rounded-lg">
                        <div class="flex items-center">
                            <i class="fas fa-arrow-up text-green-500 mr-3"></i>
                            <span>Total Contributions</span>
                        </div>
                        <span class="font-semibold">BDT <?= number_format($portfolio['total_group_contributions'], 2) ?></span>
                    </div>
                </div>
            </div>

            <!-- Quick Actions - Updated Style -->
            <div class="bg-white rounded-xl shadow-md p-6">
                <h2 class="text-xl font-semibold text-gray-800 mb-6 flex items-center">
                    <i class="fas fa-bolt mr-2 text-slate-600"></i>
                    Quick Actions
                </h2>
                <div class="space-y-3">
                    <a href="/CholoSave-CS/groups.php" class="flex items-center justify-between p-4 bg-slate-50 rounded-lg hover:bg-slate-100 transition-colors">
                        <div class="flex items-center">
                            <i class="fas fa-plus text-blue-600 mr-3"></i>
                            <span class="font-medium">Join Groups</span>
                        </div>
                        <i class="fas fa-chevron-right text-gray-400"></i>
                    </a>
                    <a href="/CholoSave-CS/leaderboard.php" class="flex items-center justify-between p-4 bg-slate-50 rounded-lg hover:bg-slate-100 transition-colors">
                        <div class="flex items-center">
                            <i class="fas fa-trophy text-amber-600 mr-3"></i>
                            <span class="font-medium">Leaderboard</span>
                        </div>
                        <i class="fas fa-chevron-right text-gray-400"></i>
                    </a>
                    <a href="/CholoSave-CS/details_portfolio.php" class="flex items-center justify-between p-4 bg-slate-50 rounded-lg hover:bg-slate-100 transition-colors">
                        <div class="flex items-center">
                            <i class="fas fa-info-circle text-purple-600 mr-3"></i>
                            <span class="font-medium">View Details</span>
                        </div>
                        <i class="fas fa-chevron-right text-gray-400"></i>
                    </a>
                    <a href="/CholoSave-CS/forum.php" class="flex items-center justify-between p-4 bg-slate-50 rounded-lg hover:bg-slate-100 transition-colors">
                        <div class="flex items-center">
                            <i class="fas fa-comments text-slate-600 mr-3"></i>
                            <span class="font-medium">Forum</span>
                        </div>
                        <i class="fas fa-chevron-right text-gray-400"></i>
                    </a>
                </div>
            </div>
        </div>

        <!-- Group Investments Section -->
        <div class="bg-white rounded-xl shadow-md p-6">
            <h2 class="text-xl font-semibold text-gray-800 mb-6">Group Investments</h2>
            <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                <?php foreach ($portfolio['group_investments'] as $group_name => $investments): ?>
                    <div class="bg-gray-50 rounded-lg p-4">
                        <h3 class="text-lg font-bold text-gray-800 mb-3 flex items-center">
                            <i class="fas fa-building-columns mr-2 text-blue-600"></i>
                            <?= htmlspecialchars($group_name) ?>
                        </h3>
                        <ul class="space-y-2">
                            <?php foreach ($investments as $investment): ?>
                                <li class="flex justify-between items-center p-2 bg-white rounded-md">
                                    <span class="text-gray-600"><?= htmlspecialchars($investment['investment_type']) ?></span>
                                    <span class="font-semibold text-gray-800">$<?= number_format($investment['total_invested'], 2) ?></span>
                                </li>
                            <?php endforeach; ?>
                        </ul>
                    </div>
                <?php endforeach; ?>
            </div>
        </div>
    </div>

    <footer>
        <?php include 'includes/new_footer.php'; ?>
    </footer>
</body>

</html>