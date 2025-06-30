<?php
session_start();
include 'db.php';
include 'includes/header2.php';

// Check if user is logged in
if (!isset($_SESSION['user_id'])) {
    header('Location: login.php');
    exit();
}

$user_id = $_SESSION['user_id'];

// Initialize array for storing group data
$groups_data = [];

try {
    // Get all groups the user is a member of
    $query = "
        SELECT g.group_id, g.group_name
        FROM group_membership gm
        JOIN my_group g ON gm.group_id = g.group_id
        WHERE gm.user_id = ? AND gm.status = 'approved'
    ";
    $stmt = $conn->prepare($query);
    $stmt->bind_param("i", $user_id);
    $stmt->execute();
    $result = $stmt->get_result();

    while ($group = $result->fetch_assoc()) {
        $group_id = $group['group_id'];
        $group_data = [
            'group_name' => $group['group_name'],
            'contribution' => 0,
            'loans' => 0,
            'remaining_installments' => 0,
            'withdraw_amount' => 0,
            'total_investments' => 0
        ];

        // Get contribution amount
        $query = "
            SELECT COALESCE(SUM(amount), 0) as total_contribution
            FROM savings
            WHERE user_id = ? AND group_id = ?
        ";
        $stmt = $conn->prepare($query);
        $stmt->bind_param("ii", $user_id, $group_id);
        $stmt->execute();
        $contribution = $stmt->get_result()->fetch_assoc();
        $group_data['contribution'] = $contribution['total_contribution'];

        // Get total loan amount
        $query_loans = "
SELECT 
    COALESCE(SUM(amount), 0) as total_loans
FROM loan_request
WHERE user_id = ? AND group_id = ? AND status = 'approved'
";
        $stmt_loans = $conn->prepare($query_loans);
        $stmt_loans->bind_param("ii", $user_id, $group_id);
        $stmt_loans->execute();
        $loan_result = $stmt_loans->get_result()->fetch_assoc();
        $group_data['loans'] = $loan_result['total_loans'];

        // Get remaining installments
        $query_installments = "
SELECT time_period_remaining as remaining_installments
FROM group_membership
WHERE user_id = ? AND group_id = ?
";
        $stmt_installments = $conn->prepare($query_installments);
        $stmt_installments->bind_param("ii", $user_id, $group_id);
        $stmt_installments->execute();
        $installment_result = $stmt_installments->get_result()->fetch_assoc();
        $group_data['remaining_installments'] = $installment_result['remaining_installments'];

        // Get withdrawal amount
        $query = "
            SELECT COALESCE(SUM(amount), 0) as total_withdrawn
            FROM withdrawal
            WHERE user_id = ? AND group_id = ? AND status = 'approved'
        ";
        $stmt = $conn->prepare($query);
        $stmt->bind_param("ii", $user_id, $group_id);
        $stmt->execute();
        $withdrawn = $stmt->get_result()->fetch_assoc();
        $group_data['withdraw_amount'] = $withdrawn['total_withdrawn'];

        // Get total investments
        $query = "
            SELECT COALESCE(SUM(amount), 0) as total_invested
            FROM investments
            WHERE group_id = ?
        ";
        $stmt = $conn->prepare($query);
        $stmt->bind_param("i", $group_id);
        $stmt->execute();
        $investments = $stmt->get_result()->fetch_assoc();
        $group_data['total_investments'] = $investments['total_invested'];

        $groups_data[] = $group_data;
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
    <title>Group-wise Details</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
</head>

<body class="bg-gradient-to-br from-gray-50 to-gray-100 min-h-screen">
    <div class="container mx-auto p-6">
        <!-- Header Section -->
        <div class="text-center mb-8">
            <h1 class="text-4xl font-bold text-gray-800 mb-2">Group-wise Details</h1>
            <p class="text-gray-600">Detailed view of your participation in each group</p>
        </div>

        <?php if (empty($groups_data)): ?>
            <!-- Empty State Message -->
            <div class="bg-white rounded-xl shadow-md p-8 text-center">
                <div class="mb-4">
                    <i class="fas fa-users text-gray-400 text-5xl"></i>
                </div>
                <h2 class="text-2xl font-bold text-gray-800 mb-2">No Group Data Available</h2>
                <p class="text-gray-600 mb-6">You are currently not a member of any groups or there is no activity to
                    display.</p>
                <a href="/CholoSave-CS/groups.php"
                    class="inline-block bg-blue-500 text-white px-6 py-3 rounded-lg hover:bg-blue-600 transition-colors">
                    Join a Group
                </a>
            </div>
        <?php else: ?>
            <!-- Groups Grid -->
            <div class="grid grid-cols-1 gap-6">
                <?php foreach ($groups_data as $group): ?>
                    <div class="bg-white rounded-xl shadow-md p-6 hover:shadow-lg transition-shadow">
                        <!-- Group Header -->
                        <div class="border-b pb-4 mb-4">
                            <h2 class="text-2xl font-bold text-gray-800 flex items-center">
                                <i class="fas fa-users text-blue-600 mr-3"></i>
                                <?= htmlspecialchars($group['group_name']) ?>
                            </h2>
                        </div>

                        <!-- Group Stats Grid -->
                        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                            <!-- Contribution -->
                            <div class="bg-gray-50 rounded-lg p-4">
                                <div class="flex items-center justify-between">
                                    <div>
                                        <p class="text-sm text-gray-500">Total Contribution</p>
                                        <p class="text-xl font-bold text-green-600">
                                            BDT <?= number_format($group['contribution'], 2) ?>
                                        </p>
                                    </div>
                                    <div class="bg-green-100 p-3 rounded-full">
                                        <i class="fas fa-piggy-bank text-green-600"></i>
                                    </div>
                                </div>
                            </div>

                            <!-- Loans -->
                            <div class="bg-gray-50 rounded-lg p-4">
                                <div class="flex items-center justify-between">
                                    <div>
                                        <p class="text-sm text-gray-500">Active Loans</p>
                                        <p class="text-xl font-bold text-red-600">
                                            BDT <?= number_format($group['loans'], 2) ?>
                                        </p>
                                    </div>
                                    <div class="bg-red-100 p-3 rounded-full">
                                        <i class="fas fa-hand-holding-dollar text-red-600"></i>
                                    </div>
                                </div>
                            </div>

                            <!-- Remaining Installments -->
                            <div class="bg-gray-50 rounded-lg p-4">
                                <div class="flex items-center justify-between">
                                    <div>
                                        <p class="text-sm text-gray-500">Remaining Installments</p>
                                        <p class="text-xl font-bold text-orange-600">
                                            <?= number_format($group['remaining_installments']) ?>
                                        </p>
                                    </div>
                                    <div class="bg-orange-100 p-3 rounded-full">
                                        <i class="fas fa-clock text-orange-600"></i>
                                    </div>
                                </div>
                            </div>

                            <!-- Withdrawals -->
                            <div class="bg-gray-50 rounded-lg p-4">
                                <div class="flex items-center justify-between">
                                    <div>
                                        <p class="text-sm text-gray-500">Total Withdrawals</p>
                                        <p class="text-xl font-bold text-purple-600">
                                            BDT <?= number_format($group['withdraw_amount'], 2) ?>
                                        </p>
                                    </div>
                                    <div class="bg-purple-100 p-3 rounded-full">
                                        <i class="fas fa-money-bill-transfer text-purple-600"></i>
                                    </div>
                                </div>
                            </div>

                            <!-- Total Investments -->
                            <div class="bg-gray-50 rounded-lg p-4">
                                <div class="flex items-center justify-between">
                                    <div>
                                        <p class="text-sm text-gray-500">Group Investments</p>
                                        <p class="text-xl font-bold text-blue-600">
                                            BDT <?= number_format($group['total_investments'], 2) ?>
                                        </p>
                                    </div>
                                    <div class="bg-blue-100 p-3 rounded-full">
                                        <i class="fas fa-chart-line text-blue-600"></i>
                                    </div>
                                </div>
                            </div>

                            <!-- Quick Actions -->
                            <!-- <div class="bg-gray-50 rounded-lg p-4">
                                <div class="flex gap-2">
                                    <a href="#" class="flex-1 bg-blue-500 text-white text-center py-2 px-4 rounded hover:bg-blue-600 transition-colors">
                                        Details
                                    </a>
                                    <a href="#" class="flex-1 bg-green-500 text-white text-center py-2 px-4 rounded hover:bg-green-600 transition-colors">
                                        Contribute
                                    </a>
                                </div>
                            </div> -->
                        </div>
                    </div>
                <?php endforeach; ?>
            </div>
        <?php endif; ?>
    </div>
</body>

</html>

<?php include 'includes/new_footer.php'; ?>