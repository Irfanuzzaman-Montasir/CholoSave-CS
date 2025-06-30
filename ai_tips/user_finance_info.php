<?php
function fetchUserFinancialData($conn, $user_id) {
    $financial_data = [
        'individual_savings' => 0,
        'monthly_savings' => 0,
        'group_contributions' => [],
        'investments' => [],
        'loan_status' => 'No active loans',
        'emergency_fund' => 0,
        'emergency_fund_goal' => 0,
    ];

    try {
        // Total Individual Savings
        $stmt = $conn->prepare("SELECT COALESCE(SUM(amount), 0) AS total_savings FROM savings WHERE user_id = ?");
        $stmt->bind_param("i", $user_id);
        $stmt->execute();
        $result = $stmt->get_result();
        $row = $result->fetch_assoc();
        $financial_data['individual_savings'] = $row['total_savings'] ?? 0;

        // Monthly Savings
        $stmt = $conn->prepare("SELECT COALESCE(SUM(amount), 0) AS monthly_savings FROM savings WHERE user_id = ? AND MONTH(created_at) = MONTH(CURRENT_DATE) AND YEAR(created_at) = YEAR(CURRENT_DATE)");
        $stmt->bind_param("i", $user_id);
        $stmt->execute();
        $result = $stmt->get_result();
        $row = $result->fetch_assoc();
        $financial_data['monthly_savings'] = $row['monthly_savings'] ?? 0;

        // Group Contributions
        $stmt = $conn->prepare("SELECT 
            g.group_id,
            g.group_name,
            COALESCE(SUM(s.amount), 0) AS user_contribution, 
            (SELECT COALESCE(SUM(s1.amount), 0) FROM savings s1 WHERE s1.group_id = g.group_id) AS total_contribution,
            g.goal_amount,
            g.emergency_fund
        FROM group_membership gm
        JOIN my_group g ON gm.group_id = g.group_id
        LEFT JOIN savings s ON g.group_id = s.group_id AND s.user_id = ?
        WHERE gm.user_id = ? AND gm.status = 'approved'
        GROUP BY g.group_id, g.group_name, g.goal_amount, g.emergency_fund");
        $stmt->bind_param("ii", $user_id, $user_id);
        $stmt->execute();
        $financial_data['group_contributions'] = $stmt->get_result()->fetch_all(MYSQLI_ASSOC);

        // Investments
        $stmt = $conn->prepare("SELECT i.investment_type AS type, i.amount, COALESCE(SUM(ir.amount), 0) AS returns,
            ROUND((COALESCE(SUM(ir.amount), 0) / i.amount) * 100, 2) AS roi
            FROM investments i
            LEFT JOIN investment_returns ir ON i.investment_id = ir.investment_id
            WHERE i.group_id IN (SELECT group_id FROM group_membership WHERE user_id = ? AND status = 'approved')
            GROUP BY i.investment_id, i.investment_type, i.amount");
        $stmt->bind_param("i", $user_id);
        $stmt->execute();
        $financial_data['investments'] = $stmt->get_result()->fetch_all(MYSQLI_ASSOC);

        // Loan Status
        $stmt = $conn->prepare("SELECT COUNT(*) AS active_loans, COALESCE(SUM(amount - repayment_amount), 0) AS outstanding_amount
            FROM loan_request WHERE user_id = ? AND status = 'approved'");
        $stmt->bind_param("i", $user_id);
        $stmt->execute();
        $result = $stmt->get_result();
        $row = $result->fetch_assoc();
        if ($row['active_loans'] > 0) {
            $financial_data['loan_status'] = "Active loans with outstanding amount: BDT " . number_format($row['outstanding_amount'], 2);
        }

        // Emergency Fund
        if (!empty($financial_data['group_contributions'])) {
            $financial_data['emergency_fund'] = array_sum(array_column($financial_data['group_contributions'], 'emergency_fund'));
            $financial_data['emergency_fund_goal'] = array_sum(array_column($financial_data['group_contributions'], 'goal_amount'));
        }

    } catch (Exception $e) {
        error_log("Error fetching financial data: " . $e->getMessage());
    }

    return $financial_data;
}

header("Location: /CholoSave-CS/login.php");
?>