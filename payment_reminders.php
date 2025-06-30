<?php
session_start();
include 'db.php';
include 'includes/header2.php';

// Get user ID from session
$user_id = $_SESSION['user_id'];

// Find groups user is a member of with payment details
$group_query = "SELECT g.group_id, dps_type, start_date, group_name, amount 
                FROM group_membership gm
                JOIN my_group g ON gm.group_id = g.group_id
                WHERE gm.user_id = ? AND gm.status = 'approved'";
$stmt = $conn->prepare($group_query);
$stmt->bind_param("i", $user_id);
$stmt->execute();
$result = $stmt->get_result();

$payment_reminders = [];
$loan_reminders = [];
$today = date('Y-m-d');
$three_days_later = date('Y-m-d', strtotime('+3 days'));

// Group Payment Reminders
while ($group = $result->fetch_assoc()) {
    $is_payment_due = false;


// Similar modification for weekly payments
    if ($group['dps_type'] == 'monthly') {
        $next_payment_date = date('Y-m-d', strtotime('+1 month', strtotime($group['start_date'])));
        $days_until_payment = (strtotime($next_payment_date) - strtotime($today)) / (60 * 60 * 24);
        if ($days_until_payment <= 2 && $days_until_payment >= 0) {
            $is_payment_due = true;
        }
    }
    
    // Similar modification for weekly payments
    if ($group['dps_type'] == 'weekly') {
        $next_payment_date = date('Y-m-d', strtotime('+7 days', strtotime($group['start_date'])));
        $days_until_payment = (strtotime($next_payment_date) - strtotime($today)) / (60 * 60 * 24);
        if ($days_until_payment <= 2 && $days_until_payment >= 0) {
            $is_payment_due = true;
        }
    }

    if ($is_payment_due) {
        $payment_reminders[] = [
            'group_id' => $group['group_id'],
            'group_name' => $group['group_name'],
            'payment_type' => $group['dps_type'],
            'next_payment_date' => $next_payment_date,
            'amount' => $group['amount']
        ];
    }
}

// Loan Reminders (3 days within)
$three_days_before = date('Y-m-d', strtotime('-3 days', strtotime($three_days_later)));
$loan_query = "SELECT lr.group_id, mg.group_name, lr.return_time, lr.amount 
               FROM loan_request lr
               JOIN my_group mg ON lr.group_id = mg.group_id
               WHERE lr.user_id = ? 
               AND lr.status = 'approved' 
               AND lr.return_time BETWEEN ? AND ?";
$loan_stmt = $conn->prepare($loan_query);
$loan_stmt->bind_param("iss", $user_id, $three_days_before, $three_days_later);
$loan_stmt->execute();
$loan_result = $loan_stmt->get_result();

while ($loan = $loan_result->fetch_assoc()) {
    $loan_reminders[] = [
        'group_id' => $loan['group_id'],
        'group_name' => $loan['group_name'],
        'return_date' => $loan['return_time'],
        'amount' => $loan['amount']
    ];
}
?>
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Notifications</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>

<body class="bg-gray-100 min-h-screen">
    <div class="container mx-auto px-4 py-8">
        <div class="bg-white shadow-md rounded-lg overflow-hidden">
            <div class="bg-blue-500 text-white p-4 flex justify-center items-center">
                <h1 class="text-2xl font-bold">Reminders</h1>
            </div>

            <div class="p-4">
                <?php
                // Display loan reminders
                if (!empty($loan_reminders)) {
                    foreach ($loan_reminders as $reminder) {
                        echo "
                        <div class='bg-red-100 border-l-4 border-red-500 p-4 mb-4'>
                            <div class='flex items-center'>
                                <svg class='w-6 h-6 text-red-600 mr-3' fill='none' stroke='currentColor' viewBox='0 0 24 24' xmlns='http://www.w3.org/2000/svg'>
                                    <path stroke-linecap='round' stroke-linejoin='round' stroke-width='2' d='M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z'></path>
                                </svg>
                                <div>
                                    <p class='font-bold'>Loan Due Reminder</p>
                                    <p class='text-sm'>Group: " . htmlspecialchars($reminder['group_name']) . "</p>
                                    <p class='text-sm'>Return Date: " . htmlspecialchars($reminder['return_date']) . "</p>
                                    <p class='text-sm'>Amount: BDT " . number_format($reminder['amount'], 2) . "</p>
                                </div>
                            </div>
                        </div>";
                    }
                }

                // Display payment reminders
                if (!empty($payment_reminders)) {
                    foreach ($payment_reminders as $reminder) {
                        echo "
                        <div class='bg-yellow-100 border-l-4 border-yellow-500 p-4 mb-4'>
                            <div class='flex items-center'>
                                <svg class='w-6 h-6 text-yellow-600 mr-3' fill='none' stroke='currentColor' viewBox='0 0 24 24' xmlns='http://www.w3.org/2000/svg'>
                                    <path stroke-linecap='round' stroke-linejoin='round' stroke-width='2' d='M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z'></path>
                                </svg>
                                <div>
                                    <p class='font-bold'>Payment Reminder</p>
                                    <p class='text-sm'>Group: " . htmlspecialchars($reminder['group_name']) . "</p>
                                    <p class='text-sm'>Payment Type: " . htmlspecialchars($reminder['payment_type']) . "</p>
                                    <p class='text-sm'>Next Payment Date: " . htmlspecialchars($reminder['next_payment_date']) . "</p>
                                    <p class='text-sm'>Amount: BDT " . number_format($reminder['amount'], 2) . "</p>
                                </div>
                            </div>
                        </div>";
                    }
                }

                // No reminders message
                if (empty($loan_reminders) && empty($payment_reminders)) {
                    echo "
                    <div class='bg-green-100 border-l-4 border-green-500 p-4'>
                        <p class='text-green-700'>No reminders for today.</p>
                    </div>";
                }
                ?>
            </div>
        </div>
    </div>
</body>

</html>

<?php include 'includes/new_footer.php'; ?>