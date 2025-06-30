<?php
session_start();

// Redirect if loan_id or group_id is not set
if (!isset($_SESSION['loan_id']) || !isset($_SESSION['group_id'])) {
    header("Location: /test_project/error_page.php");
    exit;
}

$loan_id = $_SESSION['loan_id'];
$group_id = $_SESSION['group_id'];
$user_id = $_SESSION['user_id'];

// Ensure database connection
if (!isset($conn)) {
    include 'db.php';
}

// Fetch order summary details
$stmt = $conn->prepare("
    SELECT 
        CONCAT('CHS', UPPER(SUBSTRING(MD5(RAND()), 1, 2)), LOWER(SUBSTRING(MD5(RAND()), 3, 2)), FLOOR(RAND() * 10), 'AVE') AS transaction_id, 
        lr.amount AS Total, 
        mg.group_name AS merchants 
    FROM 
        my_group mg
    JOIN 
        loan_request lr ON lr.group_id = mg.group_id 
    WHERE 
        mg.group_id = ? AND lr.id = ?
");
$stmt->bind_param('ii', $group_id, $loan_id);
$stmt->execute();
$result = $stmt->get_result()->fetch_assoc();

$transaction_id = $result['transaction_id'];
$total_amount = $result['Total'];
$merchant = $result['merchants'];

// Fetch user name
$user_stmt = $conn->prepare("SELECT name FROM users WHERE id = ?");
$user_stmt->bind_param('i', $user_id);
$user_stmt->execute();
$user_name = $user_stmt->get_result()->fetch_assoc()['name'];

// Fetch payment method details
$payment_stmt = $conn->prepare("SELECT bkash, Rocket, Nagad FROM my_group WHERE group_id = ?");
$payment_stmt->bind_param('i', $group_id);
$payment_stmt->execute();
$payment_methods = $payment_stmt->get_result()->fetch_assoc();

// Handle form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $selected_method = $_POST['payment_method'] ?? '';
    if (!empty($selected_method)) {
        $conn->begin_transaction();

        try {
            // Update loan_request table after successful payment
            $update_stmt = $conn->prepare("
                UPDATE loan_request 
                SET 
                    status = 'repaid', 
                    repayment_date = CURDATE(),
                    repayment_amount = ?, 
                    payment_method = ?, 
                    transaction_id = ?, 
                    payment_time = CURTIME() 
                WHERE id = ?
            ");

            if ($update_stmt === false) {
                throw new Exception("Prepare failed: " . $conn->error);
            }

            $update_stmt->bind_param('dssi', $total_amount, $selected_method, $transaction_id, $loan_id);

            if (!$update_stmt->execute()) {
                throw new Exception("Execute failed: " . $update_stmt->error);
            }

            // Update emergency_fund in my_group table
            $update_emergency_fund = $conn->prepare("
                UPDATE my_group 
                SET emergency_fund = COALESCE(emergency_fund, 0) + ? 
                WHERE group_id = ?
            ");

            if ($update_emergency_fund === false) {
                throw new Exception("Prepare failed for emergency fund update: " . $conn->error);
            }

            $update_emergency_fund->bind_param('di', $total_amount, $group_id);

            if (!$update_emergency_fund->execute()) {
                throw new Exception("Execute failed for emergency fund update: " . $update_emergency_fund->error);
            }

            // Commit the transaction
            $conn->commit();

            // Clear loan_id from session after success
            unset($_SESSION['loan_id']);
            header("Location: loan_success_payment.php");
            exit;
        } catch (Exception $e) {
            // Rollback in case of error
            $conn->rollback();
            error_log("Payment failed: " . $e->getMessage());
            header("Location: failure_page.php");
            exit;
        }
    }
}

?>

<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <script src="https://cdn.tailwindcss.com"></script>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/alpinejs/3.13.3/cdn.js"></script>
  <title>Payment Gateway</title>
</head>
<body class="bg-gray-100 min-h-screen" style="background-image: url('/test_project/group_member/test/american.jpg'); background-size: cover; background-position: center;">
  <div class="bg-gray-700/80 text-white p-2 text-right text-sm">
    Having Problems? Call Support: +880 9612 22 1000
  </div>

  <div class="container mx-auto p-4 md:p-8 max-w-6xl">
    <div class="grid md:grid-cols-2 gap-6">
      <!-- Order Summary -->
      <div class="bg-white rounded shadow-sm mt-48">
        <div class="bg-blue-700 text-white p-4 rounded-t flex justify-between items-center">
          <h2 class="text-xl">Order Summary</h2>
        </div>
        <div class="p-6 space-y-4">
          <div class="grid grid-cols-2 gap-2 text-gray-600">
            <div>Member Name:</div>
            <div><?= htmlspecialchars($user_name) ?></div>
            <div>Merchant:</div>
            <div><?= htmlspecialchars($merchant) ?></div>
            <div>Transaction ID:</div>
            <div><?= htmlspecialchars($transaction_id) ?></div>
            <div>Total (BDT):</div>
            <div class="text-2xl font-bold text-gray-800">৳<?= number_format($total_amount, 2) ?></div>
          </div>
          <div class="pt-4 text-sm text-red-500">
            <form method="POST">
              <button type="submit" name="cancel_payment" class="hover:underline text-red-600">Cancel Payment & Return to Loan History</button>
            </form>
          </div>
        </div>
      </div>

      <!-- Payment Method -->
      <div x-data="{ selectedMethod: '' }" class="bg-white rounded shadow-sm mt-48">
        <div class="bg-blue-700 text-white p-4 rounded-t flex justify-between items-center">
          <h2 class="text-xl">Select Payment Method</h2>
        </div>
        <div class="p-6">
          <div class="space-y-4">
            <h3 class="text-gray-500 font-medium">Mobile Banking</h3>
            <div class="grid grid-cols-2 md:grid-cols-4 gap-4">
              <?php if (!empty($payment_methods['bkash'])): ?>
                <button @click="selectedMethod = 'bKash'" :class="{ 'ring-2 ring-blue-500': selectedMethod === 'bKash' }"
                  class="p-4 border rounded hover:shadow-md transition-all duration-200 focus:outline-none">
                  <img src="/test_project/group_member/test/bkash.png" alt="bKash" class="w-full h-12 object-contain">
                </button>
              <?php endif; ?>
              <?php if (!empty($payment_methods['Rocket'])): ?>
                <button @click="selectedMethod = 'Rocket'" :class="{ 'ring-2 ring-blue-500': selectedMethod === 'Rocket' }"
                  class="p-4 border rounded hover:shadow-md transition-all duration-200 focus:outline-none">
                  <img src="/test_project/group_member/test/rocket.png" alt="Rocket" class="w-full h-12 object-contain">
                </button>
              <?php endif; ?>
              <?php if (!empty($payment_methods['Nagad'])): ?>
                <button @click="selectedMethod = 'Nagad'" :class="{ 'ring-2 ring-blue-500': selectedMethod === 'Nagad' }"
                  class="p-4 border rounded hover:shadow-md transition-all duration-200 focus:outline-none">
                  <img src="/test_project/group_member/test/nagad.png" alt="Nagad" class="w-full h-12 object-contain">
                </button>
              <?php endif; ?>
            </div>
          </div>

          <div class="mt-8">
            <div id="loadingOverlay" class="fixed inset-0 bg-black bg-opacity-50 hidden flex items-center justify-center z-50">
              <div class="bg-white p-6 rounded-lg shadow-xl flex flex-col items-center">
                <div class="animate-spin rounded-full h-12 w-12 border-4 border-blue-500 border-t-transparent"></div>
                <p class="mt-4 text-gray-700 font-medium">Processing payment...</p>
              </div>
            </div>

            <form method="POST" id="paymentForm" onsubmit="handleSubmit(event)">
              <input type="hidden" name="payment_method" x-model="selectedMethod">
              <button
                :class="{ 'bg-blue-600 hover:bg-blue-700': selectedMethod, 'bg-gray-300 cursor-not-allowed': !selectedMethod }"
                :disabled="!selectedMethod"
                class="w-full py-3 rounded font-medium text-white transition-colors duration-200">
                Pay Now
              </button>
            </form>
          </div>
        </div>
      </div>
    </div>
  </div>

  <div class="fixed bottom-4 right-4">
    <img src="/api/placeholder/150/50" class="h-8">
    <p>Powered by CholoSave</p>
  </div>

  <script>
    function handleSubmit(event) {
      event.preventDefault();

      const loadingOverlay = document.getElementById('loadingOverlay');
      loadingOverlay.classList.remove('hidden');

      setTimeout(() => {
        document.getElementById('paymentForm').submit();
      }, 2500);
    }
  </script>
</body>
</html>
