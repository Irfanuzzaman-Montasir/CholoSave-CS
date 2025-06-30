<?php
session_start();

// Check if the transaction details are set in the session
if (!isset($_SESSION['transaction_id'], $_SESSION['total_amount'], $_SESSION['payment_method'], $_SESSION['transaction_date'])) {
    header("Location: error_page.php"); // Redirect to error page if details are not set
    exit;
}

// Get session data
$transaction_id = $_SESSION['transaction_id'];
$total_amount = $_SESSION['total_amount'];
$payment_method = $_SESSION['payment_method'];
$transaction_date = $_SESSION['transaction_date'];

// echo'This is Transaction_id'. $transaction_id;


?>

<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Payment Completed</title>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/js/all.min.js"></script>
  <script src="https://cdn.tailwindcss.com"></script>
  <style>
    @keyframes slideDown {
      from { transform: translateY(-20px); opacity: 0; }
      to { transform: translateY(0); opacity: 1; }
    }
    @keyframes checkmark {
      from { transform: scale(0); }
      to { transform: scale(1); }
    }
    .animate-slide-down {
      animation: slideDown 0.6s ease-out forwards;
    }
    .animate-checkmark {
      animation: checkmark 0.5s ease-out forwards;
      animation-delay: 0.3s;
      transform: scale(0);
    }
  </style>
</head>
<body class="bg-gradient-to-br from-green-50 to-blue-50 min-h-screen flex items-center justify-center p-4">
  <div class="text-center p-8 rounded-2xl shadow-2xl bg-white w-full max-w-md animate-slide-down">
    <!-- Success Icon -->
    <div class="mb-6">
      <div class="mx-auto h-20 w-20 rounded-full bg-green-100 flex items-center justify-center">
        <i class="fas fa-check text-4xl text-green-500 animate-checkmark"></i>
      </div>
    </div>

    <h2 class="text-3xl font-bold text-green-600 mb-4">Payment Successful!</h2>
    <p class="text-xl text-gray-600 mb-6">Your transaction has been processed securely.</p>

    <!-- Transaction Details -->
    <div class="bg-gray-50 rounded-lg p-4 mb-6">
      <div class="flex justify-between items-center mb-2">
        <span class="text-gray-600">Transaction ID:</span>
        <span class="text-gray-800 font-medium"><?= htmlspecialchars($transaction_id) ?></span>
      </div>
      <div class="flex justify-between items-center mb-2">
        <span class="text-gray-600">Date:</span>
        <span class="text-gray-800 font-medium"><?= htmlspecialchars($transaction_date) ?></span>
      </div>
      <div class="border-t border-gray-200 my-2"></div>
      <div class="flex justify-between items-center">
        <span class="text-gray-600">Payment Method:</span>
        <span class="text-gray-800 font-medium">
          <i class="fas fa-credit-card mr-2"></i>
          <?= htmlspecialchars($payment_method) ?>
        </span>
      </div>
    </div>

   <!-- Receipt Button -->
<a href="generate_receipt.php" 
   class="w-full mb-4 bg-gray-100 hover:bg-gray-200 text-gray-700 px-6 py-3 rounded-lg text-lg transition duration-300 flex items-center justify-center">
  <i class="fas fa-download mr-2"></i>
  Download Receipt
</a>

    <!-- Home Button -->
    <a href="/test_project/group_admin/group_admin_dashboard.php" 
       class="w-full block bg-green-600 text-white px-6 py-3 rounded-lg text-lg hover:bg-green-500 transition duration-300 flex items-center justify-center">
      <i class="fas fa-home mr-2"></i>
      Return to Homepage
    </a>

    <!-- Support Link -->
    <p class="mt-6 text-sm text-gray-500">
      Need help? <a href="#" class="text-green-600 hover:text-green-500">Contact support</a>
    </p>
  </div>
</body>
</html>
