<?php
session_start();

if (!isset($_SESSION['group_id'])) {
  header("Location: /CholoSave-CS/error_page.php");
  exit;
}

$group_id = $_SESSION['group_id'];
$user_id = $_SESSION['user_id'];

if (!isset($conn)) {
  include 'db.php';
  include 'vendor/autoload.php';
}

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

// Fetch order summary details
$stmt = $conn->prepare("SELECT CONCAT('CHS', UPPER(SUBSTRING(MD5(RAND()), 1, 2)), LOWER(SUBSTRING(MD5(RAND()), 3, 2)), FLOOR(RAND() * 10), 'AVE') AS transaction_id, amount AS Total, group_name AS merchants FROM my_group WHERE group_id = ?");
$stmt->bind_param('i', $group_id);
$stmt->execute();
$result = $stmt->get_result()->fetch_assoc();

$transaction_id = $result['transaction_id'];
$total_amount = $result['Total'];
$merchant = $result['merchants'];

// Fetch user name and email
$user_stmt = $conn->prepare("SELECT name, email FROM users WHERE id = ?");
$user_stmt->bind_param('i', $user_id);
$user_stmt->execute();
$user_result = $user_stmt->get_result()->fetch_assoc();
$user_name = $user_result['name'];
$user_email = $user_result['email'];

// Fetch payment method details
$payment_stmt = $conn->prepare("SELECT bkash, Rocket, Nagad FROM my_group WHERE group_id = ?");
$payment_stmt->bind_param('i', $group_id);
$payment_stmt->execute();
$payment_methods = $payment_stmt->get_result()->fetch_assoc();

// Handle form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  $selected_method = $_POST['payment_method'] ?? '';
  if (!empty($selected_method)) {
    // Check if the user has remaining payments
    $check_stmt = $conn->prepare("SELECT time_period_remaining FROM group_membership WHERE user_id = ? AND group_id = ?");
    $check_stmt->bind_param('ii', $user_id, $group_id);
    $check_stmt->execute();
    $time_period_remaining = $check_stmt->get_result()->fetch_assoc()['time_period_remaining'];

    if ($time_period_remaining <= 0) {
      echo "
        <script src='https://cdn.jsdelivr.net/npm/sweetalert2@11'></script>
        <script>
          Swal.fire({
            title: 'Savings Completed',
            text: 'You have completed your savings for this group. No further payments are needed.',
            icon: 'success',
            confirmButtonText: 'OK'
          }).then((result) => {
            if (result.isConfirmed) {
              window.location.href = '/CholoSave-CS/group_member/group_member_dashboard.php';
            }
          });
        </script>";
      exit;
    }

    // OTP Generation
    $otp = sprintf("%06d", mt_rand(1, 999999));
    $otp_expiry = date('Y-m-d H:i:s', strtotime('+2 minutes'));

    // Clear any previous OTP for this transaction
    $clear_otp_stmt = $conn->prepare("DELETE FROM payment_otps WHERE user_id = ? AND group_id = ?");
    $clear_otp_stmt->bind_param('ii', $user_id, $group_id);
    $clear_otp_stmt->execute();

    // Store OTP in a separate table
    $store_otp_stmt = $conn->prepare("INSERT INTO payment_otps (user_id, group_id, otp, otp_expiry, transaction_id, amount, payment_method) VALUES (?, ?, ?, ?, ?, ?, ?)");
    $store_otp_stmt->bind_param('iisssds', $user_id, $group_id, $otp, $otp_expiry, $transaction_id, $total_amount, $selected_method);
    $store_otp_stmt->execute();

    // Send OTP via email
    $mail = new PHPMailer(true);
    try {
        $mail->isSMTP();
        $mail->Host = 'smtp.gmail.com';
        $mail->SMTPAuth = true;
        $mail->Username = 'cholosave.uiu@gmail.com';
        $mail->Password = 'yayd tytg zrwt igjw'; // Use App Password
        $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
        $mail->Port = 587;

        $mail->setFrom('cholosave.uiu@gmail.com', 'CholoSave');
        $mail->addAddress($user_email);
        $mail->isHTML(true);
        $mail->Subject = 'Payment OTP Verification';
        $mail->Body = "Your OTP for payment verification is: <b>$otp</b>. This OTP will expire in 2 minutes.";

        $mail->send();

        // Redirect to OTP verification page
        header("Location: otp_verify_payment.php");
        exit;
    } catch (Exception $e) {
        // Handle email sending error
        echo "OTP could not be sent. Error: {$mail->ErrorInfo}";
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

<body class="bg-gray-100 min-h-screen"
  style="background-image: url('/CholoSave-CS/group_member/test/american.jpg'); background-size: cover; background-position: center;">

  <!-- Support Header -->
  <div class="bg-gray-700/80 text-white p-2 text-right text-sm">
    Having Problems? Call Support: +880 9612 22 1000
  </div>

  <div class="container mx-auto p-4 md:p-8 max-w-6xl">
    <div class="grid md:grid-cols-2 gap-6">
      <!-- Order Summary Card -->
      <div class="bg-white rounded shadow-sm mt-48">
        <div class="bg-blue-700 text-white p-4 rounded-t flex justify-between items-center">
          <h2 class="text-xl">Deposit Summary</h2>
        </div>
        <div class="p-6 space-y-4">
          <div class="grid grid-cols-2 gap-2 text-gray-600">
            <div>Customer Name:</div>
            <div><?= htmlspecialchars($user_name) ?></div>
            <div>Group:</div>
            <div><?= htmlspecialchars($merchant) ?></div>
            <div>Transaction ID:</div>
            <div><?= htmlspecialchars($transaction_id) ?></div>
            <div>Total (BDT):</div>
            <div class="text-2xl font-bold text-gray-800">৳<?= number_format($total_amount, 2) ?></div>
          </div>
          <div class="pt-4 text-sm text-red-500">
            <a href="/CholoSave-CS/group_member/group_member_dashboard.php" class="hover:underline">Cancel Payment &
              return to Dashboard</a>
          </div>
        </div>
      </div>

      <!-- Payment Methods Card -->
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
                  <img src="/CholoSave-CS/group_member/test/bkash.png" alt="bKash" class="w-full h-12 object-contain">
                </button>
              <?php endif; ?>
              <?php if (!empty($payment_methods['Rocket'])): ?>
                <button @click="selectedMethod = 'Rocket'"
                  :class="{ 'ring-2 ring-blue-500': selectedMethod === 'Rocket' }"
                  class="p-4 border rounded hover:shadow-md transition-all duration-200 focus:outline-none">
                  <img src="/CholoSave-CS/group_member/test/rocket.png" alt="Rocket" class="w-full h-12 object-contain">
                </button>
              <?php endif; ?>
              <?php if (!empty($payment_methods['Nagad'])): ?>
                <button @click="selectedMethod = 'Nagad'" :class="{ 'ring-2 ring-blue-500': selectedMethod === 'Nagad' }"
                  class="p-4 border rounded hover:shadow-md transition-all duration-200 focus:outline-none">
                  <img src="/CholoSave-CS/group_member/test/nagad.png" alt="Nagad" class="w-full h-12 object-contain">
                </button>
              <?php endif; ?>
            </div>
          </div>

          <div class="mt-8">
            <!-- Loading Overlay -->
            <div id="loadingOverlay"
              class="fixed inset-0 bg-black bg-opacity-50 hidden flex items-center justify-center z-50">
              <div class="bg-white p-6 rounded-lg shadow-xl flex flex-col items-center">
                <div class="animate-spin rounded-full h-12 w-12 border-4 border-blue-500 border-t-transparent"></div>
                <p class="mt-4 text-gray-700 font-medium">Processing payment...</p>
              </div>
            </div>

            <form method="POST" id="paymentForm" onsubmit="handleSubmit(event)">
              <input type="hidden" name="transaction_id" value="<?= htmlspecialchars($transaction_id) ?>">
              <input type="hidden" name="payment_method" x-model="selectedMethod">
              <input type="hidden" name="user_id" value="<?= htmlspecialchars($user_id) ?>">
              <input type="hidden" name="group_id" value="<?= htmlspecialchars($group_id) ?>">
              <input type="hidden" name="amount" value="<?= htmlspecialchars($total_amount) ?>">
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

  <!-- Powered by SSL Logo -->
  <div class="fixed bottom-4 right-4 ">
    <img src="/api/placeholder/150/50" class="h-8">
    <p>Powered by CholoSave</p>
  </div>
  <script>
    function handleSubmit(event) {
      event.preventDefault();

      // Show loading overlay
      const loadingOverlay = document.getElementById('loadingOverlay');
      loadingOverlay.classList.remove('hidden');

      // Disable the submit button
      const submitButton = event.target.querySelector('button');
      submitButton.disabled = true;

      // Submit the form after a delay to show the loading animation
      setTimeout(() => {
        document.getElementById('paymentForm').submit();
      }, 2500); // Shows loading for 1.5 seconds before submitting
    }
  </script>
</body>
</html>