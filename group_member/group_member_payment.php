<?php
session_start();

// Check if group_id is set in session
if (!isset($_SESSION['group_id'])) {
    header("Location: /CholoSave-CS/error_page.php"); // Redirect if session variables are missing
    exit;
}

$group_id = $_SESSION['group_id'];

// Ensure database connection
if (!isset($conn)) {
    include 'db.php';
}

// Fetch group details
$query = "SELECT amount, bKash, Rocket, Nagad FROM my_group WHERE group_id = ?";
$stmt = $conn->prepare($query);
$stmt->bind_param("i", $group_id);
$stmt->execute();
$stmt->bind_result($amount, $bKash, $Rocket, $Nagad);
$stmt->fetch();
$stmt->close();
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Payment Gateway</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;600&display=swap" rel="stylesheet">
    <style>
        .custom-font {
            font-family: 'Poppins', sans-serif;
        }

        .gradient-bg {
            background: linear-gradient(90deg, #1e3a8a, #3b82f6);
            color: white;
        }

        .payment-option:hover {
            background-color: #f3f4f6;
            cursor: pointer;
        }

        .disabled-field {
            background-color: #e5e7eb;
            cursor: not-allowed;
        }
    </style>
</head>

<body class="bg-gray-100">
    <div class="flex items-center justify-center min-h-screen">
        
        <div class="bg-white shadow-lg rounded-lg overflow-hidden w-full max-w-2xl">
            <div class="gradient-bg px-8 py-6 text-center">
                <h1 class="text-2xl font-bold custom-font">Payment Gateway</h1>
                <p class="text-sm mt-2">Secure and reliable payment processing</p>
            </div>

            <div class="px-8 py-6">
                <form method="POST" action="process_payment.php" class="space-y-6">
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-2">Payment Amount (BDT)</label>
                        <input type="text" name="amount" value="<?php echo $amount; ?>" class="block w-full px-4 py-3 rounded-lg border-gray-300" readonly>
                    </div>

                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-2">Select Payment Method</label>
                        <div class="space-y-2">
                            <?php if (!empty($bKash)) : ?>
                                <div class="payment-option flex items-center border px-4 py-3 rounded-lg">
                                    <input type="radio" name="payment_method" value="bKash" id="bkash" class="mr-3">
                                    <label for="bkash" class="flex-1">
                                        <span class="text-gray-800">bKash</span>
                                        <span class="block text-gray-500 text-sm">Number: <?php echo $bKash; ?></span>
                                    </label>
                                </div>
                            <?php endif; ?>

                            <?php if (!empty($Rocket)) : ?>
                                <div class="payment-option flex items-center border px-4 py-3 rounded-lg">
                                    <input type="radio" name="payment_method" value="Rocket" id="rocket" class="mr-3">
                                    <label for="rocket" class="flex-1">
                                        <span class="text-gray-800">Rocket</span>
                                        <span class="block text-gray-500 text-sm">Number: <?php echo $Rocket; ?></span>
                                    </label>
                                </div>
                            <?php endif; ?>

                            <?php if (!empty($Nagad)) : ?>
                                <div class="payment-option flex items-center border px-4 py-3 rounded-lg">
                                    <input type="radio" name="payment_method" value="Nagad" id="nagad" class="mr-3">
                                    <label for="nagad" class="flex-1">
                                        <span class="text-gray-800">Nagad</span>
                                        <span class="block text-gray-500 text-sm">Number: <?php echo $Nagad; ?></span>
                                    </label>
                                </div>
                            <?php endif; ?>
                        </div>
                    </div>

                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-2">Payment Number</label>
                        <input type="text" name="payment_number" class="block w-full px-4 py-3 rounded-lg border-gray-300" placeholder="Enter your payment number" required>
                    </div>

                    <div class="pt-6">
                        <button type="submit" class="w-full bg-blue-600 text-white py-3 px-6 rounded-lg hover:bg-blue-700">
                            Proceed to Pay
                        </button>
                    </div>
                </form>
            </div>
        </div>
    </div>
</body>

</html>
