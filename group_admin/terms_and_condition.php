<?php
session_start();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Terms and Conditions - CholoSave</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;600&display=swap" rel="stylesheet">
</head>
<body class="bg-gray-100">
    <div class="min-h-screen p-6">
        <div class="max-w-4xl mx-auto bg-white rounded-lg shadow-lg p-8">
            <div class="mb-8">
                <h1 class="text-3xl font-bold text-gray-800 mb-4">Terms and Conditions for Emergency Loan</h1>
                <p class="text-gray-600">Last updated: <?php echo date('F d, Y'); ?></p>
            </div>

            <div class="space-y-6 text-gray-700">
                <section>
                    <h2 class="text-xl font-semibold mb-3">1. Loan Terms</h2>
                    <div class="space-y-3">
                        <p>1.1. The minimum loan amount is BDT 0 and the maximum is upto Emergency Fund.</p>
                        <p>1.2. Loans must be repaid within the specified return date.</p>
                        <p>1.3. Late payments may result in penalties as determined by the group members.</p>
                    </div>
                </section>

                <section>
                    <h2 class="text-xl font-semibold mb-3">2. Eligibility</h2>
                    <div class="space-y-3">
                        <p>2.1. Only active group members can request loans.</p>
                        <p>2.2. Members must have no outstanding loans.</p>
                        <p>2.3. Members must have been part of the group for at least 30 days.</p>
                    </div>
                </section>

                <section>
                    <h2 class="text-xl font-semibold mb-3">3. Approval Process</h2>
                    <div class="space-y-3">
                        <p>3.1. Loan requests require group member approval through voting.</p>
                        <p>3.2. A minimum of 51% approval is required for loan disbursement.</p>
                        <p>3.3. The voting period lasts 24 hours from the time of request.</p>
                    </div>
                </section>

                <section>
                    <h2 class="text-xl font-semibold mb-3">4. Repayment</h2>
                    <div class="space-y-3">
                        <p>4.1. Full repayment must be made by the agreed return date.</p>
                        <p>4.2. Early repayment is allowed and encouraged.</p>
                        <p>4.3. Payment must be made through the platform's designated payment system.</p>
                    </div>
                </section>

                <section>
                    <h2 class="text-xl font-semibold mb-3">5. Default and Penalties</h2>
                    <div class="space-y-3">
                        <p>5.1. Failure to repay may result in suspension of group privileges.</p>
                        <p>5.2. Late payment fees may be applied as per group policy.</p>
                        <p>5.3. Repeated defaults may result in removal from the group.</p>
                    </div>
                </section>
            </div>

            <div class="mt-8 border-t pt-6">
                <p class="text-gray-600">For any questions about these terms, please contact your group administrator or our support team.</p>
            </div>

            <div class="mt-6">
                <button onclick="window.close()" class="bg-blue-600 text-white px-6 py-2 rounded-lg hover:bg-blue-700 transition duration-200">
                    Close Window
                </button>
            </div>
        </div>
    </div>
</body>
</html>