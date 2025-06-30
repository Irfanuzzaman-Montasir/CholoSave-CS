<?php
include 'db.php';
include 'session.php';

$error_message = '';
$success_message = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    try {
        $group_name = filter_var(trim($_POST['group_name']), FILTER_SANITIZE_STRING);
        $description = filter_var(trim($_POST['description']), FILTER_SANITIZE_STRING);
        $members = filter_var(trim($_POST['members']), FILTER_SANITIZE_NUMBER_INT);
        $dps_type = $_POST['dps_type'];
        $time_period = filter_var(trim($_POST['time_period']), FILTER_SANITIZE_NUMBER_INT);
        $amount = filter_var(trim($_POST['amount']), FILTER_SANITIZE_NUMBER_FLOAT, FILTER_FLAG_ALLOW_FRACTION);
        $start_date = $_POST['start_date'];
        $goal_amount = filter_var(trim($_POST['goal_amount']), FILTER_SANITIZE_NUMBER_INT);
        // $warning_threshold = filter_var(trim($_POST['warning_threshold']), FILTER_SANITIZE_NUMBER_INT);
        $emergency_fund = filter_var(trim($_POST['emergency_fund']), FILTER_SANITIZE_NUMBER_FLOAT, FILTER_FLAG_ALLOW_FRACTION);
        $bkash = filter_var(trim($_POST['bkash_number']), FILTER_SANITIZE_STRING);
        $rocket = filter_var(trim($_POST['rocket_number']), FILTER_SANITIZE_STRING);
        $nagad = filter_var(trim($_POST['nagad_number']), FILTER_SANITIZE_STRING);

        if (empty($group_name) || empty($members) || empty($time_period) || empty($amount)) {
            throw new Exception("Please fill in all required fields.");
        }

        // Insert into my_group table to create the group
        $query = "INSERT INTO my_group (
            group_name, description, members, group_admin_id, dps_type, 
            time_period, amount, start_date, goal_amount, 
            emergency_fund, bKash, Rocket, Nagad
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

        $stmt = $conn->prepare($query);
        $stmt->bind_param(
            "ssiisidsiddss",
            $group_name,
            $description,
            $members,
            $_SESSION['user_id'],
            $dps_type,
            $time_period,
            $amount,
            $start_date,
            $goal_amount,
            $emergency_fund,
            $bkash,
            $rocket,
            $nagad
        );

        if ($stmt->execute()) {


            // Get the last inserted group_id
            $group_id = $stmt->insert_id;
            // Calculate points: initial points (5) + 1% of emergency_fund
            $points = 5 + (0.01 * $emergency_fund);

            // Insert values into the leaderboard table
            $leaderboardQuery = "INSERT INTO leaderboard (group_id, points) VALUES (?, ?)";
            $leaderboardStmt = $conn->prepare($leaderboardQuery);
            $leaderboardStmt->bind_param("id", $group_id, $points); // Use 'id' for group_id (int) and points (double)

            if (!$leaderboardStmt->execute()) {
                throw new Exception("Error inserting into leaderboard: " . $conn->error);
            }


            // Store the group_id in the session
            $_SESSION['group_id'] = $group_id;

            // Insert the user into the group_membership table with status 'approved' and is_admin = 1
            $membershipQuery = "INSERT INTO group_membership (group_id, user_id, status, is_admin, join_date, time_period_remaining) VALUES (?, ?, 'approved', 1, NOW(),?)";
            $membershipStmt = $conn->prepare($membershipQuery);
            $membershipStmt->bind_param("iii", $group_id, $_SESSION['user_id'], $time_period);

            if ($membershipStmt->execute()) {
                // Role-checking logic
                $query = "SELECT is_admin FROM group_membership WHERE group_id = ? AND user_id = ?";
                $stmt = $conn->prepare($query);
                $stmt->bind_param("ii", $group_id, $_SESSION['user_id']);
                $stmt->execute();
                $stmt->store_result();

                if ($stmt->num_rows > 0) {
                    $stmt->bind_result($is_admin);
                    $stmt->fetch();

                    // Redirect based on role
                    if ($is_admin) {
                        header("Location: /CholoSave-CS/group_admin/group_admin_dashboard.php?group_id=" . $group_id);
                    } else {
                        header("Location: /CholoSave-CS/group_member/group_dashboard.php?group_id=" . $group_id);
                    }
                    exit();
                } else {
                    throw new Exception("Failed to retrieve user role.");
                }
            } else {
                throw new Exception("Error adding admin to group: " . $conn->error);
            }
        } else {
            throw new Exception("Error creating group: " . $conn->error);
        }
    } catch (Exception $e) {
        // Handle error
        $error_message = $e->getMessage();
        header("Location: error_page.php?error=" . urlencode($error_message));
        exit();
    }
}
?>


<?php include 'includes/header2.php'; ?>
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Create Group</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&display=swap" rel="stylesheet">

    <style>
        body {
            font-family: 'Inter', sans-serif;
            display: flex;
            flex-direction: column;
            min-height: 100vh;
        }

        .step {
            opacity: 0;
            transform: translateY(20px);
            transition: all 0.5s ease-out;
            display: none;
        }

        .step.active {
            opacity: 1;
            transform: translateY(0);
            display: block;
        }

        .progress-bar {
            transition: width 0.5s ease-out;
        }

        .content {
            flex: 1;
            /* This ensures the content area takes up the available space */
        }

        footer {
            background-color: #f1f5f9;
            padding: 2rem;
            text-align: center;
            margin-top: auto;
        }
    </style>
</head>

<body class="bg-gray-50">
    <div class="content container mx-auto px-4 py-8 max-w-5xl">
        <h1 class="text-3xl font-semibold text-center text-gray-800 mb-8">Create Group</h1>

        <!-- Progress Bar -->
        <div class="w-full bg-gray-200 rounded-full h-2.5 mb-8">
            <div class="progress-bar bg-green-600 h-2.5 rounded-full" style="width: 25%"></div>
        </div>

        <!-- Step Indicators -->
        <div class="flex justify-between mb-8">
            <div class="step-indicator flex flex-col items-center">
                <div class="w-8 h-8 bg-green-600 text-white rounded-full flex items-center justify-center">1</div>
                <span class="text-sm mt-1">Group Info</span>
            </div>
            <div class="step-indicator flex flex-col items-center">
                <div class="w-8 h-8 bg-gray-300 text-gray-600 rounded-full flex items-center justify-center">2</div>
                <span class="text-sm mt-1">Plan Details</span>
            </div>
            <div class="step-indicator flex flex-col items-center">
                <div class="w-8 h-8 bg-gray-300 text-gray-600 rounded-full flex items-center justify-center">3</div>
                <span class="text-sm mt-1">Payment</span>
            </div>
            <div class="step-indicator flex flex-col items-center">
                <div class="w-8 h-8 bg-gray-300 text-gray-600 rounded-full flex items-center justify-center">4</div>
                <span class="text-sm mt-1">Regulations</span>
            </div>
            <div class="step-indicator flex flex-col items-center">
                <div class="w-8 h-8 bg-gray-300 text-gray-600 rounded-full flex items-center justify-center">5</div>
                <span class="text-sm mt-1">Review</span>
            </div>
        </div>

        <form id="groupForm" class="space-y-6" method="POST" action="">
            <!-- Step 1: Group Information -->
            <div class="step active" id="step1">
                <h2 class="text-xl font-medium text-green-600 mb-4">Group Information</h2>
                <div class="space-y-4">
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-1">Group Name</label>
                        <input type="text" name="group_name" required placeholder="Enter group name"
                            class="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:ring-1 focus:ring-green-500 focus:border-green-500">
                    </div>
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-1">Description</label>
                        <textarea name="description" required placeholder="Enter group description" rows="3"
                            class="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:ring-1 focus:ring-green-500 focus:border-green-500"></textarea>
                    </div>
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-1">Members</label>
                        <input type="number" name="members" required placeholder="Number of members"
                            class="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:ring-1 focus:ring-green-500 focus:border-green-500">
                    </div>
                </div>
                <div class="flex justify-end">
                    <button type="button" class="bg-green-600 text-white px-4 py-2 rounded-md"
                        id="nextButton1">Next</button>
                </div>
            </div>

            <!-- Step 2: Plan Details -->
            <div class="step" id="step2">
                <h2 class="text-xl font-medium text-green-600 mb-4">Plan Details</h2>
                <div class="space-y-4">
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-1">DPS Type</label>
                        <select name="dps_type" required
                            class="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:ring-1 focus:ring-green-500 focus:border-green-500">
                            <option value="monthly">Monthly</option>
                            <option value="weekly">Weekly</option>
                        </select>
                    </div>
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-1">Time Period</label>
                        <input type="number" name="time_period" required placeholder="Enter time period (months)"
                            class="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:ring-1 focus:ring-green-500 focus:border-green-500">
                    </div>
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-1">Amount</label>
                        <input type="number" name="amount" required placeholder="Enter amount" step="0.01"
                            class="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:ring-1 focus:ring-green-500 focus:border-green-500">
                    </div>
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-1">Start Date</label>
                        <input type="date" name="start_date" required
                            class="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:ring-1 focus:ring-green-500 focus:border-green-500">
                    </div>
                </div>
                <div class="flex justify-between">
                    <button type="button" class="bg-gray-300 text-gray-700 px-4 py-2 rounded-md"
                        id="prevButton1">Previous</button>
                    <button type="button" class="bg-green-600 text-white px-4 py-2 rounded-md"
                        id="nextButton2">Next</button>
                </div>
            </div>

            <!-- Step 3: Payment -->
            <div class="step" id="step3">
                <h2 class="text-xl font-medium text-green-600 mb-4">Payment Details</h2>
                <div class="space-y-4">
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-1">bKash Number</label>
                        <input type="text" name="bkash_number" placeholder="Enter bKash number"
                            class="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:ring-1 focus:ring-green-500 focus:border-green-500">
                    </div>
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-1">Rocket Number</label>
                        <input type="text" name="rocket_number" placeholder="Enter Rocket number"
                            class="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:ring-1 focus:ring-green-500 focus:border-green-500">
                    </div>
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-1">Nagad Number</label>
                        <input type="text" name="nagad_number" required placeholder="Enter Nagad number"
                            class="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:ring-1 focus:ring-green-500 focus:border-green-500">
                    </div>
                </div>
                <div class="flex justify-between">
                    <button type="button" class="bg-gray-300 text-gray-700 px-4 py-2 rounded-md"
                        id="prevButton2">Previous</button>
                    <button type="button" class="bg-green-600 text-white px-4 py-2 rounded-md"
                        id="nextButton3">Next</button>
                </div>
            </div>

            <!-- Step 4: Regulations -->
            <div class="step" id="step4">
                <h2 class="text-xl font-medium text-green-600 mb-4">Regulations</h2>
                <div class="space-y-4">
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-1">Goal Amount</label>
                        <input type="number" name="goal_amount" required placeholder="Enter goal amount" step="0.01"
                            class="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:ring-1 focus:ring-green-500 focus:border-green-500">
                    </div>
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-1">Emergency Fund</label>
                        <input type="number" name="emergency_fund" required placeholder="Enter emergency fund amount"
                            step="0.01"
                            class="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:ring-1 focus:ring-green-500 focus:border-green-500">
                    </div>
                    <!-- <div>
                        <label class="block text-sm font-medium text-gray-700 mb-1">Warning Threshold</label>
                        <input type="number" name="warning_threshold" required
                            placeholder="Enter warning threshold amount"
                            class="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:ring-1 focus:ring-green-500 focus:border-green-500">
                    </div> -->
                </div>
                <div class="flex justify-between">
                    <button type="button" class="bg-gray-300 text-gray-700 px-4 py-2 rounded-md"
                        id="prevButton3">Previous</button>
                    <button type="button" class="bg-green-600 text-white px-4 py-2 rounded-md"
                        id="nextButton4">Next</button>
                </div>
            </div>

            <!-- Step 5: Summary Review -->
            <div class="step" id="step5">
                <h2 class="text-xl font-medium text-green-600 mb-4">Review Group Details</h2>
                <div class="bg-white shadow-md rounded-lg p-6 space-y-4">
                    <div>
                        <h3 class="font-semibold text-gray-700">Group Information</h3>
                        <div id="summaryGroupInfo" class="bg-gray-50 p-3 rounded-md space-y-2">
                            <p><strong>Group Name:</strong> <span id="summaryGroupName"></span></p>
                            <p><strong>Description:</strong> <span id="summaryDescription"></span></p>
                            <p><strong>Members:</strong> <span id="summaryMembers"></span></p>
                        </div>
                        <button type="button" class="mt-2 text-blue-600 hover:underline" onclick="editStep(0)">Edit
                            Group Info</button>
                    </div>

                    <div>
                        <h3 class="font-semibold text-gray-700">Plan Details</h3>
                        <div id="summaryPlanDetails" class="bg-gray-50 p-3 rounded-md space-y-2">
                            <p><strong>DPS Type:</strong> <span id="summaryDpsType"></span></p>
                            <p><strong>Time Period:</strong> <span id="summaryTimePeriod"></span></p>
                            <p><strong>Amount:</strong> <span id="summaryAmount"></span></p>
                            <p><strong>Start Date:</strong> <span id="summaryStartDate"></span></p>
                        </div>
                        <button type="button" class="mt-2 text-blue-600 hover:underline" onclick="editStep(1)">Edit Plan
                            Details</button>
                    </div>

                    <div>
                        <h3 class="font-semibold text-gray-700">Payment Details</h3>
                        <div id="summaryPaymentDetails" class="bg-gray-50 p-3 rounded-md space-y-2">
                            <p><strong>bKash Number:</strong> <span id="summaryBkashNumber"></span></p>
                            <p><strong>Rocket Number:</strong> <span id="summaryRocketNumber"></span></p>
                            <p><strong>Nagad Number:</strong> <span id="summaryNagadNumber"></span></p>
                        </div>
                        <button type="button" class="mt-2 text-blue-600 hover:underline" onclick="editStep(2)">Edit
                            Payment Details</button>
                    </div>

                    <div>
                        <h3 class="font-semibold text-gray-700">Regulations</h3>
                        <div id="summaryRegulations" class="bg-gray-50 p-3 rounded-md space-y-2">
                            <p><strong>Goal Amount:</strong> <span id="summaryGoalAmount"></span></p>
                            <p><strong>Emergency Fund:</strong> <span id="summaryEmergencyFund"></span></p>
                            <!-- <p><strong>Warning Threshold:</strong> <span id="summaryWarningThreshold"></span></p> -->
                        </div>
                        <button type="button" class="mt-2 text-blue-600 hover:underline" onclick="editStep(3)">Edit
                            Regulations</button>
                    </div>
                </div>

                <div class="flex justify-between mt-6">
                    <button type="button" class="bg-gray-300 text-gray-700 px-4 py-2 rounded-md"
                        id="prevButton4">Previous</button>
                    <button type="submit" class="bg-green-600 text-white px-4 py-2 rounded-md">Confirm & Submit</button>
                </div>
            </div>
        </form>
    </div>

    <script>
        let currentStep = 0;
        const totalSteps = 5;
        const steps = document.querySelectorAll('.step');
        const nextButton1 = document.getElementById('nextButton1');
        const nextButton2 = document.getElementById('nextButton2');
        const nextButton3 = document.getElementById('nextButton3');
        const nextButton4 = document.getElementById('nextButton4');
        const prevButton1 = document.getElementById('prevButton1');
        const prevButton2 = document.getElementById('prevButton2');
        const prevButton3 = document.getElementById('prevButton3');
        const prevButton4 = document.getElementById('prevButton4');

        function validateStep1() {
            const groupName = document.querySelector('input[name="group_name"]').value.trim();
            const description = document.querySelector('textarea[name="description"]').value.trim();
            const members = document.querySelector('input[name="members"]').value.trim();

            if (groupName === '') {
                alert('Please enter a group name');
                return false;
            }

            if (description === '') {
                alert('Please enter a group description');
                return false;
            }

            if (members === '' || isNaN(members) || parseInt(members) <= 0) {
                alert('Please enter a valid number of members');
                return false;
            }

            return true;
        }

        function validateStep2() {
            const dpsType = document.querySelector('select[name="dps_type"]').value;
            const timePeriod = document.querySelector('input[name="time_period"]').value.trim();
            const amount = document.querySelector('input[name="amount"]').value.trim();
            const startDate = document.querySelector('input[name="start_date"]').value;

            if (dpsType === '') {
                alert('Please select a DPS type');
                return false;
            }

            if (timePeriod === '' || isNaN(timePeriod) || parseInt(timePeriod) <= 0) {
                alert('Please enter a valid time period');
                return false;
            }

            if (amount === '' || isNaN(amount) || parseFloat(amount) <= 0) {
                alert('Please enter a valid amount');
                return false;
            }

            if (!startDate) {
                alert('Please select a start date');
                return false;
            }

            // Validate start date is today or in the future
            const today = new Date().toISOString().split('T')[0];
            if (startDate < today) {
                alert('Start date must be today or in the future');
                return false;
            }

            return true;
        }

        function validateStep3() {
            const bkashNumber = document.querySelector('input[name="bkash_number"]').value.trim();

            if (bkashNumber === '') {
                alert('Please enter a bKash number');
                return false;
            }

            return true;
        }

        function validateStep4() {
            const goalAmount = document.querySelector('input[name="goal_amount"]').value.trim();
            const emergencyFund = document.querySelector('input[name="emergency_fund"]').value.trim();

            if (goalAmount === '' || isNaN(goalAmount) || parseFloat(goalAmount) <= 0) {
                alert('Please enter a valid goal amount');
                return false;
            }

            if (emergencyFund === '' || isNaN(emergencyFund) || parseFloat(emergencyFund) < 0) {
                alert('Please enter a valid emergency fund amount');
                return false;
            }

            return true;
        }

        const showStep = (step) => {
            steps.forEach((el, index) => {
                if (index === step) {
                    el.classList.add('active');
                } else {
                    el.classList.remove('active');
                }
            });
        };

        const updateProgressBar = () => {
            const progressBar = document.querySelector('.progress-bar');
            progressBar.style.width = ((currentStep + 1) / totalSteps) * 100 + '%';

            // Update step indicator colors
            const stepIndicators = document.querySelectorAll('.step-indicator div');
            stepIndicators.forEach((indicator, index) => {
                if (index <= currentStep) {
                    indicator.classList.remove('bg-gray-300', 'text-gray-600');
                    indicator.classList.add('bg-green-600', 'text-white');
                } else {
                    indicator.classList.remove('bg-green-600', 'text-white');
                    indicator.classList.add('bg-gray-300', 'text-gray-600');
                }
            });
        };

        // Navigation button event listeners
        nextButton1.addEventListener('click', () => {
            if (validateStep1()) {
                currentStep++;
                showStep(currentStep);
                updateProgressBar();
            }
        });

        nextButton2.addEventListener('click', () => {
            if (validateStep2()) {
                currentStep++;
                showStep(currentStep);
                updateProgressBar();
            }
        });

        nextButton3.addEventListener('click', () => {
            if (validateStep3()) {
                currentStep++;
                showStep(currentStep);
                updateProgressBar();
            }
        });

        nextButton4.addEventListener('click', () => {
            if (validateStep4()) {
                updateSummary();
                currentStep++;
                showStep(currentStep);
                updateProgressBar();
            }
        });

        // Previous button event listeners
        prevButton1.addEventListener('click', () => {
            if (currentStep > 0) {
                currentStep--;
                showStep(currentStep);
                updateProgressBar();
            }
        });

        prevButton2.addEventListener('click', () => {
            if (currentStep > 0) {
                currentStep--;
                showStep(currentStep);
                updateProgressBar();
            }
        });

        prevButton3.addEventListener('click', () => {
            if (currentStep > 0) {
                currentStep--;
                showStep(currentStep);
                updateProgressBar();
            }
        });

        prevButton4.addEventListener('click', () => {
            if (currentStep > 0) {
                currentStep--;
                showStep(currentStep);
                updateProgressBar();
            }
        });

        // Function to update summary
        function updateSummary() {
            // Group Info
            document.getElementById('summaryGroupName').textContent = document.querySelector('input[name="group_name"]').value;
            document.getElementById('summaryDescription').textContent = document.querySelector('textarea[name="description"]').value;
            document.getElementById('summaryMembers').textContent = document.querySelector('input[name="members"]').value;

            // Plan Details
            document.getElementById('summaryDpsType').textContent = document.querySelector('select[name="dps_type"]').value;
            document.getElementById('summaryTimePeriod').textContent = document.querySelector('input[name="time_period"]').value + ' months';
            document.getElementById('summaryAmount').textContent = '$' + document.querySelector('input[name="amount"]').value;
            document.getElementById('summaryStartDate').textContent = document.querySelector('input[name="start_date"]').value;

            // Payment Details
            document.getElementById('summaryBkashNumber').textContent = document.querySelector('input[name="bkash_number"]').value || 'Not provided';
            document.getElementById('summaryRocketNumber').textContent = document.querySelector('input[name="rocket_number"]').value || 'Not provided';
            document.getElementById('summaryNagadNumber').textContent = document.querySelector('input[name="nagad_number"]').value || 'Not provided';

            // Regulations
            document.getElementById('summaryGoalAmount').textContent = '$' + document.querySelector('input[name="goal_amount"]').value;
            document.getElementById('summaryEmergencyFund').textContent = '$' + document.querySelector('input[name="emergency_fund"]').value;
        }

        // Function to edit a specific step
        function editStep(stepIndex) {
            currentStep = stepIndex;
            showStep(currentStep);
            updateProgressBar();
        }

        // Initialize first step
        showStep(currentStep);
    </script>
</body>

</html>

<?php include 'includes/new_footer.php'; ?>