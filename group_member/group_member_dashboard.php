<?php
session_start();

if (!isset($_SESSION['group_id'])) {
    header("Location: /test_project/error_page.php"); // Redirect if group_id is not set
    exit;
}

$group_id = $_SESSION['group_id'];
$user_id = $_SESSION['user_id'];

if (isset($_SESSION['group_id']) && isset($_SESSION['user_id'])) {
    $group_id = $_SESSION['group_id'];
    $user_id = $_SESSION['user_id'];
    // echo 'This is group id: ' . htmlspecialchars($group_id, ENT_QUOTES, 'UTF-8');
    // echo 'This is user id: ' . htmlspecialchars($user_id, ENT_QUOTES, 'UTF-8');
} else {
    echo 'Group ID is not set in the session.';
}

if (!isset($conn)) {
    include 'db.php'; // Ensure database connection
}

// Queries
$total_group_savings_query = "SELECT IFNULL(SUM(amount), 0) AS total_group_savings FROM savings WHERE group_id = ?";
$month_savings_query = "SELECT IFNULL(SUM(amount), 0) AS this_month_savings FROM savings WHERE group_id = ? AND MONTH(created_at) = MONTH(CURRENT_DATE)";
$total_members_query = "SELECT COUNT(*) AS total_members FROM group_membership WHERE group_id = ? AND status = 'approved'";
$new_members_query = "SELECT COUNT(*) AS new_members FROM group_membership WHERE group_id = ? AND status = 'approved' AND MONTH(join_date) = MONTH(CURRENT_DATE)";
$emergency_query = "SELECT emergency_fund FROM my_group WHERE group_id = ?";
$due_loans_query = "SELECT IFNULL(SUM(amount), 0) AS total_due_loans FROM loan_request WHERE group_id = ? AND status = 'approved'";
$total_withdrawals_query = "SELECT IFNULL(SUM(amount), 0) AS total_withdrawals FROM withdrawal WHERE group_id = ? AND status = 'approved'";

// Fetch Data
function fetchSingleValue($conn, $query, $param)
{
    $stmt = $conn->prepare($query);
    $stmt->bind_param("i", $param);
    $stmt->execute();
    $result = $stmt->get_result();
    $row = $result->fetch_assoc();
    return array_values($row)[0]; // Return the first value
}

$total_group_savings = fetchSingleValue($conn, $total_group_savings_query, $group_id);


$this_month_savings = fetchSingleValue($conn, $month_savings_query, $group_id);


$total_members = fetchSingleValue($conn, $total_members_query, $group_id);


$new_members = fetchSingleValue($conn, $new_members_query, $group_id);

$emergency_fund = fetchSingleValue($conn, $emergency_query, $group_id);

$due_loans = fetchSingleValue($conn, $due_loans_query, $group_id);

$total_withdrawals = fetchSingleValue($conn, $total_withdrawals_query, $group_id);

function calculateMySavings($conn, $user_id, $group_id) {
    $my_savings_query = "SELECT IFNULL(
        (SELECT SUM(amount) FROM savings WHERE user_id = ? AND group_id = ?) - 
        (SELECT IFNULL(SUM(amount), 0) FROM withdrawal WHERE user_id = ? AND group_id = ? AND status = 'approved'), 
    0) AS my_savings";

    $stmt = $conn->prepare($my_savings_query);
    $stmt->bind_param("iiii", $user_id, $group_id, $user_id, $group_id);
    $stmt->execute();
    $result = $stmt->get_result();
    $my_savings_row = $result->fetch_assoc();
    return $my_savings_row['my_savings'];
}

// Calculate my savings
$my_savings = calculateMySavings($conn, $user_id, $group_id);
?>




<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Enhanced CholoSave Dashboard</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" type="text/css" href="group_member_dashboard_style.css">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;600&display=swap" rel="stylesheet">
    
    <style>
        .custom-font {
            font-family: 'Poppins', sans-serif;
        }

        .stats-card {
        background: linear-gradient(135deg, var(--bg-start), var(--bg-end));
        color: white;
        transition: transform 0.3s ease;
    }
    .stats-card:hover {
        transform: scale(1.05);
        box-shadow: 0 10px 20px rgba(0,0,0,0.1);
    }
    .stats-card .icon {
        opacity: 0.7;
    }

    /* Color variations */
    .savings-card {
        --bg-start:rgb(105, 147, 196);
        --bg-end: #6A5ACD;
    }
    .members-card {
        --bg-start: #2ECC71;
        --bg-end: #27AE60;
    }
    .emergency-card {
        --bg-start: #F39C12;
        --bg-end: #D35400;
    }
    .loans-card {
        --bg-start: #E74C3C;
        --bg-end: #C0392B;
    }
    .withdrawals-card {
        --bg-start: #9B59B6;
        --bg-end: #8E44AD;
    }
    .mysavings-card {
        --bg-start:rgb(0, 0, 0);
        --bg-end:rgb(0, 0, 0);
    }

    </style>
</head>

<body class="bg-gray-100 dark-mode-transition">
    <div class="flex h-full">
        <!-- Sidebar -->
        <?php include 'sidebar.php'; ?>

        <!-- Main Content -->
        <div class="flex-1 flex flex-col overflow-hidden">
            <!-- Top Bar -->
            <header class="flex items-center justify-between p-4 bg-white shadow dark-mode-transition">
                <div class="flex items-center justify-center w-full">
                    <button id="menu-button"
                        class="md:hidden p-2 hover:bg-gray-100 rounded-lg transition-colors duration-200 absolute left-2">
                        <i class="fa-solid fa-bars text-xl"></i>
                    </button>
                    <h1 class="text-3xl font-semibold custom-font">
                        <i class="fa-solid fa-tachometer-alt text-blue-500 mr-3"></i>
                        Dashboard
                    </h1>
                </div>
             
            </header>

            <!-- Main Content Area -->
            <main class="flex-1 overflow-y-auto p-4">
                <!-- Stats Grid -->
                <div class="grid grid-cols-1 md:grid-cols-6 gap-4 mb-6">
                    <div class="stats-card bg-white p-6 rounded-lg shadow cursor-pointer">
                        <div class="flex justify-between items-center">
                            <div>
                                <h3 class="text-white-500 font-semibold">Total Savings</h3>
                                <p class="text-2xl font-bold" id="savings-counter">
                                    $<?php echo number_format($total_group_savings, 2); ?></p>
                                <p class="text-green-500 text-sm">+BDT <?php echo number_format($this_month_savings, 2); ?>
                                    this month</p>
                            </div>
                            <div class="text-2xl text-gray-400">
                                <i class="fas fa-dollar-sign"></i>
                            </div>
                        </div>
                    </div>

                    <div class="stats-card bg-white p-6 rounded-lg shadow cursor-pointer">
                        <div class="flex justify-between items-center">
                            <div>
                                <h3 class="text-white-500 font-semibold">Members</h3>
                                <p class="text-2xl font-bold" id="members-counter"><?php echo $total_members; ?></p>
                                <p class="text-green-500 text-sm">+<?php echo $new_members; ?> new this month</p>
                            </div>
                            <div class="text-2xl text-gray-400">
                                <i class="fas fa-users"></i>
                            </div>
                        </div>
                    </div>

                    <div class="stats-card bg-white p-6 rounded-lg shadow cursor-pointer">
                        <div class="flex justify-between items-center">
                            <div>
                                <h3 class="text-white-500 font-semibold">Emergency Fund</h3>
                                <p class="text-2xl font-bold" id="fund-counter">
                                    $<?php echo number_format($emergency_fund, 2); ?></p>
                            </div>
                            <div class="text-2xl text-gray-400">
                                <i class="fas fa-piggy-bank"></i>
                            </div>
                        </div>
                    </div>

                    <div class="stats-card bg-white p-6 rounded-lg shadow cursor-pointer">
                        <div class="flex justify-between items-center">
                            <div>
                                <h3 class="text-white-500 font-semibold">Member's Due Loans</h3>
                                <p class="text-2xl font-bold" id="loans-counter">
                                    $<?php echo number_format($due_loans, 2); ?></p>
                            </div>
                            <div class="text-2xl text-gray-400">
                                <i class="fas fa-hand-holding-usd"></i>
                            </div>
                        </div>
                    </div>

                    <div class="stats-card bg-white p-6 rounded-lg shadow cursor-pointer">
                        <div class="flex justify-between items-center">
                            <div>
                                <h3 class="text-white-500 font-semibold">My Withdrawals</h3>
                                <p class="text-2xl font-bold" id="withdrawals-counter">
                                    $<?php echo number_format($total_withdrawals, 2); ?></p>
                            </div>
                            <div class="text-2xl text-gray-400">
                                <i class="fas fa-credit-card"></i>
                            </div>
                        </div>
                    </div>
                    <div class="stats-card savings-card bg-white p-6 rounded-lg shadow cursor-pointer">
    <div class="flex justify-between items-center">
        <div>
            <h3 class="text-white-500 font-semibold">My Savings</h3>
            <p class="text-2xl font-bold" id="my-savings-counter">
                $<?php echo number_format($my_savings, 2); ?></p>
        </div>
        <div class="text-2xl text-gray-400">
            <i class="fas fa-wallet"></i>
        </div>
    </div>
</div>
                </div>

                <!-- Graph or chart showing code -->
                <div class="flex justify-between gap-4">
                    <div class="flex-1">
                        <?php include 'dashboard_graph.php'; ?>
                    </div>
                    <div class="flex-1 ">
                        <div class="h-[500px] w-full bg-blue-500 "> <?php include 'progress_bar.php'; ?> </div>
                    </div>
                </div>

                <!-- Polls Section -->
                <?php include 'polls.php'; ?>

            </main>
        </div>
    </div>



    <script>
          document.addEventListener('DOMContentLoaded', () => {
        const cards = document.querySelectorAll('.stats-card');
        const cardClasses = [
            'savings-card', 
            'withdrawals-card',
            'emergency-card', 
            'loans-card', 
            'members-card',
            'mysavings-card'
        ];

        cards.forEach((card, index) => {
            card.classList.add(cardClasses[index]);
        });
    });




        // Counter animation function
        function animateCounter(element, target, duration = 2000, prefix = '') {
            let start = 0;
            const increment = target / (duration / 16);
            const animate = () => {
                start += increment;
                if (start < target) {
                    element.textContent = prefix + Math.floor(start).toLocaleString();
                    requestAnimationFrame(animate);
                } else {
                    element.textContent = prefix + target.toLocaleString();
                }
            };
            animate();
        }

        // Initialize animations
        document.addEventListener('DOMContentLoaded', () => {
            // PHP values dynamically passed to JavaScript
            const totalSavings = <?php echo json_encode($total_group_savings); ?>;
            const totalMembers = <?php echo json_encode($total_members); ?>;
            const emergencyFund = <?php echo json_encode($emergency_fund); ?>;
            const dueLoans = <?php echo json_encode($due_loans); ?>;
            const totalWithdrawals = <?php echo json_encode($total_withdrawals); ?>;
            const mysavings = <?php echo json_encode($my_savings); ?>;


            // Animate counters
            animateCounter(document.getElementById('savings-counter'), totalSavings, 2000, 'BDT ');
            animateCounter(document.getElementById('members-counter'), totalMembers);
            animateCounter(document.getElementById('fund-counter'), emergencyFund, 2000, 'BDT ');
            animateCounter(document.getElementById('loans-counter'), dueLoans, 2000, 'BDT ');
            animateCounter(document.getElementById('withdrawals-counter'), totalWithdrawals, 2000, 'BDT ');
            animateCounter(document.getElementById('my-savings-counter'), mysavings, 2000, 'BDT ');

            // Animate poll bars
            document.querySelectorAll('.poll-option').forEach(option => {
                const bar = option.querySelector('.bg-blue-500');
                const percentage = option.querySelector('.text-gray-500').textContent;
                setTimeout(() => {
                    bar.style.width = percentage;
                }, 500);
            });
        });

        window.addEventListener('resize', handleResize);
        handleResize();

        // Add smooth scroll behavior
        document.querySelectorAll('a[href^="#"]').forEach(anchor => {
            anchor.addEventListener('click', function (e) {
                e.preventDefault();
                document.querySelector(this.getAttribute('href')).scrollIntoView({
                    behavior: 'smooth'
                });
            });
        });
    </script>
</body>

</html>

<?php include 'new_footer.php'; ?>