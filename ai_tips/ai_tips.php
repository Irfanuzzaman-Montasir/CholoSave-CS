<?php
session_start();
require_once '/CholoSave-CS/ai_tips/user_finance_info.php'; // Include the financial data fetching file
include '../includes/header2.php';
include 'db.php';

if (!isset($_SESSION['user_id'])) {
    header("Location: /CholoSave-CS/login.php");
    exit;
}

$user_id = $_SESSION['user_id'];

// Fetch user financial data
$group_id = $_GET['group_id'] ?? null; // Get group ID from request if available
$financial_data = fetchUserFinancialData($conn, $user_id);
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AI Financial Assistant</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700&display=swap" rel="stylesheet">
    <style>
        body {
            font-family: 'Inter', sans-serif;
        }

        @keyframes fadeIn {
            from {
                opacity: 0;
                transform: translateY(10px);
            }

            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        .animate-fade-in {
            animation: fadeIn 0.3s ease-out forwards;
        }

        .glass-card {
            background: rgba(255, 255, 255, 0.8);
            backdrop-filter: blur(10px);
            border-radius: 1rem;
            box-shadow: 0 10px 25px rgba(0, 0, 0, 0.1);
        }
    </style>
</head>

<body class="bg-gradient-to-br from-blue-50 to-indigo-100 min-h-screen flex items-center justify-center py-16 px-4">
    <div class="container mx-auto max-w-6xl mt-16">
        <!-- AI Caution Notice -->
        <div class="bg-yellow-50 border-l-4 border-yellow-400 p-4 mb-6">
            <div class="flex">
                <div class="flex-shrink-0">
                    <svg class="h-5 w-5 text-yellow-400" viewBox="0 0 20 20" fill="currentColor">
                        <path fill-rule="evenodd"
                            d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.494-1.646-1.742-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z"
                            clip-rule="evenodd" />
                    </svg>
                </div>
                <div class="ml-3">
                    <p class="text-sm text-yellow-700">
                        <strong>Caution:</strong> AI-generated financial advice is for informational purposes only.
                        Always consult with a professional financial advisor before making important financial
                        decisions.
                    </p>
                </div>
            </div>
        </div>

        <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
            <!-- Savings Overview -->
            <div class="md:col-span-1 bg-white/70 p-6 rounded-xl shadow-md">
                <h2 class="text-xl font-semibold mb-4 text-gray-700 border-b pb-2">Savings Overview</h2>
                <div class="space-y-3">
                    <div class="flex justify-between items-center">
                        <span class="text-gray-600">Total Savings</span>
                        <span
                            class="font-bold text-green-600">৳<?= number_format($financial_data['individual_savings'], 2) ?></span>
                    </div>
                    <div class="flex justify-between items-center">
                        <span class="text-gray-600">Monthly Savings</span>
                        <span
                            class="font-bold text-blue-600">৳<?= number_format($financial_data['monthly_savings'], 2) ?></span>
                    </div>
                </div>

                <div class="mt-6">
                    <h3 class="text-lg font-semibold mb-3 text-gray-700 border-b pb-2">Group Contributions</h3>
                    <div class="space-y-2">
                        <?php foreach ($financial_data['group_contributions'] as $group): ?>
                            <div class="flex items-center justify-between">
                                <span class="text-sm text-gray-600"><?= htmlspecialchars($group['group_name']) ?></span>
                                <span class="text-sm font-bold text-indigo-600">
                                    ৳<?= number_format($group['user_contribution'], 2) ?> /
                                    ৳<?= number_format($group['total_contribution'], 2) ?>
                                </span>
                            </div>
                        <?php endforeach; ?>
                    </div>
                </div>
            </div>

            <!-- Refactored AI Financial Guidance Section -->
            <div class="md:col-span-2 bg-white/70 p-6 rounded-xl shadow-md">
                <h2 class="text-xl font-semibold mb-4 text-gray-700 border-b pb-2">AI Financial Guidance</h2>

                <div class="grid md:grid-cols-2 gap-4 mb-4">
                    <div>
                        <label for="savings-type" class="block text-sm font-medium text-gray-700 mb-2">Savings
                            Type</label>
                        <select id="savings-type"
                            class="w-full border-gray-300 rounded-md shadow-sm focus:border-blue-300 focus:ring focus:ring-blue-200 transition">
                            <option value="individual">Individual Savings</option>
                            <option value="group">Group Savings</option>
                        </select>
                    </div>

                    <div id="group-selection" class="hidden">
                        <label for="group-id" class="block text-sm font-medium text-gray-700 mb-2">Choose Group</label>
                        <select id="group-id"
                            class="w-full border-gray-300 rounded-md shadow-sm focus:border-blue-300 focus:ring focus:ring-blue-200 transition">
                            <option value="all">All Groups</option>
                            <?php foreach ($financial_data['group_contributions'] as $group): ?>
                                <option value="<?= $group['group_id'] ?>"><?= htmlspecialchars($group['group_name']) ?></option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                </div>

                <div class="mb-4">
                    <label for="question-select" class="block text-sm font-medium text-gray-700 mb-2">Financial
                        Question</label>
                    <select id="question-select"
                        class="w-full border-gray-300 rounded-md shadow-sm focus:border-blue-300 focus:ring focus:ring-blue-200 transition">
                        <option value="financial_health">What is my financial health?</option>
                        <option value="budgeting">How can I improve my budgeting?</option>
                        <option value="investment_advice">What are the best investment options for me over [Time Period] in [Investment Type]?</option>
                        <option value="savings_strategy">What savings strategy should I follow?</option>
                        <option value="risk_management">How should I manage my financial risks?</option>
                        <!--<option value="emergency_fund">How should I handle my emergency fund?</option>
                        <option value="group_savings">How can we improve our group savings?</option>-->
                        <option value="custom">Custom Question</option>
                    </select>
                </div>

                <!-- Investment Options Section -->
                <div id="investment-options" class="mb-4 hidden">
                    <div class="mb-4">
                        <label for="investment-time" class="block text-sm font-medium text-gray-700 mb-2">Investment Time Period</label>
                        <div class="flex items-center gap-2">
                            <input type="number" id="investment-time" class="w-20 border-gray-300 rounded-md shadow-sm focus:border-blue-300 focus:ring focus:ring-blue-200 transition" placeholder="1" value="1">
                            <select id="investment-duration" class="w-32 border-gray-300 rounded-md shadow-sm focus:border-blue-300 focus:ring focus:ring-blue-200 transition">
                                <option value="month">Month</option>
                                <option value="year">Year</option>
                            </select>
                        </div>
                    </div>

                    <div class="mb-4">
                        <label for="investment-type" class="block text-sm font-medium text-gray-700 mb-2">Investment Type</label>
                        <input type="text" id="investment-type" class="w-full border-gray-300 rounded-md shadow-sm focus:border-blue-300 focus:ring focus:ring-blue-200 transition" placeholder="Enter investment type...">
                    </div>
                </div>

                <!-- Custom Question Block -->
                <div id="custom-question-block" class="mb-4 hidden">
                    <label for="custom-question" class="block text-sm font-medium text-gray-700 mb-2">Your Question:</label>
                    <input type="text" id="custom-question" class="w-full border-gray-300 rounded-md shadow-sm focus:border-blue-300 focus:ring focus:ring-blue-200 transition" placeholder="Type your question here...">
                </div>

                <button id="get-result"
                    class="w-full bg-blue-500 text-white py-3 rounded-lg hover:bg-blue-600 transition font-semibold shadow-md">
                    Get Financial Advice
                </button>

                <div id="ai-response" class="mt-6 hidden"></div>
            </div>
        </div>
    </div>

    <script>
                async function displayAdvice(result) {
    const aiResponse = document.getElementById('ai-response');
    const advice = result.advice;

    aiResponse.innerHTML = `
        <div class="space-y-6 animate-fade-in">
            <div class="bg-white rounded-xl shadow-md p-6 border border-gray-100">
                <h3 class="text-xl font-bold mb-4 text-gray-800">${advice.title || 'Financial Advice'}</h3>
                <p class="text-lg text-gray-700 mb-4">${advice.main_advice}</p>
                <div class="mt-4">
                    <h4 class="font-semibold mb-2 text-gray-700">Action Steps:</h4>
                    <ul class="space-y-2">
                        ${advice.steps.map(step => `<li class="flex items-center text-gray-600"><span class="text-green-500 mr-2">✓</span>${step}</li>`).join('')}
                    </ul>
                </div>
            </div>
        </div>
    `;
}

        document.addEventListener('DOMContentLoaded', () => {
            const questionSelect = document.getElementById('question-select');
            const customQuestionBlock = document.getElementById('custom-question-block');
            const investmentOptions = document.getElementById('investment-options');

            questionSelect.addEventListener('change', () => {
                const value = questionSelect.value;
                investmentOptions.classList.toggle('hidden', value !== 'investment_advice');
                customQuestionBlock.classList.toggle('hidden', value !== 'custom');
            });

            document.getElementById('savings-type').addEventListener('change', () => {
        const groupSelection = document.getElementById('group-selection');
        groupSelection.classList.toggle('hidden', document.getElementById('savings-type').value !== 'group');
    });


            document.getElementById('get-result').addEventListener('click', async () => {
                const question = questionSelect.value === 'custom' 
                    ? document.getElementById('custom-question').value.trim() 
                    : questionSelect.value;

                if (!question) {
                    alert('Please select or write a question.');
                    return;
                }

                const aiResponse = document.getElementById('ai-response');
                aiResponse.classList.remove('hidden');
                aiResponse.innerHTML = '<div class="flex items-center justify-center p-4"><div class="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div><span class="ml-2">Analyzing financial data...</span></div>';

const savingsType = document.getElementById('savings-type').value;
const selectedGroupId = document.getElementById('group-id').value;
const investmentTime = document.getElementById('investment-time')?.value || null;
const investmentDuration = document.getElementById('investment-duration')?.value || null;
const investmentType = document.getElementById('investment-type')?.value || null;

// Get financial data from PHP
const financialData = <?php echo json_encode($financial_data); ?>;

const response = await fetch('/CholoSave-CS/ai_tips/generate_tips.php', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
        savings_type: savingsType,
        group_id: selectedGroupId !== 'all' ? selectedGroupId : null,
        savings_data: financialData,
        question,
        investment_time: investmentTime,
        investment_duration: investmentDuration,
        investment_type: investmentType,
        all_groups_data: selectedGroupId === 'all' ? financialData.group_contributions : null
    })
});

if (!response.ok) {
    const errorData = await response.json();
    throw new Error(errorData.error || 'Failed to generate advice');
}

const result = await response.json();
if (result.status === 'success') {
    displayAdvice(result);
} else {
    throw new Error(result.error || 'Failed to generate advice');
}
});
});
</script>
</body>
</html>

