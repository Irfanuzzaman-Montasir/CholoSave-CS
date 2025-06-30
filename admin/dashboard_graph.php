<?php
if (!isset($conn)) {
    die('Database connection required');
}

// Get last 6 months of data
$query = "
    SELECT 
        DATE_FORMAT(u.created_at, '%b %Y') as month_label,
        DATE_FORMAT(u.created_at, '%Y-%m') as month_sort,
        COUNT(DISTINCT u.id) as new_users,
        IFNULL(SUM(s.amount), 0) as total_savings,
        COUNT(DISTINCT w.withdrawal_id) as withdrawal_requests,
        IFNULL(SUM(i.amount), 0) as investments
    FROM users u
    LEFT JOIN savings s ON DATE_FORMAT(s.created_at, '%Y-%m') = DATE_FORMAT(u.created_at, '%Y-%m')
    LEFT JOIN withdrawal w ON DATE_FORMAT(w.request_date, '%Y-%m') = DATE_FORMAT(u.created_at, '%Y-%m')
    LEFT JOIN investments i ON DATE_FORMAT(i.created_at, '%Y-%m') = DATE_FORMAT(u.created_at, '%Y-%m')
    WHERE u.created_at >= DATE_SUB(NOW(), INTERVAL 6 MONTH)
    GROUP BY month_label, month_sort
    ORDER BY month_sort ASC
";

$result = mysqli_query($conn, $query);
if (!$result) {
    die('Query failed: ' . mysqli_error($conn));
}

// Prepare data arrays
$data = [
    'labels' => [],
    'users' => [],
    'savings' => [],
    'withdrawals' => [],
    'investments' => []
];

while ($row = mysqli_fetch_assoc($result)) {
    $data['labels'][] = $row['month_label'];
    $data['users'][] = $row['new_users'];
    $data['savings'][] = $row['total_savings'];
    $data['withdrawals'][] = $row['withdrawal_requests'];
    $data['investments'][] = $row['investments'];
}
?>

<div class="bg-white rounded-lg shadow-lg p-6">
    <div class="flex justify-between items-center mb-4">
        <h2 class="text-xl font-bold text-gray-800">Analytics Overview</h2>
        <div class="flex gap-2">
            <select id="dataSelect" class="border rounded px-3 py-1">
                <option value="users">New Users</option>
                <option value="savings">Total Savings</option>
                <option value="withdrawals">Withdrawal Requests</option>
                <option value="investments">Investments</option>
            </select>
            <button class="chart-type-btn selected px-3 py-1 rounded" data-type="bar">Bar</button>
            <button class="chart-type-btn px-3 py-1 rounded" data-type="line">Line</button>
        </div>
    </div>
    <div class="relative h-[400px] w-full">
        <canvas id="adminChart"></canvas>
    </div>
</div>

<style>
.chart-type-btn {
    border: 1px solid #e2e8f0;
    transition: all 0.3s ease;
}

.chart-type-btn:hover {
    background-color: #f3f4f6;
}

.chart-type-btn.selected {
    background-color: #3b82f6;
    color: white;
    border-color: #3b82f6;
}
</style>

<script>
document.addEventListener('DOMContentLoaded', function() {
    const chartData = <?php echo json_encode($data); ?>;
    let currentChart = null;

    function createChart(type = 'bar', dataKey = 'users') {
        const ctx = document.getElementById('adminChart').getContext('2d');
        
        if (currentChart) {
            currentChart.destroy();
        }

        const colors = {
            users: {
                background: 'rgba(59, 130, 246, 0.2)',
                border: 'rgb(59, 130, 246)'
            },
            savings: {
                background: 'rgba(16, 185, 129, 0.2)',
                border: 'rgb(16, 185, 129)'
            },
            withdrawals: {
                background: 'rgba(245, 158, 11, 0.2)',
                border: 'rgb(245, 158, 11)'
            },
            investments: {
                background: 'rgba(139, 92, 246, 0.2)',
                border: 'rgb(139, 92, 246)'
            }
        };

        const options = {
            responsive: true,
            maintainAspectRatio: false,
            animation: {
                duration: 1000,
                easing: 'easeInOutQuart'
            },
            plugins: {
                legend: { display: false },
                tooltip: {
                    backgroundColor: 'rgba(255, 255, 255, 0.9)',
                    titleColor: '#1f2937',
                    bodyColor: '#1f2937',
                    borderColor: '#e5e7eb',
                    borderWidth: 1,
                    padding: 12,
                    displayColors: false,
                    callbacks: {
                        label: function(context) {
                            const value = context.parsed.y;
                            if (dataKey === 'savings' || dataKey === 'investments') {
                                return `$${value.toLocaleString('en-US', {
                                    minimumFractionDigits: 2,
                                    maximumFractionDigits: 2
                                })}`;
                            }
                            return value.toLocaleString('en-US');
                        }
                    }
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: {
                        callback: function(value) {
                            if (dataKey === 'savings' || dataKey === 'investments') {
                                return '$' + value.toLocaleString('en-US');
                            }
                            return value;
                        }
                    }
                }
            }
        };

        currentChart = new Chart(ctx, {
            type: type,
            data: {
                labels: chartData.labels,
                datasets: [{
                    data: chartData[dataKey],
                    backgroundColor: colors[dataKey].background,
                    borderColor: colors[dataKey].border,
                    borderWidth: type === 'bar' ? 2 : 3,
                    tension: type === 'line' ? 0.3 : 0,
                    fill: true
                }]
            },
            options: options
        });
    }

    // Initialize chart
    createChart('bar', 'users');

    // Event listeners
    document.querySelectorAll('.chart-type-btn').forEach(button => {
        button.addEventListener('click', function() {
            document.querySelectorAll('.chart-type-btn').forEach(btn => {
                btn.classList.remove('selected');
            });
            this.classList.add('selected');
            createChart(this.dataset.type, document.getElementById('dataSelect').value);
        });
    });

    document.getElementById('dataSelect').addEventListener('change', function() {
        const chartType = document.querySelector('.chart-type-btn.selected').dataset.type;
        createChart(chartType, this.value);
    });

    // Responsive resize handling
    let resizeTimer;
    window.addEventListener('resize', function() {
        clearTimeout(resizeTimer);
        resizeTimer = setTimeout(function() {
            const chartType = document.querySelector('.chart-type-btn.selected').dataset.type;
            const dataType = document.getElementById('dataSelect').value;
            createChart(chartType, dataType);
        }, 250);
    });
});
</script>