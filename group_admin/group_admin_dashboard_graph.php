<?php
// Ensure these variables are available
if (!isset($conn) || !isset($group_id)) {
    die('Required variables not set');
}

// Get last 6 months of savings data (increased from 4 to show more trends)
$query = "
    SELECT 
        DATE_FORMAT(created_at, '%b %Y') as month_label,
        DATE_FORMAT(created_at, '%Y-%m') as month_sort,
        SUM(amount) as total_amount
    FROM savings 
    WHERE group_id = ? 
    AND created_at >= DATE_SUB(NOW(), INTERVAL 6 MONTH)
    GROUP BY YEAR(created_at), MONTH(created_at)
    ORDER BY month_sort ASC
";

$stmt = $conn->prepare($query);
$stmt->bind_param("i", $group_id);
$stmt->execute();
$result = $stmt->get_result();

// Store the data in arrays for JSON encoding
$labels = [];
$values = [];
$backgroundColor = [];
$borderColor = [];

while ($row = $result->fetch_assoc()) {
    $labels[] = $row['month_label'];
    $values[] = $row['total_amount'];
    $backgroundColor[] = 'rgba(59, 130, 246, 0.2)'; // Blue with opacity
    $borderColor[] = 'rgb(59, 130, 246)'; // Solid blue
}

// Convert data arrays to JSON for JavaScript
$chartData = [
    'labels' => $labels,
    'values' => $values
];
?>

<!-- Graph Container -->
<div class="bg-white rounded-lg shadow-lg p-6">
    <div class="flex justify-between items-center mb-4">
        <h2 class="text-xl font-bold text-gray-800">Monthly Savings</h2>
        <div class="flex gap-2">
            <button class="chart-type-btn selected px-3 py-1 rounded" data-type="bar">Bar</button>
            <button class="chart-type-btn px-3 py-1 rounded" data-type="line">Line</button>
        </div>
    </div>
    <div class="relative h-[400px] w-full">
        <canvas id="savingsChart"></canvas>
    </div>
</div>

<!-- Add Chart.js library -->
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>

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
    const chartData = <?php echo json_encode($chartData); ?>;
    let currentChart = null;

    function createChart(type = 'bar') {
        const ctx = document.getElementById('savingsChart').getContext('2d');
        
        // Destroy existing chart if it exists
        if (currentChart) {
            currentChart.destroy();
        }

        // Common options for both chart types
        const options = {
            responsive: true,
            maintainAspectRatio: false,
            interaction: {
                intersect: false,
                mode: 'index'
            },
            plugins: {
                legend: {
                    display: false
                },
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
                            return `$${context.parsed.y.toLocaleString('en-US', {
                                minimumFractionDigits: 2,
                                maximumFractionDigits: 2
                            })}`;
                        }
                    }
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: {
                        callback: function(value) {
                            return 'BDT ' + value.toLocaleString('en-US');
                        }
                    },
                    grid: {
                        color: 'rgba(0, 0, 0, 0.05)'
                    }
                },
                x: {
                    grid: {
                        display: false
                    }
                }
            }
        };

        // Specific configurations for each chart type
        const configs = {
            bar: {
                backgroundColor: 'rgba(59, 130, 246, 0.2)',
                borderColor: 'rgb(59, 130, 246)',
                borderWidth: 2
            },
            line: {
                backgroundColor: 'rgba(59, 130, 246, 0.1)',
                borderColor: 'rgb(59, 130, 246)',
                borderWidth: 3,
                tension: 0.3,
                fill: true
            }
        };

        currentChart = new Chart(ctx, {
            type: type,
            data: {
                labels: chartData.labels,
                datasets: [{
                    data: chartData.values,
                    ...configs[type]
                }]
            },
            options: options
        });
    }

    // Initialize chart
    createChart('bar');

    // Add click handlers for chart type buttons
    document.querySelectorAll('.chart-type-btn').forEach(button => {
        button.addEventListener('click', function() {
            // Update button states
            document.querySelectorAll('.chart-type-btn').forEach(btn => {
                btn.classList.remove('selected');
            });
            this.classList.add('selected');

            // Create new chart
            createChart(this.dataset.type);
        });
    });

    // Add window resize handler
    let resizeTimer;
    window.addEventListener('resize', function() {
        clearTimeout(resizeTimer);
        resizeTimer = setTimeout(function() {
            createChart(document.querySelector('.chart-type-btn.selected').dataset.type);
        }, 250);
    });
});
</script>