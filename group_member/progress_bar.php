
<?php
// Ensure these variables are available
if (!isset($conn) || !isset($group_id)) {
    die('Required variables not set');
}

// Fetch the goal amount from the my_group table
$goal_amount = 0;
$query_goal = "SELECT goal_amount FROM my_group WHERE group_id = ?";
$stmt_goal = $conn->prepare($query_goal);
$stmt_goal->bind_param("i", $group_id);
$stmt_goal->execute();
$stmt_goal->bind_result($goal_amount);
$stmt_goal->fetch();
$stmt_goal->close();

// Fetch the total achieved amount from the savings table
$achieved_amount = 0;
$query_achieved = "SELECT SUM(amount) AS total_achieved FROM savings WHERE group_id = ?";
$stmt_achieved = $conn->prepare($query_achieved);
$stmt_achieved->bind_param("i", $group_id);
$stmt_achieved->execute();
$stmt_achieved->bind_result($achieved_amount);
$stmt_achieved->fetch();
$stmt_achieved->close();

// Calculate the progress percentage
$progress_percentage = ($goal_amount > 0) ? ($achieved_amount / $goal_amount) * 100 : 0;
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Group Savings</title>
</head>
<body>
<div class="gauge-container">
    <div class="stats">
        <div class="stat-item">
            <div class="stat-label">Goal Amount</div>
            <div class="stat-value">BDT <?php echo number_format($goal_amount, 2); ?></div>
        </div>
        <div class="stat-item">
            <div class="stat-label">Achieved</div>
            <div class="stat-value">BDT <?php echo number_format($achieved_amount, 2); ?></div>
        </div>
    </div>
    <div class="gauge">
        <div class="gauge-body">
            <div class="gauge-fill"></div>
            <div class="gauge-cover">
                <div class="gauge-value">0%</div>
            </div>
        </div>
        <div class="gauge-ticks">
            <div class="tick tick-0">0</div>
            <div class="tick tick-25">25</div>
            <div class="tick tick-50">50</div>
            <div class="tick tick-75">75</div>
            <div class="tick tick-100">100</div>
        </div>
    </div>
</div>

<style>
.gauge-container {
    width: 100%;
    height: 100%;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    background: linear-gradient(135deg, #f8f9fa 0%, #ffffff 100%);
    padding: 2rem;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
    border-radius: 20px;
    box-shadow: 0 10px 30px rgba(0,0,0,0.05);
}

.stats {
    display: flex;
    justify-content: space-around;
    width: 100%;
    max-width: 500px;
    margin-bottom: 2.5rem;
    gap: 2rem;
}

.stat-item {
    text-align: center;
    padding: 1.5rem 2rem;
    background: white;
    border-radius: 16px;
    box-shadow: 0 4px 15px rgba(0,0,0,0.05);
    transition: transform 0.2s ease;
    flex: 1;
}

.stat-item:hover {
    transform: translateY(-5px);
}

.stat-label {
    font-size: 0.9rem;
    color: #6c757d;
    margin-bottom: 0.5rem;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}

.stat-value {
    font-size: 1.5rem;
    font-weight: 700;
    color: #2d3436;
    text-shadow: 0 1px 2px rgba(0,0,0,0.1);
}

.gauge {
    width: 100%;
    max-width: 300px;
    position: relative;
    padding-bottom: 60px;
}

.gauge-body {
    width: 100%;
    height: 0;
    padding-bottom: 50%;
    background: #f1f3f5;
    position: relative;
    border-top-left-radius: 100% 200%;
    border-top-right-radius: 100% 200%;
    overflow: hidden;
    box-shadow: inset 0 4px 15px rgba(0,0,0,0.1);
}

.gauge-fill {
    position: absolute;
    top: 100%;
    left: 0;
    width: inherit;
    height: 100%;
    background: linear-gradient(90deg, #4361ee, #3a0ca3);
    transform-origin: center top;
    transform: rotate(0turn);
    transition: transform 0.5s cubic-bezier(0.34, 1.56, 0.64, 1);
}

.gauge-cover {
    width: 75%;
    height: 150%;
    background: white;
    border-radius: 50%;
    position: absolute;
    top: 25%;
    left: 50%;
    transform: translateX(-50%);
    display: flex;
    align-items: center;
    justify-content: center;
    padding-bottom: 25%;
    box-sizing: border-box;
    box-shadow: 0 4px 15px rgba(0,0,0,0.07);
}

.gauge-value {
    font-family: inherit;
    font-size: 2rem;
    font-weight: 800;
    color: #2d3436;
    text-shadow: 0 2px 4px rgba(0,0,0,0.1);
}

.gauge-ticks {
    position: absolute;
    width: 100%;
    height: 100%;
    top: 0;
    left: 0;
}

.tick {
    position: absolute;
    font-size: 0.8rem;
    font-weight: 600;
    color: #6c757d;
}

.tick::after {
    content: '%';
    font-size: 0.7em;
    margin-left: 1px;
}

.tick-0 { left: 7%; top: 50%; }
.tick-25 { left: 27%; top: 20%; }
.tick-50 { left: 50%; top: 10%; transform: translateX(-50%); }
.tick-75 { right: 27%; top: 20%; }
.tick-100 { right: 7%; top: 50%; }

@media (max-width: 768px) {
    .gauge-container {
        padding: 1rem;
    }
    
    .stats {
        flex-direction: column;
        gap: 1rem;
    }
    
    .stat-item {
        padding: 1rem;
    }
    
    .gauge {
        max-width: 250px;
    }
    
    .gauge-value {
        font-size: 1.5rem;
    }
}
</style>

<script>
function setGaugeValue(gauge, value) {
    if (value < 0 || value > 100) {
        return;
    }

    const gaugeFill = gauge.querySelector(".gauge-fill");
    const gaugeValue = gauge.querySelector(".gauge-value");
    
    gaugeFill.style.transform = `rotate(${value/200}turn)`;
    gaugeValue.textContent = `${Math.round(value)}%`;
}

const gauge = document.querySelector(".gauge");
let currentValue = 0;
const targetValue = <?php echo round($progress_percentage, 2); ?>;

const animateGauge = () => {
    if (currentValue < targetValue) {
        const step = Math.max(1, (targetValue - currentValue) / 30);
        currentValue = Math.min(targetValue, currentValue + step);
        setGaugeValue(gauge, currentValue);
        if (currentValue < targetValue) {
            requestAnimationFrame(animateGauge);
        }
    }
};

document.addEventListener('DOMContentLoaded', animateGauge);
</script>
</body>
</html>