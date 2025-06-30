<?php
// Include session, database connection, and header
include 'session.php';
include 'db.php';
include 'includes/header2.php';

// Check if the user is logged in
if (!isLoggedIn()) {
    echo json_encode(["status" => "error", "message" => "User not logged in."]);
    exit();
}

// Query to get group details and member count
$query = "
    SELECT 
        g.group_id, 
        g.group_name, 
        g.dps_type, 
        g.amount AS installment, 
        COUNT(gm.user_id) AS members_count 
    FROM 
        my_group g
    LEFT JOIN 
        group_membership gm 
    ON 
        g.group_id = gm.group_id AND gm.status = 'approved'
    GROUP BY 
        g.group_id
";

$result = $conn->query($query);

if ($result) {
    $groups = [];
    while ($row = $result->fetch_assoc()) {
        $groups[] = [
            "group_id" => $row['group_id'],
            "group_name" => $row['group_name'],
            "dps_type" => $row['dps_type'],
            "installment" => $row['installment'],
            "members_count" => $row['members_count']
        ];
    }
} else {
    $groups = [];
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>All Groups</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/animate.css/4.1.1/animate.min.css">
    <style>
        body {
            background: linear-gradient(135deg, #f6f8fd 0%, #f1f4f9 100%);
            min-height: 100vh;
        }
        .group-card {
            max-width: 350px;
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.2);
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        }
        .group-card:hover {
            transform: translateY(-8px);
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1);
        }
        .card-gradient {
            background: linear-gradient(135deg, #6366f1 0%, #4f46e5 100%);
        }
        .shine-effect {
            position: relative;
            overflow: hidden;
        }
        .shine-effect::after {
            content: '';
            position: absolute;
            top: -50%;
            left: -50%;
            width: 200%;
            height: 200%;
            background: linear-gradient(
                to bottom right,
                rgba(255, 255, 255, 0) 0%,
                rgba(255, 255, 255, 0.1) 50%,
                rgba(255, 255, 255, 0) 100%
            );
            transform: rotate(45deg);
            animation: shine 3s infinite;
        }
        @keyframes shine {
            0% { transform: translateX(-100%) rotate(45deg); }
            100% { transform: translateX(100%) rotate(45deg); }
        }
        .pulse {
            animation: pulse 2s infinite;
        }
        @keyframes pulse {
            0% { transform: scale(1); }
            50% { transform: scale(1.05); }
            100% { transform: scale(1); }
        }
    </style>
</head>
<body class="font-inter">
    <div class="container mx-auto px-6 py-16">
        <div class="text-center mb-16 animate__animated animate__fadeIn">
            <h1 class="text-5xl font-bold text-gray-800 mb-4">Discover Your Perfect Group</h1>
            <p class="text-xl text-gray-600 max-w-2xl mx-auto">Join a community of like-minded individuals and achieve your financial goals together.</p>
        </div>

        <div class="flex flex-wrap justify-center gap-8">
            <?php if (!empty($groups)): ?>
                <?php foreach ($groups as $index => $group): ?>
                    <div class="group-card rounded-2xl overflow-hidden animate__animated animate__fadeInUp" style="animation-delay: <?php echo $index * 0.1; ?>s">
                        <div class="card-gradient p-4">
                            <h3 class="text-2xl font-bold text-white mb-1"><?php echo htmlspecialchars($group['group_name']); ?></h3>
                            <p class="text-indigo-200"><?php echo htmlspecialchars($group['dps_type']); ?></p>
                        </div>
                        <div class="p-6">
                            <div class="mb-6">
                                <div class="flex justify-between items-center mb-4">
                                    <span class="text-gray-600">Monthly Installment</span>
                                    <span class="text-2xl font-bold text-indigo-600">$<?php echo htmlspecialchars($group['installment']); ?></span>
                                </div>
                                <div class="flex justify-between items-center">
                                    <span class="text-gray-600">Active Members</span>
                                    <span class="text-lg font-semibold text-gray-800"><?php echo htmlspecialchars($group['members_count']); ?> members</span>
                                </div>
                            </div>
                            <form action="join_group.php" method="POST">
                                <input type="hidden" name="group_id" value="<?php echo htmlspecialchars($group['group_id']); ?>">
                                <button type="submit" class="shine-effect w-full bg-indigo-600 text-white py-3 px-6 rounded-xl text-lg font-semibold transition duration-300 ease-in-out hover:bg-indigo-700 focus:outline-none focus:ring-4 focus:ring-indigo-500 focus:ring-opacity-50">
                                    Join Group
                                </button>
                            </form>
                        </div>
                    </div>
                <?php endforeach; ?>
            <?php else: ?>
                <div class="text-center py-16 animate__animated animate__fadeIn">
                    <div class="text-6xl mb-4">🏦</div>
                    <h3 class="text-2xl font-semibold text-gray-800 mb-2">No Groups Available</h3>
                    <p class="text-gray-600">Check back soon for new groups to join!</p>
                </div>
            <?php endif; ?>
        </div>
    </div>

    <script>
        // Add intersection observer for smooth scroll animations
        const observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    entry.target.classList.add('animate__fadeInUp');
                }
            });
        }, { threshold: 0.1 });

        document.querySelectorAll('.group-card').forEach((card) => {
            observer.observe(card);
        });
    </script>
</body>
</html>