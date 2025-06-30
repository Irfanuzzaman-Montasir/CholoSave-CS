<?php
include 'db.php';
session_start();

// Fetch all experts from database
$query = "SELECT * FROM expert_team ORDER BY name ASC";
$result = $conn->query($query);
$experts = [];

if ($result) {
    while ($row = $result->fetch_assoc()) {
        $experts[] = $row;
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;500;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css">
    <title>Expert Team - CholoSave</title>
    <style>
        /* Existing styles remain the same */
        body {
            font-family: 'Poppins', sans-serif;
            margin: 0;
            padding: 0;
            background-color: #f4f7f9;
        }

        .main-content {
            max-width: 1200px;
            margin: 2rem auto;
            padding: 0 1rem;
            opacity: 0;
            animation: fadeIn 1s ease forwards;
        }

        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(20px); }
            to { opacity: 1; transform: translateY(0); }
        }

        .page-title {
            text-align: center;
            margin-bottom: 3rem;
            animation: slideDown 1s ease forwards;
        }

        @keyframes slideDown {
            from { opacity: 0; transform: translateY(-30px); }
            to { opacity: 1; transform: translateY(0); }
        }

        .page-title h1 {
            font-size: 2.5rem;
            font-weight: 700;
            background: linear-gradient(135deg, #003366 0%, #004080 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 1rem;
        }

        .experts-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
            gap: 2rem;
            padding: 1rem;
        }

        .expert-card {
            background: #ffffff;
            border-radius: 0.75rem;
            overflow: hidden;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
            transition: all 0.5s cubic-bezier(0.4, 0, 0.2, 1);
            opacity: 0;
            animation: cardAppear 0.8s ease forwards;
            animation-delay: calc(var(--card-index) * 0.1s);
        }

        @keyframes cardAppear {
            from {
                opacity: 0;
                transform: scale(0.8) translateY(50px);
            }
            to {
                opacity: 1;
                transform: scale(1) translateY(0);
            }
        }

        .expert-card:hover {
            transform: translateY(-5px) scale(1.02);
            box-shadow: 0 8px 16px rgba(0, 0, 0, 0.15);
        }

        .expert-image-container {
            position: relative;
            height: 300px;
            overflow: hidden;
        }

        .expert-image {
            width: 100%;
            height: 100%;
            object-fit: cover;
            transition: transform 0.5s ease;
        }

        .expert-card:hover .expert-image {
            transform: scale(1.1);
        }

        .expert-placeholder {
            width: 100%;
            height: 100%;
            display: flex;
            align-items: center;
            justify-content: center;
            background-color: #e5e7eb;
            transition: background-color 0.3s ease;
        }

        .expert-card:hover .expert-placeholder {
            background-color: #d1d5db;
        }

        .expert-info {
            padding: 1.5rem;
            transform: translateY(0);
            transition: transform 0.3s ease;
        }

        .expert-card:hover .expert-info {
            transform: translateY(-5px);
        }

        .expert-name {
            font-size: 1.25rem;
            font-weight: 600;
            color: #1E40AF;
            margin-bottom: 0.5rem;
            transition: color 0.3s ease;
        }

        .expert-expertise {
            color: #22C55E;
            font-weight: 500;
            margin-bottom: 1rem;
            transition: color 0.3s ease;
        }

        .expert-bio {
            position: absolute;
            bottom: -100%;
            left: 0;
            right: 0;
            background: linear-gradient(to top, rgba(0, 0, 0, 0.9), transparent);
            padding: 1.5rem;
            color: white;
            transition: bottom 0.5s cubic-bezier(0.4, 0, 0.2, 1);
        }

        .expert-image-container:hover .expert-bio {
            bottom: 0;
        }

        .contact-item {
            display: flex;
            align-items: center;
            color: #4B5563;
            text-decoration: none;
            transition: all 0.3s ease;
            padding: 0.5rem 0;
        }

        .contact-item:hover {
            color: #1E40AF;
            transform: translateX(5px);
        }

        .contact-item i {
            width: 1.5rem;
            margin-right: 0.5rem;
            transition: transform 0.3s ease;
        }

        .contact-item:hover i {
            transform: scale(1.2);
        }

        .empty-state {
            text-align: center;
            padding: 4rem 1rem;
            color: #6B7280;
            animation: emptyStatePulse 2s infinite;
        }

        @keyframes emptyStatePulse {
            0% { transform: scale(1); }
            50% { transform: scale(1.05); }
            100% { transform: scale(1); }
        }

        @media (max-width: 768px) {
            .experts-grid {
                grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
            }

            .page-title h1 {
                font-size: 2rem;
            }
        }
    </style>
</head>
<body>
    <?php include 'includes/new_header.php'; ?>

    <main class="main-content">
        <div class="page-title">
            <h1>Meet Our Expert Team</h1>
        </div>

        <div class="experts-grid">
            <?php foreach ($experts as $index => $expert): ?>
                <div class="expert-card" style="--card-index: <?php echo $index; ?>">
                    <div class="expert-image-container">
                        <?php if ($expert['image']): ?>
                            <img src="uploads/experts/<?php echo htmlspecialchars($expert['image']); ?>" 
                                 alt="<?php echo htmlspecialchars($expert['name']); ?>"
                                 class="expert-image">
                        <?php else: ?>
                            <div class="expert-placeholder">
                                <i class="fas fa-user-tie" style="font-size: 4rem; color: #9CA3AF;"></i>
                            </div>
                        <?php endif; ?>
                        <?php if ($expert['bio']): ?>
                            <div class="expert-bio">
                                <p><?php echo htmlspecialchars($expert['bio']); ?></p>
                            </div>
                        <?php endif; ?>
                    </div>

                    <div class="expert-info">
                        <h2 class="expert-name"><?php echo htmlspecialchars($expert['name']); ?></h2>
                        <p class="expert-expertise"><?php echo htmlspecialchars($expert['expertise']); ?></p>
                        
                        <div class="expert-contact">
                            <a href="mailto:<?php echo htmlspecialchars($expert['email']); ?>" class="contact-item">
                                <i class="fas fa-envelope"></i>
                                <span><?php echo htmlspecialchars($expert['email']); ?></span>
                            </a>
                            <?php if ($expert['phone']): ?>
                                <a href="tel:<?php echo htmlspecialchars($expert['phone']); ?>" class="contact-item">
                                    <i class="fas fa-phone"></i>
                                    <span><?php echo htmlspecialchars($expert['phone']); ?></span>
                                </a>
                            <?php endif; ?>
                        </div>
                    </div>
                </div>
            <?php endforeach; ?>
        </div>

        <?php if (empty($experts)): ?>
            <div class="empty-state">
                <i class="fas fa-users"></i>
                <p>No experts found. Check back later!</p>
            </div>
        <?php endif; ?>
    </main>

    <?php include 'includes/test_footer.php'; ?>

    <script>
    document.getElementById('mobile-menu')?.addEventListener('click', function() {
        document.querySelector('.nav')?.classList.toggle('active');
    });
    </script>
</body>
</html>