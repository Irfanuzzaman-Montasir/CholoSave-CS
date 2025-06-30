<?php
// Include database connection
include 'db.php';

// Get total users count
$userQuery = "SELECT COUNT(id) as total_users FROM users";
$userResult = mysqli_query($conn, $userQuery);
$userCount = mysqli_fetch_assoc($userResult)['total_users'];

// Get total groups count
$groupQuery = "SELECT COUNT(group_id) as total_groups FROM my_group";
$groupResult = mysqli_query($conn, $groupQuery);
$groupCount = mysqli_fetch_assoc($groupResult)['total_groups'];

// Close connection
mysqli_close($conn);
?>

<?php include 'includes/new_header.php'; ?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;500;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css">
    <title>Our Vision - CholoSave</title>
    <style>
        body {
            font-family: 'Poppins', sans-serif;
            margin: 0;
            padding: 0;
            background-color: #f4f7f9;
        }

        /* Hero Section */
        .hero-section {
            position: relative;
            height: 500px;
            display: flex;
            align-items: center;
            justify-content: center;
            margin-top: 5rem;
        }

        .hero-image {
            position: absolute;
            inset: 0;
            width: 100%;
            height: 100%;
            object-fit: cover;
            object-position: center;
            filter: brightness(0.5);
        }

        .hero-content {
            position: relative;
            z-index: 10;
            text-align: center;
            padding: 0 1rem;
            max-width: 800px;
            margin: 0 auto;
        }

        .hero-title {
            font-size: 3rem;
            font-weight: 700;
            color: white;
            margin-bottom: 1.5rem;
        }

        .hero-description {
            font-size: 1.25rem;
            color: #f3f4f6;
            line-height: 1.6;
        }

        /* Impact Section */
        .impact-section {
            padding: 5rem 0;
            background: white;
        }

        .section-container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 0 1rem;
        }

        .section-title {
            font-size: 2rem;
            font-weight: 700;
            text-align: center;
            margin-bottom: 3rem;
            background: linear-gradient(135deg, #003366 0%, #004080 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .impact-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 2rem;
        }

        .impact-card {
            background: #f8fafc;
            border-radius: 1rem;
            padding: 2rem;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            transition: transform 0.3s ease;
        }

        .impact-card:hover {
            transform: translateY(-5px);
        }

        .impact-icon {
            width: 64px;
            height: 64px;
            border-radius: 0.5rem;
            margin-bottom: 1.5rem;
        }

        .impact-title {
            font-size: 1.25rem;
            font-weight: 600;
            color: #1E40AF;
            margin-bottom: 1rem;
        }

        .impact-description {
            color: #4B5563;
            line-height: 1.6;
        }

        /* Goals Section */
        .goals-section {
            padding: 5rem 0;
            background: #f4f7f9;
        }

        .goal-item {
            display: flex;
            align-items: center;
            gap: 1.5rem;
            background: white;
            padding: 1.5rem;
            border-radius: 0.75rem;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
            margin-bottom: 1rem;
        }

        .goal-icon {
            width: 48px;
            height: 48px;
            border-radius: 0.5rem;
        }

        .goal-text {
            font-size: 1.125rem;
            color: #4B5563;
        }

        /* Stats Section */
        .stats-section {
            padding: 5rem 0;
            background: linear-gradient(135deg, #1E40AF 0%, #1E3A8A 100%);
            color: white;
        }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 2rem;
            max-width: 800px;
            margin: 0 auto;
        }

        .stat-card {
            background: rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(10px);
            border-radius: 1rem;
            padding: 2rem;
            text-align: center;
            transition: transform 0.3s ease;
        }

        .stat-card:hover {
            transform: scale(1.05);
        }

        .stat-icon {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            width: 64px;
            height: 64px;
            background: rgba(255, 255, 255, 0.2);
            border-radius: 50%;
            margin-bottom: 1rem;
        }

        .stat-title {
            font-size: 1.125rem;
            font-weight: 500;
            margin-bottom: 0.5rem;
        }

        .stat-number {
            font-size: 2.5rem;
            font-weight: 700;
            margin-bottom: 0.5rem;
        }

        .stat-description {
            color: rgba(255, 255, 255, 0.9);
        }

        .cta-button {
            display: inline-block;
            background: white;
            color: #1E40AF;
            padding: 1rem 2rem;
            border-radius: 0.5rem;
            font-weight: 600;
            text-decoration: none;
            transition: all 0.3s ease;
            margin-top: 3rem;
        }

        .cta-button:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }

        @media (max-width: 768px) {
            .hero-title {
                font-size: 2rem;
            }

            .hero-description {
                font-size: 1rem;
            }

            .impact-grid {
                grid-template-columns: 1fr;
            }

            .stats-grid {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <main>
        <!-- Hero Section -->
        <section class="hero-section">
            <img src="/CholoSave-CS/assets/images/login.png" alt="Financial Vision" class="hero-image"/>
            <div class="hero-content">
                <h1 class="hero-title">Our Vision</h1>
                <p class="hero-description">
                    At CholoSave, our vision is to empower people to achieve financial independence through collaboration and smart investments. We believe in creating a platform that supports financial growth for everyone, regardless of background or financial knowledge.
                </p>
            </div>
        </section>

        <!-- Impact Section -->
        <section class="impact-section">
            <div class="section-container">
                <h2 class="section-title">How We Make an Impact</h2>
                <div class="impact-grid">
                    <div class="impact-card">
                        <img src="/CholoSave-CS/assets/images/cloab.png" alt="Collaboration" class="impact-icon"/>
                        <h3 class="impact-title">Collaboration</h3>
                        <p class="impact-description">
                            By pooling resources and working together, we unlock greater investment opportunities and savings potential for everyone involved.
                        </p>
                    </div>
                    <div class="impact-card">
                        <img src="/CholoSave-CS/assets/images/invest.png" alt="Smart Investment" class="impact-icon"/>
                        <h3 class="impact-title">Smart Investment</h3>
                        <p class="impact-description">
                            We provide intelligent tools and guidance to ensure that your investments grow steadily, maximizing returns with minimal risk.
                        </p>
                    </div>
                    <div class="impact-card">
                        <img src="/CholoSave-CS/assets/images/freedom.png" alt="Financial Freedom" class="impact-icon"/>
                        <h3 class="impact-title">Financial Freedom</h3>
                        <p class="impact-description">
                            Our goal is to help you gain financial freedom through consistent savings, smart investments, and the support of like-minded individuals.
                        </p>
                    </div>
                </div>
            </div>
        </section>

        <!-- Goals Section -->
        <section class="goals-section">
            <div class="section-container">
                <h2 class="section-title">Our Goals</h2>
                <div class="goals-grid">
                    <div class="goal-item">
                        <img src="/CholoSave-CS/assets/images/1.jpg" alt="Goal 1" class="goal-icon"/>
                        <p class="goal-text">Provide accessible financial tools for everyone.</p>
                    </div>
                    <div class="goal-item">
                        <img src="/CholoSave-CS/assets/images/2.jpg" alt="Goal 2" class="goal-icon"/>
                        <p class="goal-text">Encourage a culture of saving and smart investing.</p>
                    </div>
                    <div class="goal-item">
                        <img src="/CholoSave-CS/assets/images/3.jpg" alt="Goal 3" class="goal-icon"/>
                        <p class="goal-text">Foster a community of financial empowerment and collaboration.</p>
                    </div>
                    <div class="goal-item">
                        <img src="/CholoSave-CS/assets/images/4.jpg" alt="Goal 4" class="goal-icon"/>
                        <p class="goal-text">Help members achieve long-term financial independence.</p>
                    </div>
                </div>
            </div>
        </section>

        <!-- Stats Section -->
        <!-- <section class="stats-section">
            <div class="section-container">
                <h2 class="section-title" style="color: white; background: none; -webkit-text-fill-color: white;">Our Growing Community</h2>
                <div class="stats-grid">
                    <div class="stat-card">
                        <div class="stat-icon">
                            <i class="fas fa-users fa-2x"></i>
                        </div>
                        <h3 class="stat-title">Total Users</h3>
                        <div class="stat-number" id="userCount" data-target="<?php echo $userCount; ?>">0</div>
                        <p class="stat-description">Active members in our community</p>
                    </div>
                    <div class="stat-card">
                        <div class="stat-icon">
                            <i class="fas fa-users fa-2x"></i>
                        </div>
                        <h3 class="stat-title">Active Groups</h3>
                        <div class="stat-number" id="groupCount" data-target="<?php echo $groupCount; ?>">0</div>
                        <p class="stat-description">Collaborative saving groups</p>
                    </div>
                </div>
                <div style="text-align: center;">
                    <a href="/CholoSave-CS/register.php" class="cta-button">Join Our Community</a>
                </div>
            </div>
        </section> -->
    </main>

    <?php include 'includes/test_footer.php'; ?>

    <script>
        const countElements = document.querySelectorAll('#userCount, #groupCount');
        
        const animateValue = (element, start, end, duration) => {
            let startTimestamp = null;
            const step = (timestamp) => {
                if (!startTimestamp) startTimestamp = timestamp;
                const progress = Math.min((timestamp - startTimestamp) / duration, 1);
                const current = Math.floor(progress * (end - start) + start);
                element.textContent = new Intl.NumberFormat().format(current);
                if (progress < 1) {
                    window.requestAnimationFrame(step);
                }
            };
            window.requestAnimationFrame(step);
        };

        const observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    const target = parseInt(entry.target.getAttribute('data-target'));
                    animateValue(entry.target, 0, target, 2000);
                    observer.unobserve(entry.target);
                }
            });
        }, {
            threshold: 0.5
        });

        countElements.forEach(counter => {
            observer.observe(counter);
        });
    </script>
</body>
</html>