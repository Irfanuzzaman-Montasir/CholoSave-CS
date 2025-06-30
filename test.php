<?php
session_start();

if (!isset($_SESSION['user_id'])) {
    header("Location: /test_project/login.php");
    exit();
}

include 'includes/header2.php';

// Add database connection
require_once 'db.php'; // Make sure this file exists with your database credentials

// Fetch user name from database
$user_id = $_SESSION['user_id'];
$sql = "SELECT name FROM users WHERE id = ?";
$stmt = $conn->prepare($sql);
$stmt->bind_param("i", $user_id);
$stmt->execute();
$result = $stmt->get_result();

if ($result->num_rows > 0) {
    $user = $result->fetch_assoc();
    $user_name = $user['name'];
} else {
    $user_name = "User"; // Default fallback
}

$stmt->close();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Cholosave</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: 'Poppins', system-ui, -apple-system, sans-serif;
        }

        body {
            background-color: #fff;
            min-height: 80vh;
            opacity: 0;
            animation: fadeInPage 1s ease-in forwards;
        }

        @keyframes fadeInPage {
            from {
                opacity: 0;
                transform: translateY(20px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        @keyframes slideInLeft {
            from {
                opacity: 0;
                transform: translateX(-50px);
            }
            to {
                opacity: 1;
                transform: translateX(0);
            }
        }

        @keyframes slideInRight {
            from {
                opacity: 0;
                transform: translateX(50px);
            }
            to {
                opacity: 1;
                transform: translateX(0);
            }
        }

        @keyframes fadeInButton {
            from {
                opacity: 0;
                transform: translateY(20px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        main {
            padding-top: 120px;
            max-width: 1200px;
            margin: 0 auto;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding-left: 2rem;
            padding-right: 2rem;
        }

        .hero-content {
            max-width: 600px;
            animation: slideInLeft 1s ease-out 0.5s forwards;
            opacity: 0;
        }

        h1 {
            font-size: 3rem;
            line-height: 1.1;
            margin-bottom: 1.5rem;
            font-weight: 600;
        }

        .subtitle {
            font-size: 1.2rem;
            color: #666;
            margin-bottom: 2rem;
        }

        .cta-button {
            display: inline-block;
            padding: 0.7rem 2rem;
            background-color: rgb(0, 63, 238);
            color: white;
            text-decoration: none;
            border-radius: 10px;
            transition: background-color 0.3s ease;
            opacity: 0;
            animation: fadeInButton 0.5s ease-out 1.5s forwards;
        }

        .cta-button:hover {
            background-color: #333;
            transform: translateY(-2px);
            transition: all 0.3s ease;
        }

        .decoration {
            position: relative;
            animation: slideInRight 1s ease-out 0.5s forwards;
            opacity: 0;
        }

        .custom-image {
            width: 80%;
            max-width: 500px;
            position: relative;
            right: -20px;
            transition: all 0.3s ease;
        }

        .custom-image:hover {
            transform: scale(1.05);
        }

        @media (max-width: 768px) {
            main {
                flex-direction: column;
                text-align: center;
                padding-top: 100px;
            }

            h1 {
                font-size: 3rem;
            }

            .decoration {
                margin-top: 3rem;
            }

            .hero-content, .decoration {
                animation: slideInLeft 1s ease-out 0.5s forwards;
            }
        }
    </style>
</head>

<body>
    <?php
    $pageTitle = "Welcome " . htmlspecialchars($user_name);
    $subtitle = "Start your savings journey together now";
    $currentYear = date("Y");
    ?>

    <main>
        <div class="hero-content -mt-80">
            <h1><?php echo $pageTitle; ?></h1>
            <p class="subtitle"><?php echo $subtitle; ?></p>
            <a href="/test_project/groups.php" class="cta-button">Start</a>
        </div>
        <div class="decoration -mt-80">
            <img src="land.png" alt="Land Image" class="custom-image">
        </div>
    </main>
</body>
</html>
<?php include 'includes/new_footer.php'; ?>

