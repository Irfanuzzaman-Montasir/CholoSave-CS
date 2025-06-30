<?php
session_start();

if (!isset($_SESSION['user_id'])) {
    header("Location: /CholoSave-CS/login.php");
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
    <script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js"></script>
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
        }

        h1 {
            font-size: 3rem;
            line-height: 1.1;
            margin-bottom: 1.5rem;
            font-weight: 600;
        }

        .typing-text {
            border-right: 2px solid #000;
            white-space: nowrap;
            overflow: hidden;
            width: 0;
            animation: typing 2s steps(30, end) forwards,
                       blink-caret 0.75s step-end infinite;
        }

        @keyframes typing {
            from { width: 0 }
            to { width: 100% }
        }

        @keyframes blink-caret {
            from, to { border-color: transparent }
            50% { border-color: #000 }
        }

        .welcome-container {
            display: inline-block;
        }

        .subtitle {
            font-size: 1.2rem;
            color: #666;
            margin-bottom: 2rem;
        }

        .cta-button {
            display: inline-block;
            padding: 0.7rem 2rem;
            background-color: rgb(0, 42, 196);
            color: white;
            text-decoration: none;
            border-radius: 10px;
            transition: background-color 0.3s ease;
        }

        .cta-button:hover {
            background-color: #333;
        }

        .decoration {
            position: relative;
        }

        .custom-image {
            width: 80%;
            max-width: 500px;
            position: relative;
            right: -20px;
            /* transition: all 0.3s ease; */
        }

        .custom-image:hover {
            /* transform: scale(1.05); */
        }

        .flower {
            width: 150px;
            height: 150px;
            background-color: #4CAF50;
            border-radius: 50%;
            position: relative;
            transform: rotate(45deg);
        }

        .geometric {
            position: absolute;
            bottom: -50px;
            right: -50px;
            width: 200px;
            height: 200px;
            border: 2px solid #1a1a1a;
            transform: rotate(-15deg);
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
       
        <div class="hero-content -mt-40">
            <h1>
                <div class="welcome-container">
                    <div id="welcome-text" data-text="<?php echo $pageTitle; ?>"></div>
                </div>
            </h1>
            <p class="subtitle"><?php echo $subtitle; ?></p>
            <a href="/CholoSave-CS/groups.php" class="cta-button">Start</a>
        </div>
        <div class="decoration -mt-40">
            <img src="land.png" alt="Land Image" class="custom-image">
        </div>
    </main>

    <script>
        function startTypingAnimation(text) {
            const container = document.querySelector('.welcome-container');
            const typingElement = document.createElement('div');
            typingElement.className = 'typing-text';
            typingElement.textContent = text;
            container.innerHTML = '';
            container.appendChild(typingElement);
        }

        // Start animation when page loads
        document.addEventListener('DOMContentLoaded', () => {
            const welcomeText = document.getElementById('welcome-text').dataset.text;
            startTypingAnimation(welcomeText);
        });
    </script>
</body>

</html>
<?php include 'includes/new_footer.php'; ?>