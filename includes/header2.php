<?php
include 'db.php';
$user_id = $_SESSION['user_id'];

$notificationCount = 0;

// Get notification count for current user using conn
$sql = "SELECT COUNT(*) as count FROM notifications WHERE target_user_id = ? AND status = 'unread'";
$stmt = $conn->prepare($sql);
$stmt->bind_param("i", $user_id);
$stmt->execute();
$result = $stmt->get_result();
$row = $result->fetch_assoc();
$notificationCount = $row['count'];

// Get user information including profile picture
$user_name = '';
$user_email = '';
$profile_picture = '';
$sql_user = "SELECT name, email, profile_picture FROM users WHERE id = ?";
$stmt = $conn->prepare($sql_user);
$stmt->bind_param("i", $user_id);
$stmt->execute();
$result_user = $stmt->get_result();

if ($result_user) {
    $user_data = $result_user->fetch_assoc();
    $user_name = $user_data['name'];
    $user_email = $user_data['email'];
    $profile_picture = $user_data['profile_picture'];
}
?>


<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="ie=edge">
    <title>CholoSave | Dashboard</title>

    <!-- Google Fonts -->
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;500;600;700&display=swap" rel="stylesheet">

    <!-- Tailwind CSS CDN -->
    <script src="https://cdn.tailwindcss.com"></script>

    <!-- Font Awesome -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css">

    <style>
        body {
            font-family: 'Poppins', sans-serif;
        }

        .nav-item {
            transition: all 0.3s ease;
            position: relative;
        }

        .nav-item::after {
            content: '';
            position: absolute;
            width: 0;
            height: 2px;
            bottom: -4px;
            left: 0;
            background-color: #1E40AF;
            /* Changed to dark blue */
            transition: width 0.3s ease;
        }

        .nav-item:hover::after {
            width: 100%;
        }

        .logo a {
            font-size: 1.8rem;
            font-weight: 700;
            background: linear-gradient(135deg, #003366 0%, #004080 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            text-decoration: none;
        }

        .brand {
            background: linear-gradient(135deg, #22C55E 0%, #16A34A 100%);
            /* Changed to green */
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .profile-dropdown {
            transform-origin: top right;
            transition: all 0.3s ease;
        }

        .notification-badge {
            position: absolute;
            top: -6px;
            right: -6px;
            background: #1E40AF;
            /* Changed to dark blue */
            border-radius: 50%;
            width: 18px;
            height: 18px;
            font-size: 11px;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            border: 2px solid white;
        }

        /* Modified hover states */
        .group-hover\:opacity-100:hover a:hover {
            background-color: #EEF2FF;
            /* Light blue hover */
            color: #1E40AF;
            /* Dark blue text */
        }




        /* for animatiobn the icons  */
        @keyframes pulse {

            0%,
            100% {
                transform: scale(1);
            }

            50% {
                transform: scale(1.1);
            }
        }

        .animate-pulse {
            animation: pulse 1s infinite;
        }

        @keyframes glow {

            0%,
            100% {
                text-shadow: 0 0 5px #ffd700, 0 0 10px #ffd700, 0 0 20px #ffa700, 0 0 30px #ffa700;
            }

            50% {
                text-shadow: 0 0 10px #ffd700, 0 0 20px #ffa700, 0 0 30px #ffa700, 0 0 40px #ff8700;
            }
        }

        .animate-glow {
            animation: glow 2s infinite;
            color: #ffd700;
        }

        .logo-image {
            max-height: 3rem;
            width: auto;
            object-fit: contain;
        }
    </style>
</head>

<body class="bg-gray-50">
    <header class="bg-white shadow-sm">
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div class="flex items-center justify-between h-20">
                <!-- Logo -->
                <div class="logo flex items-center space-x-4">
                    <a href="/CholoSave-CS/user_landing_page.php" class="flex items-center">
                        <img src="/CholoSave-CS/includes/project_logo1.png" alt="CholoSave Logo" class="logo-image">
                    </a>
                </div>

                <!-- Navigation Menu -->
                <div class="hidden md:flex items-center space-x-8">
                    <!-- Groups Section -->
                    <div class="relative group">
                        <button
                            class="nav-item flex items-center space-x-2 px-3 py-2 text-gray-700 hover:text-gray-900">
                            <i class="fas fa-users text-lg"></i>
                            <span class="font-medium">Groups</span>
                        </button>
                        <div
                            class="absolute left-0 w-48 mt-2 bg-white rounded-xl shadow-lg opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-all duration-200 transform -translate-y-2 group-hover:translate-y-0">
                            <div class="py-2">
                                <a href="/CholoSave-CS/create_group.php"
                                    class="block px-4 py-2 text-sm text-gray-700 hover:bg-blue-50 hover:text-blue-700 transition-colors duration-200">Create
                                    Group</a>
                                <a href="/CholoSave-CS/groups.php"
                                    class="block px-4 py-2 text-sm text-gray-700 hover:bg-blue-50 hover:text-blue-700 transition-colors duration-200">Groups</a>
                            </div>
                        </div>
                    </div>

                    <!-- Savings Section -->
                    <!-- <div class="relative group">
                        <a href="/CholoSave-CS/portfolio.php"
                            class="nav-item flex items-center space-x-2 px-3 py-2 text-gray-700 hover:text-gray-900">
                            <i class="fas fa-tachometer-alt text-lg"></i> 
                            <span class="font-medium">Dashboard</span>
                        </a>
                    </div> -->

                    <!-- AI Tips Section -->
                    <div class="relative group">
                        <a href="/CholoSave-CS/ai_tips/ai_tips.php">
                            <button
                                class="nav-item flex items-center space-x-2 px-3 py-2 text-gray-700 hover:text-gray-900">
                                <i class="fas fa-lightbulb text-lg text-yellow-600 animate-pulse"></i>
                                <span class="font-medium">AI Tips</span>
                            </button>
                        </a>
                    </div>

                    <!-- Community Section -->
                    <div class="relative group">
                        <button
                            class="nav-item flex items-center space-x-2 px-3 py-2 text-gray-700 hover:text-gray-900">
                            <i class="fas fa-users-cog text-lg"></i>
                            <span class="font-medium">Community</span>
                        </button>
                        <div
                            class="absolute left-0 w-48 mt-2 bg-white rounded-xl shadow-lg opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-all duration-200 transform -translate-y-2 group-hover:translate-y-0">
                            <div class="py-2">
                                <!-- <a href="/CholoSave-CS/leaderboard.php"
                                    class="block px-4 py-2 text-sm text-gray-700 hover:bg-orange-50 hover:text-orange-500 transition-colors duration-200">Leaderboard</a> -->
                                <a href="/CholoSave-CS/forum.php"
                                    class="block px-4 py-2 text-sm text-gray-700 hover:bg-orange-50 hover:text-orange-500 transition-colors duration-200">Forum</a>
                                <!-- <a href="my_posts.php" class="text-gray-600 hover:text-gray-900">
                                    <i class="fas fa-user-edit"></i> My Posts
                                </a> -->
                            </div>
                        </div>
                    </div>



                    <!-- Notifications -->
                    <div class="relative">
                        <a href="/CholoSave-CS/notification.php"
                            class="nav-item flex items-center space-x-2 px-3 py-2 text-gray-700 hover:text-gray-900">
                            <div class="relative">
                                <i class="fas fa-bell text-lg"></i>
                                <?php if ($notificationCount > 0): ?>
                                    <span class="notification-badge"><?php echo $notificationCount; ?></span>
                                <?php endif; ?>
                            </div>
                        </a>
                    </div>



                    <!-- Profile Section -->
                    <div class="relative group">
                        <button
                            class="flex items-center space-x-3 px-3 py-2 rounded-full hover:bg-gray-100 transition-colors duration-200">
                            <div class="relative w-10 h-10 rounded-full overflow-hidden ring-2 ring-gray-200">
                                <?php if (!empty($profile_picture) && file_exists('uploads/profile/' . $profile_picture)): ?>
                                    <img src="uploads/profile/<?php echo htmlspecialchars($profile_picture); ?>"
                                        alt="Profile" class="w-full h-full object-cover">
                                <?php else: ?>
                                    <div class="w-full h-full bg-gray-200 flex items-center justify-center">
                                        <i class="fas fa-user text-gray-400"></i>
                                    </div>
                                <?php endif; ?>
                            </div>
                            <span
                                class="text-sm font-medium text-gray-700"><?php echo htmlspecialchars($user_name); ?></span>
                            <i class="fas fa-chevron-down text-sm text-gray-500"></i>
                        </button>

                        <div
                            class="absolute right-0 w-64 mt-2 bg-white rounded-xl shadow-lg opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-all duration-200 transform -translate-y-2 group-hover:translate-y-0">
                            <div class="p-4 border-b border-gray-100">
                                <div class="flex items-center space-x-3">
                                    <div class="w-14 h-14 rounded-full overflow-hidden ring-2 ring-gray-200">
                                        <?php if (!empty($profile_picture) && file_exists('uploads/profile/' . $profile_picture)): ?>
                                            <img src="uploads/profile/<?php echo htmlspecialchars($profile_picture); ?>"
                                                alt="Profile" class="w-full h-full object-cover">
                                        <?php else: ?>
                                            <div class="w-full h-full bg-gray-200 flex items-center justify-center">
                                                <i class="fas fa-user text-gray-400"></i>
                                            </div>
                                        <?php endif; ?>
                                    </div>
                                    <div>
                                        <p class="font-semibold text-gray-800">
                                            <?php echo htmlspecialchars($user_name); ?>
                                        </p>
                                        <p class="text-sm text-gray-500"><?php echo htmlspecialchars($user_email); ?>
                                        </p>
                                    </div>
                                </div>
                            </div>

                            <div class="py-2">
                                <a href="/CholoSave-CS/profile.php"
                                    class="flex items-center px-4 py-2 text-sm text-gray-700 hover:bg-orange-50 hover:text-orange-500 transition-colors duration-200">
                                    <i class="fas fa-user-circle w-5 h-5 mr-3"></i>
                                    My Profile
                                </a>

                                <a href="/CholoSave-CS/payment_reminders.php"
                                    class="flex items-center px-4 py-2 text-sm text-gray-700 hover:bg-orange-50 hover:text-orange-500 transition-colors duration-200">
                                    <i class="fas fa-calendar-alt w-5 h-5 mr-3"></i>
                                    Payment Reminder
                                </a>

                                <div class="border-t border-gray-100 my-1"></div>
                                <a href="/CholoSave-CS/logout.php"
                                    class="flex items-center px-4 py-2 text-sm text-red-600 hover:bg-red-50 transition-colors duration-200">
                                    <i class="fas fa-sign-out-alt w-5 h-5 mr-3"></i>
                                    Logout
                                </a>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
    </header>
</body>

</html>