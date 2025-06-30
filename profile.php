<?php
include 'session.php';
include 'db.php';

if (!isset($_SESSION['user_id'])) {
    header('Location: login.php');
    exit();
}

include 'includes/header2.php';

// Fetch user data
$user_id = $_SESSION['user_id'];
$query = "SELECT id, name, email, role, phone_number, profile_picture FROM users WHERE id = ?";
$stmt = $conn->prepare($query);
$stmt->bind_param("i", $user_id);
$stmt->execute();
$result = $stmt->get_result();
$user = $result->fetch_assoc();
$stmt->close();

$message = '';
$imageMessage = '';

// Handle profile picture upload
if (isset($_FILES['profile_picture']) && $_FILES['profile_picture']['error'] === UPLOAD_ERR_OK) {
    $upload_dir = 'uploads/profile/';
    if (!file_exists($upload_dir)) {
        mkdir($upload_dir, 0777, true);
    }

    $file_extension = strtolower(pathinfo($_FILES['profile_picture']['name'], PATHINFO_EXTENSION));
    $allowed_extensions = array('jpg', 'jpeg', 'png');

    if (in_array($file_extension, $allowed_extensions)) {
        $new_filename = 'user_' . $user_id . '.' . $file_extension;
        $upload_path = $upload_dir . $new_filename;

        if (move_uploaded_file($_FILES['profile_picture']['tmp_name'], $upload_path)) {
            // Update database with new profile picture path
            $query = "UPDATE users SET profile_picture = ? WHERE id = ?";
            $stmt = $conn->prepare($query);
            $stmt->bind_param("si", $new_filename, $user_id);
            $stmt->execute();
            $stmt->close();
            $imageMessage = 'Profile picture updated successfully!';
            $user['profile_picture'] = $new_filename;
        } else {
            $imageMessage = 'Error uploading file.';
        }
    } else {
        $imageMessage = 'Invalid file type. Please upload JPG, JPEG, or PNG files only.';
    }
}

// Handle password change
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['current_password'])) {
    $currentPassword = $_POST['current_password'];
    $newPassword = $_POST['new_password'];
    $confirmPassword = $_POST['confirm_password'];

    // Verify current password
    $query = "SELECT password FROM users WHERE id = ?";
    $stmt = $conn->prepare($query);
    $stmt->bind_param("i", $user_id);
    $stmt->execute();
    $result = $stmt->get_result();
    $row = $result->fetch_assoc();
    $storedPassword = $row['password'];
    $stmt->close();

    if (password_verify($currentPassword, $storedPassword)) {
        if ($newPassword === $confirmPassword) {
            $hashed_password = password_hash($newPassword, PASSWORD_BCRYPT);
            $query = "UPDATE users SET password = ? WHERE id = ?";
            $stmt = $conn->prepare($query);
            $stmt->bind_param("si", $hashed_password, $user_id);
            $stmt->execute();
            $stmt->close();
            $message = 'Password updated successfully!';
        } else {
            $message = 'New passwords do not match!';
        }
    } else {
        $message = 'Current password is incorrect!';
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Profile Settings</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
</head>
<body class="bg-gray-50">
    <div class="min-h-screen py-12 sm:px-6 lg:px-8">
        <div class="max-w-7xl mx-auto">
            <!-- Profile Header -->
            <div class="md:flex md:items-center md:justify-between mb-8 px-4 sm:px-0">
                <div class="flex-1 min-w-0">
                    <h2 class="text-2xl font-bold leading-7 text-gray-900 sm:text-3xl sm:truncate">Profile Settings</h2>
                    <p class="mt-1 text-sm text-gray-500">Manage your account settings and preferences</p>
                </div>
            </div>

            <div class="bg-white shadow overflow-hidden sm:rounded-lg">
                <!-- Profile Information Section -->
                <div class="border-b border-gray-200 px-4 py-5 sm:px-6">
                    <div class="flex items-center space-x-5">
                        <div class="relative">
                            <div class="w-20 h-20 rounded-full overflow-hidden bg-gray-100 border-4 border-white ring-2 ring-gray-200">
                                <?php if (!empty($user['profile_picture']) && file_exists('uploads/profile/' . $user['profile_picture'])): ?>
                                    <img src="uploads/profile/<?php echo htmlspecialchars($user['profile_picture']); ?>" 
                                         alt="Profile Picture"
                                         class="w-full h-full object-cover">
                                <?php else: ?>
                                    <div class="w-full h-full flex items-center justify-center bg-gray-50">
                                        <i class="fas fa-user text-2xl text-gray-400"></i>
                                    </div>
                                <?php endif; ?>
                            </div>
                            <label for="profile_picture" 
                                   class="absolute bottom-0 right-0 bg-white rounded-full p-1.5 shadow-lg cursor-pointer hover:bg-gray-50">
                                <i class="fas fa-camera text-gray-600 text-sm"></i>
                            </label>
                        </div>
                        <div>
                            <h3 class="text-xl font-semibold text-gray-900"><?php echo htmlspecialchars($user['name']); ?></h3>
                            <p class="text-sm text-gray-500"><?php echo htmlspecialchars($user['email']); ?></p>
                        </div>
                    </div>
                </div>

                <!-- Hidden File Upload Form -->
                <form method="POST" enctype="multipart/form-data" class="hidden">
                    <input type="file" 
                           id="profile_picture" 
                           name="profile_picture" 
                           accept="image/jpeg,image/png"
                           onchange="this.form.submit()">
                </form>

                <?php if ($imageMessage): ?>
                    <div class="px-4 py-3 sm:px-6">
                        <div class="rounded-md p-4 <?php echo strpos($imageMessage, 'successfully') !== false ? 'bg-green-50 text-green-700' : 'bg-red-50 text-red-700'; ?>">
                            <?php echo htmlspecialchars($imageMessage); ?>
                        </div>
                    </div>
                <?php endif; ?>

                <!-- User Details Grid -->
                <div class="px-4 py-5 sm:p-6">
                    <dl class="grid grid-cols-1 gap-x-4 gap-y-6 sm:grid-cols-2">
                        <div class="sm:col-span-1">
                            <dt class="text-sm font-medium text-gray-500">Phone Number</dt>
                            <dd class="mt-1 text-sm text-gray-900"><?php echo htmlspecialchars($user['phone_number']); ?></dd>
                        </div>
                        <div class="sm:col-span-1">
                            <dt class="text-sm font-medium text-gray-500">Role</dt>
                            <dd class="mt-1">
                                <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-blue-100 text-blue-800">
                                    <?php echo htmlspecialchars($user['role']); ?>
                                </span>
                            </dd>
                        </div>
                    </dl>
                </div>

                <!-- Password Change Section -->
                <div class="border-t border-gray-200 px-4 py-5 sm:p-6">
                    <div class="md:grid md:grid-cols-3 md:gap-6">
                        <div class="md:col-span-1">
                            <h3 class="text-lg font-medium leading-6 text-gray-900">Change Password</h3>
                            <p class="mt-1 text-sm text-gray-500">Ensure your account is using a long, random password to stay secure.</p>
                        </div>
                        <div class="mt-5 md:mt-0 md:col-span-2">
                            <?php if ($message): ?>
                                <div class="mb-4">
                                    <div class="rounded-md p-4 <?php echo strpos($message, 'successfully') !== false ? 'bg-green-50 text-green-700' : 'bg-red-50 text-red-700'; ?>">
                                        <?php echo htmlspecialchars($message); ?>
                                    </div>
                                </div>
                            <?php endif; ?>

                            <form method="POST">
                                <div class="grid grid-cols-6 gap-6">
                                    <div class="col-span-6 sm:col-span-4">
                                        <label for="current_password" class="block text-sm font-medium text-gray-700">Current Password</label>
                                        <input type="password" 
                                               name="current_password" 
                                               id="current_password" 
                                               required 
                                               class="mt-1 block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm">
                                    </div>

                                    <div class="col-span-6 sm:col-span-4">
                                        <label for="new_password" class="block text-sm font-medium text-gray-700">New Password</label>
                                        <input type="password" 
                                               name="new_password" 
                                               id="new_password" 
                                               required 
                                               class="mt-1 block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm">
                                    </div>

                                    <div class="col-span-6 sm:col-span-4">
                                        <label for="confirm_password" class="block text-sm font-medium text-gray-700">Confirm New Password</label>
                                        <input type="password" 
                                               name="confirm_password" 
                                               id="confirm_password" 
                                               required 
                                               class="mt-1 block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm">
                                    </div>
                                </div>

                                <div class="mt-6">
                                    <button type="submit" 
                                            class="inline-flex justify-center py-2 px-4 border border-transparent shadow-sm text-sm font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500">
                                        Update Password
                                    </button>
                                </div>
                            </form>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        // Auto-submit form when file is selected
        document.getElementById('profile_picture').addEventListener('change', function() {
            this.form.submit();
        });
    </script>
</body>
</html>

<?php include 'includes/new_footer.php'; ?>