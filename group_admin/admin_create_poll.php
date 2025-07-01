<?php
// --- Secure Session Management ---
ini_set('session.cookie_httponly', 1);
ini_set('session.cookie_secure', 1);
ini_set('session.cookie_samesite', 'Strict');
session_start();

// --- HTTPS Enforcement ---
if (empty($_SERVER['HTTPS']) || $_SERVER['HTTPS'] === 'off') {
    if ($_SERVER['HTTP_HOST'] !== 'localhost' && $_SERVER['HTTP_HOST'] !== '127.0.0.1') {
        header('Location: https://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI']);
        exit();
    }
}

// --- Session Timeout (optional, 30 min) ---
$timeout = 1800;
if (isset($_SESSION['LAST_ACTIVITY']) && (time() - $_SESSION['LAST_ACTIVITY'] > $timeout)) {
    session_unset();
    session_destroy();
    header('Location: /CholoSave-CS/login.php');
    exit();
}
$_SESSION['LAST_ACTIVITY'] = time();

// --- CSRF Token Generation ---
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
$csrf_token = $_SESSION['csrf_token'];

// --- DB Connection ---
if (!isset($conn)) {
    include 'db.php';
}

// --- Authorization: Check Admin ---
if (!isset($_SESSION['group_id']) || !isset($_SESSION['user_id'])) {
    header('Location: /CholoSave-CS/error_page.php');
    exit;
}
$group_id = $_SESSION['group_id'];
$user_id = $_SESSION['user_id'];
$is_admin = false;
$checkAdminQuery = "SELECT group_admin_id FROM my_group WHERE group_id = ?";
if ($stmt = $conn->prepare($checkAdminQuery)) {
    $stmt->bind_param('i', $group_id);
    $stmt->execute();
    $stmt->bind_result($group_admin_id);
    $stmt->fetch();
    $stmt->close();
    if ($group_admin_id === $user_id) {
        $is_admin = true;
    }
}
if (!$is_admin) {
    // Log unauthorized access attempt
    error_log("[ADMIN LOG] Unauthorized access attempt by user $user_id to group $group_id at " . date('c'));
    header('Location: /CholoSave-CS/error_page.php');
    exit;
}

$errors = [];
$rate_limit = 5; // 5 submissions per hour
$rate_limit_time = 3600;
$ip_address = $_SERVER['REMOTE_ADDR'];

// --- Rate Limiting ---
if (!isset($_SESSION['poll_rate_limit'])) {
    $_SESSION['poll_rate_limit'] = [
        'count' => 0,
        'start_time' => time(),
        'ip' => $ip_address
    ];
}
if (time() - $_SESSION['poll_rate_limit']['start_time'] > $rate_limit_time) {
    $_SESSION['poll_rate_limit'] = [
        'count' => 0,
        'start_time' => time(),
        'ip' => $ip_address
    ];
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // --- CSRF Token Check ---
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        error_log("[ADMIN LOG] CSRF token mismatch for user $user_id at " . date('c'));
        die('Invalid form submission.');
    }
    // --- Rate Limiting Check ---
    if ($_SESSION['poll_rate_limit']['count'] >= $rate_limit) {
        error_log("[ADMIN LOG] Rate limit exceeded for user $user_id at " . date('c'));
        $errors['rate_limit'] = 'Too many submissions. Please try again later.';
    } else {
        $_SESSION['poll_rate_limit']['count']++;
    }
    // --- Authorization Check Again ---
    $is_admin = false;
    $stmt = $conn->prepare($checkAdminQuery);
    $stmt->bind_param('i', $group_id);
    $stmt->execute();
    $stmt->bind_result($group_admin_id);
    $stmt->fetch();
    $stmt->close();
    if ($group_admin_id === $user_id) {
        $is_admin = true;
    }
    if (!$is_admin) {
        error_log("[ADMIN LOG] Unauthorized POST attempt by user $user_id to group $group_id at " . date('c'));
        die('Unauthorized.');
    }
    // --- Input Validation & Sanitization ---
    $poll_question = htmlspecialchars(trim($_POST['poll_question']), ENT_QUOTES, 'UTF-8');
    if (strlen($poll_question) > 500) {
        $errors['poll_question'] = 'Poll question is too long (max 500 chars).';
    }
    if (empty($poll_question)) {
        $errors['poll_question'] = 'Please provide a poll question.';
    }
    // --- User/Admin Activity Logging ---
    error_log("[ADMIN LOG] User $user_id submitted poll for group $group_id at " . date('c'));
    // If no errors, proceed with database insertion
    if (empty($errors)) {
        $status = 'active';
        $created_at = date('Y-m-d H:i:s');
        $createPollQuery = "INSERT INTO polls (group_id, poll_question, status, created_at) VALUES (?, ?, ?, ?)";
        if ($stmt = $conn->prepare($createPollQuery)) {
            $stmt->bind_param('isss', $group_id, $poll_question, $status, $created_at);
            if ($stmt->execute()) {
                // Log successful insert
                error_log("[ADMIN LOG] Poll inserted by user $user_id for group $group_id at " . date('c'));
                echo "<script>
                        document.addEventListener('DOMContentLoaded', function() {
                            Swal.fire({
                                title: 'Success!',
                                text: 'Poll created successfully.',
                                icon: 'success',
                                confirmButtonText: 'OK'
                            }).then(() => {
                                window.location.href = '/CholoSave-CS/group_admin/admin_create_poll.php';
                            });
                        });
                      </script>";
            } else {
                $errors['submission'] = 'Error submitting poll.';
                error_log("[ADMIN LOG] DB error for user $user_id: " . $stmt->error);
            }
            $stmt->close();
        } else {
            $errors['query'] = 'Error preparing poll query.';
            error_log("[ADMIN LOG] Query preparation error for user $user_id at " . date('c'));
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Create Poll</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/sweetalert2@11.0.0/dist/sweetalert2.all.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>
    <style>
        body {
            font-family: 'Inter', sans-serif;
        }
        .glass-effect {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            -webkit-backdrop-filter: blur(10px);
        }
    </style>
</head>
<body class="bg-gradient-to-br from-white-50 to-blue-100 min-h-screen">
    <div class="flex h-screen">
        <?php include 'group_admin_sidebar.php'; ?>

        <div class="flex-1 flex flex-col overflow-hidden">
            <header class="glass-effect shadow-sm border-b border-gray-200">
                <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6 flex justify-center">
                    <div class="flex items-center justify-center">
                        <h1 class="text-2xl font-semibold text-gray-800 ml-4">
                            <i class="fa-solid fa-plus text-blue-600 mr-3"></i>
                            Create Poll
                        </h1>
                    </div>
                </div>
            </header>

            <div class="flex-1 overflow-y-auto p-6">
                <div class="max-w-3xl mx-auto">
                    <div class="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
                        <form method="POST" class="p-6 space-y-6">
                            <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                            <div>
                                <label for="poll_question" class="block text-sm font-medium text-gray-700">Poll Question</label>
                                <div class="mt-1">
                                    <textarea id="poll_question" name="poll_question" rows="4" required
                                        class="block w-full shadow-sm sm:text-sm border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"><?php echo isset($poll_question) ? htmlspecialchars($poll_question) : ''; ?></textarea>
                                </div>
                                <div id="pollQuestionError" class="text-red-500 text-sm mt-2">
                                    <?php echo isset($errors['poll_question']) ? $errors['poll_question'] : ''; ?>
                                    <?php echo isset($errors['rate_limit']) ? $errors['rate_limit'] : ''; ?>
                                </div>
                            </div>

                            <div class="flex justify-end">
                                <button type="submit" name="create_poll" value="create"
                                    class="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500">
                                    <i class="fas fa-check-circle mr-2"></i>Create Poll
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
        </div>
    </div>
</body>
</html>
<?php include 'new_footer.php'; ?>