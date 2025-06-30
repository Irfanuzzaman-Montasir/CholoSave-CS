<?php
session_start();

$group_id = $_SESSION['group_id'];
$user_id = $_SESSION['user_id'];

if (!isset($_SESSION['group_id']) || !isset($_SESSION['user_id'])) {
    header("Location: /CholoSave-CS/error_page.php");
    exit;
}

if (!isset($conn)) {
    include 'db.php';
}


// Check if the user is an admin for the group
$is_admin = false;
$checkAdminQuery = "SELECT group_admin_id FROM my_group WHERE group_id = ?";
if ($stmt = $conn->prepare($checkAdminQuery)) {
    $stmt->bind_param('i', $group_id);
    $stmt->execute();
    $stmt->bind_result($group_admin_id);
    $stmt->fetch();
    $stmt->close();
    
    // If the user is the admin of the group, proceed; otherwise, redirect to an error page
    if ($group_admin_id === $user_id) {
        $is_admin = true;
    }
}

if (!$is_admin) {
    // Redirect to error page if the user is not an admin
    header("Location: /CholoSave-CS/error_page.php");
    exit;
}


if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['create_poll'])) {
        $poll_question = $_POST['poll_question'];
        $status = 'active'; // Default status for a new poll
        $created_at = date('Y-m-d H:i:s');

        $createPollQuery = "INSERT INTO polls (group_id, poll_question, status, created_at) VALUES (?, ?, ?, ?)";
        
        if ($stmt = $conn->prepare($createPollQuery)) {
            $stmt->bind_param('isss', $group_id, $poll_question, $status, $created_at);
            if ($stmt->execute()) {
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
            }
            $stmt->close();
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
                            <div>
                                <label for="poll_question" class="block text-sm font-medium text-gray-700">Poll Question</label>
                                <div class="mt-1">
                                    <textarea id="poll_question" name="poll_question" rows="4" required
                                        class="block w-full shadow-sm sm:text-sm border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"></textarea>
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