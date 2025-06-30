<?php
session_start();

if (!isset($_SESSION['user_id']) || $_SESSION['role'] !== 'admin') {
    header("Location: /CholoSave-CS/error_page.php");
    exit;
}

if (!isset($conn)) {
    include 'db.php';
}

// Handle mark as done action
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['mark_done'])) {
    $message_id = $_POST['message_id'];
    
    $updateQuery = "UPDATE contact_us SET status = 'done' WHERE id = ?";
    if ($stmt = $conn->prepare($updateQuery)) {
        $stmt->bind_param('i', $message_id);
        if ($stmt->execute()) {
            echo json_encode(['success' => true]);
        } else {
            echo json_encode(['success' => false, 'message' => 'Failed to update status']);
        }
        exit;
    }
}

// Handle filtering
$status_filter = isset($_GET['status']) ? $_GET['status'] : 'all';
$where_clause = $status_filter !== 'all' ? "WHERE status = '$status_filter'" : "";

// Fetch filtered contact messages
$query = "SELECT * FROM contact_us $where_clause ORDER BY created_at DESC";
$result = $conn->query($query);
$messages = [];
if ($result) {
    while ($row = $result->fetch_assoc()) {
        $messages[] = $row;
    }
}
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Contact Messages</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
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

        .message-cell {
            max-width: 300px;
            position: relative;
        }

        .message-content {
            position: relative;
            cursor: pointer;
        }

        .message-tooltip {
            display: none;
            position: absolute;
            background: white;
            border: 1px solid #e2e8f0;
            border-radius: 0.5rem;
            padding: 1rem;
            z-index: 50;
            width: 400px;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
            left: 0;
            top: 100%;
        }

        .message-content:hover .message-tooltip {
            display: block;
        }
    </style>
</head>

<body class="bg-gradient-to-br from-white-50 to-blue-100 min-h-screen">
    <div class="flex h-screen">
        <?php include 'sidebar.php'; ?>

        <div class="flex-1 flex flex-col overflow-hidden">
            <header class="glass-effect shadow-sm border-b border-gray-200">
                <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
                    <div class="flex items-center justify-between">
                        <h1 class="text-2xl font-semibold text-gray-800">
                            <i class="fa-solid fa-envelope text-blue-600 mr-3"></i>
                            Contact Messages
                        </h1>
                        <div class="flex gap-2">
                            <a href="?status=all" class="px-4 py-2 rounded-md <?php echo $status_filter === 'all' ? 'bg-blue-600 text-white' : 'bg-gray-100 text-gray-700'; ?> hover:bg-blue-700 hover:text-white transition-colors">
                                All
                            </a>
                            <a href="?status=pending" class="px-4 py-2 rounded-md <?php echo $status_filter === 'pending' ? 'bg-blue-600 text-white' : 'bg-gray-100 text-gray-700'; ?> hover:bg-blue-700 hover:text-white transition-colors">
                                Pending
                            </a>
                            <a href="?status=done" class="px-4 py-2 rounded-md <?php echo $status_filter === 'done' ? 'bg-blue-600 text-white' : 'bg-gray-100 text-gray-700'; ?> hover:bg-blue-700 hover:text-white transition-colors">
                                Done
                            </a>
                        </div>
                    </div>
                </div>
            </header>

            <div class="flex-1 overflow-y-auto p-6">
                <div class="max-w-7xl mx-auto">
                    <div class="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
                        <div class="p-6">
                            <div class="overflow-x-auto">
                                <table class="min-w-full divide-y divide-gray-200">
                                    <thead>
                                        <tr class="bg-gray-50">
                                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                                Serial
                                            </th>
                                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                                Name
                                            </th>
                                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                                Email
                                            </th>
                                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                                Message
                                            </th>
                                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                                Date
                                            </th>
                                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                                Status
                                            </th>
                                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                                Action
                                            </th>
                                        </tr>
                                    </thead>
                                    <tbody class="bg-white divide-y divide-gray-200">
                                        <?php
                                        $serial = 1;
                                        foreach ($messages as $message):
                                            $date = new DateTime($message['created_at']);
                                        ?>
                                            <tr class="hover:bg-gray-50 transition-colors duration-200">
                                                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                                                    <?php echo $serial++; ?>
                                                </td>
                                                <td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">
                                                    <?php echo htmlspecialchars($message['name']); ?>
                                                </td>
                                                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                                                    <?php echo htmlspecialchars($message['email']); ?>
                                                </td>
                                                <td class="px-6 py-4 text-sm text-gray-500 message-cell">
                                                    <div class="message-content">
                                                        <div class="truncate">
                                                            <?php echo htmlspecialchars($message['description']); ?>
                                                        </div>
                                                        <div class="message-tooltip">
                                                            <?php echo nl2br(htmlspecialchars($message['description'])); ?>
                                                        </div>
                                                    </div>
                                                </td>
                                                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                                                    <?php echo $date->format('d F, Y'); ?>
                                                </td>
                                                <td class="px-6 py-4 whitespace-nowrap">
                                                    <span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full 
                                                        <?php echo $message['status'] === 'done' 
                                                            ? 'bg-green-100 text-green-800' 
                                                            : 'bg-yellow-100 text-yellow-800'; ?>">
                                                        <?php echo ucfirst($message['status']); ?>
                                                    </span>
                                                </td>
                                                <td class="px-6 py-4 whitespace-nowrap text-sm font-medium">
                                                    <?php if ($message['status'] !== 'done'): ?>
                                                        <button onclick="confirmMarkAsDone(<?php echo $message['id']; ?>)"
                                                            class="inline-flex items-center px-3 py-2 border border-transparent text-sm leading-4 font-medium rounded-md text-white bg-green-600 hover:bg-green-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-green-500 transition-colors duration-200">
                                                            <i class="fas fa-check mr-2"></i> Mark as Done
                                                        </button>
                                                    <?php endif; ?>
                                                </td>
                                            </tr>
                                        <?php endforeach; ?>
                                        <?php if (empty($messages)): ?>
                                            <tr>
                                                <td colspan="7" class="px-6 py-10 text-center text-gray-500">
                                                    <i class="fas fa-inbox text-4xl mb-4"></i>
                                                    <p>No messages found</p>
                                                </td>
                                            </tr>
                                        <?php endif; ?>
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        function confirmMarkAsDone(messageId) {
            Swal.fire({
                title: 'Mark as Done?',
                text: "Are you sure you want to mark this message as done?",
                icon: 'question',
                showCancelButton: true,
                confirmButtonColor: '#3085d6',
                cancelButtonColor: '#d33',
                confirmButtonText: 'Yes, mark as done!'
            }).then((result) => {
                if (result.isConfirmed) {
                    const formData = new FormData();
                    formData.append('mark_done', true);
                    formData.append('message_id', messageId);

                    fetch(window.location.href, {
                        method: 'POST',
                        body: formData
                    })
                    .then(response => response.json())
                    .then(data => {
                        if (data.success) {
                            Swal.fire(
                                'Marked as Done!',
                                'The message has been marked as done.',
                                'success'
                            ).then(() => {
                                window.location.reload();
                            });
                        } else {
                            Swal.fire(
                                'Error!',
                                'Something went wrong.',
                                'error'
                            );
                        }
                    });
                }
            });
        }
    </script>
</body>
</html>

<?php include 'new_footer.php'; ?>