<?php
session_start();

if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit();
}

require 'db.php';
$user_id = $_SESSION['user_id'];
$group_id = $_SESSION['group_id'];

// Check if user is in this group and get admin status
$sql = "SELECT is_admin FROM group_membership WHERE user_id = ? AND group_id = ?";
$stmt = $conn->prepare($sql);
$stmt->bind_param("ii", $user_id, $group_id);
$stmt->execute();
$result = $stmt->get_result();

if ($result->num_rows !== 1) {
    // User is not in this group
    header("Location: user_landing_page.php");
    exit();
}

$membership = $result->fetch_assoc();
$is_admin = $membership['is_admin'];
$stmt->close();

// Check if the username is already set in the session
if (!isset($_SESSION['username'])) {
    $sql = "SELECT name FROM users WHERE id = ?";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("i", $user_id);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows === 1) {
        $user = $result->fetch_assoc();
        $_SESSION['username'] = $user['name'];
    } else {
        session_destroy();
        header("Location: login.php");
        exit();
    }
    $stmt->close();
}

// Fetch group messages with admin status
$sql = "SELECT m.*, u.name, gm.is_admin 
        FROM messages m
        JOIN users u ON m.user_id = u.id 
        JOIN group_membership gm ON m.user_id = gm.user_id AND m.group_id = gm.group_id
        WHERE m.group_id = ? 
        ORDER BY m.created_at ASC";
$stmt = $conn->prepare($sql);
$stmt->bind_param("i", $group_id);
$stmt->execute();
$result = $stmt->get_result();
$messages = $result->fetch_all(MYSQLI_ASSOC);
$stmt->close();

// Function to determine which sidebar to include
function include_sidebar($is_admin) {
    if ($is_admin) {
        return 'group_admin/group_admin_sidebar.php';
    }
    return 'group_member/sidebar.php';
}

// Function to determine return path
function get_return_path($is_admin) {
    if ($is_admin) {
        return 'group_admin/group_admin_dashboard.php';
    }
    return 'group_member/group_member_dashboard.php';
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Chat</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        /* Custom scrollbar */
        .messages::-webkit-scrollbar {
            width: 6px;
        }
        
        .messages::-webkit-scrollbar-track {
            background: #f1f1f1;
            border-radius: 10px;
        }
        
        .messages::-webkit-scrollbar-thumb {
            background: #cbd5e1;
            border-radius: 10px;
        }
        
        .messages::-webkit-scrollbar-thumb:hover {
            background: #94a3b8;
        }

        /* Message animations */
        .message {
            animation: fadeIn 0.3s ease-in-out;
        }

        @keyframes fadeIn {
            from {
                opacity: 0;
                transform: translateY(10px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        /* Message input styles */
        .message-input {
            min-height: 48px;
            max-height: 120px;
        }

        /* Custom shadow for messages */
        .message-bubble {
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
        }
    </style>
</head>
<body class="bg-slate-50 h-screen antialiased">
    <div class="flex h-screen">
        <?php include include_sidebar($is_admin); ?>

        <div class="flex-1 flex flex-col">
            <!-- Header -->
            <header class="bg-white shadow-sm border-b border-slate-200">
                <div class="max-w-7xl mx-auto px-4 py-4 flex justify-between items-center">
                    <div class="flex items-center gap-4">
                        <a href="<?php echo get_return_path($is_admin); ?>" 
                           class="text-slate-600 hover:text-slate-800 transition-colors">
                            <i class="fas fa-arrow-left"></i>
                        </a>
                        <div class="flex items-center gap-3">
                            <div class="w-2 h-2 bg-green-500 rounded-full animate-pulse"></div>
                            <h1 class="text-xl font-semibold text-slate-800">
                                Group Chat <?php echo ($is_admin) ? '<span class="text-sm font-normal text-blue-600 bg-blue-50 px-2 py-1 rounded-full ml-2">Admin Mode</span>' : ''; ?>
                            </h1>
                        </div>
                    </div>
                </div>
            </header>
            
            <!-- Chat Container -->
            <div class="flex-1 max-w-7xl mx-auto w-full p-4 overflow-hidden">
                <div class="bg-white rounded-xl shadow-sm border border-slate-200 h-full flex flex-col">
                    <!-- Messages Area -->
                    <div class="flex-1 p-6 overflow-y-auto messages space-y-4">
                        <?php foreach ($messages as $message): ?>
                            <div class="message <?php echo $message['user_id'] === $user_id ? 'flex justify-end' : 'flex justify-start'; ?>">
                                <div class="max-w-[70%] group">
                                    <div class="flex items-center mb-1 <?php echo $message['user_id'] === $user_id ? 'justify-end' : 'justify-start'; ?>">
                                        <span class="text-sm text-slate-600 font-medium">
                                            <?php 
                                                echo htmlspecialchars($message['name']); 
                                                if ($message['is_admin']) {
                                                    echo ' <span class="bg-blue-50 text-blue-600 text-xs px-2 py-0.5 rounded-full">Admin</span>';
                                                }
                                            ?>
                                        </span>
                                        <span class="text-xs text-slate-400 ml-2">
                                            <?php echo date('h:i A', strtotime($message['created_at'])); ?>
                                        </span>
                                    </div>
                                    <div class="message-bubble <?php echo $message['user_id'] === $user_id 
                                        ? 'bg-blue-500 text-white rounded-2xl rounded-tr-sm' 
                                        : 'bg-slate-100 text-slate-800 rounded-2xl rounded-tl-sm'; ?> 
                                        p-4 transition-all">
                                        <?php echo htmlspecialchars($message['message']); ?>
                                    </div>
                                </div>
                            </div>
                        <?php endforeach; ?>
                    </div>

                    <!-- Message Input Area -->
                    <div class="border-t border-slate-200 p-4 bg-slate-50">
                        <form class="message-form flex gap-3">
                            <div class="flex-1 relative">
                                <textarea 
                                    name="message" 
                                    class="message-input w-full px-4 py-3 border border-slate-200 rounded-xl focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent resize-none bg-white"
                                    placeholder="Type your message..."
                                ></textarea>
                            </div>
                            <button 
                                type="submit" 
                                class="px-6 py-3 bg-blue-500 text-white rounded-xl hover:bg-blue-600 transition-colors duration-200 flex items-center gap-2 font-medium shadow-sm hover:shadow focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2"
                            >
                                <i class="fas fa-paper-plane"></i>
                                <span>Send</span>
                            </button>
                        </form>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        const groupId = <?php echo json_encode($group_id); ?>;
        const userId = <?php echo json_encode($user_id); ?>;
        const username = <?php echo json_encode($_SESSION['username']); ?>;
        const isAdmin = <?php echo json_encode((bool)$is_admin); ?>;

        // Auto-resize textarea
        const textarea = document.querySelector('textarea[name="message"]');
        textarea.addEventListener('input', function() {
            this.style.height = 'auto';
            this.style.height = Math.min(this.scrollHeight, 120) + 'px';
        });

        const socket = new WebSocket('ws://localhost:8080/chat');

        socket.onopen = function () {
            console.log('WebSocket connection established.');
        };

        socket.onmessage = function (event) {
            const data = JSON.parse(event.data);

            if (data.group_id === groupId) {
                const messagesDiv = document.querySelector('.messages');
                const messageElem = document.createElement('div');
                const time = new Date().toLocaleTimeString([], { hour: 'numeric', minute: '2-digit', hour12: true });
                
                const adminBadge = data.is_admin 
                    ? '<span class="bg-blue-50 text-blue-600 text-xs px-2 py-0.5 rounded-full">Admin</span>' 
                    : '';
                
                messageElem.className = `message ${data.user_id === userId ? 'flex justify-end' : 'flex justify-start'}`;
                messageElem.innerHTML = `
                    <div class="max-w-[70%] group">
                        <div class="flex items-center mb-1 ${data.user_id === userId ? 'justify-end' : 'justify-start'}">
                            <span class="text-sm text-slate-600 font-medium">
                                ${data.username} ${adminBadge}
                            </span>
                            <span class="text-xs text-slate-400 ml-2">${time}</span>
                        </div>
                        <div class="message-bubble ${data.user_id === userId 
                            ? 'bg-blue-500 text-white rounded-2xl rounded-tr-sm' 
                            : 'bg-slate-100 text-slate-800 rounded-2xl rounded-tl-sm'} 
                            p-4">
                            ${data.message}
                        </div>
                    </div>`;
                messagesDiv.appendChild(messageElem);
                messagesDiv.scrollTop = messagesDiv.scrollHeight;
            }
        };

        function sendMessage() {
            const messageInput = document.querySelector('textarea[name="message"]');
            const message = messageInput.value.trim();

            if (message !== '') {
                const msgData = {
                    group_id: groupId,
                    user_id: userId,
                    username: username,
                    message: message,
                    is_admin: isAdmin
                };

                socket.send(JSON.stringify(msgData));
                messageInput.value = '';
                messageInput.style.height = 'auto';
            }
        }

        document.querySelector('.message-form').addEventListener('submit', function (e) {
            e.preventDefault();
            sendMessage();
        });

        // Auto-scroll to bottom on page load
        document.addEventListener('DOMContentLoaded', function() {
            const messagesDiv = document.querySelector('.messages');
            messagesDiv.scrollTop = messagesDiv.scrollHeight;
        });
    </script>
</body>
</html>