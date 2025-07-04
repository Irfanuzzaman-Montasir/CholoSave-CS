<?php
session_start();
include 'db.php';
include 'includes/header2.php';

if (!isset($_SESSION['user_id']) || !isset($_GET['id'])) {
    header('Location: forum.php');
    exit();
}

$question_id = $_GET['id'];

// Update view count
$stmt = $conn->prepare("UPDATE questions SET views = views + 1 WHERE id = ?");
$stmt->bind_param('i', $question_id);
$stmt->execute();
$stmt->close();

// Fetch question with user info
$stmt = $conn->prepare("
    SELECT 
        q.*,
        u.name as author_name
    FROM questions q
    LEFT JOIN users u ON q.user_id = u.id
    WHERE q.id = ?
");
$stmt->bind_param('i', $question_id);
$stmt->execute();
$question_result = $stmt->get_result();
$question = $question_result->fetch_assoc();
$stmt->close();

// Fetch replies with user info
$stmt = $conn->prepare("
    SELECT 
        r.*,
        u.name as author_name
    FROM replies r
    LEFT JOIN users u ON r.user_id = u.id
    WHERE r.question_id = ?
    ORDER BY r.created_at ASC
");
$stmt->bind_param('i', $question_id);
$stmt->execute();
$replies_result = $stmt->get_result();
$replies = [];
while ($reply = $replies_result->fetch_assoc()) {
    $replies[] = $reply;
}
$stmt->close();

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
$csrf_token = $_SESSION['csrf_token'];
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo htmlspecialchars($question['title'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); ?> - Forum</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
</head>

<body class="bg-gray-100">

    <div class="container mx-auto px-4 py-8">

    <!-- Bcak btn -->
        <a href="forum.php" class="text-blue-500 hover:text-blue-700 mr-4">
            <i class="fas fa-arrow-left text-2xl"></i>
        </a>
        <!-- Question Section -->
        <div class="bg-white rounded-lg shadow-md p-6 mb-8">
            <div class="flex items-center mb-4">

                <div class="flex justify-between items-start w-full">
                    <div class="flex-1">
                        <h1 class="text-3xl font-bold text-gray-800 mb-4">
                            <?php echo htmlspecialchars($question['title'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); ?>
                        </h1>
                        <div class="prose max-w-none">
                            <?php echo nl2br(htmlspecialchars($question['content'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')); ?>
                        </div>
                        <div class="flex items-center mt-6 space-x-4">
                            <span class="text-sm text-gray-500">
                                <i class="fas fa-user"></i> <?php echo htmlspecialchars($question['author_name'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); ?>
                            </span>

                            <span class="text-sm text-gray-500">
                                <i class="fas fa-clock"></i>
                                <?php echo date('M d, Y', strtotime($question['created_at'])); ?>
                            </span>
                            <span class="text-sm text-gray-500">
                                <i class="fas fa-eye"></i> <?php echo $question['views']; ?> views
                            </span>

                            <?php if ($_SESSION['user_id'] == $question['user_id']): ?>
                                <button onclick="deleteQuestion(<?php echo $question['id']; ?>)"
                                    class="ml-4 text-red-500 hover:text-red-700">
                                    <i class="fas fa-trash"></i> Delete Question
                                </button>
                            <?php endif; ?>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Replies Section -->
        <div class="space-y-6">
            <h2 class="text-2xl font-bold text-gray-800"><?php echo count($replies); ?> Replies</h2>

            <?php foreach ($replies as $reply): ?>
                <div class="bg-white rounded-lg shadow-md p-6">
                    <div class="flex justify-between">
                        <div class="flex-1">
                            <div class="prose max-w-none">
                                <?php echo nl2br(htmlspecialchars($reply['content'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')); ?>
                            </div>
                            <div class="flex items-center mt-4 space-x-4">
                                <span class="text-sm text-gray-500">
                                    <i class="fas fa-user"></i> <?php echo htmlspecialchars($reply['author_name'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); ?>
                                </span>
                                <span class="text-sm text-gray-500">
                                    <i class="fas fa-clock"></i>
                                    <?php echo date('M d, Y', strtotime($reply['created_at'])); ?>
                                </span>
                            </div>
                        </div>
                    </div>
                </div>
            <?php endforeach; ?>

            <!-- Reply Form -->
            <div class="bg-white rounded-lg shadow-md p-6">
                <h3 class="text-xl font-bold text-gray-800 mb-4">Add Your Reply</h3>
                <form action="submit_reply.php" method="POST">
                    <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                    <input type="hidden" name="question_id" value="<?php echo $question_id; ?>">
                    <div class="mb-4">
                        <textarea name="content" rows="4" required
                            class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:border-blue-500"
                            placeholder="Write your reply here..."></textarea>
                    </div>
                    <div class="flex justify-end">
                        <button type="submit"
                            class="bg-blue-500 hover:bg-blue-600 text-white font-semibold px-6 py-2 rounded-lg transition duration-200">
                            Post Reply
                        </button>
                    </div>
                </form>
            </div>
        </div>
    </div>

    <script>
        function deleteQuestion(questionId) {
            if (confirm('Are you sure you want to delete this question? This cannot be undone.')) {
                fetch('delete_question.php', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                    },
                    body: `question_id=${questionId}`
                })
                    .then(response => response.json())
                    .then(data => {
                        if (data.success) {
                            window.location.href = 'forum.php';
                        } else {
                            alert('Error deleting question. Please try again.');
                        }
                    });
            }
        }
    </script>
</body>

</html>

<?php include 'includes/new_footer.php'; ?>