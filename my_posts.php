<?php
session_start();
include 'db.php';
include 'includes/header2.php';

if (!isset($_SESSION['user_id'])) {
    header('Location: login.php');
    exit();
}

$user_id = mysqli_real_escape_string($conn, $_SESSION['user_id']);

// Get user's questions with stats
$questions_query = "
    SELECT 
        q.*, 
        COUNT(DISTINCT r.id) as reply_count,
        COUNT(DISTINCT CASE WHEN rc.reaction_type = 'upvote' THEN rc.id END) as upvotes,
        COUNT(DISTINCT CASE WHEN rc.reaction_type = 'downvote' THEN rc.id END) as downvotes
    FROM questions q
    LEFT JOIN replies r ON q.id = r.question_id
    LEFT JOIN reactions rc ON q.id = rc.question_id
    WHERE q.user_id = '$user_id'
    GROUP BY q.id
    ORDER BY q.created_at DESC
";
$questions_result = mysqli_query($conn, $questions_query);

// Get user's replies with question info
$replies_query = "
    SELECT 
        r.*,
        q.title as question_title,
        q.id as question_id,
        COUNT(DISTINCT CASE WHEN rc.reaction_type = 'upvote' THEN rc.id END) as upvotes,
        COUNT(DISTINCT CASE WHEN rc.reaction_type = 'downvote' THEN rc.id END) as downvotes
    FROM replies r
    JOIN questions q ON r.question_id = q.id
    LEFT JOIN reactions rc ON r.id = rc.reply_id
    WHERE r.user_id = '$user_id'
    GROUP BY r.id
    ORDER BY r.created_at DESC
";
$replies_result = mysqli_query($conn, $replies_query);
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>My Posts - Forum</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
</head>

<body class="bg-gray-100">
    <div class="container mx-auto px-4 py-8">
        <!-- Page Header -->
        <div class="bg-white rounded-lg shadow-md p-6 mb-8">
            <h1 class="text-2xl font-bold text-gray-800">My Posts</h1>
            <div class="mt-4">
                <button onclick="switchTab('questions')" id="questionsTab"
                    class="px-4 py-2 mr-2 rounded-lg bg-blue-500 text-white">
                    My Questions
                </button>
                <button onclick="switchTab('replies')" id="repliesTab" class="px-4 py-2 rounded-lg text-gray-600">
                    My Replies
                </button>
            </div>
        </div>

        <!-- Questions Section -->
        <div id="questionsSection" class="space-y-4">
            <h2 class="text-xl font-bold text-gray-800 mb-4">Questions You've Asked</h2>
            <?php if (mysqli_num_rows($questions_result) > 0): ?>
                <?php while ($question = mysqli_fetch_assoc($questions_result)): ?>
                    <div class="bg-white rounded-lg shadow-md p-6 hover:shadow-lg transition duration-200">
                        <div class="flex justify-between">
                            <div class="flex-1">
                                <a href="question.php?id=<?php echo $question['id']; ?>"
                                    class="text-xl font-semibold text-blue-600 hover:text-blue-800">
                                    <?php echo htmlspecialchars($question['title']); ?>
                                </a>
                                <p class="text-gray-600 mt-2">
                                    <?php echo substr(htmlspecialchars($question['content']), 0, 200) . '...'; ?>
                                </p>
                                <div class="flex items-center mt-4 space-x-4">
                                    <span class="text-sm text-gray-500">
                                        <i class="fas fa-clock"></i>
                                        <?php echo date('M d, Y', strtotime($question['created_at'])); ?>
                                    </span>
                                    <span class="text-sm text-gray-500">
                                        <i class="fas fa-comment"></i>
                                        <?php echo $question['reply_count']; ?> replies
                                    </span>
                                    <span class="text-sm text-gray-500">
                                        <i class="fas fa-arrow-up"></i>
                                        <?php echo $question['upvotes'] - $question['downvotes']; ?> votes
                                    </span>
                                    <button onclick="deleteQuestion(<?php echo $question['id']; ?>)"
                                        class="text-red-500 hover:text-red-700">
                                        <i class="fas fa-trash"></i> Delete
                                    </button>
                                </div>
                            </div>
                        </div>
                    </div>
                <?php endwhile; ?>
            <?php else: ?>
                <div class="bg-white rounded-lg shadow-md p-6">
                    <p class="text-gray-600">You haven't asked any questions yet.</p>
                </div>
            <?php endif; ?>
        </div>

        <!-- Replies Section -->
        <div id="repliesSection" class="space-y-4 hidden">
            <h2 class="text-xl font-bold text-gray-800 mb-4">Your Replies</h2>
            <?php if (mysqli_num_rows($replies_result) > 0): ?>
                <?php while ($reply = mysqli_fetch_assoc($replies_result)): ?>
                    <div class="bg-white rounded-lg shadow-md p-6">
                        <div class="flex justify-between">
                            <div class="flex-1">
                                <a href="question.php?id=<?php echo $reply['question_id']; ?>"
                                    class="text-lg font-semibold text-blue-600 hover:text-blue-800">
                                    Re: <?php echo htmlspecialchars($reply['question_title']); ?>
                                </a>
                                <p class="text-gray-600 mt-2">
                                    <?php echo htmlspecialchars($reply['content']); ?>
                                </p>
                                <div class="flex items-center mt-4 space-x-4">
                                    <span class="text-sm text-gray-500">
                                        <i class="fas fa-clock"></i>
                                        <?php echo date('M d, Y', strtotime($reply['created_at'])); ?>
                                    </span>
                                    <span class="text-sm text-gray-500">
                                        <i class="fas fa-arrow-up"></i>
                                        <?php echo $reply['upvotes'] - $reply['downvotes']; ?> votes
                                    </span>
                                </div>
                            </div>
                        </div>
                    </div>
                <?php endwhile; ?>
            <?php else: ?>
                <div class="bg-white rounded-lg shadow-md p-6">
                    <p class="text-gray-600">You haven't replied to any questions yet.</p>
                </div>
            <?php endif; ?>
        </div>
    </div>

    <script>
        function switchTab(tab) {
            const questionsSection = document.getElementById('questionsSection');
            const repliesSection = document.getElementById('repliesSection');
            const questionsTab = document.getElementById('questionsTab');
            const repliesTab = document.getElementById('repliesTab');

            if (tab === 'questions') {
                questionsSection.classList.remove('hidden');
                repliesSection.classList.add('hidden');
                questionsTab.classList.add('bg-blue-500', 'text-white');
                questionsTab.classList.remove('text-gray-600');
                repliesTab.classList.remove('bg-blue-500', 'text-white');
                repliesTab.classList.add('text-gray-600');
            } else {
                questionsSection.classList.add('hidden');
                repliesSection.classList.remove('hidden');
                repliesTab.classList.add('bg-blue-500', 'text-white');
                repliesTab.classList.remove('text-gray-600');
                questionsTab.classList.remove('bg-blue-500', 'text-white');
                questionsTab.classList.add('text-gray-600');
            }
        }

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
                            location.reload();
                        } else {
                            alert('Error deleting question. Please try again.');
                        }
                    });
            }
        }
    </script>
</body>

</html>