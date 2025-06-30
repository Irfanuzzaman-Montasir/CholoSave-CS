<?php
session_start();
include 'db.php';
include 'includes/header2.php';

if (!isset($_SESSION['user_id'])) {
    header('Location: login.php');
    exit();
}

// Get user information
$user_id = $_SESSION['user_id'];
$user_query = "SELECT name FROM users WHERE id = '$user_id'";
$user_result = mysqli_query($conn, $user_query);
$user = mysqli_fetch_assoc($user_result);

// Fetch questions with user info and stats
$filter = isset($_GET['filter']) ? $_GET['filter'] : '';
$questions_query = "
    SELECT 
        q.*, 
        u.name as author_name,
        COUNT(DISTINCT r.id) as reply_count
    FROM questions q
    LEFT JOIN users u ON q.user_id = u.id
    LEFT JOIN replies r ON q.id = r.question_id
    " . ($filter === 'my_questions' ? "WHERE q.user_id = '$user_id'" : "") . "
    GROUP BY q.id
    ORDER BY q.created_at DESC
";
$questions_result = mysqli_query($conn, $questions_query);
$questions = [];
while ($row = mysqli_fetch_assoc($questions_result)) {
    $questions[] = $row;
}
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Forum - Discussion Board</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
</head>

<body class="bg-gray-100">
    <div class="container mx-auto px-4 py-8">
        <!-- Welcome Section -->
        <div class="bg-white rounded-lg shadow-md p-6 mb-8">
            <div class="flex justify-between items-center">
                <div>
                    <h1 class="text-2xl font-bold text-gray-800">Welcome,
                        <?php echo htmlspecialchars($user['name']); ?>!</h1>
                    <p class="text-gray-600">Join the discussion or start your own topic</p>
                </div>
                <div class="flex space-x-4">
                    <a href="#" onclick="showAskQuestionModal()"
                        class="bg-blue-500 hover:bg-blue-600 text-white font-semibold px-6 py-2 rounded-lg transition duration-200">
                        Ask Question
                    </a>
                    <a href="forum.php?filter=my_questions"
                        class="bg-green-500 hover:bg-green-600 text-white font-semibold px-6 py-2 rounded-lg transition duration-200">
                        My Questions
                    </a>
                </div>
            </div>
        </div>

        <!-- Filter Indicator -->
        <?php if (isset($_GET['filter']) && $_GET['filter'] === 'my_questions'): ?>
            <div class="mb-4">
                <div class="flex items-center justify-between bg-blue-50 p-4 rounded-lg">
                    <span class="text-blue-700">Showing your questions only</span>
                    <a href="forum.php" class="text-blue-600 hover:text-blue-800 font-medium">
                        Show all questions
                    </a>
                </div>
            </div>
        <?php endif; ?>

        <!-- Questions List -->
        <?php if (empty($questions)): ?>
            <div class="bg-white rounded-lg shadow-md p-6">
                <p class="text-gray-600">
                    <?php echo isset($_GET['filter']) ? "You haven't asked any questions yet." : "No questions found."; ?>
                </p>
            </div>
        <?php else: ?>
            <?php foreach ($questions as $question): ?>
                <div class="bg-white rounded-lg shadow-md p-6 hover:shadow-lg transition duration-200">
                    <div class="flex justify-between">
                        <div class="flex-1">
                            <a href="question.php?id=<?php echo $question['id']; ?>"
                                class="text-xl font-semibold text-blue-600 hover:text-blue-800">
                                <?php echo htmlspecialchars($question['title']); ?>
                            </a>
                            <p class="text-gray-600 mt-2">
                                <?php echo substr(htmlspecialchars($question['content']), 0, 200) . '...'; ?></p>
                            <div class="flex items-center mt-4 space-x-4">
                                <span class="text-sm text-gray-500">
                                    <i class="fas fa-user"></i> <?php echo htmlspecialchars($question['author_name']); ?>
                                </span>
                                <span class="text-sm text-gray-500">
                                    <i class="fas fa-clock"></i>
                                    <?php echo date('M d, Y', strtotime($question['created_at'])); ?>
                                </span>
                                <span class="text-sm text-gray-500">
                                    <i class="fas fa-comment"></i> <?php echo $question['reply_count']; ?> replies
                                </span>
                                <span class="text-sm text-gray-500">
                                    <i class="fas fa-eye"></i> <?php echo $question['views']; ?> views
                                </span>
                            </div>
                        </div>
                    </div>
                </div>
            <?php endforeach; ?>
        <?php endif; ?>
    </div>

    <!-- Ask Question Modal -->
    <div id="askQuestionModal" class="hidden fixed inset-0 bg-black bg-opacity-50 z-50">
        <div
            class="fixed top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 bg-white rounded-lg p-8 w-full max-w-2xl">
            <h2 class="text-2xl font-bold mb-4">Ask a Question</h2>
            <form id="questionForm" action="submit_question.php" method="POST">
                <div class="mb-4">
                    <label class="block text-gray-700 text-sm font-bold mb-2" for="title">
                        Title
                    </label>
                    <input type="text" id="title" name="title" required
                        class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:border-blue-500">
                </div>
                <div class="mb-4">
                    <label class="block text-gray-700 text-sm font-bold mb-2" for="content">
                        Content
                    </label>
                    <textarea id="content" name="content" rows="6" required
                        class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:border-blue-500"></textarea>
                </div>
                <div class="flex justify-end space-x-4">
                    <button type="button" onclick="hideAskQuestionModal()"
                        class="bg-gray-500 hover:bg-gray-600 text-white font-semibold px-6 py-2 rounded-lg">
                        Cancel
                    </button>
                    <button type="submit"
                        class="bg-blue-500 hover:bg-blue-600 text-white font-semibold px-6 py-2 rounded-lg">
                        Submit Question
                    </button>
                </div>
            </form>
        </div>
    </div>

    <script>
        function showAskQuestionModal() {
            document.getElementById('askQuestionModal').classList.remove('hidden');
        }

        function hideAskQuestionModal() {
            document.getElementById('askQuestionModal').classList.add('hidden');
        }
    </script>
</body>

</html>

<?php include 'includes/new_footer.php'; ?>