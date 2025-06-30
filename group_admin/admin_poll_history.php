<?php
session_start();

$group_id = $_SESSION['group_id'];
$user_id = $_SESSION['user_id'];

if (isset($_SESSION['group_id']) && isset($_SESSION['user_id'])) {
    $group_id = $_SESSION['group_id'];
    $user_id = $_SESSION['user_id'];
} else {
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



// Fetch polls and calculate votes
$pollsQuery = "
    SELECT 
        p.poll_id, 
        p.poll_question, 
        p.status, 
        p.created_at, 
        COALESCE(SUM(CASE WHEN pv.vote_option = 'yes' THEN 1 ELSE 0 END), 0) AS yes_votes,
        COALESCE(SUM(CASE WHEN pv.vote_option = 'no' THEN 1 ELSE 0 END), 0) AS no_votes
    FROM 
        polls p
    LEFT JOIN 
        polls_vote pv ON p.poll_id = pv.poll_id
    WHERE 
        p.group_id = ?
    GROUP BY 
        p.poll_id;
";

$polls = [];
if ($stmt = $conn->prepare($pollsQuery)) {
    $stmt->bind_param('i', $group_id);
    $stmt->execute();
    $result = $stmt->get_result();
    while ($row = $result->fetch_assoc()) {
        $row['yes_percentage'] = $row['yes_votes'] + $row['no_votes'] > 0 ? round(($row['yes_votes'] / ($row['yes_votes'] + $row['no_votes'])) * 100, 2) : 0;
        $row['no_percentage'] = $row['yes_votes'] + $row['no_votes'] > 0 ? round(($row['no_votes'] / ($row['yes_votes'] + $row['no_votes'])) * 100, 2) : 0;
        $polls[] = $row;
    }
    $stmt->close();
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['delete_poll'])) {
        $poll_id = $_POST['poll_id'];
        $deleteVotesQuery = "DELETE FROM polls_vote WHERE poll_id = ?";
        $deletePollQuery = "DELETE FROM polls WHERE poll_id = ?";

        if ($stmt = $conn->prepare($deleteVotesQuery)) {
            $stmt->bind_param('i', $poll_id);
            $stmt->execute();
            $stmt->close();
        }

        if ($stmt = $conn->prepare($deletePollQuery)) {
            $stmt->bind_param('i', $poll_id);
            $stmt->execute();
            $stmt->close();
        }

        header("Location: admin_poll_history.php");
        exit;
    } elseif (isset($_POST['edit_poll'])) {
        $poll_id = $_POST['poll_id'];
        $poll_question = $_POST['poll_question'];
        $poll_status = $_POST['poll_status'];
        $updatePollQuery = "UPDATE polls SET poll_question = ?, status = ? WHERE poll_id = ?";

        if ($stmt = $conn->prepare($updatePollQuery)) {
            $stmt->bind_param('ssi', $poll_question, $poll_status, $poll_id);
            $stmt->execute();
            $stmt->close();
        }

        header("Location: admin_poll_history.php");
        exit;
    }
}
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Poll History</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        body {
            font-family: 'Inter', sans-serif;
        }

        .glass-effect {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            -webkit-backdrop-filter: blur(10px);
        }

        .editable {
            background-color: #f9fafb;
            border: 1px solid #d1d5db;
            padding: 0.25rem;
            border-radius: 0.25rem;
        }
    </style>
   <script>
    function makeEditable(rowId) {
        const questionCell = document.getElementById(`poll-question-${rowId}`);
        const statusText = document.getElementById(`poll-status-text-${rowId}`);
        const statusSelect = document.getElementById(`poll-status-${rowId}`);

        questionCell.contentEditable = true;
        questionCell.classList.add('editable');
        statusText.style.display = 'none';
        statusSelect.style.display = 'inline-block';

        document.getElementById(`save-btn-${rowId}`).style.display = 'inline-block';
    }

    function saveChanges(rowId) {
        const questionCell = document.getElementById(`poll-question-${rowId}`);
        const statusSelect = document.getElementById(`poll-status-${rowId}`);
        const statusText = document.getElementById(`poll-status-text-${rowId}`);
        const newQuestion = questionCell.innerText;
        const newStatus = statusSelect.value;
        const pollId = document.getElementById(`poll-id-${rowId}`).value;

        fetch('admin_poll_history.php', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: new URLSearchParams({
                poll_id: pollId,
                poll_question: newQuestion,
                poll_status: newStatus,
                edit_poll: 'edit'
            })
        }).then(response => {
            if (response.ok) {
                questionCell.contentEditable = false;
                questionCell.classList.remove('editable');
                statusText.style.display = 'inline-block';
                statusSelect.style.display = 'none';
                statusText.innerText = newStatus;

                document.getElementById(`save-btn-${rowId}`).style.display = 'none';
            } else {
                alert('Failed to save changes.');
            }
        });
    }
</script>

</head>

<body class="bg-gradient-to-br from-white-50 to-blue-100 min-h-screen">
    <div class="flex h-screen">
        <?php include 'group_admin_sidebar.php'; ?>

        <div class="flex-1 flex flex-col overflow-hidden">
            <header class="glass-effect shadow-sm border-b border-gray-200">
                <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6 flex justify-center">
                    <div class="flex items-center justify-center">
                        <h1 class="text-2xl font-semibold text-gray-800 ml-4">
                            <i class="fa-solid fa-poll text-blue-600 mr-3"></i>
                            Poll History
                        </h1>
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
                                            <th
                                                class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                                Serial</th>
                                            <th
                                                class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                                Poll Question</th>
                                            <th
                                                class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                                Yes Votes (%)</th>
                                            <th
                                                class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                                No Votes (%)</th>
                                            <th
                                                class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                                Status</th>
                                            <th
                                                class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                                Actions</th>
                                        </tr>
                                    </thead>
                                    <tbody class="bg-white divide-y divide-gray-200">
                                        <?php
                                        $serial = 1;
                                        foreach ($polls as $poll):
                                            ?>
                                            <tr class="hover:bg-gray-50 transition-colors duration-200">
                                                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                                                    <?php echo $serial++; ?> </td>
                                                <td id="poll-question-<?php echo $poll['poll_id']; ?>"
                                                    class="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">
                                                    <?php echo htmlspecialchars($poll['poll_question']); ?> </td>
                                                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                                                    <?php echo $poll['yes_percentage']; ?>% </td>
                                                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                                                    <?php echo $poll['no_percentage']; ?>% </td>
                                                <td class="px-6 py-4 whitespace-nowrap text-sm font-medium">
                                                    <span id="poll-status-text-<?php echo $poll['poll_id']; ?>"
                                                        style="display: inline-block;">
                                                        <?php echo ucfirst($poll['status']); ?>
                                                    </span>
                                                    <select id="poll-status-<?php echo $poll['poll_id']; ?>"
                                                        class="border-gray-300 rounded-md" style="display: none;">
                                                        <option value="active" <?php echo $poll['status'] === 'active' ? 'selected' : ''; ?>>Active</option>
                                                        <option value="closed" <?php echo $poll['status'] === 'closed' ? 'selected' : ''; ?>>Closed</option>
                                                    </select>
                                                </td>

                                                <td class="px-6 py-4 whitespace-nowrap text-sm font-medium">
                                                    <input type="hidden" id="poll-id-<?php echo $poll['poll_id']; ?>"
                                                        value="<?php echo $poll['poll_id']; ?>">
                                                    <button onclick="makeEditable(<?php echo $poll['poll_id']; ?>)"
                                                        class="inline-flex items-center px-3 py-2 border border-transparent text-sm leading-4 font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 transition-colors duration-200">
                                                        <i class="fas fa-edit mr-2"></i> Edit
                                                    </button>
                                                    <button id="save-btn-<?php echo $poll['poll_id']; ?>"
                                                        onclick="saveChanges(<?php echo $poll['poll_id']; ?>)"
                                                        class="inline-flex items-center px-3 py-2 border border-transparent text-sm leading-4 font-medium rounded-md text-white bg-green-600 hover:bg-green-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-green-500 transition-colors duration-200"
                                                        style="display: none;">
                                                        <i class="fas fa-save mr-2"></i> Save
                                                    </button>
                                                    <form method="POST" class="inline-block">
                                                        <input type="hidden" name="poll_id"
                                                            value="<?php echo $poll['poll_id']; ?>">
                                                        <button type="submit" name="delete_poll" value="delete"
                                                            class="inline-flex items-center px-3 py-2 border border-transparent text-sm leading-4 font-medium rounded-md text-white bg-red-600 hover:bg-red-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-red-500 transition-colors duration-200">
                                                            <i class="fas fa-trash mr-2"></i> Delete
                                                        </button>
                                                    </form>
                                                </td>
                                            </tr>
                                        <?php endforeach; ?>
                                        <?php if (empty($polls)): ?>
                                            <tr>
                                                <td colspan="6" class="px-6 py-10 text-center text-gray-500">
                                                    <i class="fas fa-inbox text-4xl mb-4"></i>
                                                    <p>No polls found</p>
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
</body>

</html>

<?php include 'new_footer.php'; ?>