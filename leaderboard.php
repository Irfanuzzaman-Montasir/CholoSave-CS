<?php
session_start();
include 'db.php'; // Include the database connection
include 'includes/header2.php'; // Include the header file

// Get sort parameters
$sort = isset($_GET['sort']) ? $_GET['sort'] : 'points';
$order = isset($_GET['order']) ? $_GET['order'] : 'DESC';
$search = isset($_GET['search']) ? $_GET['search'] : '';

// Base query
$query = "SELECT l.group_id, l.points, l.updated_at, mg.group_name 
          FROM leaderboard l
          JOIN my_group mg ON l.group_id = mg.group_id";

if (!empty($search)) {
    $query .= " WHERE mg.group_name LIKE '%" . mysqli_real_escape_string($conn, $search) . "%'";
}

$query .= " ORDER BY " . mysqli_real_escape_string($conn, $sort) . " " . $order;

$result = mysqli_query($conn, $query);
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Investment Groups Leaderboard</title>
    <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        .gradient-bg {
            background: linear-gradient(135deg, #4f46e5 0%, #818cf8 100%);
        }
        .trophy-icon {
            font-size: 1.2em;
            margin-right: 0.5em;
        }
        .top-3-row {
            background: linear-gradient(90deg, rgba(249, 250, 251, 1) 0%, rgba(243, 244, 246, 0.5) 100%);
        }
    </style>
</head>

<body class="bg-gradient-to-br from-gray-50 to-gray-100 min-h-screen">
    <div class="container mx-auto px-4 py-8 mt-16">
        <!-- Header -->
        <div class="text-center mb-8">
            <h1 class="text-3xl font-extrabold text-transparent bg-clip-text bg-gradient-to-r from-indigo-600 to-purple-600 mb-2">
                Champions
            </h1>
            <p class="text-xl text-gray-600">Where Excellence Meets Investment</p>
        </div>

        <div class="flex flex-col lg:flex-row gap-6">
            <!-- Main Content (Leaderboard) -->
            <div class="lg:w-3/4">
                <!-- Filters and Search -->
                <div class="bg-white rounded-xl shadow-lg p-4 mb-6">
                    <div class="flex flex-col md:flex-row justify-between items-center gap-4">
                        <!-- Search Form -->
                        <form action="" method="GET" class="w-full md:w-auto">
                            <div class="relative">
                                <input type="text" name="search" placeholder="Search champions..."
                                    value="<?php echo htmlspecialchars($search); ?>"
                                    class="w-full md:w-64 pl-10 pr-4 py-2 border-2 border-gray-200 rounded-lg focus:outline-none focus:border-indigo-500">
                                <div class="absolute left-3 top-2.5">
                                    <i class="fas fa-search text-gray-400"></i>
                                </div>
                            </div>
                        </form>

                        <!-- Sort Options -->
                        <div class="flex gap-2">
                            <a href="?sort=points&order=DESC<?php echo !empty($search) ? '&search=' . urlencode($search) : ''; ?>"
                                class="px-4 py-2 rounded-lg font-medium <?php echo ($sort == 'points' && $order == 'DESC') ? 'gradient-bg text-white' : 'bg-gray-100 hover:bg-gray-200'; ?>">
                                <i class="fas fa-trophy mr-2"></i>Highest
                            </a>
                            <a href="?sort=points&order=ASC<?php echo !empty($search) ? '&search=' . urlencode($search) : ''; ?>"
                                class="px-4 py-2 rounded-lg font-medium <?php echo ($sort == 'points' && $order == 'ASC') ? 'gradient-bg text-white' : 'bg-gray-100 hover:bg-gray-200'; ?>">
                                <i class="fas fa-sort-amount-down mr-2"></i>Lowest
                            </a>
                        </div>
                    </div>
                </div>

                <!-- Leaderboard Table -->
                <div class="bg-white rounded-xl shadow-lg overflow-hidden">
                    <table class="min-w-full">
                        <thead class="bg-gray-50">
                            <tr>
                                <th class="px-6 py-3 text-left text-sm font-semibold text-gray-600">Rank</th>
                                <th class="px-6 py-3 text-left text-sm font-semibold text-gray-600">Group Name</th>
                                <th class="px-6 py-3 text-left text-sm font-semibold text-gray-600">Points</th>
                                <th class="px-6 py-3 text-left text-sm font-semibold text-gray-600">Last Updated</th>
                            </tr>
                        </thead>
                        <tbody class="divide-y divide-gray-100">
                            <?php
                            $rank = 1;
                            while ($row = mysqli_fetch_assoc($result)):
                                $rowClass = $rank <= 3 ? 'top-3-row' : '';
                            ?>
                            <tr class="<?php echo $rowClass; ?> hover:bg-gray-50">
                                <td class="px-6 py-4">
                                    <div class="text-lg font-bold <?php echo $rank <= 3 ? 'text-indigo-600' : 'text-gray-900'; ?>">
                                        <?php
                                        if ($rank == 1) echo '<i class="fas fa-crown trophy-icon text-yellow-500"></i>';
                                        else if ($rank == 2) echo '<i class="fas fa-medal trophy-icon text-gray-400"></i>';
                                        else if ($rank == 3) echo '<i class="fas fa-award trophy-icon text-yellow-700"></i>';
                                        echo $rank++;
                                        ?>
                                    </div>
                                </td>
                                <td class="px-6 py-4">
                                    <div class="text-sm font-semibold text-gray-900">
                                        <?php echo htmlspecialchars($row['group_name']); ?>
                                    </div>
                                </td>
                                <td class="px-6 py-4">
                                    <div class="text-sm font-bold text-indigo-600">
                                        <?php echo number_format($row['points']); ?>
                                    </div>
                                </td>
                                <td class="px-6 py-4">
                                    <div class="text-sm text-gray-500">
                                        <i class="far fa-clock mr-2"></i>
                                        <?php echo date('M d, Y H:i', strtotime($row['updated_at'])); ?>
                                    </div>
                                </td>
                            </tr>
                            <?php endwhile; ?>
                        </tbody>
                    </table>
                </div>
            </div>

            <!-- Side Rules -->
            <div class="lg:w-1/4 mt-16">
                <div class="bg-white rounded-xl shadow-lg p-4 sticky top-4">
                    <div class="flex items-center mb-4">
                        <i class="fas fa-star text-yellow-500 text-xl mr-2"></i>
                        <h2 class="text-lg font-bold text-gray-800">Points System</h2>
                    </div>
                    <div class="space-y-3">
                        <div class="p-3 bg-gray-50 rounded-lg">
                            <div class="flex items-center mb-1">
                                <i class="fas fa-users-gear text-indigo-600 mr-2"></i>
                                <h3 class="font-medium text-sm">Create Group</h3>
                            </div>
                            <p class="text-sm text-gray-600">+5 points</p>
                        </div>
                        <div class="p-3 bg-gray-50 rounded-lg">
                            <div class="flex items-center mb-1">
                                <i class="fas fa-money-bill-wave text-green-600 mr-2"></i>
                                <h3 class="font-medium text-sm">Member Payment</h3>
                            </div>
                            <p class="text-sm text-gray-600">1% of payment amount</p>
                        </div>
                        <div class="p-3 bg-gray-50 rounded-lg">
                            <div class="flex items-center mb-1">
                                <i class="fas fa-user-minus text-red-600 mr-2"></i>
                                <h3 class="font-medium text-sm">Member Leave</h3>
                            </div>
                            <p class="text-sm text-gray-600">-10 points</p>
                        </div>
                        <div class="p-3 bg-gray-50 rounded-lg">
                            <div class="flex items-center mb-1">
                                <i class="fas fa-user-plus text-blue-600 mr-2"></i>
                                <h3 class="font-medium text-sm">Member Join</h3>
                            </div>
                            <p class="text-sm text-gray-600">+5 points</p>
                        </div>
                        <div class="p-3 bg-gray-50 rounded-lg">
                            <div class="flex items-center mb-1">
                                <i class="fas fa-piggy-bank text-purple-600 mr-2"></i>
                                <h3 class="font-medium text-sm">Emergency Fund</h3>
                            </div>
                            <p class="text-sm text-gray-600">1% of fund amount</p>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        document.addEventListener('DOMContentLoaded', function () {
            const searchForm = document.querySelector('form');
            searchForm.addEventListener('submit', function (e) {
                e.preventDefault();
                const searchValue = this.search.value.trim();
                const currentUrl = new URL(window.location.href);
                if (searchValue) {
                    currentUrl.searchParams.set('search', searchValue);
                } else {
                    currentUrl.searchParams.delete('search');
                }
                window.location.href = currentUrl.toString();
            });
        });
    </script>
</body>
</html>
<?php include 'includes/new_footer.php'; ?>