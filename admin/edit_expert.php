<?php
include 'db.php';
session_start();

if (!isset($_SESSION['user_id']) || $_SESSION['role'] !== 'admin') {
    header("Location: /CholoSave-CS/admin/login.php");
    exit;
}

// Fetch all experts
$query = "SELECT * FROM expert_team ORDER BY created_at DESC";
$result = $conn->query($query);
$experts = $result->fetch_all(MYSQLI_ASSOC);

// Process form submission for updating experts
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
    if ($_POST['action'] === 'update') {
        $expert_id = $_POST['expert_id'];
        $name = $_POST['name'];
        $email = $_POST['email'];
        $phone = $_POST['phone'];
        $expertise = $_POST['expertise'];
        $bio = $_POST['bio'];
        $photo = $_FILES['photo'] ?? null;

        try {
            // Update expert information
            $update_query = "UPDATE expert_team SET name=?, email=?, phone=?, expertise=?, bio=? WHERE id=?";
            $stmt = $conn->prepare($update_query);
            $stmt->bind_param("sssssi", $name, $email, $phone, $expertise, $bio, $expert_id);
            $stmt->execute();

            // Handle photo upload if provided
            if ($photo && $photo['name']) {
                $upload_dir = '/CholoSave-CS/uploads/experts/';
                $file_extension = pathinfo($photo['name'], PATHINFO_EXTENSION);
                $new_filename = 'expert_' . $expert_id . '.' . $file_extension;
                $photo_path = $upload_dir . $new_filename;
                
                if (move_uploaded_file($photo['tmp_name'], $photo_path)) {
                    $photo_query = "UPDATE expert_team SET image = ? WHERE id = ?";
                    $photo_stmt = $conn->prepare($photo_query);
                    $photo_stmt->bind_param("si", $new_filename, $expert_id);
                    $photo_stmt->execute();
                }
            }

            header("Location: edit_expert.php?success=1");
            exit();
        } catch (Exception $e) {
            $error_message = "Failed to update expert: " . $e->getMessage();
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Manage Experts - CholoSave</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;600&display=swap" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>
</head>

<body class="bg-gray-100 custom-font">
    <div class="flex h-screen">
        <?php include 'sidebar.php'; ?>

        <div class="flex-1 flex flex-col overflow-hidden">
            <!-- Header -->
            <header class="flex items-center justify-between p-4 bg-white shadow">
                <h1 class="text-2xl font-semibold text-gray-800">
                    <i class="fas fa-users-cog mr-2"></i>Manage Experts
                </h1>
                <div class="flex items-center gap-4">
                    <a href="add_expert.php" class="px-4 py-2 bg-green-600 text-white rounded-md hover:bg-green-700">
                        <i class="fas fa-plus mr-2"></i>Add New Expert
                    </a>
                </div>
            </header>

            <!-- Main Content -->
            <main class="flex-1 overflow-y-auto p-6">
                <?php if (isset($_GET['success'])): ?>
                    <div class="bg-green-100 border-l-4 border-green-500 text-green-700 p-4 mb-6">
                        Expert information updated successfully!
                    </div>
                <?php endif; ?>
                
                <?php if (isset($_GET['deleted'])): ?>
                    <div class="bg-green-100 border-l-4 border-green-500 text-green-700 p-4 mb-6">
                        Expert deleted successfully!
                    </div>
                <?php endif; ?>
                
                <?php if (isset($_GET['error'])): ?>
                    <div class="bg-red-100 border-l-4 border-red-500 text-red-700 p-4 mb-6">
                        An error occurred. Please try again.
                    </div>
                <?php endif; ?>

                <!-- Experts Grid -->
                <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                    <?php foreach ($experts as $expert): ?>
                        <div class="bg-white rounded-lg shadow-md overflow-hidden">
                            <div class="p-4">
                                <div class="flex items-center justify-between mb-4">
                                    <img src="/CholoSave-CS/uploads/experts/<?php echo htmlspecialchars($expert['image']); ?>" 
                                         alt="<?php echo htmlspecialchars($expert['name']); ?>"
                                         class="w-20 h-20 rounded-full object-cover border-2 border-indigo-500">
                                    <div class="flex gap-2">
                                        <button onclick="openEditModal(<?php echo $expert['id']; ?>)" 
                                                class="p-2 text-blue-600 hover:bg-blue-50 rounded-full">
                                            <i class="fas fa-edit"></i>
                                        </button>
                                        <button onclick="deleteExpert(<?php echo $expert['id']; ?>)"
                                                class="p-2 text-red-600 hover:bg-red-50 rounded-full">
                                            <i class="fas fa-trash"></i>
                                        </button>
                                    </div>
                                </div>
                                <h3 class="text-lg font-semibold text-gray-800"><?php echo htmlspecialchars($expert['name']); ?></h3>
                                <p class="text-indigo-600"><?php echo htmlspecialchars($expert['expertise']); ?></p>
                                <div class="mt-2 space-y-2 text-sm text-gray-600">
                                    <p><i class="fas fa-envelope mr-2"></i><?php echo htmlspecialchars($expert['email']); ?></p>
                                    <p><i class="fas fa-phone mr-2"></i><?php echo htmlspecialchars($expert['phone']); ?></p>
                                </div>
                                <p class="mt-3 text-sm text-gray-500 line-clamp-3">
                                    <?php echo htmlspecialchars($expert['bio']); ?>
                                </p>
                            </div>
                        </div>
                    <?php endforeach; ?>
                </div>
            </main>
        </div>
    </div>

    <!-- Edit Modal -->
    <div id="editModal" class="fixed inset-0 bg-black bg-opacity-50 hidden items-center justify-center">
        <div class="bg-white rounded-lg p-6 w-full max-w-2xl max-h-[90vh] overflow-y-auto">
            <div class="flex justify-between items-center mb-4">
                <h2 class="text-xl font-semibold text-gray-800">Edit Expert Information</h2>
                <button onclick="closeEditModal()" class="text-gray-500 hover:text-gray-700">
                    <i class="fas fa-times"></i>
                </button>
            </div>
            <form id="editForm" action="/CholoSave-CS/admin/process_edit_expert.php" method="POST" enctype="multipart/form-data">
                <input type="hidden" name="action" value="update">
                <input type="hidden" name="expert_id" id="edit_expert_id">
                
                <div class="space-y-4">
                    <div>
                        <label class="block text-sm font-medium text-gray-700">Name</label>
                        <input type="text" name="name" id="edit_name" required
                               class="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:ring-indigo-500 focus:border-indigo-500">
                    </div>
                    
                    <div>
                        <label class="block text-sm font-medium text-gray-700">Email</label>
                        <input type="email" name="email" id="edit_email" required
                               class="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:ring-indigo-500 focus:border-indigo-500">
                    </div>
                    
                    <div>
                        <label class="block text-sm font-medium text-gray-700">Phone</label>
                        <input type="tel" name="phone" id="edit_phone" required
                               class="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:ring-indigo-500 focus:border-indigo-500">
                    </div>
                    
                    <div>
                        <label class="block text-sm font-medium text-gray-700">Expertise</label>
                        <input type="text" name="expertise" id="edit_expertise" required
                               class="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:ring-indigo-500 focus:border-indigo-500">
                    </div>
                    
                    <div>
                        <label class="block text-sm font-medium text-gray-700">Bio</label>
                        <textarea name="bio" id="edit_bio" rows="4" required
                                  class="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:ring-indigo-500 focus:border-indigo-500"></textarea>
                    </div>
                    
                    <div>
                        <label class="block text-sm font-medium text-gray-700">New Photo (optional)</label>
                        <input type="file" name="photo" accept="image/*"
                               class="mt-1 block w-full text-sm text-gray-500 file:mr-4 file:py-2 file:px-4 file:rounded file:border-0 file:text-sm file:font-semibold file:bg-indigo-50 file:text-indigo-700 hover:file:bg-indigo-100">
                    </div>
                </div>
                
                <div class="mt-6 flex justify-end space-x-3">
                    <button type="button" onclick="closeEditModal()"
                            class="px-4 py-2 bg-gray-100 text-gray-700 rounded-md hover:bg-gray-200">
                        Cancel
                    </button>
                    <button type="submit"
                            class="px-4 py-2 bg-indigo-600 text-white rounded-md hover:bg-indigo-700">
                        Save Changes
                    </button>
                </div>
            </form>
        </div>
    </div>

    <script>
    // Store experts data for modal
    const experts = <?php echo json_encode($experts); ?>;
    const editModal = document.getElementById('editModal');
    
    function openEditModal(expertId) {
        const expert = experts.find(e => parseInt(e.id) === expertId);
        if (!expert) return;
        
        // Populate form fields
        document.getElementById('edit_expert_id').value = expert.id;
        document.getElementById('edit_name').value = expert.name;
        document.getElementById('edit_email').value = expert.email;
        document.getElementById('edit_phone').value = expert.phone;
        document.getElementById('edit_expertise').value = expert.expertise;
        document.getElementById('edit_bio').value = expert.bio;
        
        // Show modal
        editModal.classList.remove('hidden');
        editModal.classList.add('flex');
    }
    
    function closeEditModal() {
        editModal.classList.remove('flex');
        editModal.classList.add('hidden');
    }
    
    function deleteExpert(expertId) {
        Swal.fire({
            title: 'Are you sure?',
            text: "This action cannot be undone!",
            icon: 'warning',
            showCancelButton: true,
            confirmButtonColor: '#d33',
            cancelButtonColor: '#3085d6',
            confirmButtonText: 'Yes, delete it!'
        }).then((result) => {
            if (result.isConfirmed) {
                window.location.href = `delete_expert.php?id=${expertId}`;
            }
        });
    }

    // Close modal when clicking outside
    editModal.addEventListener('click', (e) => {
        if (e.target === editModal) {
            closeEditModal();
        }
    });

    // Initialize any existing success messages
    document.addEventListener('DOMContentLoaded', function() {
        if (document.querySelector('.bg-green-100')) {
            setTimeout(() => {
                document.querySelector('.bg-green-100').style.display = 'none';
            }, 3000);
        }
    });
    </script>
</body>
</html>