<?php
include 'db.php';
session_start();

if (!isset($_SESSION['user_id']) || $_SESSION['role'] !== 'admin') {
    header("Location: ../login.php");
    exit;
}

$success_message = '';
$error_message = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $name = $_POST['name'];
    $email = $_POST['email'];
    $expertise = $_POST['expertise'];
    $bio = $_POST['bio'];
    $phone = $_POST['phone'];
    $photo = $_FILES['photo'];

    try {
        $insert_query = "INSERT INTO expert_team (name, email, expertise, bio, phone) VALUES (?, ?, ?, ?, ?)";
        $stmt = $conn->prepare($insert_query);
        $stmt->bind_param("sssss", $name, $email, $expertise, $bio, $phone);
        $stmt->execute();
        $expert_id = $stmt->insert_id;

        if ($photo['name']) {
            $upload_dir = '../uploads/experts/';
            if (!file_exists($upload_dir)) {
                mkdir($upload_dir, 0777, true);
            }
            
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
        $success_message = "Expert added successfully!";
    } catch (Exception $e) {
        $error_message = "Failed to add expert: " . $e->getMessage();
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Add Expert - CholoSave</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;600&display=swap" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>
</head>

<body class="bg-gray-100 custom-font">
    <div class="flex h-screen">
        <?php include 'sidebar.php'; ?>

        <div class="flex-1 flex flex-col overflow-hidden">
            <header class="flex items-center justify-center p-4 bg-white shadow">
                <h1 class="text-2xl font-semibold text-gray-800">Add Expert</h1>
            </header>

            <main class="flex-1 overflow-y-auto p-6">
                <?php if ($success_message): ?>
                    <div class="bg-green-100 border-l-4 border-green-500 text-green-700 p-4 mb-6" role="alert">
                        <p><?php echo $success_message; ?></p>
                    </div>
                <?php endif; ?>

                <?php if ($error_message): ?>
                    <div class="bg-red-100 border-l-4 border-red-500 text-red-700 p-4 mb-6" role="alert">
                        <p><?php echo $error_message; ?></p>
                    </div>
                <?php endif; ?>

                <div class="max-w-2xl mx-auto bg-white rounded-lg shadow-md p-6">
                    <form action="" method="POST" enctype="multipart/form-data" class="space-y-6">
                        <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                            <div>
                                <label class="block text-sm font-medium text-gray-700 mb-2">Name</label>
                                <input type="text" name="name" required 
                                       class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500">
                            </div>
                            
                            <div>
                                <label class="block text-sm font-medium text-gray-700 mb-2">Email</label>
                                <input type="email" name="email" required 
                                       class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500">
                            </div>
                            
                            <div>
                                <label class="block text-sm font-medium text-gray-700 mb-2">Phone</label>
                                <input type="tel" name="phone" required 
                                       class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500">
                            </div>
                            
                            <div>
                                <label class="block text-sm font-medium text-gray-700 mb-2">Expertise</label>
                                <input type="text" name="expertise" required 
                                       class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500">
                            </div>
                        </div>

                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-2">Bio</label>
                            <textarea name="bio" rows="4" required 
                                      class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"></textarea>
                        </div>

                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-2">Photo</label>
                            <input type="file" name="photo" accept="image/*" required 
                                   class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                                   onchange="previewImage(event)">
                            <div id="imagePreview" class="mt-2 hidden">
                                <img src="" alt="Preview" class="max-w-xs rounded-lg shadow-md">
                            </div>
                        </div>

                        <div class="flex justify-end">
                            <button type="submit" 
                                    class="px-4 py-2 bg-blue-500 text-white rounded-md hover:bg-blue-600 focus:outline-none focus:ring-2 focus:ring-blue-500">
                                Add Expert
                            </button>
                        </div>
                    </form>
                </div>
            </main>
        </div>
    </div>

    <script>
        function previewImage(event) {
            const preview = document.getElementById('imagePreview');
            const image = preview.querySelector('img');
            const file = event.target.files[0];
            const reader = new FileReader();

            reader.onload = function(e) {
                image.src = e.target.result;
                preview.classList.remove('hidden');
            }

            if (file) {
                reader.readAsDataURL(file);
            }
        }
    </script>
</body>
</html>