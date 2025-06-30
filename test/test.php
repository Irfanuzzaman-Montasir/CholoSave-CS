
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <script src="https://cdn.tailwindcss.com"></script>
  <title>Group Cards</title>
</head>
<body class="bg-gray-100 p-8">

  <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
    <!-- Card 1 -->
    <div class="bg-white shadow-md rounded-lg p-6">
      <h2 class="text-xl font-semibold text-gray-800">Saving Group</h2>
      <span class="inline-block bg-blue-100 text-blue-600 text-sm font-medium rounded-full px-3 py-1 mt-2">weekly</span>
      <p class="mt-4 text-gray-600">Installment: <span class="font-medium">$5000.50</span></p>
      <p class="text-gray-600">Members: <span class="font-medium">1/20</span></p>
      <button class="mt-4 w-full bg-gray-100 text-gray-800 py-2 rounded border border-gray-300 hover:bg-gray-200">
        View Details
      </button>
      <button class="mt-2 w-full bg-green-500 text-white py-2 rounded hover:bg-green-600">
        Enter Group
      </button>
    </div>

    <!-- Card 2 -->
    <div class="bg-white shadow-md rounded-lg p-6">
      <h2 class="text-xl font-semibold text-gray-800">Test Group</h2>
      <span class="inline-block bg-blue-100 text-blue-600 text-sm font-medium rounded-full px-3 py-1 mt-2">monthly</span>
      <p class="mt-4 text-gray-600">Installment: <span class="font-medium">$5000.50</span></p>
      <p class="text-gray-600">Members: <span class="font-medium">1/20</span></p>
      <button class="mt-4 w-full bg-gray-100 text-gray-800 py-2 rounded border border-gray-300 hover:bg-gray-200">
        View Details
      </button>
      <button class="mt-2 w-full bg-yellow-500 text-white py-2 rounded hover:bg-yellow-600">
        Pending Approval
      </button>
    </div>

    <!-- Card 3 -->
    <div class="bg-white shadow-md rounded-lg p-6">
      <h2 class="text-xl font-semibold text-gray-800">Test</h2>
      <span class="inline-block bg-blue-100 text-blue-600 text-sm font-medium rounded-full px-3 py-1 mt-2">monthly</span>
      <p class="mt-4 text-gray-600">Installment: <span class="font-medium">$335.00</span></p>
      <p class="text-gray-600">Members: <span class="font-medium">0/10</span></p>
      <button class="mt-4 w-full bg-gray-100 text-gray-800 py-2 rounded border border-gray-300 hover:bg-gray-200">
        View Details
      </button>
      <button class="mt-2 w-full bg-blue-500 text-white py-2 rounded hover:bg-blue-600">
        Request to Join
      </button>
    </div>
  </div>

</body>
</html>
