<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <script src="https://cdn.tailwindcss.com"></script>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/alpinejs/3.13.3/cdn.js"></script>
  <title>Payment Gateway</title>
</head>
<body class="bg-gray-100 min-h-screen" style="background-image: url('/test_project/group_member/test/american.jpg'); background-size: cover; background-position: center;">

  <!-- Support Header -->
  <div class="bg-gray-700/80 text-white p-2 text-right text-sm">
    Having Problems? Call Support: +880 9612 22 1000
  </div>

  <div class="container mx-auto p-4 md:p-8 max-w-6xl">
    <div class="grid md:grid-cols-2 gap-6">
      <!-- Order Summary Card -->
      <div class="bg-white rounded shadow-sm mt-48">
        <div class="bg-blue-700 text-white p-4 rounded-t flex justify-between items-center">
          <h2 class="text-xl">Order Summary</h2>
          <svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 3h2l.4 2M7 13h10l4-8H5.4M7 13L5.4 5M7 13l-2.293 2.293c-.63.63-.184 1.707.707 1.707H17m0 0a2 2 0 100 4 2 2 0 000-4zm-8 2a2 2 0 11-4 0 2 2 0 014 0z" />
          </svg>
        </div>
        <div class="p-6 space-y-4">
          <div class="grid grid-cols-2 gap-2 text-gray-600">
            <div>Customer Name:</div>
            <div>Test Customer</div>
            <div>Merchant:</div>
            <div>testcomm8bw9</div>
            <div>Transaction ID:</div>
            <div>SSLCZ_TEST_62838d1bc720e</div>
            <div>Total (BDT):</div>
            <div class="text-2xl font-bold text-gray-800">৳103.00</div>
          </div>
          <div class="pt-4 text-sm text-red-500">
            <a href="#" class="hover:underline">Cancel order & return to www.example.com</a>
          </div>
        </div>
      </div>

      <!-- Payment Methods Card -->
      <div x-data="{ selectedMethod: '' }" class="bg-white rounded shadow-sm mt-48">
        <div class="bg-blue-700 text-white p-4 rounded-t flex justify-between items-center">
          <h2 class="text-xl">Select Payment Method</h2>
          <svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 10h18M7 15h1m4 0h1m-7 4h12a3 3 0 003-3V8a3 3 0 00-3-3H6a3 3 0 00-3 3v8a3 3 0 003 3z" />
          </svg>
        </div>
        <div class="p-6">
          <div class="space-y-4">
            <h3 class="text-gray-500 font-medium">Mobile Banking</h3>
            <div class="grid grid-cols-2 md:grid-cols-4 gap-4">
              <button 
                @click="selectedMethod = 'bKash'"
                :class="{ 'ring-2 ring-blue-500': selectedMethod === 'bKash' }"
                class="p-4 border rounded hover:shadow-md transition-all duration-200 focus:outline-none">
                <img src="/test_project/group_member/test/bkash.png" alt="bKash" class="w-full h-12 object-contain">
              </button>
              <button 
                @click="selectedMethod = 'Rocket'"
                :class="{ 'ring-2 ring-blue-500': selectedMethod === 'Rocket' }"
                class="p-4 border rounded hover:shadow-md transition-all duration-200 focus:outline-none">
                <img src="/test_project/group_member/test/rocket.png" alt="Rocket" class="w-full h-12 object-contain">
              </button>
              <button 
                @click="selectedMethod = 'Nagad'"
                :class="{ 'ring-2 ring-blue-500': selectedMethod === 'Nagad' }"
                class="p-4 border rounded hover:shadow-md transition-all duration-200 focus:outline-none">
                <img src="/test_project/group_member/test/nagad.png" alt="Nagad" class="w-full h-12 object-contain">
              </button>
            </div>
          </div>

          <div class="mt-8">
            <button 
              @click="selectedMethod ? alert('Processing payment via ' + selectedMethod) : null"
              :class="{ 'bg-blue-600 hover:bg-blue-700': selectedMethod, 'bg-gray-300 cursor-not-allowed': !selectedMethod }"
              :disabled="!selectedMethod"
              class="w-full py-3 rounded font-medium text-white transition-colors duration-200">
              Pay Now
            </button>
          </div>
        </div>
      </div>
    </div>
  </div>

  <!-- Powered by SSL Logo -->
  <div class="fixed bottom-4 right-4">
    <img src="/api/placeholder/150/50" alt="Powered by CholoSave" class="h-8">
  </div>
</body>
</html>