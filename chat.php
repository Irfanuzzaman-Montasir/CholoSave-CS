<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Chat Demo</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-100">
    <div class="container mx-auto px-4 py-8 max-w-4xl">
        <!-- Header with navigation -->
        <!-- <div class="flex justify-between items-center mb-6">
            <button class="text-blue-600 hover:text-blue-800 font-medium">
                ← Back to Groups
            </button>
            <button class="bg-red-500 hover:bg-red-600 text-white px-4 py-2 rounded-lg">
                Logout
            </button>
        </div> -->

        <!-- Chat container -->
        <div class="bg-white rounded-lg shadow-lg">
            <!-- Chat messages area -->
            <div id="messages" class="h-[600px] overflow-y-auto p-6 space-y-4">
                <!-- Received message -->
                <div class="flex items-start space-x-2 mb-4">
                    <div class="flex-1">
                        <div class="bg-gray-100 rounded-lg p-3 max-w-[80%] inline-block">
                            <div class="font-medium text-gray-900 mb-1">Alice Johnson</div>
                            <p class="text-gray-700">Hey everyone! How's the project coming along?</p>
                            <span class="text-xs text-gray-500 mt-1 block">10:30 AM</span>
                        </div>
                    </div>
                </div>

                <!-- Sent message -->
                <div class="flex items-start justify-end space-x-2 mb-4">
                    <div class="flex-1 flex justify-end">
                        <div class="bg-blue-500 rounded-lg p-3 max-w-[80%] inline-block">
                            <div class="font-medium text-white mb-1">You</div>
                            <p class="text-white">Making good progress! Just finished the database schema.</p>
                            <span class="text-xs text-blue-100 mt-1 block">10:31 AM</span>
                        </div>
                    </div>
                </div>

                <!-- Received message -->
                <div class="flex items-start space-x-2 mb-4">
                    <div class="flex-1">
                        <div class="bg-gray-100 rounded-lg p-3 max-w-[80%] inline-block">
                            <div class="font-medium text-gray-900 mb-1">Bob Smith</div>
                            <p class="text-gray-700">Great! I've been working on the frontend components. Should be ready for review by tomorrow.</p>
                            <span class="text-xs text-gray-500 mt-1 block">10:33 AM</span>
                        </div>
                    </div>
                </div>

                <!-- Sent message -->
                <div class="flex items-start justify-end space-x-2 mb-4">
                    <div class="flex-1 flex justify-end">
                        <div class="bg-blue-500 rounded-lg p-3 max-w-[80%] inline-block">
                            <div class="font-medium text-white mb-1">You</div>
                            <p class="text-white">Perfect timing! We can integrate everything by the end of the week then.</p>
                            <span class="text-xs text-blue-100 mt-1 block">10:34 AM</span>
                        </div>
                    </div>
                </div>

                <!-- Received message -->
                <div class="flex items-start space-x-2 mb-4">
                    <div class="flex-1">
                        <div class="bg-gray-100 rounded-lg p-3 max-w-[80%] inline-block">
                            <div class="font-medium text-gray-900 mb-1">Charlie Brown</div>
                            <p class="text-gray-700">I'll help with the testing once everything is integrated. Should we schedule a meeting to discuss the deployment strategy?</p>
                            <span class="text-xs text-gray-500 mt-1 block">10:36 AM</span>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Message input area -->
            <div class="border-t p-4">
                <form id="messageForm" class="flex items-end space-x-4">
                    <div class="flex-1">
                        <textarea 
                            name="message" 
                            class="w-full border rounded-lg p-3 focus:outline-none focus:border-blue-500 resize-none"
                            rows="3"
                            placeholder="Type your message..."
                        ></textarea>
                    </div>
                    <button 
                        type="submit" 
                        class="bg-blue-500 hover:bg-blue-600 text-white px-6 py-3 rounded-lg font-medium"
                    >
                        Send
                    </button>
                </form>
            </div>
        </div>
    </div>

    <script>
        // Demo functionality to add new messages
        document.getElementById('messageForm').addEventListener('submit', function(e) {
            e.preventDefault();
            const textarea = this.querySelector('textarea');
            const message = textarea.value.trim();
            
            if (message) {
                const messagesDiv = document.getElementById('messages');
                const messageElement = document.createElement('div');
                messageElement.className = 'flex items-start justify-end space-x-2 mb-4';
                
                const time = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
                
                messageElement.innerHTML = `
                    <div class="flex-1 flex justify-end">
                        <div class="bg-blue-500 rounded-lg p-3 max-w-[80%] inline-block">
                            <div class="font-medium text-white mb-1">You</div>
                            <p class="text-white">${message}</p>
                            <span class="text-xs text-blue-100 mt-1 block">${time}</span>
                        </div>
                    </div>
                `;
                
                messagesDiv.appendChild(messageElement);
                textarea.value = '';
                messagesDiv.scrollTop = messagesDiv.scrollHeight;
            }
        });
    </script>
</body>
</html>