<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AI Customer Service Bot</title>
    <style>
      * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: Arial, sans-serif;
        }

        body {
            background-color: #f0f2f5;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            padding: 20px;
        }

        .chat-container {
            width: 100%;
            max-width: 400px;
            background: white;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
            overflow: hidden;
        }

        .chat-header {
            background: #2962ff;
            color: white;
            padding: 15px;
            text-align: center;
            font-size: 1.2em;
        }

        .chat-messages {
            height: 400px;
            overflow-y: auto;
            padding: 20px;
        }

        .message {
            margin-bottom: 15px;
            display: flex;
            flex-direction: column;
        }

        .user-message {
            align-items: flex-end;
        }

        .bot-message {
            align-items: flex-start;
        }

        .message-content {
            max-width: 80%;
            padding: 10px 15px;
            border-radius: 15px;
            font-size: 0.9em;
        }

        .user-message .message-content {
            background: #2962ff;
            color: white;
        }

        .bot-message .message-content {
            background: #e9ecef;
            color: black;
        }

        .typing-indicator {
            display: none;
            padding: 10px 15px;
            background: #e9ecef;
            border-radius: 15px;
            margin-bottom: 15px;
            width: fit-content;
        }

        .dot {
            display: inline-block;
            width: 8px;
            height: 8px;
            margin-right: 3px;
            background: #666;
            border-radius: 50%;
            animation: wave 1.3s linear infinite;
        }

        .dot:nth-child(2) { animation-delay: -1.1s; }
        .dot:nth-child(3) { animation-delay: -0.9s; }

        @keyframes wave {
            0%, 60%, 100% { transform: translateY(0); }
            30% { transform: translateY(-4px); }
        }

        .chat-input {
            display: flex;
            padding: 15px;
            background: #f8f9fa;
            border-top: 1px solid #dee2e6;
        }

        input {
            flex: 1;
            padding: 10px;
            border: 1px solid #dee2e6;
            border-radius: 20px;
            margin-right: 10px;
            outline: none;
        }

        button {
            padding: 10px 20px;
            background: #2962ff;
            color: white;
            border: none;
            border-radius: 20px;
            cursor: pointer;
            transition: background 0.3s;
        }

        button:hover {
            background: #1e4bd8;
        }
    </style>
</head>
<body>
    <div class="chat-container">
        <div class="chat-header">
            AI Customer Service Bot
        </div>
        <div class="chat-messages" id="chatMessages">
            <div class="message bot-message">
                <div class="message-content">
                    Hello! I'm your AI assistant. How can I help you today?
                </div>
            </div>
            <div class="typing-indicator" id="typingIndicator">
                <span class="dot"></span>
                <span class="dot"></span>
                <span class="dot"></span>
            </div>
        </div>
        <div class="chat-input">
            <input type="text" id="userInput" placeholder="Type your message...">
            <button onclick="sendMessage()">Send</button>
        </div>
    </div>

    <script>
        const knowledgeBase = {
            greetings: {
                patterns: ['hi', 'hello', 'hey', 'greetings'],
                responses: [
                    "Hello! How can I assist you today?",
                    "Hi there! What can I help you with?",
                    "Greetings! How may I be of service?",
                    "Hello! I'm here to help. What do you need?"
                ]
            },
            farewell: {
                patterns: ['bye', 'goodbye', 'see you', 'take care'],
                responses: [
                    "Goodbye! Have a wonderful day!",
                    "Take care! Feel free to return if you need more help.",
                    "Bye for now! Don't hesitate to ask if you have more questions.",
                    "See you later! Thanks for chatting with me!"
                ]
            },
            login: {
                patterns: ['login', 'sign in', 'access account', 'cant login'],
                responses: [
                    "Let me help you with logging in. Here's what you need to do:\n1. Visit our login page\n2. Enter your email/username\n3. Input your password\n4. Click 'Sign In'\n\nIf you're having trouble, I can help with password reset or other login issues.",
                    "To access your account:\n1. Go to the login section\n2. Provide your credentials\n3. Verify your identity if required\n\nAre you experiencing any specific login issues?"
                ]
            },
            account: {
                patterns: ['create account', 'open account', 'sign up', 'register'],
                responses: [
                    "I'll guide you through account creation:\n1. Click 'Sign Up'\n2. Enter your personal details\n3. Choose a strong password\n4. Verify your email\n5. Set up security questions\n\nWould you like more specific information about any of these steps?",
                    "Creating an account is easy:\n1. Start the registration process\n2. Provide required information\n3. Agree to terms and conditions\n4. Complete verification\n\nDo you have any specific questions about the process?"
                ]
            },
            groups: {
                patterns: ['create group', 'join group', 'group creation', 'group joining'],
                responses: [
                    "For groups, you have two options:\n\nTo Create a Group:\n1. Go to Groups section\n2. Click 'Create New'\n3. Set group details\n4. Invite members\n\nTo Join a Group:\n1. Search for the group\n2. Request to join\n3. Wait for approval\n\nWhich would you like to know more about?",
                    "Let me explain group features:\n\nCreating Groups:\n1. Access group settings\n2. Configure privacy options\n3. Add description\n4. Set rules\n\nJoining Groups:\n1. Browse available groups\n2. Check requirements\n3. Submit join request\n\nWhat specific information do you need?"
                ]
            },
            payment: {
                patterns: ['payment', 'pay', 'transaction', 'transfer money'],
                responses: [
                    "I can help you with payments. Here's the process:\n1. Choose payment method\n2. Enter amount\n3. Add recipient details\n4. Verify transaction\n5. Confirm payment\n\nWhat type of payment are you looking to make?",
                    "For making payments:\n1. Select payment option\n2. Input payment details\n3. Review information\n4. Authorize transaction\n\nWould you like to know about specific payment methods?"
                ]
            },
            loan: {
                patterns: ['loan', 'borrow money', 'credit', 'financing'],
                responses: [
                    "Regarding loans, here's what you need to know:\n1. Check eligibility\n2. Choose loan type\n3. Submit application\n4. Provide documents\n5. Wait for approval\n\nWhat kind of loan are you interested in?",
                    "For loan applications:\n1. Review loan options\n2. Calculate affordability\n3. Gather required documents\n4. Complete application\n\nWould you like information about specific loan types?"
                ]
            }
        };

        let conversationContext = {
            lastTopic: null,
            questionCount: 0
        };

        function showTypingIndicator() {
            const indicator = document.getElementById('typingIndicator');
            indicator.style.display = 'block';
            const chatMessages = document.getElementById('chatMessages');
            chatMessages.scrollTop = chatMessages.scrollHeight;
        }

        function hideTypingIndicator() {
            document.getElementById('typingIndicator').style.display = 'none';
        }

        function addMessage(message, isUser = false) {
            const chatMessages = document.getElementById('chatMessages');
            const messageDiv = document.createElement('div');
            messageDiv.className = `message ${isUser ? 'user-message' : 'bot-message'}`;
            messageDiv.innerHTML = `
                <div class="message-content">
                    ${message.replace(/\n/g, '<br>')}
                </div>
            `;
            chatMessages.appendChild(messageDiv);
            chatMessages.scrollTop = chatMessages.scrollHeight;
        }

        function findBestMatch(input) {
            const words = input.toLowerCase().split(' ');
            let bestMatch = null;
            let maxMatchCount = 0;

            for (const [topic, data] of Object.entries(knowledgeBase)) {
                const matchCount = data.patterns.reduce((count, pattern) => {
                    return count + words.filter(word => word.includes(pattern)).length;
                }, 0);

                if (matchCount > maxMatchCount) {
                    maxMatchCount = matchCount;
                    bestMatch = topic;
                }
            }

            return maxMatchCount > 0 ? bestMatch : null;
        }

        async function getExternalResponse(query) {
            try {
                // Using the DuckDuckGo API endpoint (replace with your preferred API)
                const response = await fetch(`https://api.duckduckgo.com/?q=${encodeURIComponent(query)}&format=json`);
                const data = await response.json();
                
                if (data.Abstract) {
                    return data.Abstract;
                } else if (data.RelatedTopics && data.RelatedTopics.length > 0) {
                    return data.RelatedTopics[0].Text;
                } else {
                    throw new Error('No relevant information found');
                }
            } catch (error) {
                console.error('Error fetching external response:', error);
                return null;
            }
        }

        async function generateResponse(userInput) {
            const topic = findBestMatch(userInput);
            
            if (topic) {
                const responses = knowledgeBase[topic].responses;
                const response = responses[Math.floor(Math.random() * responses.length)];

                if (topic === conversationContext.lastTopic) {
                    conversationContext.questionCount++;
                    if (conversationContext.questionCount > 1) {
                        return response + "\n\nWould you like to explore a different topic? I can help with various other services as well.";
                    }
                } else {
                    conversationContext.lastTopic = topic;
                    conversationContext.questionCount = 1;
                }

                return response;
            } else {
                // Try to get response from external API
                const externalResponse = await getExternalResponse(userInput);
                if (externalResponse) {
                    return externalResponse;
                } else {
                    return "I apologize, but I couldn't find a specific answer to your question. Could you please rephrase it or ask about something else? I can help with account creation, login help, groups, payments, or loans.";
                }
            }
        }

        async function sendMessage() {
            const userInput = document.getElementById('userInput');
            const message = userInput.value.trim();
            
            if (message) {
                addMessage(message, true);
                userInput.value = '';
                
                showTypingIndicator();
                
                try {
                    const response = await generateResponse(message);
                    hideTypingIndicator();
                    addMessage(response);
                } catch (error) {
                    hideTypingIndicator();
                    addMessage("I apologize, but I encountered an error while processing your request. Please try again.");
                }
            }
        }

        // Allow Enter key to send message
        document.getElementById('userInput').addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                sendMessage();
            }
        });
    </script>
</body>
</html>

