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
            max-width: 500px;
            background: white;
            border-radius: 15px;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.1);
            overflow: hidden;
        }

        .chat-header {
            background: linear-gradient(135deg, #2962ff, #1e88e5);
            color: white;
            padding: 20px;
            text-align: center;
            font-size: 1.2em;
            position: relative;
        }

        .ai-status {
            position: absolute;
            right: 20px;
            top: 50%;
            transform: translateY(-50%);
            display: flex;
            align-items: center;
            font-size: 0.8em;
        }

        .status-dot {
            width: 8px;
            height: 8px;
            background: #4CAF50;
            border-radius: 50%;
            margin-right: 5px;
            animation: pulse 2s infinite;
        }

        @keyframes pulse {
            0% { transform: scale(1); opacity: 1; }
            50% { transform: scale(1.2); opacity: 0.7; }
            100% { transform: scale(1); opacity: 1; }
        }

        .chat-messages {
            height: 400px;
            overflow-y: auto;
            padding: 20px;
        }

        .message {
            margin-bottom: 20px;
            display: flex;
            flex-direction: column;
            opacity: 0;
            transform: translateY(20px);
            animation: fadeIn 0.3s forwards;
        }

        @keyframes fadeIn {
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        .user-message { align-items: flex-end; }
        .bot-message { align-items: flex-start; }

        .message-content {
            max-width: 80%;
            padding: 12px 18px;
            border-radius: 20px;
            font-size: 0.95em;
            position: relative;
        }

        .user-message .message-content {
            background: linear-gradient(135deg, #2962ff, #1e88e5);
            color: white;
            border-bottom-right-radius: 5px;
        }

        .bot-message .message-content {
            background: #f8f9fa;
            color: #333;
            border-bottom-left-radius: 5px;
        }

        .message-meta {
            font-size: 0.7em;
            margin-top: 5px;
            opacity: 0.7;
        }

        .typing-indicator {
            display: none;
            padding: 12px 18px;
            background: #f8f9fa;
            border-radius: 20px;
            margin-bottom: 20px;
            width: fit-content;
        }

        .dot {
            display: inline-block;
            width: 6px;
            height: 6px;
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
            padding: 20px;
            background: #f8f9fa;
            border-top: 1px solid #dee2e6;
            position: relative;
        }

        .input-wrapper {
            flex: 1;
            position: relative;
        }

        input {
            width: 100%;
            padding: 12px 45px 12px 15px;
            border: 1px solid #dee2e6;
            border-radius: 25px;
            outline: none;
            font-size: 0.95em;
            transition: border-color 0.3s, box-shadow 0.3s;
        }

        input:focus {
            border-color: #2962ff;
            box-shadow: 0 0 0 3px rgba(41, 98, 255, 0.1);
        }

        .suggestion-chips {
            padding: 10px 20px;
            display: flex;
            gap: 10px;
            overflow-x: auto;
            background: #f8f9fa;
            border-top: 1px solid #dee2e6;
        }

        .chip {
            padding: 8px 15px;
            background: white;
            border: 1px solid #dee2e6;
            border-radius: 20px;
            font-size: 0.85em;
            cursor: pointer;
            white-space: nowrap;
            transition: all 0.3s;
        }

        .chip:hover {
            background: #2962ff;
            color: white;
            border-color: #2962ff;
        }

        button {
            padding: 12px 25px;
            background: linear-gradient(135deg, #2962ff, #1e88e5);
            color: white;
            border: none;
            border-radius: 25px;
            margin-left: 10px;
            cursor: pointer;
            transition: all 0.3s;
            font-weight: 500;
        }

        button:hover {
            background: linear-gradient(135deg, #1e88e5, #1565c0);
            transform: translateY(-1px);
        }

        .sentiment-indicator {
            position: absolute;
            right: 15px;
            top: 50%;
            transform: translateY(-50%);
            width: 24px;
            height: 24px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.2em;
            opacity: 0.5;
        }
    </style>
</head>
<body>
    <div class="chat-container">
        <div class="chat-header">
            AI Customer Service Assistant
            <div class="ai-status">
                <div class="status-dot"></div>
                Active
            </div>
        </div>
        <div class="chat-messages" id="chatMessages">
            <div class="message bot-message">
                <div class="message-content">
                    Hello! I'm your AI assistant powered by advanced natural language processing. I can help you with a wide range of topics and learn from our conversation. How can I assist you today?
                    <div class="message-meta">AI Assistant • Just now</div>
                </div>
            </div>
            <div class="typing-indicator" id="typingIndicator">
                <span class="dot"></span>
                <span class="dot"></span>
                <span class="dot"></span>
            </div>
        </div>
        <div class="suggestion-chips" id="suggestionChips">
            <div class="chip" onclick="selectSuggestion('Create Account')">Create Account</div>
            <div class="chip" onclick="selectSuggestion('Login Help')">Login Help</div>
            <div class="chip" onclick="selectSuggestion('Payment Issues')">Payment Issues</div>
            <div class="chip" onclick="selectSuggestion('Group Management')">Group Management</div>
        </div>
        <div class="chat-input">
            <div class="input-wrapper">
                <input type="text" id="userInput" placeholder="Type your message...">
                <div class="sentiment-indicator" id="sentimentIndicator"></div>
            </div>
            <button onclick="sendMessage()">Send</button>
        </div>
    </div>

    <script>
        // Knowledge Base
        const knowledgeBase = {
            greetings: {
                patterns: ['hi', 'hello', 'hey', 'greetings'],
                responses: [
                    "Hello! I'm analyzing your query pattern to provide the most relevant assistance. How can I help you today?",
                    "Hi there! My natural language processing is ready to help you. What can I assist you with?",
                    "Greetings! I'm your AI assistant with context-aware responses. What brings you here today?",
                    "Hello! I've been trained on a wide range of topics to help you better. What do you need?"
                ]
            },
            account: {
                patterns: ['account', 'signup', 'register', 'create account'],
                responses: [
                    "I can help you create an account. Would you like to start the process?",
                    "Setting up a new account is easy. Shall we begin?",
                    "I'll guide you through the account creation process. What information do you have ready?"
                ]
            },
            login: {
                patterns: ['login', 'sign in', 'password', 'cant login', 'forgot password'],
                responses: [
                    "I can help you with login issues. Have you forgotten your password?",
                    "Let's get you logged in. What specific login problem are you experiencing?",
                    "I'll help you resolve your login issue. First, could you specify what's happening?"
                ]
            },
            payment: {
                patterns: ['payment', 'pay', 'billing', 'invoice', 'charge'],
                responses: [
                    "I can assist you with payment-related questions. What specific information do you need?",
                    "Let me help you with your payment inquiry. What seems to be the issue?",
                    "I'm here to help with any payment concerns. Could you provide more details?"
                ]
            },
            groups: {
                patterns: ['group', 'team', 'manage group', 'add member'],
                responses: [
                    "I can help you with group management. What would you like to do with your group?",
                    "Let's handle your group-related request. What specific group function do you need help with?",
                    "I'm here to assist with group management. What are you trying to achieve?"
                ]
            }
        };

        // Conversation Context
        let conversationContext = {
            lastTopic: null,
            questionCount: 0,
            userSentiment: 'neutral',
            conversationHistory: [],
            suggestions: new Set()
        };

        // Contextual Memory
        let contextualMemory = {
            topics: new Set(),
            userPreferences: {},
            complexityLevel: 'medium',
            interactionCount: 0
        };

        // Find Best Match Function
        function findBestMatch(userInput) {
            const input = userInput.toLowerCase();
            let bestMatch = null;
            let highestScore = 0;

            for (const topic in knowledgeBase) {
                const patterns = knowledgeBase[topic].patterns;
                const score = patterns.some(pattern => input.includes(pattern)) ? 1 : 0;
                
                if (score > highestScore) {
                    highestScore = score;
                    bestMatch = topic;
                }
            }

            return bestMatch;
        }

        // Sentiment Analysis
        function analyzeSentiment(text) {
            const positiveWords = ['great', 'good', 'excellent', 'thanks', 'helpful', 'perfect', 'awesome'];
            const negativeWords = ['bad', 'poor', 'terrible', 'unhelpful', 'wrong', 'awful', 'confused'];
            
            const words = text.toLowerCase().split(' ');
            let sentiment = 'neutral';
            
            const positiveCount = words.filter(word => positiveWords.includes(word)).length;
            const negativeCount = words.filter(word => negativeWords.includes(word)).length;
            
            if (positiveCount > negativeCount) sentiment = 'positive';
            if (negativeCount > positiveCount) sentiment = 'negative';
            
            return sentiment;
        }

        // Update Sentiment Indicator
        function updateSentimentIndicator(sentiment) {
            const indicator = document.getElementById('sentimentIndicator');
            const emotions = {
                positive: '😊',
                negative: '😕',
                neutral: '😐'
            };
            indicator.textContent = emotions[sentiment];
        }

        // Generate Suggestions
        function generateSuggestions(userInput) {
            const suggestions = new Set();
            const words = userInput.toLowerCase().split(' ');
            
            if (words.some(word => ['account', 'login', 'signup'].includes(word))) {
                suggestions.add('Create Account');
                suggestions.add('Login Help');
            }
            
            if (words.some(word => ['pay', 'money', 'transfer'].includes(word))) {
                suggestions.add('Payment Methods');
                suggestions.add('Transaction History');
            }
            
            return Array.from(suggestions);
        }

        // Update Suggestion Chips
        function updateSuggestionChips(suggestions) {
            const container = document.getElementById('suggestionChips');
            container.innerHTML = suggestions.map(suggestion => 
                `<div class="chip" onclick="selectSuggestion('${suggestion}')">${suggestion}</div>`
            ).join('');
        }

        // Select Suggestion
        function selectSuggestion(suggestion) {
            document.getElementById('userInput').value = suggestion;
            sendMessage();
        }

        // Update Contextual Memory
        function updateContextualMemory(userInput, response) {
            contextualMemory.interactionCount++;
            
            Object.keys(knowledgeBase).forEach(topic => {
                if (findBestMatch(userInput) === topic) {
                    contextualMemory.topics.add(topic);
                }
            });

            if (userInput.length > 50 || userInput.includes('explain') || userInput.includes('detail')) {
                contextualMemory.complexityLevel = 'high';
            } else if (userInput.length < 20 || userInput.includes('simple') || userInput.includes('quick')) {
                contextualMemory.complexityLevel = 'low';
            }

            if (userInput.includes('prefer') || userInput.includes('like')) {
                const words = userInput.toLowerCase().split(' ');
                const preferenceIndex = words.findIndex(word => word === 'prefer' || word === 'like');
                if (preferenceIndex !== -1 && words[preferenceIndex + 1]) {
                    contextualMemory.userPreferences[words[preferenceIndex + 1]] = true;
                }
            }
        }

        // Enhance Response with Context
        function enhanceResponseWithContext(baseResponse) {
            let enhancedResponse = baseResponse;

            if (contextualMemory.interactionCount > 5) {
                enhancedResponse = enhancedResponse.replace(
                    "Hello!",
                    "Welcome back! Based on our previous conversations,"
                );
            }

            if (contextualMemory.complexityLevel === 'high') {
                enhancedResponse += "\n\nWould you like me to provide more detailed information on any specific aspect?";
            } else if (contextualMemory.complexityLevel === 'low') {
                enhancedResponse = enhancedResponse.split('\n')[0]; // Keep it concise
            }

            if (contextualMemory.topics.size > 1) {
                const relatedTopics = Array.from(contextualMemory.topics)
                    .filter(topic => !baseResponse.toLowerCase().includes(topic.toLowerCase()));
                if (relatedTopics.length > 0) {
                    enhancedResponse += `\n\nYou might also be interested in: ${relatedTopics.join(', ')}`;
                }
            }

            return enhancedResponse;
        }

        // Generate Response
        async function generateResponse(userInput) {
            await new Promise(resolve => setTimeout(resolve, 1000 + Math.random() * 1000));

            conversationContext.conversationHistory.push({
                role: 'user',
                content: userInput,
                timestamp: new Date(),
                sentiment: analyzeSentiment(userInput)
            });

            const topic = findBestMatch(userInput);
            let response = '';

            if (topic) {
                const responses = knowledgeBase[topic].responses;
                response = responses[Math.floor(Math.random() * responses.length)];

                if (conversationContext.conversationHistory.length > 1) {
                    if (conversationContext.userSentiment === 'negative') {
                        response = `I understand this might be frustrating. Let me help you specifically with ${topic}. ${response}`;
                    } else if (conversationContext.userSentiment === 'positive') {
                        response = `Great! I'm glad I can help with ${topic}. ${response}`;
                    }
                }

                updateContextualMemory(userInput, response);
                response = enhanceResponseWithContext(response);
            } else {
                response = `I'm analyzing your request using advanced natural language processing. While I don't have a specific answer, I can help with related topics like ${Array.from(contextualMemory.topics).join(', ')}. Could you provide more details about what you're looking for?`;
            }

            const suggestions = generateSuggestions(userInput);
            if (suggestions.length > 0) {
                response += "\n\nYou might also want to explore: " + suggestions.join(', ');
            }

            updateSuggestionChips(suggestions);
            return response;
        }

        // Calculate Typing Delay
        function calculateTypingDelay(message) {
            const wordsPerMinute = 200;
            const wordCount = message.split(' ').length;
            return Math.min(Math.max(1000, (wordCount / wordsPerMinute) * 60000), 3000);
        }

        // Show/Hide Typing Indicator
        function showTypingIndicator() {
            const indicator = document.getElementById('typingIndicator');
            indicator.style.display = 'block';
            const chatMessages = document.getElementById('chatMessages');
            chatMessages.scrollTop = chatMessages.scrollHeight;
        }

        function hideTypingIndicator() {
            document.getElementById('typingIndicator').style.display = 'none';
        }

        // Add Message to Chat
        function addMessage(message, isUser = false) {
            const chatMessages = document.getElementById('chatMessages');
            const messageDiv = document.createElement('div');
            messageDiv.className = `message ${isUser ? 'user-message' : 'bot-message'}`;
            
            const timestamp = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
            const sender = isUser ? 'You' : 'AI Assistant';
            
            messageDiv.innerHTML = `
                <div class="message-content">
                    ${message.replace(/\n/g, '<br>')}
                    <div class="message-meta">${sender} • ${timestamp}</div>
                </div>
            `;
            
            chatMessages.appendChild(messageDiv);
            chatMessages.scrollTop = chatMessages.scrollHeight;
        }

        // Send Message
        async function sendMessage() {
            const userInput = document.getElementById('userInput');
            const message = userInput.value.trim();
            
            if (message) {
                addMessage(message, true);
                userInput.value = '';
                
                const sentiment = analyzeSentiment(message);
                conversationContext.userSentiment = sentiment;
                updateSentimentIndicator(sentiment);
                
                showTypingIndicator();
                
                try {
                    const response = await generateResponse(message);
                    await new Promise(resolve => setTimeout(resolve, calculateTypingDelay(response)));
                    hideTypingIndicator();
                    addMessage(response);
                } catch (error) {
                    hideTypingIndicator();
                    addMessage("I encountered an error but my neural networks are learning from this interaction. Please try rephrasing your question.");
                }
            }
        }

        // Event Listeners
        document.getElementById('userInput').addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                sendMessage();
            }
        });

        document.getElementById('userInput').addEventListener('input', function(e) {
            const sentiment = analyzeSentiment(e.target.value);
            updateSentimentIndicator(sentiment);
            
            const suggestions = generateSuggestions(e.target.value);
            updateSuggestionChips(suggestions);
        });

        // Initial Setup
        window.onload = function() {
            updateSentimentIndicator('neutral');
            const initialSuggestions = ['Create Account', 'Login Help', 'Payment Issues', 'Group Management'];
            updateSuggestionChips(initialSuggestions);
        };
    </script>
</body>
</html>