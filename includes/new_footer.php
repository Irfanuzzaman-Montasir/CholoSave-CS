<!DOCTYPE html>
<html>
<head>
    <style>
        /* Reset default margins and ensure full height */
        html, body {
            height: 100%;
            margin: 0;
            padding: 0;
            font-family: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
        }

        /* Main wrapper to create sticky footer */
        .wrapper {
            min-height: 50%;
            display: flex;
            flex-direction: column;
        }

        /* Content area that will grow to push footer down */
        .content {
            flex: 1;
        }

        .footer {
            width: 100%;
            background-color: #ffffff;
            border-top: 1px solid #eaeaea;
            padding: 24px 0;
            text-align: center;
            margin-top: auto;
            box-shadow: 0 -2px 10px rgba(0, 0, 0, 0.02);
        }

        .footer-nav {
            max-width: 1200px;
            margin: 0 auto;
            padding: 0 32px;
        }

        .footer-links {
            list-style: none;
            padding: 0;
            margin: 0;
            display: flex;
            justify-content: center;
            flex-wrap: wrap;
            gap: 32px;
        }

        .footer-link {
            color: #4b5563;
            text-decoration: none;
            font-size: 15px;
            font-weight: 500;
            transition: color 0.2s ease;
            letter-spacing: -0.01em;
        }

        .footer-link:hover {
            color: #111827;
        }

        /* Responsive adjustments */
        @media (max-width: 768px) {
            .footer {
                padding: 20px 0;
            }
            
            .footer-links {
                gap: 24px;
            }
            
            .footer-link {
                font-size: 14px;
            }
        }
    </style>
</head>
<body>
    <div class="wrapper">
        <div class="content">
            <!-- Your page content goes here -->
        </div>

        <footer class="footer">
            <nav class="footer-nav">
                <ul class="footer-links">
                    <li><a href="#" class="footer-link">Help</a></li>
                    <li><a href="/CholoSave-CS/portfolio.php" class="footer-link">Dashboard</a></li>
                    <li><a href="/CholoSave-CS/groups.php" class="footer-link">Groups</a></li>
                    <li><a href="/CholoSave-CS/notification.php" class="footer-link">Notifications</a></li>
                    <li><a href="/CholoSave-CS/forum.php" class="footer-link">Forum</a></li>
                    <li><a href="#" class="footer-link">Blog</a></li>
                    <li><a href="#" class="footer-link">Terms</a></li>
                    <li><a href="#" class="footer-link">AI Tips</a></li>
                </ul>
            </nav>
        </footer>
    </div>
</body>
</html>