<?php
// footer.php
?>
<!DOCTYPE html>
<html>
<head>
<style>
.footer {
    background-color: #ffffff;
    border-top: 1px solid #e5e7eb;
    padding: 3rem 0;
    margin-top: 2rem;
}

.footer-container {
    max-width: 1200px;
    margin: 0 auto;
    padding: 0 1rem;
}

.footer-grid {
    display: grid;
    grid-template-columns: 2fr 1fr 1fr 1fr;
    gap: 2rem;
}

.footer-brand {
    margin-bottom: 1rem;
}

.footer-brand a {
    font-size: 1.5rem;
    font-weight: 700;
    background: linear-gradient(135deg, #003366 0%, #004080 100%);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    text-decoration: none;
}

.footer-brand span {
    background: linear-gradient(135deg, #22C55E 0%, #16A34A 100%);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
}

.footer-description {
    color: #4B5563;
    font-size: 0.875rem;
    line-height: 1.5;
    margin-bottom: 1.5rem;
}

.footer-section h3 {
    color: #1E40AF;
    font-size: 1.125rem;
    font-weight: 600;
    margin-bottom: 1rem;
}

.footer-links {
    list-style: none;
    padding: 0;
    margin: 0;
}

.footer-links li {
    margin-bottom: 0.75rem;
}

.footer-links a {
    color: #4B5563;
    text-decoration: none;
    font-size: 0.875rem;
    transition: color 0.3s ease;
}

.footer-links a:hover {
    color: #1E40AF;
}

.social-links {
    display: flex;
    gap: 1rem;
    margin-top: 1rem;
}

.social-links a {
    color: #4B5563;
    text-decoration: none;
    transition: color 0.3s ease;
}

.social-links a:hover {
    color: #1E40AF;
}

.footer-bottom {
    margin-top: 2rem;
    padding-top: 2rem;
    border-top: 1px solid #e5e7eb;
    text-align: center;
    color: #6B7280;
    font-size: 0.875rem;
}

@media (max-width: 768px) {
    .footer-grid {
        grid-template-columns: 1fr;
        gap: 2rem;
        text-align: center;
    }

    .social-links {
        justify-content: center;
    }

    .footer-section {
        margin-bottom: 1.5rem;
    }
}
</style>
</head>
<body>
    <footer class="footer">
        <div class="footer-container">
            <div class="footer-grid">
                <div class="footer-section">
                    <div class="footer-brand">
                        <a href="/CholoSave-CS/">Cholo<span>Save</span></a>
                    </div>
                    <p class="footer-description">
                        Empowering your financial journey with smart savings solutions and expert guidance.
                    </p>
                    <div class="social-links">
                        <a href="#" aria-label="Facebook"><i class="fab fa-facebook-f"></i></a>
                        <a href="#" aria-label="Twitter"><i class="fab fa-twitter"></i></a>
                        <a href="#" aria-label="Instagram"><i class="fab fa-instagram"></i></a>
                        <a href="#" aria-label="LinkedIn"><i class="fab fa-linkedin-in"></i></a>
                    </div>
                </div>

                <div class="footer-section">
                    <h3>Quick Links</h3>
                    <ul class="footer-links">
                        <li><a href="/CholoSave-CS/">Home</a></li>
                        <li><a href="/CholoSave-CS/vision.php">Our Vision</a></li>
                        <li><a href="/CholoSave-CS/expert.php">Expert Team</a></li>
                        <li><a href="/CholoSave-CS/contact_us.php">Contact Us</a></li>
                    </ul>
                </div>

                <div class="footer-section">
                    <h3>Services</h3>
                    <ul class="footer-links">
                        <li><a href="#">Financial Planning</a></li>
                        <li><a href="#">Investment Advice</a></li>
                        <li><a href="#">Savings Strategies</a></li>
                        <li><a href="#">Budget Planning</a></li>
                    </ul>
                </div>

                <div class="footer-section">
                    <h3>Support</h3>
                    <ul class="footer-links">
                        <li><a href="#">FAQ</a></li>
                        <li><a href="#">Privacy Policy</a></li>
                        <li><a href="#">Terms of Service</a></li>
                        <li><a href="#">Help Center</a></li>
                    </ul>
                </div>
            </div>

            <div class="footer-bottom">
                <p>&copy; <?php echo date('Y'); ?> CholoSave. All rights reserved.</p>
            </div>
        </div>
    </footer>
</body>
</html>