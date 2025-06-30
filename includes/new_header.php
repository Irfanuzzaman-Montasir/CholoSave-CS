<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;500;600;700&display=swap" rel="stylesheet">
    <!-- <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@600;800&display=swap" rel="stylesheet"> -->
                
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css">
    <!-- <link rel="stylesheet" href="/CholoSave-CS/assets/css/style.css"> -->
    <title>CholoSave</title>
</head>
<body>
     <header class="header">
        <div class="container">
            <div class="logo">
                <a href="/CholoSave-CS/">
                    <img src="/CholoSave-CS/includes/project_logo1.png" alt="CholoSave Logo" class="logo-image">
                </a>
            </div>
            <nav class="nav">
                <a href="/CholoSave-CS/" class="nav-item">
                    <i class="fas fa-home text-lg"></i>
                    <span>Home</span>
                </a>
                <a href="/CholoSave-CS/vision.php" class="nav-item">
                    <i class="fas fa-eye text-lg"></i>
                    <span>Vision</span>
                </a>
                <a href="/CholoSave-CS/expert.php" class="nav-item">
                    <i class="fas fa-users text-lg"></i>
                    <span>Expert Team</span>
                </a>
                <a href="/CholoSave-CS/contact_us.php" class="nav-item">
                    <i class="fas fa-envelope text-lg"></i>
                    <span>Contact Us</span>
                </a>
                <a href="/CholoSave-CS/login.php" class="btn-login">
                    <i class="fas fa-sign-in-alt"></i>
                    Login
                </a>
            </nav>
            <div class="menu-toggle" id="mobile-menu">
                <span></span>
                <span></span>
                <span></span>
            </div>
        </div>
    </header>

<style>
body {
    font-family: 'Poppins', sans-serif;
    margin: 0;
    padding: 0;
    background-color: #f4f7f9;
}

.header {
    background-color: rgba(255, 255, 255, 0.8);
    backdrop-filter: blur(8px);
    -webkit-backdrop-filter: blur(8px);
    box-shadow: 0 4px 6px rgba(0, 0, 0, 0.05);
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    z-index: 1000;
    border-bottom: 1px solid rgba(255, 255, 255, 0.3);
}

.container {
    max-width: 1200px;
    margin: 0 auto;
    padding: 0 1rem;
    height: 5rem;
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.logo-image {
    max-height: 3.5rem; /* Adjust height to fit within header */
    width: auto;
    object-fit: contain;
}


/* Update nav background for mobile to match glassmorphism */
@media screen and (max-width: 768px) {
    .nav {
        background-color: rgba(255, 255, 255, 0.8);
        backdrop-filter: blur(8px);
        -webkit-backdrop-filter: blur(8px);
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.05);
    }
}

/* Add some padding to the body to prevent content from going under the fixed header */
body {
    padding-top: 5rem;
}

/* Until here  */


.logo a {
    font-size: 1.8rem;
    font-weight: 700;
    background: linear-gradient(135deg, #003366 0%, #004080 100%);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    text-decoration: none;
}

.brand {
    background: linear-gradient(135deg, #22C55E 0%, #16A34A 100%);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
}

.nav {
    display: flex;
    gap: 2rem;
    align-items: center;
}

.nav-item {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    color: #4B5563;
    text-decoration: none;
    padding: 0.5rem 0.75rem;
    transition: all 0.3s ease;
    position: relative;
}

.nav-item::after {
    content: '';
    position: absolute;
    width: 0;
    height: 2px;
    bottom: -4px;
    left: 0;
    background-color: #1E40AF;
    transition: width 0.3s ease;
}

.nav-item:hover {
    color: #1E40AF;
}

.nav-item:hover::after {
    width: 100%;
}

.btn-login {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    background-color: #1E40AF;
    color: white;
    padding: 0.625rem 1.25rem;
    border-radius: 0.375rem;
    font-weight: 600;
    text-decoration: none;
    transition: all 0.3s ease;
}

.btn-login:hover {
    background-color: #1E3A8A;
}

.menu-toggle {
    display: none;
    flex-direction: column;
    gap: 5px;
    cursor: pointer;
}

.menu-toggle span {
    width: 30px;
    height: 3px;
    background-color: #333;
    transition: all 0.3s ease;
}

@media screen and (max-width: 768px) {
    .nav {
        display: none;
        flex-direction: column;
        position: absolute;
        top: 5rem;
        left: 0;
        right: 0;
        background-color: white;
        padding: 1rem;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
    }

    .nav.active {
        display: flex;
    }

    .menu-toggle {
        display: flex;
    }

    .nav-item {
        padding: 0.75rem;
    }

    .nav-item::after {
        display: none;
    }
}
</style>

<script>
document.getElementById('mobile-menu').addEventListener('click', function() {
    document.querySelector('.nav').classList.toggle('active');
});
</script>
</body>
</html>