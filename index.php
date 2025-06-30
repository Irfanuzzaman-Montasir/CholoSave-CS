<?php
// Include database connection
include 'db.php';

// Get total users count
$userQuery = "SELECT COUNT(id) as total_users FROM users";
$userResult = mysqli_query($conn, $userQuery);
$userCount = mysqli_fetch_assoc($userResult)['total_users'];

// Get total groups count
$groupQuery = "SELECT COUNT(group_id) as total_groups FROM my_group";
$groupResult = mysqli_query($conn, $groupQuery);
$groupCount = mysqli_fetch_assoc($groupResult)['total_groups'];

// Close connection
mysqli_close($conn);
?>


<?php include 'includes/new_header.php'; ?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link href="https://cdn.tailwindcss.com" rel="stylesheet">
    <script src="https://cdn.tailwindcss.com"></script>
    <!-- <link rel="stylesheet" href="/CholoSave-CS/assets/css/style.css"> -->
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap" rel="stylesheet">
    <title>CholoSave</title>
</head>

<body>
    <main class="landing">
    
        <div class="relative h-screen">
            <div class="carousel relative h-full overflow-hidden">
                <!-- Carousel Slides -->
                <div class="slide absolute w-full h-full transition-transform duration-500 ease-in-out transform">
                    <img src="4.jpg" alt="Slide 1" class="w-full h-full object-cover">
                    <div class="absolute inset-0 bg-black bg-opacity-40 flex items-center justify-center">
                        <div class="text-center text-white px-4">
                            <h1 class="text-5xl font-bold mb-4">Welcome to CholoSave</h1>
                            <p class="text-xl mb-8">Discover amazing possibilities with us</p>
                            <a href="/CholoSave-CS/register.php" class="inline-block">
                                <button
                                    class="bg-blue-600 text-white px-8 py-3 rounded-full hover:bg-blue-700 transition">
                                    Get Started
                                </button>
                            </a>

                        </div>
                    </div>
                </div>
                <div
                    class="slide absolute w-full h-full transition-transform duration-500 ease-in-out transform translate-x-full">
                    <img src="5.jpg" alt="Slide 2" class="w-full h-full object-cover">
                    <div class="absolute inset-0 bg-black bg-opacity-40 flex items-center justify-center">
                        <div class="text-center text-white px-4">
                            <h1 class="text-5xl font-bold mb-4">Innovation at Its Best</h1>
                            <p class="text-xl mb-8">Leading the way in technology</p>
                            <!-- <button class="bg-blue-600 text-white px-8 py-3 rounded-full hover:bg-blue-700 transition">Learn More</button> -->
                        </div>
                    </div>
                </div>
                <div
                    class="slide absolute w-full h-full transition-transform duration-500 ease-in-out transform translate-x-full">
                    <img src="6.jpg" alt="Slide 3" class="w-full h-full object-cover">
                    <div class="absolute inset-0 bg-black bg-opacity-40 flex items-center justify-center">
                        <div class="text-center text-white px-4">
                            <h1 class="text-5xl font-bold mb-4">Expert Solutions</h1>
                            <p class="text-xl mb-8">Professional team at your service</p>
                            <a href="/CholoSave-CS/expert.php" class="inline-block">
                                <button
                                    class="bg-blue-600 text-white px-8 py-3 rounded-full hover:bg-blue-700 transition">
                                    Contact
                                </button>
                            </a>

                        </div>
                    </div>
                </div>

                <!-- Carousel Navigation -->
                <button
                    class="absolute left-4 top-1/2 transform -translate-y-1/2 bg-white p-2 rounded-full shadow-lg hover:bg-gray-100"
                    onclick="previousSlide()">
                    <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 19l-7-7 7-7">
                        </path>
                    </svg>
                </button>
                <button
                    class="absolute right-4 top-1/2 transform -translate-y-1/2 bg-white p-2 rounded-full shadow-lg hover:bg-gray-100"
                    onclick="nextSlide()">
                    <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"></path>
                    </svg>
                </button>

                <!-- Carousel Indicators -->
                <div class="absolute bottom-4 left-1/2 transform -translate-x-1/2 flex space-x-2">
                    <button class="w-3 h-3 rounded-full bg-white opacity-50 hover:opacity-100 transition"
                        onclick="goToSlide(0)"></button>
                    <button class="w-3 h-3 rounded-full bg-white opacity-50 hover:opacity-100 transition"
                        onclick="goToSlide(1)"></button>
                    <button class="w-3 h-3 rounded-full bg-white opacity-50 hover:opacity-100 transition"
                        onclick="goToSlide(2)"></button>
                </div>
            </div>
        </div>
        <div class="pt-16">
            <main class="w-full">
                <!-- Hero Section -->
                <section class="relative h-[500px] flex items-center justify-center">
                    <img src="/CholoSave-CS/assets/images/login.png" alt="Financial Vision"
                        class="absolute inset-0 w-full h-full object-cover object-center brightness-50" />
                    <div class="relative z-10 text-center px-4 max-w-4xl mx-auto">
                        <h1 class="text-5xl font-bold text-white mb-6">Our Vision</h1>
                        <p class="text-xl text-gray-100 leading-relaxed">
                            At CholoSave, our vision is to empower people to achieve financial independence through
                            collaboration and smart investments. We believe in creating a platform that supports
                            financial growth for everyone, regardless of background or financial knowledge.
                        </p>
                    </div>
                </section>

                <!-- Impact Section -->
                <section class="py-20 bg-white">
                    <div class="max-w-7xl mx-auto px-4">
                        <h2 class="text-3xl font-bold text-center text-gray-800 mb-16">How We Make an Impact</h2>
                        <div class="grid md:grid-cols-3 gap-8">
                            <div
                                class="bg-gray-50 rounded-xl p-8 shadow-lg transform hover:scale-105 transition-transform duration-300">
                                <img src="/CholoSave-CS/assets/images/cloab.png" alt="Collaboration"
                                    class="w-16 h-16 mb-6 rounded-lg" />
                                <h3 class="text-xl font-semibold text-gray-800 mb-4">Collaboration</h3>
                                <p class="text-gray-600 leading-relaxed">
                                    By pooling resources and working together, we unlock greater investment
                                    opportunities and savings potential for everyone involved.
                                </p>
                            </div>
                            <div
                                class="bg-gray-50 rounded-xl p-8 shadow-lg transform hover:scale-105 transition-transform duration-300">
                                <img src="/CholoSave-CS/assets/images/invest.png" alt="Smart Investment"
                                    class="w-16 h-16 mb-6 rounded-lg" />
                                <h3 class="text-xl font-semibold text-gray-800 mb-4">Smart Investment</h3>
                                <p class="text-gray-600 leading-relaxed">
                                    We provide intelligent tools and guidance to ensure that your investments grow
                                    steadily, maximizing returns with minimal risk.
                                </p>
                            </div>
                            <div
                                class="bg-gray-50 rounded-xl p-8 shadow-lg transform hover:scale-105 transition-transform duration-300">
                                <img src="/CholoSave-CS/assets/images/freedom.png" alt="Financial Freedom"
                                    class="w-16 h-16 mb-6 rounded-lg" />
                                <h3 class="text-xl font-semibold text-gray-800 mb-4">Financial Freedom</h3>
                                <p class="text-gray-600 leading-relaxed">
                                    Our goal is to help you gain financial freedom through consistent savings, smart
                                    investments, and the support of like-minded individuals.
                                </p>
                            </div>
                        </div>
                    </div>
                </section>

                <!-- Goals Section -->
                <section class="py-20 bg-gray-50">
                    <div class="max-w-4xl mx-auto px-4">
                        <h2 class="text-3xl font-bold text-center text-gray-800 mb-16">Our Goals</h2>
                        <div class="grid gap-6">
                            <div class="flex items-center space-x-6 bg-white p-6 rounded-lg shadow-md">
                                <div class="flex-shrink-0">
                                    <img src="/CholoSave-CS/assets/images/1.jpg" alt="Goal 1"
                                        class="w-12 h-12 rounded" />
                                </div>
                                <p class="text-lg text-gray-700">Provide accessible financial tools for everyone.</p>
                            </div>
                            <div class="flex items-center space-x-6 bg-white p-6 rounded-lg shadow-md">
                                <div class="flex-shrink-0">
                                    <img src="/CholoSave-CS/assets/images/2.jpg" alt="Goal 2"
                                        class="w-12 h-12 rounded" />
                                </div>
                                <p class="text-lg text-gray-700">Encourage a culture of saving and smart investing.</p>
                            </div>
                            <div class="flex items-center space-x-6 bg-white p-6 rounded-lg shadow-md">
                                <div class="flex-shrink-0">
                                    <img src="/CholoSave-CS/assets/images/3.jpg" alt="Goal 3"
                                        class="w-12 h-12 rounded" />
                                </div>
                                <p class="text-lg text-gray-700">Foster a community of financial empowerment and
                                    collaboration.</p>
                            </div>
                            <div class="flex items-center space-x-6 bg-white p-6 rounded-lg shadow-md">
                                <div class="flex-shrink-0">
                                    <img src="/CholoSave-CS/assets/images/4.jpg" alt="Goal 4"
                                        class="w-12 h-12 rounded" />
                                </div>
                                <p class="text-lg text-gray-700">Help members achieve long-term financial independence.
                                </p>
                            </div>
                        </div>
                    </div>
                </section>

                
                <!-- Stats Section -->
                <section class="py-20 bg-gradient-to-r from-blue-600 to-blue-800">
                    <div class="max-w-7xl mx-auto px-4">
                        <h2 class="text-3xl font-bold text-white text-center mb-16">Our Growing Community</h2>

                        <div class="grid md:grid-cols-2 gap-8 max-w-4xl mx-auto">
                            <!-- Users Stats -->
                            <!-- <div
                                class="bg-white/10 backdrop-blur-lg rounded-2xl p-8 text-center transform hover:scale-105 transition-transform duration-300">
                                <div
                                    class="inline-flex items-center justify-center w-16 h-16 bg-white/20 rounded-full mb-4">
                                    <svg xmlns="http://www.w3.org/2000/svg" class="h-8 w-8 text-white" fill="none"
                                        viewBox="0 0 24 24" stroke="currentColor">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                                            d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z" />
                                    </svg>
                                </div>
                                <h3 class="text-white text-lg font-medium mb-2">Total Users</h3>
                                <div class="text-4xl font-bold text-white mb-2">
                                <span id="userCount" data-target="<?php echo $userCount; ?>">0</span>
                                </div>
                                <p class="text-blue-100">Active members in our community</p>
                            </div> -->

                            <!-- Groups Stats -->
                            <!-- <div
                                class="bg-white/10 backdrop-blur-lg rounded-2xl p-8 text-center transform hover:scale-105 transition-transform duration-300">
                                <div
                                    class="inline-flex items-center justify-center w-16 h-16 bg-white/20 rounded-full mb-4">
                                    <svg xmlns="http://www.w3.org/2000/svg" class="h-8 w-8 text-white" fill="none"
                                        viewBox="0 0 24 24" stroke="currentColor">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                                            d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z" />
                                    </svg>
                                </div>
                                <h3 class="text-white text-lg font-medium mb-2">Active Groups</h3>
                                <div class="text-4xl font-bold text-white mb-2">
                                <span id="groupCount" data-target="<?php echo $groupCount; ?>">0</span>
                                </div>
                                <p class="text-blue-100">Collaborative saving groups</p>
                            </div> -->
                        </div>

                        <!-- CTA Button -->
                        <div class="text-center mt-12">
                            <a href="/CholoSave-CS/register.php"
                                class="inline-block bg-white text-blue-600 px-8 py-4 rounded-lg font-semibold text-lg hover:bg-gray-100 transition-colors duration-300">Join
                                Our Community</a>
                        </div>
                    </div>

                    <script>
                        const countElements = document.querySelectorAll('#userCount, #groupCount');

                        const animateValue = (element, start, end, duration) => {
                            let startTimestamp = null;
                            const step = (timestamp) => {
                                if (!startTimestamp) startTimestamp = timestamp;
                                const progress = Math.min((timestamp - startTimestamp) / duration, 1);
                                const current = Math.floor(progress * (end - start) + start);
                                element.textContent = new Intl.NumberFormat().format(current);
                                if (progress < 1) {
                                    window.requestAnimationFrame(step);
                                }
                            };
                            window.requestAnimationFrame(step);
                        };

                        // Intersection Observer for triggering animation when element is in view
                        const observer = new IntersectionObserver((entries) => {
                            entries.forEach(entry => {
                                if (entry.isIntersecting) {
                                    const target = parseInt(entry.target.getAttribute('data-target'));
                                    animateValue(entry.target, 0, target, 2000); // 2000ms = 2 seconds duration
                                    observer.unobserve(entry.target); // Only animate once
                                }
                            });
                        }, {
                            threshold: 0.5 // Trigger when element is 50% visible
                        });

                        // Observe each counter element
                        countElements.forEach(counter => {
                            observer.observe(counter);
                        });

                        // Carousel functionality
                        let currentSlide = 0;
                        const slides = document.querySelectorAll('.slide');
                        const indicators = document.querySelectorAll('.carousel-indicator');

                        function updateSlides() {
                            slides.forEach((slide, index) => {
                                if (index === currentSlide) {
                                    slide.style.transform = 'translateX(0)';
                                } else if (index < currentSlide) {
                                    slide.style.transform = 'translateX(-100%)';
                                } else {
                                    slide.style.transform = 'translateX(100%)';
                                }
                            });
                        }

                        function nextSlide() {
                            currentSlide = (currentSlide + 1) % slides.length;
                            updateSlides();
                        }

                        function previousSlide() {
                            currentSlide = (currentSlide - 1 + slides.length) % slides.length;
                            updateSlides();
                        }

                        function goToSlide(index) {
                            currentSlide = index;
                            updateSlides();
                        }

                        // Auto-advance carousel
                        setInterval(nextSlide, 5000);

                        // Initial setup
                        updateSlides();
                    </script>
                </section>
            </main>

            <!-- Footer -->

        </div>

    </main>

    <?php include 'includes/test_footer.php'; ?>
</body>

</html>