<?php
/**
 * Enhanced Password Hashing Utilities
 * Provides strong password hashing with automatic salt generation and algorithm selection
 */

class PasswordUtils {
    
    // Preferred algorithms in order of preference
    private static $preferred_algorithms = [
        PASSWORD_ARGON2ID,  // Best - Argon2id (PHP 7.3+)
        PASSWORD_ARGON2I,   // Good - Argon2i (PHP 7.2+)
        PASSWORD_BCRYPT     // Fallback - bcrypt (PHP 5.5+)
    ];
    
    // Optimal parameters for each algorithm
    private static $algorithm_params = [
        PASSWORD_ARGON2ID => [
            'memory_cost' => 65536,    // 64MB
            'time_cost' => 4,          // 4 iterations
            'threads' => 3             // 3 threads
        ],
        PASSWORD_ARGON2I => [
            'memory_cost' => 65536,    // 64MB
            'time_cost' => 4,          // 4 iterations
            'threads' => 3             // 3 threads
        ],
        PASSWORD_BCRYPT => [
            'cost' => 12               // 2^12 iterations
        ]
    ];
    
    /**
     * Hash a password using the best available algorithm
     * Automatically generates and embeds salt
     * 
     * @param string $password The plain text password
     * @param string $algorithm Optional specific algorithm to use
     * @return string|false The hashed password or false on failure
     */
    public static function hashPassword($password, $algorithm = null) {
        // Validate password
        if (empty($password) || strlen($password) < 8) {
            throw new InvalidArgumentException("Password must be at least 8 characters long");
        }
        
        // Determine best available algorithm
        $best_algorithm = $algorithm ?: self::getBestAvailableAlgorithm();
        
        // Get parameters for the algorithm
        $options = self::$algorithm_params[$best_algorithm] ?? [];
        
        // Hash the password with automatic salt generation
        $hashed = password_hash($password, $best_algorithm, $options);
        
        if ($hashed === false) {
            throw new RuntimeException("Failed to hash password");
        }
        
        return $hashed;
    }
    
    /**
     * Verify a password against a hash
     * 
     * @param string $password The plain text password
     * @param string $hash The stored hash
     * @return bool True if password matches, false otherwise
     */
    public static function verifyPassword($password, $hash) {
        if (empty($password) || empty($hash)) {
            return false;
        }
        
        return password_verify($password, $hash);
    }
    
    /**
     * Check if a hash needs to be rehashed (algorithm upgrade)
     * 
     * @param string $hash The stored hash
     * @param string $algorithm Optional specific algorithm to check against
     * @return bool True if rehash is needed, false otherwise
     */
    public static function needsRehash($hash, $algorithm = null) {
        $best_algorithm = $algorithm ?: self::getBestAvailableAlgorithm();
        $options = self::$algorithm_params[$best_algorithm] ?? [];
        
        return password_needs_rehash($hash, $best_algorithm, $options);
    }
    
    /**
     * Get information about a password hash
     * 
     * @param string $hash The stored hash
     * @return array|false Hash information or false on failure
     */
    public static function getHashInfo($hash) {
        return password_get_info($hash);
    }
    
    /**
     * Generate a cryptographically secure random salt
     * (Note: password_hash() automatically generates salts, this is for legacy systems)
     * 
     * @param int $length Length of the salt (default: 32 bytes)
     * @return string The generated salt
     */
    public static function generateSalt($length = 32) {
        if ($length < 16) {
            throw new InvalidArgumentException("Salt length must be at least 16 bytes");
        }
        
        return bin2hex(random_bytes($length));
    }
    
    /**
     * Get the best available hashing algorithm
     * 
     * @return int The best available algorithm constant
     */
    private static function getBestAvailableAlgorithm() {
        foreach (self::$preferred_algorithms as $algorithm) {
            if (defined($algorithm)) {
                return constant($algorithm);
            }
        }
        
        // Fallback to bcrypt if nothing else is available
        return PASSWORD_BCRYPT;
    }
    
    /**
     * Get algorithm name from constant
     * 
     * @param int $algorithm The algorithm constant
     * @return string The algorithm name
     */
    public static function getAlgorithmName($algorithm) {
        $names = [
            PASSWORD_BCRYPT => 'bcrypt',
            PASSWORD_ARGON2I => 'argon2i',
            PASSWORD_ARGON2ID => 'argon2id'
        ];
        
        return $names[$algorithm] ?? 'unknown';
    }
    
    /**
     * Validate password strength
     * 
     * @param string $password The password to validate
     * @return array Array with 'valid' => bool and 'errors' => array
     */
    public static function validatePasswordStrength($password) {
        $errors = [];
        
        if (strlen($password) < 8) {
            $errors[] = "Password must be at least 8 characters long";
        }
        
        if (!preg_match('/[A-Z]/', $password)) {
            $errors[] = "Password must contain at least one uppercase letter";
        }
        
        if (!preg_match('/[a-z]/', $password)) {
            $errors[] = "Password must contain at least one lowercase letter";
        }
        
        if (!preg_match('/[0-9]/', $password)) {
            $errors[] = "Password must contain at least one number";
        }
        
        if (!preg_match('/[^A-Za-z0-9]/', $password)) {
            $errors[] = "Password must contain at least one special character";
        }
        
        return [
            'valid' => empty($errors),
            'errors' => $errors
        ];
    }
    
    /**
     * Generate a secure random password
     * 
     * @param int $length Length of the password (default: 16)
     * @param bool $include_symbols Whether to include symbols (default: true)
     * @return string The generated password
     */
    public static function generateSecurePassword($length = 16, $include_symbols = true) {
        if ($length < 8) {
            throw new InvalidArgumentException("Password length must be at least 8 characters");
        }
        
        $chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
        
        if ($include_symbols) {
            $chars .= '!@#$%^&*()_+-=[]{}|;:,.<>?';
        }
        
        $password = '';
        $char_length = strlen($chars);
        
        // Ensure at least one character from each required category
        $password .= $chars[rand(0, 25)]; // lowercase
        $password .= $chars[rand(26, 51)]; // uppercase
        $password .= $chars[rand(52, 61)]; // number
        
        if ($include_symbols) {
            $password .= $chars[rand(62, strlen($chars) - 1)]; // symbol
        }
        
        // Fill the rest randomly
        for ($i = strlen($password); $i < $length; $i++) {
            $password .= $chars[rand(0, $char_length - 1)];
        }
        
        // Shuffle the password to avoid predictable patterns
        return str_shuffle($password);
    }
    
    /**
     * Log password security events
     * 
     * @param string $event_type Type of event
     * @param string $details Event details
     * @param string $ip_address IP address
     */
    public static function logPasswordEvent($event_type, $details, $ip_address) {
        global $conn;
        
        if (isset($conn)) {
            $stmt = $conn->prepare("INSERT INTO security_logs (event_type, details, ip_address, timestamp) VALUES (?, ?, ?, NOW())");
            $stmt->bind_param("sss", $event_type, $details, $ip_address);
            $stmt->execute();
            $stmt->close();
        }
    }
}

// Example usage and testing functions
if (basename(__FILE__) == basename($_SERVER['SCRIPT_NAME'])) {
    echo "<h2>🔒 Password Hashing Test</h2>";
    
    $test_password = "SecurePass123!";
    
    echo "<h3>Testing Password Hashing:</h3>";
    echo "<p><strong>Test Password:</strong> $test_password</p>";
    
    try {
        // Hash password
        $hash = PasswordUtils::hashPassword($test_password);
        echo "<p><strong>Generated Hash:</strong> " . substr($hash, 0, 50) . "...</p>";
        
        // Get hash info
        $info = PasswordUtils::getHashInfo($hash);
        echo "<p><strong>Algorithm:</strong> " . PasswordUtils::getAlgorithmName($info['algo']) . "</p>";
        echo "<p><strong>Cost:</strong> " . ($info['cost'] ?? 'N/A') . "</p>";
        
        // Verify password
        $verified = PasswordUtils::verifyPassword($test_password, $hash);
        echo "<p><strong>Verification:</strong> " . ($verified ? "✅ Success" : "❌ Failed") . "</p>";
        
        // Test wrong password
        $wrong_verified = PasswordUtils::verifyPassword("WrongPassword123!", $hash);
        echo "<p><strong>Wrong Password Test:</strong> " . ($wrong_verified ? "❌ Failed (should reject)" : "✅ Success (correctly rejected)") . "</p>";
        
        // Test password strength validation
        $strength = PasswordUtils::validatePasswordStrength($test_password);
        echo "<p><strong>Password Strength:</strong> " . ($strength['valid'] ? "✅ Valid" : "❌ Invalid") . "</p>";
        
        if (!$strength['valid']) {
            echo "<ul>";
            foreach ($strength['errors'] as $error) {
                echo "<li>❌ $error</li>";
            }
            echo "</ul>";
        }
        
        // Generate secure password
        $generated = PasswordUtils::generateSecurePassword(16, true);
        echo "<p><strong>Generated Secure Password:</strong> $generated</p>";
        
    } catch (Exception $e) {
        echo "<p style='color: red;'>❌ Error: " . $e->getMessage() . "</p>";
    }
}
?> 