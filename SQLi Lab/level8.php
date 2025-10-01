<?php
// Level 8: Registration + Login System - Second Order Injection
// Goal: Register with malicious payload, then trigger it during login

session_start();

// Database connection
$host = $_ENV['DB_HOST'] ?? 'db';
$user = $_ENV['DB_USER'] ?? 'root'; 
$pass = $_ENV['DB_PASS'] ?? 'rootpassword';
$dbname = $_ENV['DB_NAME'] ?? 'sqli_lab';

$conn = new mysqli($host, $user, $pass, $dbname);

if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

$message = "";
$success = false;
$mode = $_GET['mode'] ?? 'login';

// Registration process
if ($_POST && $mode === 'register') {
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';
    $email = $_POST['email'] ?? '';
    
    // Vulnerable registration - stores user input directly
    $sql = "INSERT INTO users (username, password, email) VALUES ('$username', '$password', '$email')";
    
    try {
        if ($conn->query($sql)) {
            $message = "✅ Registration successful! You can now login with your credentials.";
        } else {
            $message = "❌ Registration failed: " . $conn->error;
        }
    } catch (Exception $e) {
        $message = "❌ Registration failed: " . $e->getMessage();
    }
}

// Login process - triggers second order injection
if ($_POST && $mode === 'login') {
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';
    
    // First query - retrieves user data (including malicious stored data)
    $sql1 = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";
    $result1 = $conn->query($sql1);
    
    if ($result1 && $result1->num_rows > 0) {
        $user_data = $result1->fetch_assoc();
        
        // Second query - uses stored user data (VULNERABLE!)
        $stored_email = $user_data['email'];
        $sql2 = "SELECT COUNT(*) as count FROM users WHERE email = '$stored_email' AND role = 'admin'";
        
        try {
            $result2 = $conn->query($sql2);
            if ($result2) {
                $admin_check = $result2->fetch_assoc();
                if ($admin_check['count'] > 0 || $user_data['role'] === 'admin') {
                    $success = true;
                    $message = "🎉 Brilliant! You exploited second-order injection to become admin!<br>";
                    $message .= "🏁 <strong>FLAG: LEVEL7_SECOND_ORDER_MASTERY</strong><br>";
                    $message .= "🔄 Your payload was stored during registration and executed during login!<br>";
                    $message .= "👤 Welcome, " . htmlspecialchars($user_data['username']) . "!";
                } else {
                    $message = "✅ Login successful as: " . htmlspecialchars($user_data['username']) . " (" . htmlspecialchars($user_data['role'] ?? 'user') . ")";
                }
            }
        } catch (Exception $e) {
            $message = "💥 Second query error: " . $e->getMessage();
            $message .= "<br>🔄 Your stored payload triggered an error - injection successful!";
        }
    } else {
        $message = "❌ Login failed: Invalid credentials";
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Level 7 - Registration System | SQL Injection Lab</title>
    <link rel="stylesheet" href="css/styles.css">
    <style>
        .system-container {
            max-width: 700px;
            margin: 2rem auto;
            background: #2d1b3d;
            color: #e2e8f0;
            padding: 2rem;
            border-radius: 16px;
            box-shadow: 0 8px 25px rgba(45, 27, 61, 0.3);
            border: 1px solid #553c9a;
        }
        
        .tab-switcher {
            display: flex;
            gap: 1rem;
            margin-bottom: 2rem;
        }
        
        .tab {
            padding: 0.8rem 1.5rem;
            background: #1a1a2e;
            border: 2px solid #553c9a;
            border-radius: 8px;
            color: #a0aec0;
            text-decoration: none;
            transition: all 0.3s;
        }
        
        .tab.active {
            background: #553c9a;
            color: white;
        }
        
        .form-group input {
            background: #1a1a2e;
            color: #e2e8f0;
            border: 2px solid #553c9a;
        }
        
        .form-group input:focus {
            border-color: #7c3aed;
            box-shadow: 0 0 0 3px rgba(124, 58, 237, 0.2);
        }
        
        .submit-btn {
            background: linear-gradient(135deg, #7c3aed 0%, #553c9a 100%);
            color: white;
            padding: 1rem;
            border: none;
            border-radius: 8px;
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s;
        }
        
        .submit-btn:hover {
            box-shadow: 0 6px 20px rgba(124, 58, 237, 0.4);
        }
        
        .second-order-info {
            background: #1a1a2e;
            border: 2px solid #7c3aed;
            border-radius: 8px;
            padding: 1rem;
            margin: 1rem 0;
            color: #c084fc;
        }
        
        body {
            background: linear-gradient(135deg, #1a1a2e 0%, #2d1b3d 100%);
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔄 Level 7 - Registration System</h1>
            <p>Exploit second-order injection through registration and login process</p>
            <a href="index.php" class="back-btn">← Back to Labs</a>
        </div>
        
        <div class="system-container">
            <div class="tab-switcher">
                <a href="?mode=register" class="tab <?= $mode === 'register' ? 'active' : '' ?>">📝 Register</a>
                <a href="?mode=login" class="tab <?= $mode === 'login' ? 'active' : '' ?>">🔐 Login</a>
            </div>
            
            <div class="second-order-info">
                <h4>🔄 Second-Order Injection Challenge</h4>
                <p>Register with a malicious payload, then trigger it during login!</p>
            </div>
            
            <?php if ($message): ?>
                <div class="message <?= $success ? 'success' : 'error' ?>">
                    <?= $message ?>
                </div>
            <?php endif; ?>
            
            <?php if ($mode === 'register'): ?>
                <h3>📝 Create Account</h3>
                <form method="POST" class="login-form">
                    <div class="form-group">
                        <label for="username">Username:</label>
                        <input type="text" id="username" name="username" placeholder="Enter username" required>
                    </div>
                    
                    <div class="form-group">
                        <label for="password">Password:</label>
                        <input type="password" id="password" name="password" placeholder="Enter password" required>
                    </div>
                    
                    <div class="form-group">
                        <label for="email">Email:</label>
                        <input type="text" id="email" name="email" placeholder="Enter email (vulnerable field!)" required>
                    </div>
                    
                    <button type="submit" class="submit-btn">📝 Register</button>
                </form>
            <?php else: ?>
                <h3>🔐 Login</h3>
                <form method="POST" class="login-form">
                    <div class="form-group">
                        <label for="username">Username:</label>
                        <input type="text" id="username" name="username" placeholder="Enter username" required>
                    </div>
                    
                    <div class="form-group">
                        <label for="password">Password:</label>
                        <input type="password" id="password" name="password" placeholder="Enter password" required>
                    </div>
                    
                    <button type="submit" class="submit-btn">🚀 Login</button>
                </form>
            <?php endif; ?>
        </div>
        
        <div class="hints">
            <h3>💡 Hints for Level 7:</h3>
            <ul>
                <li><strong>Two-Step Process:</strong> 1) Register with payload, 2) Login to trigger</li>
                <li><strong>Vulnerable Field:</strong> Email field is stored and used in second query</li>
                <li><strong>Example Registration:</strong></li>
            </ul>
            <div class="code-example">
Username: hacker<br>
Password: pass<br>
Email: test@test.com' UNION SELECT 'admin' as role--
            </div>
            <ul>
                <li><strong>Then Login:</strong> Use the same username/password to trigger stored payload</li>
                <li><strong>Alternative:</strong> Register admin-like data directly in email field</li>
                <li><strong>Goal:</strong> Make the second query return admin role</li>
            </ul>
        </div>
        
        <div class="navigation">
            <a href="level6.php">← Previous Level</a>
            <a href="level8.php">Next Level →</a>
        </div>
    </div>
</body>
</html>

<?php $conn->close(); ?>