<?php
// Level 4: Basic WAF Bypass - Multiple Security Layers
// Goal: Bypass multiple security measures to login as admin

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
$show_hint = false;

// Simple anti-automation
session_start();
if (!isset($_SESSION['attempts'])) {
    $_SESSION['attempts'] = 0;
}

if ($_POST) {
    $_SESSION['attempts']++;
    
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';
    
    // Advanced WAF simulation - multiple filters
    $blocked_words = ['union', 'select', 'or', 'and', 'admin', '--', '#', '/*', '*/', 'drop', 'insert', 'update', 'delete'];
    $username_lower = strtolower($username);
    $password_lower = strtolower($password);
    
    // Check for blocked words
    foreach ($blocked_words as $word) {
        if (strpos($username_lower, $word) !== false || strpos($password_lower, $word) !== false) {
            $message = "🚨 WAF Blocked: Suspicious pattern detected: '$word'";
            break;
        }
    }
    
    if (!$message) {
        // Remove quotes and some special chars (but can be bypassed)
        $username = str_replace(["'", '"', ';'], "", $username);
        $password = str_replace(["'", '"', ';'], "", $password);
        
        // Query with role check
        $sql = "SELECT * FROM users WHERE username = '$username' AND password = '$password' AND role = 'admin'";
        
        try {
            $result = $conn->query($sql);
            if ($result && $result->num_rows > 0) {
                $admin_data = $result->fetch_assoc();
                $success = true;
                $message = "🎉 INCREDIBLE! You bypassed the advanced WAF and logged in as admin!<br>";
                $message .= "🏁 <strong>FLAG: LEVEL4_WAF_BYPASS_MASTER</strong><br>";
                $message .= "🔑 Welcome, " . htmlspecialchars($admin_data['username']) . "!<br>";
                $message .= "🛡️ You've demonstrated expert-level bypass skills!";
            } else {
                $message = "❌ Authentication failed. Invalid credentials.";
            }
        } catch (Exception $e) {
            $message = "❌ Authentication failed. Security violation detected.";
        }
    }
    
    // Show progressive hints based on attempts
    if ($_SESSION['attempts'] > 3 && !$success) {
        $show_hint = true;
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Level 4 - Basic WAF Bypass | SQL Injection Lab</title>
    <link rel="stylesheet" href="css/styles.css">
    <style>
        body {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
        }
        
        .admin-portal {
            max-width: 500px;
            margin: 3rem auto;
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            padding: 3rem;
            border-radius: 20px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.2);
            border: 1px solid rgba(255,255,255,0.3);
        }
        
        .portal-header {
            text-align: center;
            margin-bottom: 2rem;
        }
        
        .portal-header h1 {
            color: #2d3748;
            margin-bottom: 0.5rem;
            font-size: 2rem;
        }
        
        .portal-header .subtitle {
            color: #4a5568;
            font-size: 0.9rem;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .security-badge {
            background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
            color: white;
            padding: 0.5rem 1rem;
            border-radius: 50px;
            font-size: 0.8rem;
            font-weight: 600;
            display: inline-block;
            margin: 1rem 0;
        }
        
        .login-form {
            display: flex;
            flex-direction: column;
            gap: 1.5rem;
        }
        
        .form-group {
            position: relative;
        }
        
        .form-group label {
            position: absolute;
            top: -0.5rem;
            left: 1rem;
            background: white;
            padding: 0 0.5rem;
            color: #4a5568;
            font-size: 0.8rem;
            font-weight: 600;
        }
        
        .form-group input {
            width: 100%;
            padding: 1rem 1.5rem;
            border: 2px solid #e2e8f0;
            border-radius: 12px;
            font-size: 1rem;
            transition: all 0.3s;
            background: rgba(255,255,255,0.8);
        }
        
        .form-group input:focus {
            outline: none;
            border-color: #667eea;
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
            background: white;
        }
        
        .login-btn {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 1rem 2rem;
            border: none;
            border-radius: 12px;
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .login-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 25px rgba(102, 126, 234, 0.3);
        }
        
        .message {
            margin: 1.5rem 0;
            padding: 1rem;
            border-radius: 12px;
            border-left: 4px solid;
        }
        
        .message.success {
            background: linear-gradient(135deg, #d4edda, #c3e6cb);
            border-color: #28a745;
            color: #155724;
        }
        
        .message.error {
            background: linear-gradient(135deg, #f8d7da, #f1b0b7);
            border-color: #dc3545;
            color: #721c24;
        }
        
        .message.warning {
            background: linear-gradient(135deg, #fff3cd, #ffeaa7);
            border-color: #ffc107;
            color: #856404;
        }
        
        .security-info {
            background: rgba(102, 126, 234, 0.1);
            padding: 1rem;
            border-radius: 8px;
            margin-top: 1rem;
            border-left: 4px solid #667eea;
        }
        
        .attempts-counter {
            text-align: center;
            color: #4a5568;
            font-size: 0.9rem;
            margin-top: 1rem;
        }
        
        .hints {
            background: rgba(255,255,255,0.9);
            padding: 1.5rem;
            border-radius: 12px;
            margin-top: 2rem;
            border: 1px solid rgba(102, 126, 234, 0.3);
        }
        
        .hints h3 {
            color: #2d3748;
            margin-bottom: 1rem;
        }
        
        .hints ul {
            margin: 0;
            padding-left: 1.5rem;
        }
        
        .hints li {
            margin-bottom: 0.5rem;
            color: #4a5568;
        }
        
        .code-example {
            background: #2d3748;
            color: #e2e8f0;
            padding: 0.8rem;
            border-radius: 8px;
            font-family: 'Courier New', monospace;
            margin: 0.5rem 0;
            overflow-x: auto;
            font-size: 0.9rem;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header" style="text-align: center; padding: 2rem; color: white;">
            <h1>🚪 Level 9 - Professional Admin Portal</h1>
            <p>The ultimate SQL injection challenge with multiple security layers</p>
            <a href="index.php" class="back-btn" style="color: white;">← Back to Labs</a>
        </div>
        
        <div class="admin-portal">
            <div class="portal-header">
                <h1>🏢 CyberCorp</h1>
                <div class="subtitle">Administrator Access Portal</div>
                <span class="security-badge">🛡️ Enhanced Security</span>
            </div>
            
            <div class="security-info">
                <strong>🔒 WAF Rules Active:</strong><br>
                • Blocked keywords: union, select, or, and, admin, --, #<br>
                • Quote removal: ' and " characters stripped<br>
                • Semicolon blocking: ; character removed<br>
                • Pattern detection: Suspicious SQL patterns flagged
            </div>
            
            <?php if ($message): ?>
                <div class="message <?= $success ? 'success' : ($show_hint ? 'warning' : 'error') ?>">
                    <?= $message ?>
                </div>
            <?php endif; ?>
            
            <form method="POST" class="login-form">
                <div class="form-group">
                    <label for="username">Administrator ID</label>
                    <input type="text" id="username" name="username" placeholder="Enter administrator username" required>
                </div>
                
                <div class="form-group">
                    <label for="password">Security Key</label>
                    <input type="password" id="password" name="password" placeholder="Enter security passphrase" required>
                </div>
                
                <button type="submit" class="login-btn">🚀 Authenticate</button>
            </form>
            
            <div class="attempts-counter">
                Security Check: <?= $_SESSION['attempts'] ?> authentication attempts
            </div>
        </div>
        
        <div class="hints">
            <h3>🎯 WAF Bypass Techniques:</h3>
            <ul>
                <li><strong>Case Variation:</strong> Try different cases - ADMIN, Admin, aDmIn</li>
                <li><strong>Encoding:</strong> Use hex, URL encoding, or double encoding</li>
                <li><strong>Comments:</strong> Use MySQL comments: /**/ or /*! */</li>
                <li><strong>Alternative Keywords:</strong> Instead of OR use ||, instead of AND use &&</li>
                <li><strong>Example 1:</strong> Hex encoding bypass</li>
            </ul>
            <div class="code-example">0x61646d696e</div>
            <ul>
                <li><strong>Example 2:</strong> Comment-based bypass</li>
            </ul>
            <div class="code-example">/**/aDmIn/**/ instead of admin</div>
            <ul>
                <li><strong>Example 3:</strong> Space alternative</li>
            </ul>
            <div class="code-example">Use /**/ or %20 instead of spaces</div>
            <ul>
                <li><strong>Key insight:</strong> You need to bypass WAF to inject admin into username field</li>
                <li><strong>Remember:</strong> Some bypasses work better in username vs password field</li>
            </ul>
        </div>
        
        <div class="navigation" style="text-align: center; margin-top: 2rem;">
            <a href="level8.php" style="color: white;">← Previous Level</a>
            <a href="level10.php" style="color: white;">Next Level →</a>
        </div>
    </div>
</body>
</html>

<?php $conn->close(); ?>