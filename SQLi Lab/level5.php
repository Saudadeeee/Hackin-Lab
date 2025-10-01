<?php
// Level 5: Blind Login - Boolean Based Injection
// Goal: Extract admin credentials using blind injection techniques

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

if ($_POST) {
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';
    
    // True blind injection - only boolean response, no data leakage
    $sql = "SELECT COUNT(*) as count FROM users WHERE username = '$username' AND password = '$password' AND role = 'admin'";
    
    try {
        $result = $conn->query($sql);
        if ($result) {
            $count = $result->fetch_assoc()['count'];
            if ($count > 0) {
                $success = true;
                $message = "🎉 Incredible! You cracked the blind injection and logged in as admin!<br>";
                $message .= "🏁 <strong>FLAG: LEVEL4_BLIND_INJECTION_EXPERT</strong><br>";
                $message .= "This required patience and skill to extract data without seeing it!";
            } else {
                $message = "❌ Access denied";
            }
        } else {
            $message = "❌ Access denied";
        }
    } catch (Exception $e) {
        // No error details in blind injection
        $message = "❌ Access denied";
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Level 4 - Blind Login | SQL Injection Lab</title>
    <link rel="stylesheet" href="css/styles.css">
    <style>
        .login-container {
            max-width: 600px;
            margin: 2rem auto;
            background: #1a1a1a;
            color: #e2e8f0;
            padding: 2rem;
            border-radius: 16px;
            box-shadow: 0 8px 25px rgba(0,0,0,0.3);
            border: 1px solid #333;
        }
        
        .login-form {
            display: flex;
            flex-direction: column;
            gap: 1rem;
        }
        
        .form-group {
            display: flex;
            flex-direction: column;
            gap: 0.5rem;
        }
        
        .form-group label {
            font-weight: 600;
            color: #e2e8f0;
        }
        
        .form-group input {
            padding: 0.8rem;
            border: 2px solid #444;
            border-radius: 8px;
            font-size: 1rem;
            background: #2d2d2d;
            color: #e2e8f0;
            transition: border-color 0.3s;
        }
        
        .form-group input:focus {
            outline: none;
            border-color: #4299e1;
            box-shadow: 0 0 0 3px rgba(66, 153, 225, 0.2);
        }
        
        .login-btn {
            background: linear-gradient(135deg, #e53e3e 0%, #c53030 100%);
            color: white;
            padding: 1rem;
            border: none;
            border-radius: 8px;
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s;
        }
        
        .login-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(229, 62, 62, 0.4);
        }
        
        .message {
            margin: 1rem 0;
            padding: 1rem;
            border-radius: 8px;
            border-left: 4px solid;
        }
        
        .message.success {
            background: #1a2e1a;
            border-color: #38a169;
            color: #68d391;
        }
        
        .message.error {
            background: #2d1b1b;
            border-color: #e53e3e;
            color: #fc8181;
        }
        
        .blind-notice {
            background: #2d1b1b;
            border: 2px solid #e53e3e;
            border-radius: 8px;
            padding: 1rem;
            margin: 1rem 0;
            color: #fc8181;
        }
        
        .blind-notice h4 {
            color: #e53e3e;
            margin: 0 0 0.5rem 0;
        }
        
        .hints {
            background: #2a2a2a;
            padding: 1.5rem;
            border-radius: 8px;
            margin-top: 2rem;
            border: 2px solid #444;
        }
        
        .hints h3 {
            color: #e2e8f0;
            margin-bottom: 1rem;
        }
        
        .hints ul {
            margin: 0;
            padding-left: 1.5rem;
        }
        
        .hints li {
            margin-bottom: 0.5rem;
            color: #a0aec0;
        }
        
        .code-example {
            background: #1a1a1a;
            color: #e2e8f0;
            padding: 1rem;
            border-radius: 8px;
            font-family: 'Courier New', monospace;
            margin: 0.5rem 0;
            overflow-x: auto;
            border: 1px solid #444;
        }
        
        body {
            background: #0f0f0f;
        }
        
        .container {
            background: #1a1a1a;
        }
        
        .header h1 {
            color: #e2e8f0;
        }
        
        .header p {
            color: #a0aec0;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Level 4 - Blind Login</h1>
            <p>No error messages, no data leakage - pure blind injection challenge</p>
            <a href="index.php" class="back-btn">← Back to Labs</a>
        </div>
        
        <div class="login-container">
            <h2>🕶️ Secure Government Portal</h2>
            <p><strong>Objective:</strong> Extract admin credentials using boolean-based blind injection</p>
            
            <div class="blind-notice">
                <h4>🚨 Maximum Security Mode</h4>
                <p>This system provides NO feedback about SQL errors or data. You'll only get "Access denied" or successful login.</p>
            </div>
            
            <?php if ($message): ?>
                <div class="message <?= $success ? 'success' : 'error' ?>">
                    <?= $message ?>
                </div>
            <?php endif; ?>
            
            <form method="POST" class="login-form">
                <div class="form-group">
                    <label for="username">Username:</label>
                    <input type="text" id="username" name="username" placeholder="Enter username" required>
                </div>
                
                <div class="form-group">
                    <label for="password">Password:</label>
                    <input type="password" id="password" name="password" placeholder="Enter password" required>
                </div>
                
                <button type="submit" class="login-btn">🚀 Login</button>
            </form>
        </div>
        
        <div class="hints">
            <h3>💡 Hints for Level 4:</h3>
            <ul>
                <li><strong>True Blind:</strong> You must know exact admin username AND password</li>
                <li><strong>Boolean Logic:</strong> Use conditions that return TRUE or FALSE</li>
                <li><strong>Extract Admin Password:</strong> Use boolean conditions to extract password character by character</li>
                <li><strong>Example 1:</strong> Test if admin password starts with 'a'</li>
            </ul>
            <div class="code-example">admin' AND (SELECT SUBSTR(password,1,1) FROM users WHERE username='admin')='a'--</div>
            <ul>
                <li><strong>Example 2:</strong> Test password length</li>
            </ul>
            <div class="code-example">admin' AND (SELECT LENGTH(password) FROM users WHERE username='admin')>5--</div>
            <ul>
                <li><strong>Example 3:</strong> Extract character using ASCII</li>
            </ul>
            <div class="code-example">admin' AND (SELECT ASCII(SUBSTR(password,1,1)) FROM users WHERE username='admin')>97--</div>
            <ul>
                <li><strong>Automation:</strong> Best solved with tools like sqlmap or custom scripts</li>
                <li><strong>Manual:</strong> Try common passwords: admin, password, admin123, root</li>
                <li><strong>Hint:</strong> Admin password is 'admin123' - but you must discover this through blind injection!</li>
            </ul>
        </div>
        
        <div class="navigation">
            <a href="level3.php">← Previous Level</a>
            <a href="level5.php">Next Level →</a>
        </div>
    </div>
</body>
</html>

<?php $conn->close(); ?>