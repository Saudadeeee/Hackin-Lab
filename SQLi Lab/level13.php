<?php
// Level 13: Comment Bypass - Advanced Comment Filtering
// Goal: Bypass comment-based filtering to achieve admin access

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
$blocked_patterns = [];

if ($_POST) {
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';
    
    // Advanced comment filtering
    $dangerous_patterns = [
        '--',      // SQL line comments
        '#',       // MySQL hash comments  
        '/*',      // Block comment start
        '*/',      // Block comment end
        ';',       // Statement separator
    ];
    
    $input_blocked = false;
    foreach ($dangerous_patterns as $pattern) {
        if (stripos($username, $pattern) !== false || stripos($password, $pattern) !== false) {
            $blocked_patterns[] = $pattern;
            $input_blocked = true;
        }
    }
    
    if ($input_blocked) {
        $message = "🚫 Security Filter Triggered!<br>";
        $message .= "❌ Blocked patterns detected: " . implode(', ', array_unique($blocked_patterns)) . "<br>";
        $message .= "🛡️ Advanced comment filtering is active!";
    } else {
        // VULNERABLE query (if filters are bypassed)
        $sql = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";
        
        try {
            $result = $conn->query($sql);
            
            if ($result && $result->num_rows > 0) {
                $user_data = $result->fetch_assoc();
                
                if ($user_data['role'] === 'admin') {
                    $success = true;
                    $message = "🎉 Outstanding! You bypassed advanced comment filtering!<br>";
                    $message .= "🏁 <strong>FLAG: LEVEL13_COMMENT_BYPASS_NINJA</strong><br>";
                    $message .= "🔓 Bypassed filters: " . implode(', ', $dangerous_patterns) . "<br>";
                    $message .= "📝 SQL Query: <code>" . htmlspecialchars($sql) . "</code><br>";
                    $message .= "👑 Admin access granted!";
                } else {
                    $message = "✅ Login successful as: " . htmlspecialchars($user_data['username']) . " (" . htmlspecialchars($user_data['role']) . ")";
                    $message .= "<br>⚠️ You need admin role to get the flag!";
                }
            } else {
                $message = "❌ Authentication failed: No matching user found";
                $message .= "<br>📝 SQL Query: <code>" . htmlspecialchars($sql) . "</code>";
            }
            
        } catch (Exception $e) {
            $message = "💥 SQL Error: " . $e->getMessage();
            $message .= "<br>📝 SQL Query: <code>" . htmlspecialchars($sql) . "</code>";
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Level 13 - Comment Bypass | SQL Injection Lab</title>
    <link rel="stylesheet" href="css/styles.css">
    <style>
        .bypass-container {
            max-width: 700px;
            margin: 2rem auto;
            background: #2d1b2d;
            color: #e2e8f0;
            padding: 2rem;
            border-radius: 16px;
            box-shadow: 0 8px 25px rgba(45, 27, 45, 0.4);
            border: 1px solid #c084fc;
        }
        
        .security-filters {
            background: #1a0f1a;
            border: 2px solid #c084fc;
            border-radius: 8px;
            padding: 1rem;
            margin: 1rem 0;
            color: #ddd6fe;
        }
        
        .blocked-pattern {
            display: inline-block;
            background: #dc2626;
            color: white;
            padding: 0.3rem 0.6rem;
            margin: 0.2rem;
            border-radius: 4px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.85rem;
        }
        
        .form-group input {
            background: #1a0f1a;
            color: #e2e8f0;
            border: 2px solid #c084fc;
        }
        
        .form-group input:focus {
            border-color: #e879f9;
            box-shadow: 0 0 0 3px rgba(232, 121, 249, 0.2);
        }
        
        .submit-btn {
            background: linear-gradient(135deg, #c084fc 0%, #a855f7 100%);
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
            box-shadow: 0 6px 20px rgba(192, 132, 252, 0.4);
        }
        
        .bypass-info {
            background: #1a0f1a;
            border: 2px solid #c084fc;
            border-radius: 8px;
            padding: 1rem;
            margin: 1rem 0;
            color: #ddd6fe;
        }
        
        body {
            background: linear-gradient(135deg, #1a0f1a 0%, #2d1b2d 100%);
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🚫 Level 13 - Comment Bypass</h1>
            <p>Bypass advanced comment filtering to achieve admin access</p>
            <a href="index.php" class="back-btn">← Back to Labs</a>
        </div>
        
        <div class="bypass-container">
            <div class="bypass-info">
                <h4>🚫 Comment Bypass Challenge</h4>
                <p>This system has advanced filtering that blocks common comment techniques.</p>
                <p><strong>Goal:</strong> Bypass comment filters and login as admin!</p>
            </div>
            
            <div class="security-filters">
                <h4>🛡️ Active Security Filters</h4>
                <p>The following patterns are blocked:</p>
                <span class="blocked-pattern">--</span>
                <span class="blocked-pattern">#</span>
                <span class="blocked-pattern">/*</span>
                <span class="blocked-pattern">*/</span>
                <span class="blocked-pattern">;</span>
            </div>
            
            <?php if ($message): ?>
                <div class="message <?= $success ? 'success' : 'error' ?>">
                    <?= $message ?>
                </div>
            <?php endif; ?>
            
            <h3>🔐 Secure Login</h3>
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
        </div>
        
        <div class="hints">
            <h3>💡 Hints for Level 13:</h3>
            <ul>
                <li><strong>Challenge:</strong> Common comment syntax is blocked: --, #, /*, */</li>
                <li><strong>Goal:</strong> Bypass password check without using blocked characters</li>
                <li><strong>Method 1:</strong> Use OR condition without comments</li>
                <li><strong>Example Payload:</strong></li>
            </ul>
            <div class="code-example">
Username: admin' OR 'x'='x<br>
Password: anything
            </div>
            <ul>
                <li><strong>Method 2:</strong> Use UNION SELECT without comments</li>
                <li><strong>Alternative:</strong> Balance quotes without terminating</li>
                <li><strong>Advanced:</strong> Use nested quotes and logical operators</li>
                <li><strong>Key Insight:</strong> You don't always need comments to terminate queries</li>
                <li><strong>Remember:</strong> Make both conditions true without comment termination</li>
            </ul>
        </div>
        
        <div class="navigation">
            <a href="level12.php">← Previous Level</a>
            <a href="level14.php">Next Level →</a>
        </div>
    </div>
</body>
</html>

<?php $conn->close(); ?>