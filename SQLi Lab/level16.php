<?php
// Level 16: Advanced WAF Bypass - Final Boss Challenge
// Goal: Bypass multiple sophisticated filtering mechanisms

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
$waf_bypass_achieved = false;

if ($_POST) {
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';
    
    // Advanced WAF simulation with multiple filter layers
    $original_input = "Username: $username | Password: $password";
    
    // Layer 1: Comment filtering
    $comment_patterns = ['--', '#', '/*', '*/'];
    $has_comments = false;
    foreach ($comment_patterns as $pattern) {
        if (stripos($username . $password, $pattern) !== false) {
            $blocked_patterns[] = "Comment: $pattern";
            $has_comments = true;
        }
    }
    
    // Layer 2: Common SQL keywords
    $sql_keywords = ['UNION', 'SELECT', 'FROM', 'WHERE', 'INSERT', 'UPDATE', 'DELETE', 'DROP'];
    $has_keywords = false;
    foreach ($sql_keywords as $keyword) {
        if (stripos($username . $password, $keyword) !== false) {
            $blocked_patterns[] = "Keyword: $keyword";
            $has_keywords = true;
        }
    }
    
    // Layer 3: Special characters
    $special_chars = ["'", '"', '=', '<', '>', '(', ')'];
    $has_special = false;
    foreach ($special_chars as $char) {
        if (strpos($username . $password, $char) !== false) {
            $blocked_patterns[] = "Special: $char";
            $has_special = true;
        }
    }
    
    // Layer 4: Logical operators
    $logical_ops = ['OR', 'AND', 'NOT'];
    $has_logical = false;
    foreach ($logical_ops as $op) {
        if (stripos($username . $password, $op) !== false) {
            $blocked_patterns[] = "Logic: $op";
            $has_logical = true;
        }
    }
    
    // Layer 5: Space and whitespace
    $has_spaces = false;
    if (preg_match('/\s/', $username . $password)) {
        $blocked_patterns[] = "Whitespace detected";
        $has_spaces = true;
    }
    
    // Calculate WAF bypass score
    $total_filters = 5;
    $triggered_filters = ($has_comments ? 1 : 0) + ($has_keywords ? 1 : 0) + 
                        ($has_special ? 1 : 0) + ($has_logical ? 1 : 0) + ($has_spaces ? 1 : 0);
    
    if ($triggered_filters > 0) {
        $message = "🛡️ Advanced WAF Protection Triggered!<br>";
        $message .= "❌ Blocked patterns: " . implode(', ', $blocked_patterns) . "<br>";
        $message .= "📊 Filters triggered: $triggered_filters/$total_filters<br>";
        $message .= "🎯 You need to bypass ALL filters to proceed!<br>";
        $message .= "💡 Try more sophisticated encoding, alternatives, or creative bypasses!";
    } else {
        $waf_bypass_achieved = true;
        
        // If all filters are bypassed, check for actual injection
        $sql = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";
        
        try {
            $result = $conn->query($sql);
            
            if ($result && $result->num_rows > 0) {
                $user_data = $result->fetch_assoc();
                
                if ($user_data['role'] === 'admin') {
                    $success = true;
                    $message = "🎉🎉 ULTIMATE VICTORY! You defeated the Advanced WAF! 🎉🎉<br>";
                    $message .= "🏆 <strong>FLAG: LEVEL16_ADVANCED_WAF_BYPASS_CHAMPION</strong><br>";
                    $message .= "🛡️ All WAF filters bypassed successfully!<br>";
                    $message .= "📝 SQL Query: <code>" . htmlspecialchars($sql) . "</code><br>";
                    $message .= "👑 You are now a SQL Injection Grandmaster!<br>";
                    $message .= "🌟 Congratulations on completing all 16 levels!";
                } else {
                    $message = "🟡 WAF Bypassed but injection failed!<br>";
                    $message .= "✅ Login successful as: " . htmlspecialchars($user_data['username']) . " (" . htmlspecialchars($user_data['role']) . ")<br>";
                    $message .= "⚠️ You bypassed the WAF but need admin access for the final flag!";
                }
            } else {
                $message = "🟡 WAF Bypassed but authentication failed!<br>";
                $message .= "✅ All filters bypassed successfully!<br>";
                $message .= "❌ No matching user found<br>";
                $message .= "📝 SQL Query: <code>" . htmlspecialchars($sql) . "</code><br>";
                $message .= "💡 Try adjusting your payload to match admin credentials!";
            }
            
        } catch (Exception $e) {
            $message = "🟡 WAF Bypassed but SQL error occurred!<br>";
            $message .= "✅ All filters bypassed successfully!<br>";
            $message .= "💥 SQL Error: " . $e->getMessage() . "<br>";
            $message .= "📝 SQL Query: <code>" . htmlspecialchars($sql) . "</code>";
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Level 16 - Advanced WAF Bypass | SQL Injection Lab</title>
    <link rel="stylesheet" href="css/styles.css">
    <style>
        .waf-container {
            max-width: 800px;
            margin: 2rem auto;
            background: #0f0f0f;
            color: #e2e8f0;
            padding: 2rem;
            border-radius: 16px;
            box-shadow: 0 8px 25px rgba(15, 15, 15, 0.6);
            border: 2px solid #dc2626;
        }
        
        .waf-status {
            background: #1a0000;
            border: 2px solid #dc2626;
            border-radius: 8px;
            padding: 1rem;
            margin: 1rem 0;
            color: #fca5a5;
            text-align: center;
            font-weight: bold;
            animation: pulse 2s infinite;
        }
        
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.7; }
        }
        
        .filter-layers {
            background: #1a0000;
            border: 2px solid #dc2626;
            border-radius: 8px;
            padding: 1rem;
            margin: 1rem 0;
            color: #fca5a5;
        }
        
        .filter-layer {
            margin: 0.5rem 0;
            padding: 0.5rem;
            background: #0f0f0f;
            border-radius: 4px;
            border-left: 3px solid #dc2626;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.85rem;
        }
        
        .form-group input {
            background: #1a0000;
            color: #e2e8f0;
            border: 2px solid #dc2626;
        }
        
        .form-group input:focus {
            border-color: #ef4444;
            box-shadow: 0 0 0 3px rgba(239, 68, 68, 0.2);
        }
        
        .submit-btn {
            background: linear-gradient(135deg, #dc2626 0%, #991b1b 100%);
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
            box-shadow: 0 6px 20px rgba(220, 38, 38, 0.4);
        }
        
        .waf-info {
            background: #1a0000;
            border: 2px solid #dc2626;
            border-radius: 8px;
            padding: 1rem;
            margin: 1rem 0;
            color: #fca5a5;
        }
        
        .final-boss {
            text-align: center;
            background: linear-gradient(135deg, #dc2626, #991b1b);
            color: white;
            padding: 1rem;
            border-radius: 8px;
            margin: 1rem 0;
            font-weight: bold;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.5);
        }
        
        body {
            background: linear-gradient(135deg, #0f0f0f 0%, #1a0000 50%, #0f0f0f 100%);
            background-size: 400% 400%;
            animation: gradientShift 6s ease infinite;
        }
        
        @keyframes gradientShift {
            0%, 100% { background-position: 0% 50%; }
            50% { background-position: 100% 50%; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Level 16 - Advanced WAF Bypass</h1>
            <p>The ultimate challenge - bypass sophisticated Web Application Firewall</p>
            <a href="index.php" class="back-btn">← Back to Labs</a>
        </div>
        
        <div class="final-boss">
            🏆 FINAL BOSS CHALLENGE 🏆<br>
            Advanced WAF Protection System
        </div>
        
        <div class="waf-container">
            <div class="waf-info">
                <h4>🛡️ Advanced WAF Challenge</h4>
                <p>This is the final challenge! You must bypass ALL layers of protection.</p>
                <p><strong>Goal:</strong> Achieve admin access while bypassing every security filter!</p>
            </div>
            
            <div class="waf-status">
                🚨 ADVANCED WAF PROTECTION ACTIVE 🚨<br>
                Multiple Security Layers Engaged
            </div>
            
            <div class="filter-layers">
                <h4>🔒 Active Security Filters:</h4>
                
                <div class="filter-layer">
                    <strong>Layer 1:</strong> Comment Detection (blocks: --, #, /*, */)
                </div>
                
                <div class="filter-layer">
                    <strong>Layer 2:</strong> SQL Keyword Filtering (blocks: UNION, SELECT, FROM, WHERE, etc.)
                </div>
                
                <div class="filter-layer">
                    <strong>Layer 3:</strong> Special Character Detection (blocks: ', ", =, <, >, (, ))
                </div>
                
                <div class="filter-layer">
                    <strong>Layer 4:</strong> Logical Operator Filtering (blocks: OR, AND, NOT)
                </div>
                
                <div class="filter-layer">
                    <strong>Layer 5:</strong> Whitespace Detection (blocks: spaces, tabs, newlines)
                </div>
            </div>
            
            <?php if ($message): ?>
                <div class="message <?= $success ? 'success' : ($waf_bypass_achieved ? 'warning' : 'error') ?>">
                    <?= $message ?>
                </div>
            <?php endif; ?>
            
            <h3>🔐 Ultimate Login Challenge</h3>
            <form method="POST" class="login-form">
                <div class="form-group">
                    <label for="username">Username:</label>
                    <input type="text" id="username" name="username" placeholder="Bypass ALL filters..." required>
                </div>
                
                <div class="form-group">
                    <label for="password">Password:</label>
                    <input type="text" id="password" name="password" placeholder="Ultimate challenge awaits..." required>
                </div>
                
                <button type="submit" class="submit-btn">🚀 Face the Final Boss</button>
            </form>
        </div>
        
        <div class="hints">
            <h3>💡 Hints for Level 16 (Final Boss):</h3>
            <ul>
                <li><strong>Ultimate Challenge:</strong> Must bypass ALL 5 filter layers simultaneously</li>
                <li><strong>No Easy Path:</strong> Standard techniques won't work here</li>
                <li><strong>Think Creative:</strong> Combine multiple advanced bypass techniques</li>
                <li><strong>Possible Approaches:</strong></li>
            </ul>
            <div class="code-example">
<strong>Approach 1 - Advanced Encoding:</strong><br>
Use hex encoding, Unicode, double encoding<br><br>

<strong>Approach 2 - Alternative Functions:</strong><br>
Use MySQL functions like SUBSTR, ASCII, CHAR<br><br>

<strong>Approach 3 - Conditional Techniques:</strong><br>
Use IF statements, CASE expressions<br><br>

<strong>Approach 4 - Mathematical Operations:</strong><br>
Use arithmetic to create logical conditions<br><br>

<strong>Expert Level:</strong> Try combining all previous level techniques!
            </div>
            <ul>
                <li><strong>Remember:</strong> You've learned 15 different techniques - use them all!</li>
                <li><strong>Final Tip:</strong> Sometimes the simplest bypass is the most effective</li>
                <li><strong>Victory Condition:</strong> Login as admin while bypassing every filter</li>
            </ul>
        </div>
        
        <div class="navigation">
            <a href="level15.php">← Previous Level</a>
            <span style="color: #fca5a5;">🏆 Final Challenge! 🏆</span>
        </div>
    </div>
</body>
</html>

<?php $conn->close(); ?>