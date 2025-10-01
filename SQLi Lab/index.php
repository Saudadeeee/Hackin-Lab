<?php
// Database connection
$host = $_ENV['DB_HOST'] ?? 'db';
$user = $_ENV['DB_USER'] ?? 'root'; 
$pass = $_ENV['DB_PASS'] ?? 'rootpassword';
$dbname = $_ENV['DB_NAME'] ?? 'sqli_lab';

$conn = new mysqli($host, $user, $pass, $dbname);

if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login Challenge Labs - SQL Injection Training</title>
    <link rel="stylesheet" href="css/styles.css">
    <style>
    .level-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
        gap: 2rem;
        margin: 2rem 0;
    }
    
    .level-card {
        background: #faf7f0;
        padding: 2rem;
        border-radius: 16px;
        box-shadow: 0 6px 20px rgba(0,0,0,0.1);
        border: 2px solid #e8dcc6;
        transition: all 0.3s ease;
    }
    
    .level-card:hover {
        transform: translateY(-4px);
        box-shadow: 0 8px 25px rgba(0,0,0,0.15);
    }
    
    .level-card h3 {
        color: #2c2c2c;
        margin-bottom: 1rem;
        font-size: 1.3rem;
        font-weight: 600;
    }
    
    .level-card p {
        color: #4a4a4a;
        margin-bottom: 1.5rem;
        line-height: 1.6;
    }
    
    .level-card a {
        background: linear-gradient(135deg, #4299e1 0%, #3182ce 100%);
        color: white;
        padding: 0.8rem 1.5rem;
        text-decoration: none;
        border-radius: 8px;
        display: inline-block;
        transition: all 0.3s ease;
        font-weight: 500;
        box-shadow: 0 4px 15px rgba(66, 153, 225, 0.3);
    }
    
    .level-card a:hover {
        background: linear-gradient(135deg, #3182ce 0%, #2c5282 100%);
        transform: translateY(-2px);
        box-shadow: 0 6px 20px rgba(66, 153, 225, 0.4);
    }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 Login Challenge Labs</h1>
            <p>Master SQL injection through realistic login forms - 16 levels of increasing difficulty</p>
        </div>
        
        <div class="level-grid">
            <div class="level-card">
                <h3>🚨 Level 1 - Basic Login</h3>
                <p>Simple login form with error messages. Perfect for beginners to understand SQL injection.</p>
                <a href="level1.php">Start Level 1</a>
            </div>
            
            <div class="level-card">
                <h3>🔗 Level 2 - Union Login</h3>
                <p>Login form vulnerable to UNION-based attacks. Extract user data through login bypass.</p>
                <a href="level2.php">Start Level 2</a>
            </div>
            
            <div class="level-card">
                <h3>⚡ Level 3 - Stacked Query Login</h3>
                <p>Advanced login that allows multiple SQL statements. Execute system commands.</p>
                <a href="level3.php">Start Level 3</a>
            </div>
            
            <div class="level-card">
                <h3>🔍 Level 4 - Blind Login</h3>
                <p>Login with no error messages. Use boolean-based blind techniques to extract data.</p>
                <a href="level4.php">Start Level 4</a>
            </div>
            
            <div class="level-card">
                <h3>⏰ Level 5 - Time-Based Login</h3>
                <p>Login vulnerable to time-based blind injection. Use delays to infer information.</p>
                <a href="level5.php">Start Level 5</a>
            </div>
            
            <div class="level-card">
                <h3>📁 Level 6 - File Upload Login</h3>
                <p>Login with file operations. Extract data through file system manipulation.</p>
                <a href="level6.php">Start Level 6</a>
            </div>
            
            <div class="level-card">
                <h3>🔄 Level 7 - Second Order Login</h3>
                <p>Registration + Login system vulnerable to second-order injection attacks.</p>
                <a href="level7.php">Start Level 7</a>
            </div>
            
            <div class="level-card">
                <h3>🗂️ Level 8 - XML Login</h3>
                <p>Login system using XML data processing. Exploit XPATH injection vulnerabilities.</p>
                <a href="level8.php">Start Level 8</a>
            </div>
            
            <div class="level-card">
                <h3>🚪 Level 9 - Admin Portal</h3>
                <p>Professional admin login interface. Multiple security layers to bypass.</p>
                <a href="level9.php">Start Level 9</a>
            </div>
            
            <div class="level-card">
                <h3>➕ Level 10 - Registration Login</h3>
                <p>Registration form with INSERT injection. Create accounts to bypass authentication.</p>
                <a href="level10.php">Start Level 10</a>
            </div>
            
            <div class="level-card">
                <h3>✏️ Level 11 - Profile Update Login</h3>
                <p>Login with profile update functionality. Exploit UPDATE statement vulnerabilities.</p>
                <a href="level11.php">Start Level 11</a>
            </div>
            
            <div class="level-card">
                <h3>🛡️ Level 12 - WAF Protected Login</h3>
                <p>Login protected by Web Application Firewall. Learn advanced bypass techniques.</p>
                <a href="level12.php">Start Level 12</a>
            </div>
            
            <div class="level-card">
                <h3>📋 Level 13 - JSON API Login</h3>
                <p>Modern API-based login using JSON. Exploit JSON injection vulnerabilities.</p>
                <a href="level13.php">Start Level 13</a>
            </div>
            
            <div class="level-card">
                <h3>💬 Level 14 - Comment Filtered Login</h3>
                <p>Login with comment-based filters. Use SQL comments to bypass keyword detection.</p>
                <a href="level14.php">Start Level 14</a>
            </div>
            
            <div class="level-card">
                <h3>🔤 Level 15 - Encoded Login</h3>
                <p>Login with character encoding filters. Master various encoding bypass techniques.</p>
                <a href="level15.php">Start Level 15</a>
            </div>
            
            <div class="level-card">
                <h3>🚀 Level 16 - Space Filtered Login</h3>
                <p>Elite challenge: Login with space character filters. Ultimate bypass techniques.</p>
                <a href="level16.php">Start Level 16</a>
            </div>
        </div>
        
        <div class="navigation">
            <a href="sandbox.php">🔬 SQL Sandbox</a>
            <a href="submit.php?level=1">🏆 Submit Flags</a>
        </div>
    </div>
</body>
</html>

<?php
$conn->close();
?>
