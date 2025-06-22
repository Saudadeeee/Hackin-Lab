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
    <title>SQLi Labs - Security Training Platform</title>
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
            <h1>🔒 SQL Injection Labs</h1>
            <p>A comprehensive platform for learning SQL injection techniques</p>
        </div>
        
        <div class="level-grid">
            <div class="level-card">
                <h3>🚨 Level 1 - Error Based</h3>
                <p>Learn the basics of error-based SQL injection by exploiting database error messages.</p>
                <a href="level1.php?id=1">Start Level 1</a>
            </div>
            
            <div class="level-card">
                <h3>🔗 Level 2 - UNION Based</h3>
                <p>Master UNION-based attacks to extract data from multiple tables.</p>
                <a href="level2.php?id=1">Start Level 2</a>
            </div>
            
            <div class="level-card">
                <h3>⚡ Level 3 - Stacked Queries</h3>
                <p>Execute multiple SQL statements in a single injection attack.</p>
                <a href="level3.php?id=1">Start Level 3</a>
            </div>
            
            <div class="level-card">
                <h3>🔍 Level 4 - Boolean Blind</h3>
                <p>Extract data using boolean-based blind injection techniques.</p>
                <a href="level4.php?cond=alice">Start Level 4</a>
            </div>
            
            <div class="level-card">
                <h3>⏰ Level 5 - Time Based</h3>
                <p>Use time delays to infer database information in blind scenarios.</p>
                <a href="level5.php?cond=alice">Start Level 5</a>
            </div>
            
            <div class="level-card">
                <h3>📁 Level 6 - Out-of-Band</h3>
                <p>Leverage file system operations for data extraction.</p>
                <a href="level6.php?cond=alice">Start Level 6</a>
            </div>
            
            <div class="level-card">
                <h3>🔄 Level 7 - Second Order</h3>
                <p>Exploit second-order injections through stored payloads.</p>
                <a href="level7_set.php?key=test&value=1">Setup</a> | <a href="level7.php?key=test">Execute</a>
            </div>
            
            <div class="level-card">
                <h3>🗂️ Level 8 - XPATH Injection</h3>
                <p>Attack applications using XPATH for XML data processing.</p>
                <a href="level8.php?user=admin&pass=test">Start Level 8</a>
            </div>
            
            <div class="level-card">
                <h3>🚪 Level 9 - Authentication Bypass</h3>
                <p>Bypass login mechanisms using SQL injection techniques.</p>
                <a href="level9.php">Start Level 9</a>
            </div>
            
            <div class="level-card">
                <h3>➕ Level 10 - INSERT Injection</h3>
                <p>Exploit vulnerabilities in INSERT statements.</p>
                <a href="level10.php">Start Level 10</a>
            </div>
            
            <div class="level-card">
                <h3>✏️ Level 11 - UPDATE Injection</h3>
                <p>Attack UPDATE statements to modify or extract data.</p>
                <a href="level11.php">Start Level 11</a>
            </div>
            
            <div class="level-card">
                <h3>🛡️ Level 12 - WAF Bypass</h3>
                <p>Learn techniques to bypass Web Application Firewalls.</p>
                <a href="level12.php?id=1">Start Level 12</a>
            </div>
            
            <div class="level-card">
                <h3>📋 Level 13 - JSON Injection</h3>
                <p>Exploit JSON-based query construction vulnerabilities.</p>
                <a href="level13.php?filter={&quot;username&quot;:&quot;alice&quot;}">Start Level 13</a>
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
