<?php
// Level 9: XPATH Injection - XML-based Authentication  
// Goal: Bypass XML-based authentication system using XPATH injection

session_start();

$message = "";
$success = false;

// XML user database (simulated)
$xml_data = '<?xml version="1.0"?>
<users>
    <user>
        <username>admin</username>
        <password>secret123</password>
        <role>administrator</role>
        <email>admin@company.com</email>
    </user>
    <user>
        <username>guest</username>
        <password>guest123</password>
        <role>user</role>
        <email>guest@company.com</email>
    </user>
    <user>
        <username>manager</username>
        <password>manage456</password>
        <role>manager</role>
        <email>manager@company.com</email>
    </user>
</users>';

if ($_POST) {
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';
    
    try {
        // Create XML document
        $xml = new DOMDocument();
        $xml->loadXML($xml_data);
        
        // Create XPath object
        $xpath = new DOMXPath($xml);
        
        // VULNERABLE XPATH query - directly concatenating user input
        $query = "//user[username/text()='{$username}' and password/text()='{$password}']";
        
        // Execute XPATH query
        $users = $xpath->query($query);
        
        if ($users && $users->length > 0) {
            $user = $users->item(0);
            $role = $xpath->query('role/text()', $user)->item(0)->nodeValue;
            $email = $xpath->query('email/text()', $user)->item(0)->nodeValue;
            
            if ($role === 'administrator') {
                $success = true;
                $message = "🎉 Excellent! You bypassed XPATH authentication!<br>";
                $message .= "🏁 <strong>FLAG: LEVEL8_XPATH_INJECTION_MASTER</strong><br>";
                $message .= "🔍 XPATH Query: <code>" . htmlspecialchars($query) . "</code><br>";
                $message .= "👑 Admin access granted! Email: " . htmlspecialchars($email);
            } else {
                $message = "✅ Login successful as: " . htmlspecialchars($username) . " (" . htmlspecialchars($role) . ")";
                $message .= "<br>📧 Email: " . htmlspecialchars($email);
                $message .= "<br>⚠️ You need administrator role to get the flag!";
            }
        } else {
            $message = "❌ Authentication failed: No matching user found";
            $message .= "<br>🔍 XPATH Query: <code>" . htmlspecialchars($query) . "</code>";
        }
        
    } catch (Exception $e) {
        $message = "💥 XPATH Error: " . $e->getMessage();
        $message .= "<br>🔍 XPATH Query: <code>" . htmlspecialchars($query ?? 'N/A') . "</code>";
        $message .= "<br>🎯 Error indicates successful injection attempt!";
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Level 8 - XPATH Authentication | SQL Injection Lab</title>
    <link rel="stylesheet" href="css/styles.css">
    <style>
        .xpath-container {
            max-width: 650px;
            margin: 2rem auto;
            background: #1a2332;
            color: #e2e8f0;
            padding: 2rem;
            border-radius: 16px;
            box-shadow: 0 8px 25px rgba(26, 35, 50, 0.4);
            border: 1px solid #2563eb;
        }
        
        .xml-viewer {
            background: #0f172a;
            border: 2px solid #1e40af;
            border-radius: 8px;
            padding: 1rem;
            margin: 1rem 0;
            color: #94a3b8;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.85rem;
            overflow-x: auto;
        }
        
        .xml-viewer .xml-tag {
            color: #60a5fa;
        }
        
        .xml-viewer .xml-content {
            color: #34d399;
        }
        
        .form-group input {
            background: #0f172a;
            color: #e2e8f0;
            border: 2px solid #1e40af;
        }
        
        .form-group input:focus {
            border-color: #3b82f6;
            box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.2);
        }
        
        .submit-btn {
            background: linear-gradient(135deg, #3b82f6 0%, #1e40af 100%);
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
            box-shadow: 0 6px 20px rgba(59, 130, 246, 0.4);
        }
        
        .xpath-info {
            background: #0f172a;
            border: 2px solid #2563eb;
            border-radius: 8px;
            padding: 1rem;
            margin: 1rem 0;
            color: #60a5fa;
        }
        
        body {
            background: linear-gradient(135deg, #0f172a 0%, #1a2332 100%);
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Level 8 - XPATH Authentication</h1>
            <p>Bypass XML-based authentication using XPATH injection techniques</p>
            <a href="index.php" class="back-btn">← Back to Labs</a>
        </div>
        
        <div class="xpath-container">
            <div class="xpath-info">
                <h4>🔍 XPATH Injection Challenge</h4>
                <p>This system uses XML database with XPATH queries for authentication.</p>
                <p><strong>Goal:</strong> Login as administrator to capture the flag!</p>
            </div>
            
            <div class="xml-viewer">
                <div class="xml-tag">&lt;users&gt;</div>
                <div style="margin-left: 1rem;">
                    <div class="xml-tag">&lt;user&gt;</div>
                    <div style="margin-left: 1rem;">
                        <div class="xml-tag">&lt;username&gt;</div><span class="xml-content">admin</span><div class="xml-tag">&lt;/username&gt;</div>
                        <div class="xml-tag">&lt;password&gt;</div><span class="xml-content">secret123</span><div class="xml-tag">&lt;/password&gt;</div>
                        <div class="xml-tag">&lt;role&gt;</div><span class="xml-content">administrator</span><div class="xml-tag">&lt;/role&gt;</div>
                    </div>
                    <div class="xml-tag">&lt;/user&gt;</div>
                    <div style="margin-top: 0.5rem; color: #64748b;">... more users ...</div>
                </div>
                <div class="xml-tag">&lt;/users&gt;</div>
            </div>
            
            <?php if ($message): ?>
                <div class="message <?= $success ? 'success' : 'error' ?>">
                    <?= $message ?>
                </div>
            <?php endif; ?>
            
            <h3>🔐 XML Authentication</h3>
            <form method="POST" class="login-form">
                <div class="form-group">
                    <label for="username">Username:</label>
                    <input type="text" id="username" name="username" placeholder="Enter username" required>
                </div>
                
                <div class="form-group">
                    <label for="password">Password:</label>
                    <input type="password" id="password" name="password" placeholder="Enter password" required>
                </div>
                
                <button type="submit" class="submit-btn">🚀 Authenticate</button>
            </form>
        </div>
        
        <div class="hints">
            <h3>💡 Hints for Level 8:</h3>
            <ul>
                <li><strong>XPATH Syntax:</strong> //user[username/text()='input' and password/text()='input']</li>
                <li><strong>Boolean Logic:</strong> Use 'or' operator to bypass authentication</li>
                <li><strong>Example Payload:</strong></li>
            </ul>
            <div class="code-example">
Username: admin' or '1'='1<br>
Password: anything
            </div>
            <ul>
                <li><strong>Alternative:</strong> Comment out password check</li>
                <li><strong>XPATH Comments:</strong> Use (: comment :) syntax</li>
                <li><strong>Goal:</strong> Make XPATH return the admin user node</li>
                <li><strong>Advanced:</strong> Try extracting specific admin data</li>
            </ul>
        </div>
        
        <div class="navigation">
            <a href="level7.php">← Previous Level</a>
            <a href="level9.php">Next Level →</a>
        </div>
    </div>
</body>
</html>