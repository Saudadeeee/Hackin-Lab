<?php
// Level 14: Encoding Bypass - URL/HTML Entity Filtering
// Goal: Bypass encoding-based input filtering

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
$raw_input = "";
$decoded_input = "";

if ($_POST) {
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';
    
    $raw_input = "Username: " . htmlspecialchars($username) . " | Password: " . htmlspecialchars($password);
    
    // Decode URL encoding and HTML entities
    $username = urldecode($username);
    $username = html_entity_decode($username, ENT_QUOTES);
    $password = urldecode($password);
    $password = html_entity_decode($password, ENT_QUOTES);
    
    $decoded_input = "Username: " . htmlspecialchars($username) . " | Password: " . htmlspecialchars($password);
    
    // Basic filtering on decoded input
    $dangerous_chars = ["'", '"', '=', 'OR', 'UNION', 'SELECT'];
    $blocked_chars = [];
    
    foreach ($dangerous_chars as $char) {
        if (stripos($username . $password, $char) !== false) {
            $blocked_chars[] = $char;
        }
    }
    
    if (!empty($blocked_chars)) {
        $message = "🚫 Security Filter Triggered!<br>";
        $message .= "❌ Dangerous characters detected after decoding: " . implode(', ', $blocked_chars) . "<br>";
        $message .= "🔍 Raw Input: <code>" . $raw_input . "</code><br>";
        $message .= "🔓 Decoded Input: <code>" . $decoded_input . "</code><br>";
        $message .= "🛡️ Try encoding your payload to bypass filters!";
    } else {
        // VULNERABLE query (if filters are bypassed)
        $sql = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";
        
        try {
            $result = $conn->query($sql);
            
            if ($result && $result->num_rows > 0) {
                $user_data = $result->fetch_assoc();
                
                if ($user_data['role'] === 'admin') {
                    $success = true;
                    $message = "🎉 Brilliant! You bypassed encoding-based filtering!<br>";
                    $message .= "🏁 <strong>FLAG: LEVEL14_ENCODING_BYPASS_EXPERT</strong><br>";
                    $message .= "🔍 Raw Input: <code>" . $raw_input . "</code><br>";
                    $message .= "🔓 Decoded Input: <code>" . $decoded_input . "</code><br>";
                    $message .= "📝 SQL Query: <code>" . htmlspecialchars($sql) . "</code><br>";
                    $message .= "👑 Admin access granted through encoding bypass!";
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
    <title>Level 14 - Encoding Bypass | SQL Injection Lab</title>
    <link rel="stylesheet" href="css/styles.css">
    <style>
        .encoding-container {
            max-width: 750px;
            margin: 2rem auto;
            background: #1c1917;
            color: #e2e8f0;
            padding: 2rem;
            border-radius: 16px;
            box-shadow: 0 8px 25px rgba(28, 25, 23, 0.4);
            border: 1px solid #f59e0b;
        }
        
        .encoding-examples {
            background: #0c0a09;
            border: 2px solid #f59e0b;
            border-radius: 8px;
            padding: 1rem;
            margin: 1rem 0;
            color: #fbbf24;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.85rem;
        }
        
        .form-group input {
            background: #0c0a09;
            color: #e2e8f0;
            border: 2px solid #f59e0b;
        }
        
        .form-group input:focus {
            border-color: #fbbf24;
            box-shadow: 0 0 0 3px rgba(251, 191, 36, 0.2);
        }
        
        .submit-btn {
            background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%);
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
            box-shadow: 0 6px 20px rgba(245, 158, 11, 0.4);
        }
        
        .encoding-info {
            background: #0c0a09;
            border: 2px solid #f59e0b;
            border-radius: 8px;
            padding: 1rem;
            margin: 1rem 0;
            color: #fbbf24;
        }
        
        .encoder-tool {
            background: #0c0a09;
            border: 2px solid #d97706;
            border-radius: 8px;
            padding: 1rem;
            margin: 1rem 0;
        }
        
        .encoder-tool input {
            background: #1c1917;
            color: #e2e8f0;
            border: 1px solid #f59e0b;
            padding: 0.5rem;
            margin: 0.25rem;
            border-radius: 4px;
            width: 100%;
        }
        
        .encode-btn {
            background: #d97706;
            color: white;
            border: none;
            padding: 0.5rem 1rem;
            border-radius: 4px;
            cursor: pointer;
            margin: 0.25rem;
            font-size: 0.9rem;
        }
        
        body {
            background: linear-gradient(135deg, #0c0a09 0%, #1c1917 100%);
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔤 Level 14 - Encoding Bypass</h1>
            <p>Bypass input filtering using URL encoding and HTML entities</p>
            <a href="index.php" class="back-btn">← Back to Labs</a>
        </div>
        
        <div class="encoding-container">
            <div class="encoding-info">
                <h4>🔤 Encoding Bypass Challenge</h4>
                <p>This system decodes URL encoding and HTML entities before applying filters.</p>
                <p><strong>Goal:</strong> Encode your payload to bypass character filtering!</p>
            </div>
            
            <div class="encoding-examples">
                <strong>🔧 Encoding Examples:</strong><br>
                <strong>Single Quote:</strong> ' → %27 (URL) → &#39; (HTML)<br>
                <strong>Double Quote:</strong> " → %22 (URL) → &quot; (HTML)<br>
                <strong>Equals:</strong> = → %3D (URL) → &#61; (HTML)<br>
                <strong>Space:</strong> (space) → %20 (URL) → &#32; (HTML)<br>
                <strong>OR:</strong> OR → %4F%52 (URL) → &#79;&#82; (HTML)
            </div>
            
            <div class="encoder-tool">
                <h4>🛠️ Payload Encoder Tool</h4>
                <input type="text" id="plain-text" placeholder="Enter text to encode...">
                <button class="encode-btn" onclick="urlEncode()">URL Encode</button>
                <button class="encode-btn" onclick="htmlEncode()">HTML Encode</button>
                <button class="encode-btn" onclick="clearEncoder()">Clear</button>
                <input type="text" id="encoded-text" placeholder="Encoded result..." readonly>
            </div>
            
            <?php if ($message): ?>
                <div class="message <?= $success ? 'success' : 'error' ?>">
                    <?= $message ?>
                </div>
            <?php endif; ?>
            
            <h3>🔐 Encoded Login</h3>
            <form method="POST" class="login-form">
                <div class="form-group">
                    <label for="username">Username:</label>
                    <input type="text" id="username" name="username" placeholder="Enter username (can be encoded)" required>
                </div>
                
                <div class="form-group">
                    <label for="password">Password:</label>
                    <input type="text" id="password" name="password" placeholder="Enter password (can be encoded)" required>
                </div>
                
                <button type="submit" class="submit-btn">🚀 Login</button>
            </form>
        </div>
        
        <div class="hints">
            <h3>💡 Hints for Level 14:</h3>
            <ul>
                <li><strong>Challenge:</strong> Filters check for: ', ", =, OR, UNION, SELECT after decoding</li>
                <li><strong>Solution:</strong> URL encode or HTML encode your malicious characters</li>
                <li><strong>Example Payload (URL Encoded):</strong></li>
            </ul>
            <div class="code-example">
Username: admin%27%20%4F%52%20%27x%27%3D%27x<br>
Password: anything<br>
<em>(Decodes to: admin' OR 'x'='x)</em>
            </div>
            <ul>
                <li><strong>Alternative (HTML Entities):</strong></li>
            </ul>
            <div class="code-example">
Username: admin&#39;&#32;&#79;&#82;&#32;&#39;x&#39;&#61;&#39;x<br>
Password: anything<br>
<em>(Decodes to: admin' OR 'x'='x)</em>
            </div>
            <ul>
                <li><strong>Mix Encoding:</strong> Combine URL and HTML encoding</li>
                <li><strong>Tip:</strong> Use the encoder tool above to help craft payloads</li>
            </ul>
        </div>
        
        <div class="navigation">
            <a href="level13.php">← Previous Level</a>
            <a href="level15.php">Next Level →</a>
        </div>
    </div>
    
    <script>
        function urlEncode() {
            const plain = document.getElementById('plain-text').value;
            const encoded = encodeURIComponent(plain);
            document.getElementById('encoded-text').value = encoded;
        }
        
        function htmlEncode() {
            const plain = document.getElementById('plain-text').value;
            let encoded = plain
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;')
                .replace(/'/g, '&#39;')
                .replace(/ /g, '&#32;')
                .replace(/=/g, '&#61;');
            
            // Encode letters to decimal entities
            encoded = encoded.replace(/[A-Za-z]/g, function(match) {
                return '&#' + match.charCodeAt(0) + ';';
            });
            
            document.getElementById('encoded-text').value = encoded;
        }
        
        function clearEncoder() {
            document.getElementById('plain-text').value = '';
            document.getElementById('encoded-text').value = '';
        }
    </script>
</body>
</html>

<?php $conn->close(); ?>