<?php
$mysqli = new mysqli('db','root','rootpassword','sqli_lab');
$filter = $_GET['filter'] ?? '{}';

$json = json_decode($filter, true);
if ($json && isset($json['username'])) {
    $username = $json['username'];
    $sql = "SELECT * FROM users WHERE username = '$username'";
    $result = $mysqli->query($sql);
    
    if (!$result) {
        die('Error: '.$mysqli->error);
    }
    
    $users = [];
    while ($row = $result->fetch_assoc()) {
        $users[] = $row;
    }
    echo json_encode($users);
} else {
    echo 'Invalid JSON filter';
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Level 13 - JSON Injection</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #f8fafc;
            color: #334155;
            line-height: 1.6;
        }
        
        .container {
            max-width: 900px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .header {
            background: #1e293b;
            color: white;
            padding: 2rem;
            border-radius: 12px;
            margin-bottom: 2rem;
        }
        
        .header h1 {
            font-size: 2rem;
            margin-bottom: 0.5rem;
        }
        
        .form-container {
            background: white;
            padding: 2rem;
            border-radius: 12px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            margin-bottom: 2rem;
        }
        
        .code-block {
            background: #1e293b;
            color: #e2e8f0;
            padding: 1rem;
            border-radius: 8px;
            font-family: 'Courier New', monospace;
            margin: 1rem 0;
            overflow-x: auto;
        }
        
        .form-group {
            margin-bottom: 1.5rem;
        }
        
        .form-group label {
            display: block;
            margin-bottom: 0.5rem;
            font-weight: 600;
            color: #374151;
        }
        
        .form-group textarea {
            width: 100%;
            padding: 0.75rem;
            border: 1px solid #d1d5db;
            border-radius: 6px;
            font-size: 1rem;
            font-family: 'Courier New', monospace;
            resize: vertical;
        }
        
        .btn {
            background: #3b82f6;
            color: white;
            padding: 0.75rem 1.5rem;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-size: 1rem;
            transition: background 0.2s;
        }
        
        .btn:hover {
            background: #2563eb;
        }
        
        .hint-btn {
            background: #10b981;
            margin-bottom: 1rem;
        }
        
        .hint-btn:hover {
            background: #059669;
        }
        
        .hint-box {
            background: #f0fdf4;
            border: 1px solid #16a34a;
            border-radius: 8px;
            padding: 1.5rem;
            margin: 1rem 0;
        }
        
        .hint-box h4 {
            color: #166534;
            margin-bottom: 0.5rem;
        }
        
        .hint-box code {
            background: #1e293b;
            color: #e2e8f0;
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
        }
        
        .result {
            background: #eff6ff;
            border: 1px solid #3b82f6;
            padding: 1rem;
            border-radius: 8px;
            margin: 1rem 0;
        }
        
        .error {
            background: #fef2f2;
            border: 1px solid #ef4444;
            color: #dc2626;
            padding: 1rem;
            border-radius: 8px;
            margin: 1rem 0;
        }
        
        .navigation {
            display: flex;
            justify-content: center;
            gap: 1rem;
            flex-wrap: wrap;
        }
        
        .navigation a {
            background: #64748b;
            color: white;
            padding: 0.75rem 1.5rem;
            text-decoration: none;
            border-radius: 6px;
            transition: background 0.2s;
        }
        
        .navigation a:hover {
            background: #475569;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>📋 Level 13 - JSON Injection</h1>
            <p><strong>Attack Type:</strong> Exploit JSON-based query construction vulnerabilities to bypass filters and extract data</p>
        </div>

        <div class="form-container">
            <h3>Current Query:</h3>
            <div class="code-block">SELECT * FROM users WHERE username = '<?php 
            $filter = $_GET['filter'] ?? '{}';
            $json = json_decode($filter, true);
            echo htmlspecialchars($json['username'] ?? 'NULL');
            ?>'</div>
            
            <?php
            if (isset($_GET['filter'])) {
                echo '<h3>Result:</h3>';
                echo '<div class="result">';
                
                $mysqli = new mysqli('db','root','rootpassword','sqli_lab');
                $filter = $_GET['filter'];

                $json = json_decode($filter, true);
                if ($json && isset($json['username'])) {
                    $username = $json['username'];
                    $sql = "SELECT * FROM users WHERE username = '$username'";
                    $result = $mysqli->query($sql);
                    
                    if (!$result) {
                        echo '<div class="error">Error: '.$mysqli->error.'</div>';
                    } else {
                        $users = [];
                        while ($row = $result->fetch_assoc()) {
                            $users[] = $row;
                        }
                        if (count($users) > 0) {
                            echo '<pre>' . json_encode($users, JSON_PRETTY_PRINT) . '</pre>';
                        } else {
                            echo 'No users found';
                        }
                    }
                } else {
                    echo '<div class="error">Invalid JSON filter</div>';
                }
                echo '</div>';
            }
            ?>
            
            <!-- Form input for custom payload -->
            <h3>🔧 Try Your Own JSON Filter:</h3>
            <form method="get" style="margin: 20px 0;">
                <div class="form-group">
                    <label for="filter">JSON Filter:</label>
                    <textarea id="filter" name="filter" rows="4" placeholder='{"username":"alice"}' oninput="updateQuery()"><?php echo htmlspecialchars($_GET['filter'] ?? ''); ?></textarea>
                </div>
                <button type="submit" class="btn">🚀 Execute Query</button>
            </form>

            <div class="hint-container">
                <button onclick="showNextHint()" class="btn hint-btn">💡 Get Hint</button>
                <div id="hint-1" class="hint-box" style="display: none;">
                    <h4>💡 Hint 1: Understanding JSON Processing</h4>
                    <p>The application parses JSON input and extracts the username field for the SQL query.</p>
                    <p>Try: <code>{"username":"alice"}</code> - This should return alice's user data.</p>
                    <p>Notice how the JSON value gets inserted directly into the SQL WHERE clause.</p>
                </div>
                <div id="hint-2" class="hint-box" style="display: none;">
                    <h4>💡 Hint 2: SQL Injection in JSON Values</h4>
                    <p>Since the username value is inserted directly into SQL without sanitization, we can inject SQL.</p>
                    <p>Try: <code>{"username":"alice' OR '1'='1"}</code></p>
                    <p>This should return all users because the OR condition is always true.</p>
                </div>
                <div id="hint-3" class="hint-box" style="display: none;">
                    <h4>💡 Hint 3: Using UNION in JSON Values</h4>
                    <p>We can use UNION SELECT to combine results from different tables.</p>
                    <p>Try: <code>{"username":"alice' UNION SELECT 1,2,3--"}</code></p>
                    <p>Adjust the number of columns (1,2,3) to match the users table structure.</p>
                </div>
                <div id="hint-4" class="hint-box" style="display: none;">
                    <h4>💡 Hint 4: Exploring Database Structure</h4>
                    <p>Find the correct table structure and target the levels table for the flag.</p>
                    <p>Try: <code>{"username":"alice' UNION SELECT id,flag,NULL FROM levels--"}</code></p>
                    <p>This attempts to get flags from the levels table.</p>
                </div>
                <div id="hint-5" class="hint-box" style="display: none;">
                    <h4>🎯 Final Payload</h4>
                    <p>Extract the specific flag for level 13:</p>
                    <p><code>{"username":"alice' UNION SELECT id,flag,NULL FROM levels WHERE id=13--"}</code></p>
                    <p>This payload bypasses the JSON processing and extracts the flag for level 13.</p>
                </div>
            </div>
        </div>
        
        <div class="navigation">
            <a href="index.php">🏠 Home</a>
            <a href="level12.php">⬅️ Previous Level</a>
            <a href="submit.php?level=13">🏆 Submit Flag</a>
        </div>
    </div>

    <script>
    let currentHint = 0;
    const maxHints = 5;

    function updateQuery() {
        const input = document.getElementById('filter').value;
        const codeBlock = document.querySelector('.code-block');
        try {
            const json = JSON.parse(input || '{}');
            const username = json.username || 'NULL';
            codeBlock.innerHTML = "SELECT * FROM users WHERE username = '" + username + "'";
        } catch(e) {
            codeBlock.innerHTML = "SELECT * FROM users WHERE username = 'INVALID_JSON'";
        }
    }

    function showNextHint() {
        if (currentHint < maxHints) {
            currentHint++;
            document.getElementById('hint-' + currentHint).style.display = 'block';
            
            if (currentHint >= maxHints) {
                document.querySelector('.hint-btn').style.display = 'none';
            }
        }
    }
    </script>

    <style>
    .hint-container {
        margin: 20px 0;
    }
    .hint-box {
        margin: 15px 0;
        padding: 15px;
        background: #fff3cd;
        border-radius: 8px;
        border-left: 4px solid #ffc107;
        animation: fadeIn 0.5s ease-in;
    }
    .hint-btn {
        margin-bottom: 10px;
    }
    @keyframes fadeIn {
        from { opacity: 0; transform: translateY(-10px); }
        to { opacity: 1; transform: translateY(0); }
    }
    </style>
</body>
</html>
