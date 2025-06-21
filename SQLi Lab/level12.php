<?php
$mysqli = new mysqli('db','root','rootpassword','sqli_lab');
$id = $_GET['id'] ?? '';

// Only process if id parameter is provided and not empty
if ($id !== '') {
    $blocked_keywords = ['union', 'select', 'or', 'and', 'drop', 'delete', 'insert', 'update'];
    $id_lower = strtolower($id);

    $blocked = false;
    foreach ($blocked_keywords as $keyword) {
        if (strpos($id_lower, $keyword) !== false) {
            $blocked = true;
            break;
        }
    }

    if (!$blocked) {
        $sql = "SELECT username FROM users WHERE id = $id";
        $result = $mysqli->query($sql);

        if (!$result) {
            die('Error: '.$mysqli->error);
        }

        $row = $result->fetch_row();
        if ($row) {
            echo htmlspecialchars($row[0]);
        } else {
            echo 'No user found';
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Level 12 - WAF Bypass</title>
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
        
        .form-group input {
            width: 100%;
            padding: 0.75rem;
            border: 1px solid #d1d5db;
            border-radius: 6px;
            font-size: 1rem;
            font-family: 'Courier New', monospace;
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
        
        .waf-warning {
            background: #fef3c7;
            border: 1px solid #f59e0b;
            color: #92400e;
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
            <h1>🛡️ Level 12 - WAF Bypass</h1>
            <p><strong>Attack Type:</strong> Learn techniques to bypass Web Application Firewalls and filter restrictions</p>
        </div>

        <div class="form-container">
            <h3>Current Query:</h3>
            <div class="code-block">SELECT username FROM users WHERE id = <?php echo htmlspecialchars($_GET['id'] ?? 'NULL'); ?></div>
            
            <h3>🚨 WAF Rules:</h3>
            <div class="waf-warning">
                <strong>Blocked keywords:</strong> union, select, or, and, drop, delete, insert, update
            </div>
            
            <?php
            if (isset($_GET['id']) && $_GET['id'] !== '') {
                $id = $_GET['id'];
                
                echo '<h3>Result:</h3>';
                echo '<div class="result">';
                
                $blocked_keywords = ['union', 'select', 'or', 'and', 'drop', 'delete', 'insert', 'update'];
                $id_lower = strtolower($id);

                $blocked = false;
                $blocked_keyword = '';
                foreach ($blocked_keywords as $keyword) {
                    if (strpos($id_lower, $keyword) !== false) {
                        $blocked = true;
                        $blocked_keyword = $keyword;
                        break;
                    }
                }

                if ($blocked) {
                    echo '<div class="error">🚨 WAF blocked: Suspicious keyword detected: ' . $blocked_keyword . '</div>';
                } else {
                    $mysqli = new mysqli('db','root','rootpassword','sqli_lab');
                    $sql = "SELECT username FROM users WHERE id = $id";
                    $result = $mysqli->query($sql);

                    if (!$result) {
                        echo '<div class="error">Error: '.$mysqli->error.'</div>';
                    } else {
                        $row = $result->fetch_row();
                        if ($row) {
                            echo '<strong>Username:</strong> ' . htmlspecialchars($row[0]);
                        } else {
                            echo 'No user found';
                        }
                    }
                }
                echo '</div>';
            } elseif (isset($_GET['id']) && $_GET['id'] === '') {
                echo '<h3>Result:</h3>';
                echo '<div class="error">❌ Please provide an ID parameter</div>';
            }
            ?>
            
            <!-- Form input for custom payload -->
            <h3>🔧 Try Your Own Payload:</h3>
            <form method="get" style="margin: 20px 0;">
                <div class="form-group">
                    <label for="id">ID Parameter:</label>
                    <input type="text" id="id" name="id" value="<?php echo htmlspecialchars($_GET['id'] ?? ''); ?>" placeholder="Enter your payload here..." oninput="updateQuery()">
                </div>
                <button type="submit" class="btn">🚀 Execute Query</button>
            </form>

            <div class="hint-container">
                <button onclick="showNextHint()" class="btn hint-btn">💡 Get Hint</button>
                <div id="hint-1" class="hint-box" style="display: none;">
                    <h4>💡 Hint 1: Test the WAF</h4>
                    <p>First, understand how the WAF works by testing blocked keywords.</p>
                    <p>Try: <code>1 union</code> - This should be blocked by the WAF.</p>
                    <p>Try: <code>1 select</code> - This should also be blocked.</p>
                    <p>The WAF converts input to lowercase before checking.</p>
                </div>
                <div id="hint-2" class="hint-box" style="display: none;">
                    <h4>💡 Hint 2: Case Variations Don't Work</h4>
                    <p>The WAF converts everything to lowercase, so case variations won't help.</p>
                    <p>Try: <code>1 UnIoN</code> - Still blocked because it becomes "union" after lowercase conversion.</p>
                    <p>We need a different bypass technique.</p>
                </div>
                <div id="hint-3" class="hint-box" style="display: none;">
                    <h4>💡 Hint 3: Using Different Operators</h4>
                    <p>Since basic keywords are blocked, we can try other SQL techniques.</p>
                    <p>Try: <code>1||1</code> - Double pipe is OR in MySQL</p>
                    <p>Try: <code>1&&1</code> - Double ampersand is AND in MySQL</p>
                    <p>These aren't blocked by the keyword filter!</p>
                </div>
                <div id="hint-4" class="hint-box" style="display: none;">
                    <h4>💡 Hint 4: Using Subqueries and Functions</h4>
                    <p>We can extract data without using blocked keywords.</p>
                    <p>Try: <code>1||(ASCII(MID((DATABASE()),1,1))>100)</code></p>
                    <p>This uses functions to check database name character by character.</p>
                </div>
                <div id="hint-5" class="hint-box" style="display: none;">
                    <h4>🎯 Final Payload</h4>
                    <p>Extract the flag using WAF bypass techniques:</p>
                    <p><code>1||(ASCII(MID((REVERSE((MID((REVERSE((DATABASE()))),1,8)))),1,1))>70)</code></p>
                    <p>Alternative simpler approach:</p>
                    <p><code>-1||(1)</code> - This will return true and show results</p>
                    <p>Then manually check database with: <code>1||(DATABASE()='sqli_lab')</code></p>
                    <p>Note: This level demonstrates keyword filtering - in real scenarios, you'd need to be more creative!</p>
                </div>
            </div>
        </div>
        
        <div class="navigation">
            <a href="index.php">🏠 Home</a>
            <a href="level11.php">⬅️ Previous Level</a>
            <a href="level13.php">➡️ Next Level</a>
            <a href="submit.php?level=12">🏆 Submit Flag</a>
        </div>
    </div>

    <script>
    let currentHint = 0;
    const maxHints = 5;

    function updateQuery() {
        const input = document.getElementById('id').value;
        const codeBlock = document.querySelector('.code-block');
        codeBlock.innerHTML = 'SELECT username FROM users WHERE id = ' + (input || 'NULL');
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
