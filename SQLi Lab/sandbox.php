<?php
$mysqli = new mysqli('db','root','rootpassword','sqli_lab');
$query = $_GET['query'] ?? '';
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SQL Sandbox</title>
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
        
        .info-box {
            background: #f0f9ff;
            border: 1px solid #0ea5e9;
            padding: 1.5rem;
            border-radius: 8px;
            margin: 2rem 0;
        }
        
        .info-box h4 {
            color: #0c4a6e;
            margin-bottom: 1rem;
        }
        
        .info-box ul {
            margin-left: 1.5rem;
            color: #374151;
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
            <h1>🔬 SQL Sandbox</h1>
            <p>Practice SQL queries in a safe environment</p>
        </div>

        <div class="form-container">
            <form method="get">
                <div class="form-group">
                    <label for="query">SQL Query:</label>
                    <input type="text" id="query" name="query" 
                           placeholder="e.g., SELECT * FROM users LIMIT 5" 
                           value="<?php echo htmlspecialchars($_GET['query'] ?? ''); ?>">
                </div>
                <button type="submit" class="btn">🚀 Execute Query</button>
            </form>

            <?php
            $mysqli = new mysqli('db','root','rootpassword','sqli_lab');
            $query = $_GET['query'] ?? '';
            
            if ($query) {
                echo '<h3>Query Preview:</h3>';
                echo '<div class="code-block">' . htmlspecialchars($query) . '</div>';
                
                $start = microtime(true);
                $result = $mysqli->query($query);
                $delta = microtime(true) - $start;
                
                if (!$result) {
                    echo '<div class="error">❌ Error: ' . $mysqli->error . '</div>';
                } else {
                    echo '<div class="result">';
                    echo '<p><strong>✅ Query executed successfully!</strong></p>';
                    echo '<p>⏱️ Execution time: ' . number_format($delta, 4) . ' seconds</p>';
                    
                    if ($result === true) {
                        echo '<p>Rows affected: ' . $mysqli->affected_rows . '</p>';
                    } else {
                        echo '<p>Rows returned: ' . $result->num_rows . '</p>';
                        $result->free();
                    }
                    echo '</div>';
                }
            }
            ?>
            
            <div class="info-box">
                <h4>📚 Available Tables:</h4>
                <ul>
                    <li><strong>users</strong> - id, username, password</li>
                    <li><strong>levels</strong> - id, flag</li>
                    <li><strong>meta</strong> - id, mkey, mvalue</li>
                </ul>
            </div>
        </div>
        
        <div class="navigation">
            <a href="index.php">🏠 Home</a>
            <a href="submit.php?level=1">🏆 Submit Flags</a>
        </div>
    </div>
</body>
</html>