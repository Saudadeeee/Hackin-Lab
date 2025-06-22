<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Level 2 - UNION Based SQLi</title>
    <link rel="stylesheet" href="css/styles.css">
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔗 Level 2 - UNION Based Injection</h1>
            <p><strong>Objective:</strong> Use UNION SELECT to combine results from multiple queries and extract data</p>
        </div>

        <div class="form-container">
            <h3>🔍 Current Query:</h3>
            <div class="code-block">SELECT id, username FROM users WHERE id = <?php echo htmlspecialchars($_GET['id'] ?? 'NULL'); ?></div>
            
            <?php
            if (isset($_GET['id'])) {
                echo '<h3>📊 Result:</h3>';
                echo '<div class="result">';
                
                $mysqli = new mysqli('db','root','rootpassword','sqli_lab');
                $id = $_GET['id'];
                $sql = "SELECT id, username FROM users WHERE id = $id";
                if ($res = $mysqli->query($sql)) {
                    if ($res->num_rows > 0) {
                        while ($row = $res->fetch_row()) {
                            echo '<strong>ID:</strong> ' . htmlspecialchars($row[0]) . ' - <strong>Username:</strong> ' . htmlspecialchars($row[1]) . '<br>';
                        }
                    } else {
                        echo 'No results found';
                    }
                } else {
                    echo '<div class="error">❌ Error: '.$mysqli->error.'</div>';
                }
                echo '</div>';
            }
            ?>
            
            <h3>🔧 Try Your Payload:</h3>
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
                    <h4>💡 Hint 1: Determine Column Count</h4>
                    <p><strong>🎯 Goal:</strong> Find how many columns the original query returns</p>
                    <p><strong>📝 Method:</strong> Use ORDER BY to test</p>
                    <p>• Try: <code>1 ORDER BY 1</code> ✅</p>
                    <p>• Try: <code>1 ORDER BY 2</code> ✅</p> 
                    <p>• Try: <code>1 ORDER BY 3</code> ❌ (will error)</p>
                    <p><strong>🔍 Conclusion:</strong> Query has 2 columns (id, username)</p>
                </div>
                <div id="hint-2" class="hint-box" style="display: none;">
                    <h4>💡 Hint 2: Basic UNION</h4>
                    <p><strong>🎯 Test UNION:</strong> Original query has 2 columns</p>
                    <p><strong>📝 Test:</strong> <code>1 UNION SELECT 1,2</code></p>
                    <p><strong>🔍 Expected Result:</strong></p>
                    <p>• Row 1: ID from user (e.g., 1 - alice)</p>
                    <p>• Row 2: Test data (1 - 2)</p>
                    <p><strong>💡 Explanation:</strong> UNION combines 2 SELECT statements</p>
                </div>
                <div id="hint-3" class="hint-box" style="display: none;">
                    <h4>💡 Hint 3: Explore Database Structure</h4>
                    <p><strong>🎯 Goal:</strong> Find tables in the database</p>
                    <p><strong>📝 Test:</strong> <code>1 UNION SELECT 1,table_name FROM information_schema.tables</code></p>
                    <p><strong>🔍 Result:</strong> List of all tables in the database</p>
                    <p><strong>📋 Important table to find:</strong> 'levels' (contains flags)</p>
                    <p><strong>💡 Tip:</strong> information_schema is MySQL's system database</p>
                </div>
                <div id="hint-4" class="hint-box" style="display: none;">
                    <h4>💡 Hint 4: Explore levels Table</h4>
                    <p><strong>🎯 Goal:</strong> View structure of levels table</p>
                    <p><strong>📝 View all columns:</strong> <code>1 UNION SELECT 1,column_name FROM information_schema.columns WHERE table_name='levels'</code></p>
                    <p><strong>📝 View data:</strong> <code>1 UNION SELECT id,flag FROM levels</code></p>
                    <p><strong>🔍 Result:</strong> Will display all flags from all levels</p>
                    <p><strong>⚠️ Note:</strong> We need the specific flag for level 2</p>
                </div>
                <div id="hint-5" class="hint-box" style="display: none;">
                    <h4>🎯 Hint 5: FINAL PAYLOAD</h4>
                    <p><strong>🚀 Get level 2 flag:</strong></p>
                    <p><code>1 UNION SELECT id,flag FROM levels WHERE id=2</code></p>
                    <p><strong>📋 Payload Explanation:</strong></p>
                    <p>• <code>1</code> - Get user with ID=1 (valid result)</p>
                    <p>• <code>UNION</code> - Combine with second query</p>
                    <p>• <code>SELECT id,flag FROM levels</code> - Get id and flag from levels table</p>
                    <p>• <code>WHERE id=2</code> - Only get flag for level 2</p>
                    <p><strong>🏆 Result:</strong> Flag will display in the username column!</p>
                </div>
            </div>
        </div>
        
        <div class="navigation">
            <a href="index.php">🏠 Home</a>
            <a href="level1.php">⬅️ Previous Level</a>
            <a href="level3.php">➡️ Next Level</a>
            <a href="submit.php?level=2">🏆 Submit Flag</a>
        </div>
    </div>

    <script>
    let currentHint = 0;
    const maxHints = 5;

    function updateQuery() {
        const input = document.getElementById('id').value;
        const codeBlock = document.querySelector('.code-block');
        codeBlock.innerHTML = 'SELECT id, username FROM users WHERE id = ' + (input || 'NULL');
    }

    function showNextHint() {
        if (currentHint < maxHints) {
            currentHint++;
            document.getElementById('hint-' + currentHint).style.display = 'block';
            
            if (currentHint >= maxHints) {
                document.querySelector('.hint-btn').textContent = '✅ All hints viewed';
                document.querySelector('.hint-btn').disabled = true;
                document.querySelector('.hint-btn').style.opacity = '0.6';
            } else {
                document.querySelector('.hint-btn').textContent = `💡 Next Hint (${currentHint}/${maxHints})`;
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