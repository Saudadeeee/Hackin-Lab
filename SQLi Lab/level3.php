<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Level 3 - Stacked Queries</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>⚡ Level 3 - Stacked Queries</h1>
            <p><strong>Objective:</strong> Execute multiple SQL statements simultaneously by separating them with semicolons</p>
        </div>

        <div class="form-container">
            <h3>🔍 Current Query:</h3>
            <div class="code-block">SELECT username FROM users WHERE id = <?php echo htmlspecialchars($_GET['id'] ?? 'NULL'); ?></div>
            
            <?php
            if (isset($_GET['id'])) {
                echo '<h3>📊 Result:</h3>';
                echo '<div class="result">';
                
                $mysqli = new mysqli('db','root','rootpassword','sqli_lab');
                $id = $_GET['id'];
                $sql = "SELECT username FROM users WHERE id = $id";
                if ($mysqli->multi_query($sql)) {
                    do {
                        if ($result = $mysqli->store_result()) {
                            while ($row = $result->fetch_row()) {
                                echo '<strong>Username:</strong> ' . htmlspecialchars($row[0])."<br>";
                            }
                            $result->free();
                        }
                    } while ($mysqli->more_results() && $mysqli->next_result());
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
                    <h4>💡 Hint 1: Understanding Stacked Queries</h4>
                    <p><strong>🎯 Concept:</strong> Stacked Queries allow executing multiple SQL statements</p>
                    <p><strong>📝 Syntax:</strong> Use semicolon (;) to separate statements</p>
                    <p><strong>🔍 Basic Example:</strong> <code>SELECT * FROM table1; SELECT * FROM table2;</code></p>
                    <p><strong>⚠️ Note:</strong> Very powerful but also very dangerous!</p>
                    <p><strong>🧪 Test:</strong> <code>1</code> to see normal behavior first</p>
                </div>
                <div id="hint-2" class="hint-box" style="display: none;">
                    <h4>💡 Hint 2: Execute Simple Query</h4>
                    <p><strong>🎯 Goal:</strong> Execute a second query after the original</p>
                    <p><strong>📝 Test:</strong> <code>1; SELECT 'test' as message</code></p>
                    <p><strong>🔍 Expected Result:</strong></p>
                    <p>• Query 1: Display username of user ID=1</p>
                    <p>• Query 2: Display 'test' (if shown)</p>
                    <p><strong>💡 Note:</strong> Not all results may be displayed on the interface</p>
                </div>
                <div id="hint-3" class="hint-box" style="display: none;">
                    <h4>💡 Hint 3: Query levels Table</h4>
                    <p><strong>🎯 Goal:</strong> Execute query to get data from levels table</p>
                    <p><strong>📝 Test:</strong> <code>1; SELECT flag FROM levels</code></p>
                    <p><strong>🔍 Explanation:</strong></p>
                    <p>• Query 1: <code>SELECT username FROM users WHERE id = 1</code></p>
                    <p>• Query 2: <code>SELECT flag FROM levels</code></p>
                    <p><strong>💡 Result:</strong> May display all flags or just a portion</p>
                </div>
                <div id="hint-4" class="hint-box" style="display: none;">
                    <h4>💡 Hint 4: Filter Specific Results</h4>
                    <p><strong>🎯 Goal:</strong> Get only level 3 flag</p>
                    <p><strong>📝 Test:</strong> <code>1; SELECT flag FROM levels WHERE id=3</code></p>
                    <p><strong>🔍 Detailed Explanation:</strong></p>
                    <p>• <code>1</code> - Valid parameter for first query</p>
                    <p>• <code>;</code> - End first query</p>
                    <p>• <code>SELECT flag FROM levels WHERE id=3</code> - Second query</p>
                    <p><strong>⚡ Power:</strong> Can perform INSERT, UPDATE, DELETE!</p>
                </div>
                <div id="hint-5" class="hint-box" style="display: none;">
                    <h4>🎯 Hint 5: FINAL PAYLOAD</h4>
                    <p><strong>🚀 Get level 3 flag:</strong></p>
                    <p><code>1; SELECT flag FROM levels WHERE id=3</code></p>
                    <p><strong>📋 Payload Explanation:</strong></p>
                    <p>• <code>1</code> - Get username of user with ID=1 (valid query)</p>
                    <p>• <code>;</code> - End first statement</p>
                    <p>• <code>SELECT flag FROM levels WHERE id=3</code> - Separate query to get level 3 flag</p>
                    <p><strong>🏆 Result:</strong> Level 3 flag will be displayed!</p>
                </div>
            </div>
        </div>
        
        <div class="navigation">
            <a href="index.php">🏠 Home</a>
            <a href="level2.php">⬅️ Previous Level</a>
            <a href="level4.php">➡️ Next Level</a>
            <a href="submit.php?level=3">🏆 Submit Flag</a>
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
                document.querySelector('.hint-btn').textContent = '✅ All hints viewed';
                document.querySelector('.hint-btn').disabled = true;
                document.querySelector('.hint-btn').style.opacity = '0.6';
            } else {
                document.querySelector('.hint-btn').textContent = `💡 Next Hint (${currentHint}/${maxHints})`;
            }
        }
    }
    </script>
</body>
</html>