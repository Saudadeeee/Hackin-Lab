<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Submit Flag</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🏆 Flag Submission</h1>
            <p>Submit your discovered flags for Level <?php echo intval($_GET['level'] ?? 1); ?></p>
        </div>

        <div class="form-container">
            <?php
            $level = intval($_GET['level'] ?? 1);
            $mysqli = new mysqli('db','root','rootpassword','sqli_lab');
            
            // Check if level is already completed
            $isCompleted = false;
            if (isset($_COOKIE['completed_levels'])) {
                $completedLevels = json_decode($_COOKIE['completed_levels'], true);
                $isCompleted = in_array($level, $completedLevels ?? []);
            }

            if ($_SERVER['REQUEST_METHOD'] === 'POST') {
                $flag = $_POST['flag'];
                $res = $mysqli->query("SELECT flag FROM levels WHERE id = $level") or die($mysqli->error);
                $row = $res->fetch_assoc();
                
                if ($row && $row['flag'] === $flag) {
                    echo '<div class="result" style="background: #d4edda; border-left-color: #28a745;">';
                    echo '<h2>🎉 Congratulations!</h2>';
                    echo '<p>Level ' . $level . ' completed successfully!</p>';
                    echo '<p><strong>Flag:</strong> <code>' . htmlspecialchars($flag) . '</code></p>';
                    echo '</div>';
                    
                    // Mark level as completed
                    $completedLevels = isset($_COOKIE['completed_levels']) ? 
                        json_decode($_COOKIE['completed_levels'], true) : [];
                    if (!in_array($level, $completedLevels)) {
                        $completedLevels[] = $level;
                        setcookie('completed_levels', json_encode($completedLevels), time() + (86400 * 30), '/');
                    }
                    $isCompleted = true;
                } else {
                    echo '<div class="error">❌ Incorrect flag. Keep trying!</div>';
                }
            }
            
            if ($isCompleted && $_SERVER['REQUEST_METHOD'] !== 'POST') {
                echo '<div class="result" style="background: #d1ecf1; border-left-color: #0c5460;">';
                echo '<h3>✅ Level ' . $level . ' Already Completed</h3>';
                echo '<p>You have successfully completed this level!</p>';
                echo '</div>';
            }
            ?>

            <form method="post">
                <div class="form-group">
                    <label for="flag">Flag for Level <?php echo $level; ?>:</label>
                    <input type="text" id="flag" name="flag" placeholder="FLAG{...}" 
                           style="font-family: 'Courier New', monospace;">
                </div>
                <button type="submit" class="btn">🚀 Submit Flag</button>
            </form>
            
            <div style="margin-top: 20px;">
                <h4>Select Different Level:</h4>
                <div style="display: flex; gap: 10px; flex-wrap: wrap; margin: 15px 0;">
                    <?php 
                    $completed = isset($_COOKIE['completed_levels']) ? 
                        json_decode($_COOKIE['completed_levels'], true) : [];
                    for($i = 1; $i <= 13; $i++): 
                        $isLevelCompleted = in_array($i, $completed ?? []);
                        $buttonClass = $isLevelCompleted ? 'btn completed' : 'btn';
                        $completedIcon = $isLevelCompleted ? ' ✅' : '';
                    ?>
                        <a href="?level=<?php echo $i; ?>" class="<?php echo $buttonClass; ?>" style="font-size: 14px; padding: 8px 16px;">
                            Level <?php echo $i; ?><?php echo $completedIcon; ?>
                        </a>
                    <?php endfor; ?>
                </div>
            </div>
        </div>
        
        <div class="navigation">
            <a href="index.php">🏠 Home</a>
            <a href="sandbox.php">🔬 Sandbox</a>
        </div>
    </div>
    
    <style>
    .btn.completed {
        background: #28a745;
        border-color: #28a745;
        color: white;
    }
    .btn.completed:hover {
        background: #218838;
        border-color: #1e7e34;
    }
    </style>
</body>
</html>