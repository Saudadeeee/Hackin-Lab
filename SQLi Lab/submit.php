<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Submit Flag</title>
    <link rel="stylesheet" href="css/styles.css">
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Flag Submission</h1>
            <p>Submit your discovered flags for Level <?php echo intval($_GET['level'] ?? 1); ?></p>
        </div>

        <div class="form-container">
            <?php
            $level = intval($_GET['level'] ?? 1);
            $dbHost = $_ENV['FLAG_DB_HOST'] ?? ($_ENV['DB_HOST'] ?? 'db');
            $dbUser = $_ENV['FLAG_DB_USER'] ?? ($_ENV['DB_USER'] ?? 'webapp');
            $dbPass = $_ENV['FLAG_DB_PASS'] ?? ($_ENV['DB_PASS'] ?? 'webapp123');
            $dbName = $_ENV['DB_NAME'] ?? 'sqli_lab';

            $mysqli = new mysqli($dbHost, $dbUser, $dbPass, $dbName);
            
            // Check if level is already completed
            $isCompleted = false;
            if (isset($_COOKIE['completed_levels'])) {
                $completedLevels = json_decode($_COOKIE['completed_levels'], true);
                $isCompleted = in_array($level, $completedLevels ?? []);
            }

            if ($_SERVER['REQUEST_METHOD'] === 'POST') {
                $flag = $_POST['flag'];
                $res = $mysqli->query("SELECT flag FROM levels WHERE id = $level");
                $row = $res->fetch_assoc();
                
                if ($row && $row['flag'] === $flag) {
                    echo '<div class="message success">';
                    echo '<h2>Congratulations!</h2>';
                    echo '<p>Level ' . $level . ' completed successfully.</p>';
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
                    echo '<div class="message error">Incorrect flag. Keep trying!</div>';
                }
            }
            
            if ($isCompleted && $_SERVER['REQUEST_METHOD'] !== 'POST') {
                echo '<div class="message info">';
                echo '<h3>Level ' . $level . ' Already Completed</h3>';
                echo '<p>You have already submitted the correct flag for this level.</p>';
                echo '</div>';
            }
            ?>

            <form method="post">
                <div class="form-group">
                    <label for="flag">Flag for Level <?php echo $level; ?>:</label>
                    <input type="text" id="flag" name="flag" placeholder="FLAG{...}">
                </div>
                <button type="submit" class="btn">Submit Flag</button>
            </form>
            
            <div style="margin-top: 20px;">
                <h4>Select Different Level:</h4>
                <div style="display: flex; gap: 10px; flex-wrap: wrap; margin: 15px 0;">
                    <?php 
                    $completed = isset($_COOKIE['completed_levels']) ? 
                        json_decode($_COOKIE['completed_levels'], true) : [];
                    for($i = 1; $i <= 16; $i++): 
                        $isLevelCompleted = in_array($i, $completed ?? []);
                        $buttonClass = $isLevelCompleted ? 'btn level-button completed' : 'btn level-button';
                        $completedIcon = $isLevelCompleted ? ' &check;' : '';
                    ?>
                        <a href="?level=<?php echo $i; ?>" class="<?php echo $buttonClass; ?>">
                            Level <?php echo $i; ?><?php echo $completedIcon; ?>
                        </a>
                    <?php endfor; ?>
                </div>
            </div>
        </div>
        
        <div class="navigation">
            <a href="index.php"> Home</a>
            <a href="sandbox.php"> Sandbox</a>
        </div>
    </div>
</body>
</html>
