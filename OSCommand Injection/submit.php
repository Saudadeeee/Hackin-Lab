<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Submit Flag - OS Command Injection Lab</title>
    <link rel="stylesheet" href="css/styles.css">
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Submit Your Flag</h1>
            <p>Submit the flag you found from Level <?php echo htmlspecialchars($_GET['level'] ?? '?'); ?></p>
        </div>

        <div class="form-container">
            <?php
            $level = isset($_GET['level']) && is_numeric($_GET['level']) ? (int)$_GET['level'] : null;
            $submitted_flag = $_POST['flag'] ?? null;

            // Load progress from cookie
            $completedLevels = [];
            if (!empty($_COOKIE['oscommand_lab_progress'])) {
                $decoded = json_decode($_COOKIE['oscommand_lab_progress'], true);
                if (is_array($decoded)) $completedLevels = $decoded;
            }

            // Define correct flags for each level
            $correct_flags = [
                1  => 'FLAG{basic_injection_discovered}',
                2  => 'FLAG{semicolon_filter_bypassed}',
                3  => ['FLAG{space_filter_0_bypassed}', 'FLAG{space_filter_1000_bypassed}'],
                4  => ['FLAG{keyword_Linux_bypass_complete}', 'FLAG{keyword_linux_bypass_complete}'],
                5  => 'FLAG{blind_execution_confirmed}',
                6  => 'FLAG{timing_attack_successful}',
                7  => 'FLAG{advanced_encoding_bypass_successful}',
                8  => 'FLAG{waf_bypass_master_level}',
                9  => 'FLAG{out_of_band_data_exfiltration}',
                10 => 'FLAG{race_condition_automation_bypass}',
            ];

            if ($submitted_flag && $level) {
                $is_correct = false;

                if (isset($correct_flags[$level])) {
                    $expected = $correct_flags[$level];

                    // Handle array of possible flags (for dynamic flags)
                    if (is_array($expected)) {
                        $is_correct = in_array($submitted_flag, $expected);
                    } else {
                        $is_correct = ($submitted_flag === $expected);
                    }

                    // Additional check for dynamic flags with patterns
                    if (!$is_correct) {
                        switch ($level) {
                            case 3:
                                $is_correct = (bool) preg_match('/^FLAG\{space_filter_\d+_bypassed\}$/', $submitted_flag);
                                break;
                            case 4:
                                $is_correct = (bool) preg_match('/^FLAG\{keyword_[A-Za-z]+_bypass_complete\}$/', $submitted_flag);
                                break;
                        }
                    }
                }

                if ($is_correct) {
                    echo '<div class="message success">';
                    echo '<h2>Congratulations!</h2>';
                    echo '<p><strong>Correct Flag:</strong> ' . htmlspecialchars($submitted_flag) . '</p>';
                    echo '<p>You have successfully completed Level ' . (int)$level . '!</p>';
                    echo '</div>';

                    // Mark level as completed in cookie
                    if (!in_array((int)$level, $completedLevels)) {
                        $completedLevels[] = (int)$level;
                        sort($completedLevels);
                        setcookie('oscommand_lab_progress', json_encode($completedLevels), time() + 86400 * 30, '/');
                    }
                } else {
                    echo '<div class="error">';
                    echo '<h2>Incorrect Flag</h2>';
                    echo '<p>The flag you entered is incorrect. Keep trying!</p>';
                    echo '<p><strong>Hint:</strong> Flag format: FLAG{...}</p>';
                    echo '</div>';
                }
            }

            $isCompleted = $level && in_array((int)$level, $completedLevels);
            if ($isCompleted && $_SERVER['REQUEST_METHOD'] !== 'POST') {
                echo '<div class="message info"><h3>Level ' . (int)$level . ' Already Completed</h3><p>You have already submitted the correct flag for this level.</p></div>';
            }
            ?>

            <h3>Submit Flag for Level <?php echo htmlspecialchars((string)$level); ?></h3>
            <form method="post">
                <div class="form-group">
                    <label for="flag">Flag:</label>
                    <input type="text" id="flag" name="flag" placeholder="FLAG{...}" required>
                </div>
                <button type="submit" class="btn">Submit Flag</button>
            </form>

            <div style="margin-top: 20px;">
                <h4>Select Different Level:</h4>
                <div style="display: flex; gap: 10px; flex-wrap: wrap; margin: 15px 0;">
                    <?php
                    for ($i = 1; $i <= 10; $i++):
                        $isLevelCompleted = in_array($i, $completedLevels ?? []);
                        $buttonClass = $isLevelCompleted ? 'btn level-button completed' : 'btn level-button';
                        $completedIcon = $isLevelCompleted ? ' &#10003;' : '';
                    ?>
                        <a href="?level=<?php echo $i; ?>" class="<?php echo $buttonClass; ?>">
                            Level <?php echo $i; ?><?php echo $completedIcon; ?>
                        </a>
                    <?php endfor; ?>
                </div>
            </div>

            <div class="info-card">
                <h3>What you learned from this Level</h3>
                <ul>
                    <li><strong>OS Command Injection:</strong> Understanding how this vulnerability works</li>
                    <li><strong>Bypass Techniques:</strong> Techniques for bypassing filters</li>
                    <li><strong>Detection Methods:</strong> How to detect blind injection</li>
                    <li><strong>Prevention:</strong> The importance of input validation</li>
                </ul>
            </div>
        </div>

        <div class="navigation">
            <?php if ($level): ?>
                <a href="level<?php echo (int)$level; ?>.php">Back to Level <?php echo (int)$level; ?></a>
                <?php if ($level < 10): ?>
                    <a href="level<?php echo (int)$level + 1; ?>.php">Next Level</a>
                <?php endif; ?>
            <?php endif; ?>
            <a href="index.php">Home</a>
        </div>

        <div class="footer">
            <h3>Security Best Practices</h3>
            <div class="tools-grid">
                <div class="tool-card">
                    <h3>Input Validation</h3>
                    <p>Validate all user input</p>
                </div>
                <div class="tool-card">
                    <h3>Whitelist Approach</h3>
                    <p>Only allow safe characters</p>
                </div>
                <div class="tool-card">
                    <h3>Parameterized Commands</h3>
                    <p>Use prepared statements</p>
                </div>
                <div class="tool-card">
                    <h3>Principle of Least Privilege</h3>
                    <p>Run with minimal permissions</p>
                </div>
            </div>
        </div>
    </div>
</body>
</html>
