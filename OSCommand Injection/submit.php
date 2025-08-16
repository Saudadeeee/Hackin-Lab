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
            <h1>🏆 Submit Your Flag</h1>
            <p>Nhập flag bạn đã tìm được từ Level <?php echo htmlspecialchars($_GET['level'] ?? '?'); ?></p>
        </div>

        <div class="form-container">
            <?php
            $level = $_GET['level'] ?? null;
            $submitted_flag = $_POST['flag'] ?? null;
            
            // Define correct flags for each level
            $correct_flags = [
                '1' => 'FLAG{hidden_in_system}',
                '2' => 'FLAG{command_injection_master}',
                '3' => 'FLAG{blind_injection_success}',
                '4' => 'FLAG{command_injection_master}',
                '5' => 'FLAG{blind_injection_success}',
                '6' => 'FLAG{blind_injection_success}',
            ];
            
            if ($submitted_flag && $level) {
                if (isset($correct_flags[$level]) && $submitted_flag === $correct_flags[$level]) {
                    echo '<div class="success">';
                    echo '<h2>🎉 Congratulations!</h2>';
                    echo '<p><strong>Correct Flag:</strong> ' . htmlspecialchars($submitted_flag) . '</p>';
                    echo '<p>Bạn đã hoàn thành thành công Level ' . htmlspecialchars($level) . '!</p>';
                    echo '</div>';
                } else {
                    echo '<div class="error">';
                    echo '<h2>❌ Incorrect Flag</h2>';
                    echo '<p>Flag bạn nhập không đúng. Hãy thử lại!</p>';
                    echo '<p><strong>Gợi ý:</strong> Flag có format: FLAG{...}</p>';
                    echo '</div>';
                }
            }
            ?>

            <h3>🚩 Submit Flag for Level <?php echo htmlspecialchars($level); ?></h3>
            <form method="post">
                <div class="form-group">
                    <label for="flag">Flag:</label>
                    <input type="text" id="flag" name="flag" placeholder="FLAG{...}" required>
                </div>
                <button type="submit" class="btn">🚀 Submit Flag</button>
            </form>

            <?php if ($level): ?>
            <div class="info-card" style="margin-top: 30px;">
                <h3>💡 Level <?php echo htmlspecialchars($level); ?> - Tips</h3>
                <?php
                switch($level) {
                    case '1':
                        echo '<p><strong>Mục tiêu:</strong> Thực hiện command injection cơ bản</p>';
                        echo '<p><strong>Kỹ thuật:</strong> Sử dụng ; && || | để nối lệnh</p>';
                        echo '<p><strong>Flag location:</strong> /etc/flag.txt</p>';
                        break;
                    case '2':
                        echo '<p><strong>Mục tiêu:</strong> Hiểu về command chaining operators</p>';
                        echo '<p><strong>Kỹ thuật:</strong> Phân biệt ; && || | và cách sử dụng</p>';
                        echo '<p><strong>Flag location:</strong> /var/www/secret_flag.txt</p>';
                        break;
                    case '3':
                        echo '<p><strong>Mục tiêu:</strong> Bypass space character filtering</p>';
                        echo '<p><strong>Kỹ thuật:</strong> ${IFS}, $IFS$9, %09, brace expansion</p>';
                        echo '<p><strong>Flag location:</strong> /tmp/blind_flag.txt</p>';
                        break;
                    case '4':
                        echo '<p><strong>Mục tiêu:</strong> Bypass keyword filtering</p>';
                        echo '<p><strong>Kỹ thuật:</strong> String concatenation, variables, wildcards</p>';
                        echo '<p><strong>Flag location:</strong> /var/www/secret_flag.txt</p>';
                        break;
                    case '5':
                        echo '<p><strong>Mục tiêu:</strong> Blind command injection</p>';
                        echo '<p><strong>Kỹ thuật:</strong> Time-based, file-based detection</p>';
                        echo '<p><strong>Flag location:</strong> /tmp/blind_flag.txt</p>';
                        break;
                    case '6':
                        echo '<p><strong>Mục tiêu:</strong> Time-based blind injection</p>';
                        echo '<p><strong>Kỹ thuật:</strong> Conditional timing, binary search</p>';
                        echo '<p><strong>Flag location:</strong> /tmp/blind_flag.txt</p>';
                        break;
                    default:
                        echo '<p>Level không tồn tại hoặc chưa được implement.</p>';
                }
                ?>
            </div>
            <?php endif; ?>

            <div class="info-card" style="margin-top: 20px;">
                <h3>📚 Học được gì từ Level này?</h3>
                <ul>
                    <li><strong>OS Command Injection:</strong> Hiểu cách lỗ hổng hoạt động</li>
                    <li><strong>Bypass Techniques:</strong> Các kỹ thuật vượt qua filter</li>
                    <li><strong>Detection Methods:</strong> Cách phát hiện blind injection</li>
                    <li><strong>Prevention:</strong> Tầm quan trọng của input validation</li>
                </ul>
            </div>
        </div>

        <div class="navigation">
            <?php if ($level && is_numeric($level)): ?>
                <a href="level<?php echo htmlspecialchars($level); ?>.php">⬅️ Back to Level <?php echo htmlspecialchars($level); ?></a>
                <?php if ($level < 6): ?>
                    <a href="level<?php echo $level + 1; ?>.php">➡️ Next Level</a>
                <?php endif; ?>
            <?php endif; ?>
            <a href="index.php">🏠 Home</a>
        </div>

        <div class="footer">
            <h3>🔐 Security Best Practices</h3>
            <div class="tools-grid">
                <div class="tool-card">
                    <h3>Input Validation</h3>
                    <p>Validate tất cả input từ user</p>
                </div>
                <div class="tool-card">
                    <h3>Whitelist Approach</h3>
                    <p>Chỉ cho phép ký tự an toàn</p>
                </div>
                <div class="tool-card">
                    <h3>Parameterized Commands</h3>
                    <p>Sử dụng prepared statements</p>
                </div>
                <div class="tool-card">
                    <h3>Principle of Least Privilege</h3>
                    <p>Chạy với quyền tối thiểu</p>
                </div>
            </div>
        </div>
    </div>
</body>
</html>
