<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OS Command Injection Labs - Security Training Platform</title>
    <link rel="stylesheet" href="css/styles.css">
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ OS Command Injection Labs</h1>
            <p>A comprehensive platform for learning OS command injection techniques</p>
        </div>

        <div class="intro-section">
            <h2>📚 Giới thiệu về OS Command Injection</h2>
            <p><strong>OS Command Injection</strong> là một lỗ hổng bảo mật nghiêm trọng xảy ra khi ứng dụng web thực thi các lệnh hệ điều hành với dữ liệu đầu vào từ người dùng mà không được kiểm tra đúng cách.</p>
            
            <div class="info-grid">
                <div class="info-card">
                    <h3>⚠️ Nguy hiểm</h3>
                    <ul>
                        <li>Thực thi lệnh tùy ý</li>
                        <li>Đọc/ghi file hệ thống</li>
                        <li>Leo thang đặc quyền</li>
                        <li>Kiểm soát hoàn toàn server</li>
                    </ul>
                </div>
                <div class="info-card">
                    <h3>🔍 Phát hiện</h3>
                    <ul>
                        <li>Thử các ký tự đặc biệt</li>
                        <li>Command chaining (;&|)</li>
                        <li>Time-based detection</li>
                        <li>Output analysis</li>
                    </ul>
                </div>
                <div class="info-card">
                    <h3>🛡️ Phòng chống</h3>
                    <ul>
                        <li>Input validation</li>
                        <li>Whitelist approach</li>
                        <li>Parameterized commands</li>
                        <li>Sandboxing</li>
                    </ul>
                </div>
            </div>
        </div>

        <div class="levels-grid">
            <h2>🎯 Các Level Thử thách</h2>
            
            <div class="level-card">
                <h3>Level 1 - Basic Injection</h3>
                <p>Học cách thực hiện OS Command Injection cơ bản</p>
                <div class="level-info">
                    <span class="difficulty easy">Dễ</span>
                    <span class="objective">Tìm flag đầu tiên</span>
                </div>
                <a href="level1.php" class="btn">Bắt đầu Level 1</a>
            </div>

            <div class="level-card">
                <h3>Level 2 - Basic Filter Bypass</h3>
                <p>Bypass filter đơn giản bằng các toán tử thay thế</p>
                <div class="level-info">
                    <span class="difficulty easy">Dễ</span>
                    <span class="objective">Bypass semicolon filter</span>
                </div>
                <a href="level2.php" class="btn">Bắt đầu Level 2</a>
            </div>

            <div class="level-card">
                <h3>Level 3 - Space Filter Bypass</h3>
                <p>Bypass space character filtering</p>
                <div class="level-info">
                    <span class="difficulty medium">Trung bình</span>
                    <span class="objective">Bypass space filter</span>
                </div>
                <a href="level3.php" class="btn">Bắt đầu Level 3</a>
            </div>

            <div class="level-card">
                <h3>Level 4 - Keyword Filtering</h3>
                <p>Bypass filter từ khóa nguy hiểm</p>
                <div class="level-info">
                    <span class="difficulty medium">Trung bình</span>
                    <span class="objective">Bypass keyword filter</span>
                </div>
                <a href="level4.php" class="btn">Bắt đầu Level 4</a>
            </div>

            <div class="level-card">
                <h3>Level 5 - Blind Injection</h3>
                <p>Khai thác khi không thấy output trực tiếp</p>
                <div class="level-info">
                    <span class="difficulty hard">Khó</span>
                    <span class="objective">Blind command injection</span>
                </div>
                <a href="level5.php" class="btn">Bắt đầu Level 5</a>
            </div>

            <div class="level-card">
                <h3>Level 6 - Time-based Detection</h3>
                <p>Sử dụng time delay để detect injection</p>
                <div class="level-info">
                    <span class="difficulty hard">Khó</span>
                    <span class="objective">Time-based payload</span>
                </div>
                <a href="level6.php" class="btn">Bắt đầu Level 6</a>
            </div>

            <div class="level-card">
                <h3>Level 7 - Encoding Bypass</h3>
                <p>Advanced encoding và output redirection</p>
                <div class="level-info">
                    <span class="difficulty hard">Khó</span>
                    <span class="objective">Advanced bypass</span>
                </div>
                <a href="level7.php" class="btn">Bắt đầu Level 7</a>
            </div>

            <div class="level-card">
                <h3>Level 8 - WAF Bypass</h3>
                <p>Bypass Web Application Firewall</p>
                <div class="level-info">
                    <span class="difficulty hard">Khó</span>
                    <span class="objective">WAF evasion</span>
                </div>
                <a href="level8.php" class="btn">Bắt đầu Level 8</a>
            </div>

            <div class="level-card">
                <h3>Level 9 - Out-of-Band</h3>
                <p>Data exfiltration qua network channels</p>
                <div class="level-info">
                    <span class="difficulty hard">Khó</span>
                    <span class="objective">Network exfiltration</span>
                </div>
                <a href="level9.php" class="btn">Bắt đầu Level 9</a>
            </div>

            <div class="level-card">
                <h3>Level 10 - Race Conditions</h3>
                <p>Khai thác race conditions và automation</p>
                <div class="level-info">
                    <span class="difficulty hard">Khó</span>
                    <span class="objective">Timing attacks</span>
                </div>
                <a href="level10.php" class="btn">Bắt đầu Level 10</a>
            </div>
        </div>

        <div class="tools-section">
            <h2>🛠️ Công cụ hữu ích</h2>
            <div class="tools-grid">
                <div class="tool-card">
                    <h3>Command Chaining</h3>
                    <code>; | && || `</code>
                    <p>Các ký tự để nối lệnh</p>
                </div>
                <div class="tool-card">
                    <h3>Common Payloads</h3>
                    <code>whoami; id; ls -la</code>
                    <p>Lệnh thông dụng để test</p>
                </div>
                <div class="tool-card">
                    <h3>File Operations</h3>
                    <code>cat /etc/passwd</code>
                    <p>Đọc file hệ thống</p>
                </div>
                <div class="tool-card">
                    <h3>Network Tools</h3>
                    <code>ping; wget; curl</code>
                    <p>Công cụ mạng cho blind injection</p>
                </div>
            </div>
        </div>

        <div class="footer">
            <p>⚠️ <strong>Cảnh báo:</strong> Lab này chỉ dành cho mục đích học tập. Không sử dụng trên hệ thống thực tế!</p>
            <p>📚 Tìm hiểu thêm: <a href="https://owasp.org/www-community/attacks/Command_Injection" target="_blank">OWASP Command Injection</a></p>
        </div>
    </div>
</body>
</html>
