<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🔐 SQL Injection Login Challenge</title>
    <link rel="stylesheet" href="css/styles.css">
    <style>
        body {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            margin: 0;
            font-family: 'Arial', sans-serif;
        }
        
        .hero-container {
            max-width: 800px;
            margin: 0 auto;
            padding: 50px 20px;
            text-align: center;
            color: white;
        }
        
        .hero-title {
            font-size: 3.5em;
            margin: 0;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }
        
        .hero-subtitle {
            font-size: 1.3em;
            margin: 20px 0;
            opacity: 0.9;
        }
        
        .challenge-card {
            background: rgba(255,255,255,0.95);
            padding: 40px;
            border-radius: 20px;
            color: #333;
            margin: 40px auto;
            max-width: 600px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.2);
        }
        
        .challenge-description {
            font-size: 1.1em;
            line-height: 1.6;
            margin: 20px 0;
        }
        
        .start-button {
            background: linear-gradient(135deg, #ff6b35 0%, #f7931e 100%);
            color: white;
            border: none;
            padding: 15px 40px;
            border-radius: 50px;
            font-size: 1.2em;
            font-weight: bold;
            cursor: pointer;
            transition: all 0.3s ease;
            text-decoration: none;
            display: inline-block;
            margin: 20px 0;
        }
        
        .start-button:hover {
            transform: translateY(-3px);
            box-shadow: 0 10px 20px rgba(255, 107, 53, 0.3);
        }
        
        .features {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 30px 0;
        }
        
        .feature {
            text-align: center;
            padding: 20px;
        }
        
        .feature-icon {
            font-size: 2em;
            margin-bottom: 10px;
        }
        
        .difficulty-badge {
            background: #28a745;
            color: white;
            padding: 8px 16px;
            border-radius: 20px;
            font-size: 0.9em;
            font-weight: bold;
            display: inline-block;
            margin: 10px 0;
        }
        
        .lab-links {
            background: rgba(255,255,255,0.1);
            padding: 20px;
            border-radius: 10px;
            margin: 20px 0;
        }
        
        .lab-link {
            display: inline-block;
            background: rgba(255,255,255,0.2);
            color: white;
            padding: 10px 15px;
            margin: 5px;
            border-radius: 8px;
            text-decoration: none;
            transition: background 0.3s;
        }
        
        .lab-link:hover {
            background: rgba(255,255,255,0.3);
        }
    </style>
</head>
<body>
    <div class="hero-container">
        <h1 class="hero-title">🔐 SQL Injection</h1>
        <h2 class="hero-subtitle">Admin Login Challenge</h2>
        
        <div class="challenge-card">
            <h3 style="color: #667eea; margin-top: 0;">🎯 Thử Thách Hack Đăng Nhập</h3>
            
            <div class="difficulty-badge">Độ khó: Beginner - Intermediate</div>
            
            <div class="challenge-description">
                <p><strong>Mục tiêu chính:</strong> Sử dụng kỹ thuật SQL Injection để bypass hệ thống authentication và đăng nhập với quyền admin.</p>
                
                <div class="features">
                    <div class="feature">
                        <div class="feature-icon">🎯</div>
                        <h4>Mục tiêu rõ ràng</h4>
                        <p>Đăng nhập admin để lấy flag</p>
                    </div>
                    <div class="feature">
                        <div class="feature-icon">🐛</div>
                        <h4>Debug Mode</h4>
                        <p>Xem SQL query để phân tích</p>
                    </div>
                    <div class="feature">
                        <div class="feature-icon">💡</div>
                        <h4>Hệ thống gợi ý</h4>
                        <p>Hints từ cơ bản đến nâng cao</p>
                    </div>
                </div>
                
                <h4>📚 Bạn sẽ học được:</h4>
                <ul style="text-align: left; display: inline-block;">
                    <li>Cách SQL Injection hoạt động</li>
                    <li>Kỹ thuật bypass authentication</li>
                    <li>Sử dụng toán tử OR và comment trong SQL</li>
                    <li>Phân tích và debug SQL queries</li>
                </ul>
            </div>
            
            <a href="admin_login_challenge.php" class="start-button">
                🚀 Bắt Đầu Challenge
            </a>
        </div>
        
        <div class="lab-links">
            <h3>🧪 Hoặc khám phá các SQLi Labs khác:</h3>
            <a href="level1.php" class="lab-link">Level 1 - Error Based</a>
            <a href="level2.php" class="lab-link">Level 2 - Union Based</a>
            <a href="level3.php" class="lab-link">Level 3 - Stacked Queries</a>
            <a href="level4.php" class="lab-link">Level 4 - Boolean Blind</a>
            <a href="level5.php" class="lab-link">Level 5 - Time Based</a>
            <a href="level6.php" class="lab-link">Level 6 - Out-of-Band</a>
            <a href="level7_set.php" class="lab-link">Level 7 - Second Order</a>
            <a href="level8.php" class="lab-link">Level 8 - XPath Injection</a>
            <a href="level9.php" class="lab-link">Level 9 - Auth Bypass (Original)</a>
            <a href="level10.php" class="lab-link">Level 10 - Insert Injection</a>
            <br>
            <a href="level11.php" class="lab-link">Level 11 - Update Injection</a>
            <a href="level12.php" class="lab-link">Level 12 - WAF Bypass</a>
            <a href="level13.php" class="lab-link">Level 13 - JSON Injection</a>
            <a href="level14.php" class="lab-link">Level 14 - Comment Bypass</a>
            <a href="level15.php" class="lab-link">Level 15 - Encoding Bypass</a>
            <a href="level16.php" class="lab-link">Level 16 - Space Bypass</a>
        </div>
        
        <div style="margin-top: 40px; opacity: 0.8;">
            <p>💻 Được phát triển cho mục đích học tập và training bảo mật</p>
            <p>⚠️ Chỉ sử dụng trong môi trường lab - Không hack hệ thống thực!</p>
        </div>
    </div>
</body>
</html>