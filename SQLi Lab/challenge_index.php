<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SQL Injection Login Challenge</title>
    <link rel="stylesheet" href="css/styles.css">
    <style>
        body {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            margin: 0;
            font-family: Arial, sans-serif;
        }
        .hero-container {
            max-width: 820px;
            margin: 0 auto;
            padding: 56px 24px;
            text-align: center;
            color: #ffffff;
        }
        .hero-title {
            font-size: 3.25rem;
            margin: 0;
            text-shadow: 2px 2px 4px rgba(0, 0, 0, 0.3);
        }
        .hero-subtitle {
            font-size: 1.25rem;
            margin: 18px 0 32px;
            opacity: 0.85;
        }
        .challenge-card {
            background: rgba(255, 255, 255, 0.95);
            padding: 40px;
            border-radius: 20px;
            color: #1f2933;
            margin: 0 auto 48px;
            max-width: 640px;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.2);
        }
        .challenge-description {
            font-size: 1.05rem;
            line-height: 1.6;
            margin: 20px 0;
        }
        .start-button {
            background: linear-gradient(135deg, #ff6b35 0%, #f7931e 100%);
            color: #ffffff;
            border: none;
            padding: 15px 40px;
            border-radius: 50px;
            font-size: 1.1rem;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.3s ease, box-shadow 0.3s ease;
            text-decoration: none;
            display: inline-block;
            margin: 24px 0 8px;
        }
        .start-button:hover {
            transform: translateY(-3px);
            box-shadow: 0 12px 24px rgba(255, 107, 53, 0.3);
        }
        .lab-links {
            background: rgba(255, 255, 255, 0.12);
            padding: 24px;
            border-radius: 12px;
            margin: 32px 0;
        }
        .lab-link {
            display: inline-block;
            background: rgba(255, 255, 255, 0.2);
            color: #ffffff;
            padding: 11px 18px;
            margin: 6px;
            border-radius: 8px;
            text-decoration: none;
            transition: background 0.3s ease;
            font-size: 0.95rem;
        }
        .lab-link:hover {
            background: rgba(255, 255, 255, 0.32);
        }
    </style>
</head>
<body>
    <div class="hero-container">
        <h1 class="hero-title">SQL Injection</h1>
        <h2 class="hero-subtitle">Admin Login Challenge</h2>
        <div class="challenge-card">
            <h3 style="color: #667eea; margin-top: 0;">Challenge Overview</h3>
            <p class="challenge-description">
                Your mission is simple: break through a vulnerable admin login and capture the flag. Watch how the
                application builds its SQL queries, experiment with payloads, and use the optional hints only when you
                need a gentle push.
            </p>
            <ul style="text-align: left; list-style: disc; margin: 0 auto; max-width: 440px; line-height: 1.6;">
                <li>Understand how inputs are blended into SQL statements.</li>
                <li>Practice authentication bypass techniques in a safe lab.</li>
                <li>Observe query output and error messages to refine payloads.</li>
                <li>Take hints gradually so you retain the learning.</li>
            </ul>
            <a href="admin_login_challenge.php" class="start-button">Start the Challenge</a>
            <div style="font-size: 0.95rem; color: #5a6170;">Expected duration: 10-20 minutes.</div>
        </div>
        <div class="lab-links">
            <h3>Explore Other SQLi Labs</h3>
            <a href="level1.php" class="lab-link">Level 1 - Error Based</a>
            <a href="level2.php" class="lab-link">Level 2 - Union Based</a>
            <a href="level3.php" class="lab-link">Level 3 - Stacked Queries</a>
            <a href="level4.php" class="lab-link">Level 4 - Boolean Blind</a>
            <a href="level5.php" class="lab-link">Level 5 - Time Based</a>
            <a href="level6.php" class="lab-link">Level 6 - Out-of-Band</a>
            <a href="level7_set.php" class="lab-link">Level 7 - Second Order</a>
            <a href="level8.php" class="lab-link">Level 8 - XPath Injection</a>
            <a href="level9.php" class="lab-link">Level 9 - Auth Bypass</a>
            <a href="level10.php" class="lab-link">Level 10 - Insert Injection</a>
            <a href="level11.php" class="lab-link">Level 11 - Update Injection</a>
            <a href="level12.php" class="lab-link">Level 12 - WAF Bypass</a>
            <a href="level13.php" class="lab-link">Level 13 - JSON Injection</a>
            <a href="level14.php" class="lab-link">Level 14 - Comment Bypass</a>
            <a href="level15.php" class="lab-link">Level 15 - Encoding Bypass</a>
            <a href="level16.php" class="lab-link">Level 16 - Space Bypass</a>
        </div>
        <div style="margin-top: 40px; opacity: 0.85; font-size: 0.95rem;">
            <p>These labs are designed for hands-on practice in a controlled environment.</p>
            <p>Please use them responsibly and only against the systems provided.</p>
        </div>
    </div>
</body>
</html>
