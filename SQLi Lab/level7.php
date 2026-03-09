<?php
// Level 7: File-Based Login - Out-of-Band data extraction
require_once __DIR__ . '/includes/helpers.php';
require_once __DIR__ . '/helpers.php';
$_flag_result = handle_inline_flag_submit(7);

// Database connection
$host = $_ENV['DB_HOST'] ?? 'db';
$user = $_ENV['DB_USER'] ?? 'webapp';
$pass = $_ENV['DB_PASS'] ?? 'webapp123';
$dbname = $_ENV['DB_NAME'] ?? 'sqli_lab';

$conn = new mysqli($host, $user, $pass, $dbname);

if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

$message = "";
$success = false;
$file_content = "";

if ($_POST) {
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';

    // File-based injection using INTO OUTFILE
    $sql = "SELECT * FROM users WHERE username = '$username' AND password = '$password' AND role = 'admin'";

    try {
        $result = $conn->query($sql);

        if ($result && $result->num_rows > 0) {
            $admin_data = $result->fetch_assoc();
            $success = true;
            $flag = get_flag_for_level(7);
            $message = "Great job! You used file-based injection to log in as admin.<br>";
            $message .= "<strong>Flag:</strong> <code>" . htmlspecialchars($flag) . "</code><br>";
            $message .= "Welcome, " . htmlspecialchars($admin_data['username']) . "!";
        } else {
           $message = "Login failed: Invalid credentials";
        }

        // Check for file operations
        if (strpos($username, 'OUTFILE') !== false || strpos($username, 'DUMPFILE') !== false) {
            $message .= "<br>File operation detected in injection attempt.";
        }

    } catch (Exception $e) {
        $message = "Database error: " . $e->getMessage();

        // Check if it's a file permission error (indicates successful injection syntax)
        if (strpos($e->getMessage(), 'Access denied') !== false || strpos($e->getMessage(), 'OUTFILE') !== false) {
            $message .= "<br>File operation attempted but blocked by permissions.";
            $message .= "<br> Your injection syntax was correct! Try extracting data differently.";
        }
    }
}

// Check if any extraction files exist
$extraction_files = ['/tmp/admin_data.txt', '/var/lib/mysql-files/users.txt', '/tmp/passwords.txt'];
foreach ($extraction_files as $file) {
    if (file_exists($file)) {
        $file_content .= " Found: $file<br>";
        $file_content .= "Content: " . htmlspecialchars(file_get_contents($file)) . "<br><br>";
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Level 7 - File-Based Login | SQL Injection Lab</title>
    <link rel="stylesheet" href="css/styles.css">
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Level 7 - File-Based Login</h1>
            <p>Use file operations for out-of-band data extraction</p>
            <a href="index.php" class="back-btn">&larr; Back to Labs</a>
        </div>

        <div class="challenge-layout">
            <!-- Left: Source Code Panel -->
            <div class="code-panel">
                <h3>Vulnerable Source Code</h3>
                <div class="source-code">
                    <pre><code><span class="php-keyword">if</span> (<span class="php-variable">$_POST</span>) {
    <span class="php-variable">$username</span> = <span class="php-variable">$_POST</span>[<span class="php-string">'username'</span>] ?? <span class="php-string">''</span>;
    <span class="php-variable">$password</span> = <span class="php-variable">$_POST</span>[<span class="php-string">'password'</span>] ?? <span class="php-string">''</span>;

    <span class="php-comment">// File-based injection using INTO OUTFILE</span>
<span class="vuln-line">    <span class="php-variable">$sql</span> = <span class="php-string">"SELECT * FROM users WHERE username = '<span class="php-variable">$username</span>' AND password = '<span class="php-variable">$password</span>' AND role = 'admin'"</span>;</span>
    <span class="php-keyword">try</span> {
        <span class="php-variable">$result</span> = <span class="php-variable">$conn</span>-&gt;<span class="php-function">query</span>(<span class="php-variable">$sql</span>);
        <span class="php-keyword">if</span> (<span class="php-variable">$result</span> &amp;&amp; <span class="php-variable">$result</span>-&gt;num_rows &gt; 0) {
            <span class="php-comment">// success — return flag</span>
        }
        <span class="php-comment">// Check for file operations in attempt</span>
        <span class="php-keyword">if</span> (<span class="php-function">strpos</span>(<span class="php-variable">$username</span>, <span class="php-string">'OUTFILE'</span>) !== <span class="php-string">false</span>) {
            <span class="php-variable">$message</span> .= <span class="php-string">"File operation detected."</span>;
        }
    } <span class="php-keyword">catch</span> (Exception <span class="php-variable">$e</span>) {
        <span class="php-variable">$message</span> = <span class="php-string">"Database error: "</span> . <span class="php-variable">$e</span>-&gt;<span class="php-function">getMessage</span>();
        <span class="php-comment">// Permission errors confirm correct OUTFILE syntax</span>
    }
}

<span class="php-comment">// Server reads back any extracted files</span>
<span class="php-variable">$extraction_files</span> = [<span class="php-string">'/tmp/admin_data.txt'</span>, <span class="php-string">'/var/lib/mysql-files/users.txt'</span>];
<span class="php-keyword">foreach</span> (<span class="php-variable">$extraction_files</span> <span class="php-keyword">as</span> <span class="php-variable">$file</span>) {
    <span class="php-keyword">if</span> (<span class="php-function">file_exists</span>(<span class="php-variable">$file</span>)) {
        <span class="php-comment">// display file contents in response</span>
    }
}</code></pre>
                </div>
                <div class="vuln-annotation">
                    <strong>Vulnerability:</strong>&nbsp; <code>$username</code> is concatenated unsanitised. MySQL file privileges are enabled, so appending <code>' UNION SELECT ... INTO OUTFILE '/tmp/admin_data.txt'-- -</code> writes query results to disk. The server then reads and displays those files back in the response.
                </div>
            </div>

            <!-- Right: Challenge Panel -->
            <div class="challenge-panel">
                <h3>Challenge</h3>
                <div class="panel-body">
                    <div class="scenario">
                        <strong>Scenario:</strong> Document Management Login<br>
                        <strong>Objective:</strong> Use file-based injection to extract admin credentials.
                        MySQL file privileges are enabled — use <code>INTO OUTFILE</code> to write data to disk,
                        then the server will display any extracted files found at known paths.
                    </div>

                    <?php if ($message): ?>
                        <div class="message <?= $success ? 'success' : (stripos($message, 'error') !== false ? 'error' : 'info') ?>">
                            <?= $message ?>
                        </div>
                    <?php endif; ?>

                    <?php if ($file_content): ?>
                        <div class="result">
                            <strong>Extracted Files:</strong><br>
                            <?= $file_content ?>
                        </div>
                    <?php endif; ?>

                    <form method="POST" class="login-form">
                        <div class="form-group">
                            <label for="username">Username:</label>
                            <input type="text" id="username" name="username" placeholder="Enter username" required>
                        </div>

                        <div class="form-group">
                            <label for="password">Password:</label>
                            <input type="password" id="password" name="password" placeholder="Enter password" required>
                        </div>

                        <button type="submit" class="login-btn">Login</button>
                    </form>
                </div>
            </div>
        </div>

        <?= render_hint_section(get_level_hints(7), 'Hints for Level 7'); ?>

    <?= render_inline_flag_form(7, $_flag_result) ?>

        <div class="navigation">
            <a href="level6.php">&larr; Previous Level</a>
            <a href="level8.php" class="next-link">Next Level &rarr;</a>
        </div>
    </div>
</body>
</html>

<?php $conn->close(); ?>
