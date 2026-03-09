<?php
// Level 14: Encoding Bypass - URL/HTML Entity Filtering
// Goal: Bypass encoding-based input filtering

session_start();

require_once __DIR__ . '/includes/helpers.php';
require_once __DIR__ . '/helpers.php';
$_flag_result = handle_inline_flag_submit(14);

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
$raw_input = "";
$decoded_input = "";

if ($_POST) {
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';

    $raw_input = "Username: " . htmlspecialchars($username) . " | Password: " . htmlspecialchars($password);

    // Decode URL encoding and HTML entities
    $username = urldecode($username);
    $username = html_entity_decode($username, ENT_QUOTES);
    $password = urldecode($password);
    $password = html_entity_decode($password, ENT_QUOTES);

    $decoded_input = "Username: " . htmlspecialchars($username) . " | Password: " . htmlspecialchars($password);

    // Basic filtering on decoded input
    $dangerous_chars = ["'", '"', '=', 'OR', 'UNION', 'SELECT'];
    $blocked_chars = [];

    foreach ($dangerous_chars as $char) {
        if (stripos($username . $password, $char) !== false) {
            $blocked_chars[] = $char;
        }
    }

    if (!empty($blocked_chars)) {
        $message = "Security filter triggered!<br>";
        $message .= "Dangerous characters detected after decoding: " . implode(', ', $blocked_chars) . "<br>";
        $message .= "Raw input: <code>" . $raw_input . "</code><br>";
        $message .= "Decoded input: <code>" . $decoded_input . "</code><br>";
        $message .= "Try encoding your payload to bypass filters.";
    } else {
        // VULNERABLE query (if filters are bypassed)
        $sql = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";

        try {
            $result = $conn->query($sql);

            if ($result && $result->num_rows > 0) {
                $user_data = $result->fetch_assoc();

                if ($user_data['role'] === 'admin') {
                    $success = true;
                    $flag = get_flag_for_level(14);
                    $message = "Great job! You bypassed the encoding filter to reach admin.<br>";
                    $message .= "<strong>Flag:</strong> <code>" . htmlspecialchars($flag) . "</code><br>";
                    $message .= "Raw input: <code>" . $raw_input . "</code><br>";
                    $message .= "Decoded input: <code>" . $decoded_input . "</code><br>";
                    $message .= "SQL query: <code>" . htmlspecialchars($sql) . "</code><br>";
                    $message .= "Administrator access granted through encoding bypass.";
                } else {
                    $message = "Login successful as: " . htmlspecialchars($user_data['username']) . " (" . htmlspecialchars($user_data['role']) . ")";
                    $message .= "<br>You still need the admin role to obtain the flag.";
                }
            } else {
                $message = "Authentication failed: no matching user found.";
                $message .= "<br>SQL query: <code>" . htmlspecialchars($sql) . "</code>";
            }

        } catch (Exception $e) {
            $message = "SQL error: " . $e->getMessage();
            $message .= "<br>SQL query: <code>" . htmlspecialchars($sql) . "</code>";
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Level 14 - Encoding Bypass | SQL Injection Lab</title>
    <link rel="stylesheet" href="css/styles.css">

</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Level 14 - Encoding Bypass</h1>
            <p>Bypass input filtering using URL encoding and HTML entities</p>
            <a href="index.php" class="back-btn">&larr; Back to Labs</a>
        </div>

        <div class="challenge-layout">
            <!-- Left: Source Code Panel -->
            <div class="code-panel">
                <h3>Vulnerable Source Code</h3>
                <div class="source-code">
                    <pre><code><span class="php-comment">// Step 1: decode before checking</span>
<span class="php-variable">$username</span> = <span class="php-function">urldecode</span>(<span class="php-variable">$username</span>);
<span class="php-variable">$username</span> = <span class="php-function">html_entity_decode</span>(<span class="php-variable">$username</span>, ENT_QUOTES);
<span class="php-variable">$password</span> = <span class="php-function">urldecode</span>(<span class="php-variable">$password</span>);
<span class="php-variable">$password</span> = <span class="php-function">html_entity_decode</span>(<span class="php-variable">$password</span>, ENT_QUOTES);

<span class="php-comment">// Step 2: filter AFTER decoding</span>
<span class="php-comment">// blocked: ', ", =, OR, UNION, SELECT</span>
<span class="php-keyword">if</span> (empty(<span class="php-variable">$blocked_chars</span>)) {
    <span class="php-comment">// VULNERABLE: decoded input in raw SQL</span>
<span class="vuln-line">    <span class="php-variable">$sql</span> = <span class="php-string">"SELECT * FROM users"</span>
         . <span class="php-string">" WHERE username='$username'"</span>
         . <span class="php-string">" AND password='$password'"</span>;</span>
    <span class="php-variable">$result</span> = <span class="php-variable">$conn</span>-&gt;<span class="php-function">query</span>(<span class="php-variable">$sql</span>);
    <span class="php-keyword">if</span> (<span class="php-variable">$result</span>[<span class="php-string">'role'</span>] === <span class="php-string">'admin'</span>) {
        <span class="php-comment">// flag awarded</span>
    }
}</code></pre>
                </div>
                <div class="vuln-annotation">
                    <strong>Vulnerability:</strong>&nbsp; The server decodes URL encoding and HTML entities <em>before</em> applying the keyword filter, then feeds the decoded string directly into SQL. Encoding the payload with a second encoding layer (or using a scheme the filter does not re-expand) lets dangerous characters survive the filter and reach the query.
                </div>
            </div>

            <!-- Right: Challenge Panel -->
            <div class="challenge-panel">
                <h3>Challenge</h3>
                <div class="panel-body">
                    <p>This form decodes URL and HTML entity encoding before filtering. The filter checks the <em>decoded</em> value, but the decoded string is then used in a raw SQL query.</p>
                    <p><strong>Goal:</strong> Encode your payload so it slips past the filter and injects SQL to log in as <code>admin</code>!</p>

                    <div class="encoding-examples">
                        <strong>Encoding Reference:</strong><br>
                        <strong>Single Quote:</strong> &apos; &rarr; <code>%27</code> (URL) &nbsp; <code>&amp;#39;</code> (HTML)<br>
                        <strong>Double Quote:</strong> &quot; &rarr; <code>%22</code> (URL) &nbsp; <code>&amp;quot;</code> (HTML)<br>
                        <strong>Equals:</strong> = &rarr; <code>%3D</code> (URL) &nbsp; <code>&amp;#61;</code> (HTML)<br>
                        <strong>Space:</strong> (space) &rarr; <code>%20</code> (URL) &nbsp; <code>&amp;#32;</code> (HTML)<br>
                        <strong>OR:</strong> OR &rarr; <code>%4F%52</code> (URL) &nbsp; <code>&amp;#79;&amp;#82;</code> (HTML)
                    </div>

                    <div class="encoder-tool">
                        <h4>Payload Encoder Tool</h4>
                        <input type="text" id="plain-text" placeholder="Enter text to encode...">
                        <button class="encode-btn" onclick="urlEncode()">URL Encode</button>
                        <button class="encode-btn" onclick="htmlEncode()">HTML Encode</button>
                        <button class="encode-btn" onclick="clearEncoder()">Clear</button>
                        <input type="text" id="encoded-text" placeholder="Encoded result..." readonly>
                    </div>

                    <?php if ($message): ?>
                        <div class="message <?= $success ? 'success' : (stripos($message, 'error') !== false ? 'error' : 'info') ?>">
                            <?= $message ?>
                        </div>
                    <?php endif; ?>

                    <h3>Encoded Login</h3>
                    <form method="POST" class="login-form">
                        <div class="form-group">
                            <label for="username">Username:</label>
                            <input type="text" id="username" name="username" placeholder="Enter username (can be encoded)" required>
                        </div>

                        <div class="form-group">
                            <label for="password">Password:</label>
                            <input type="text" id="password" name="password" placeholder="Enter password (can be encoded)" required>
                        </div>

                        <button type="submit" class="submit-btn">Login</button>
                    </form>
                </div>
            </div>
        </div>

        <?= render_hint_section(get_level_hints(14), 'Hints for Level 14'); ?>

    <?= render_inline_flag_form(14, $_flag_result) ?>

        <div class="navigation">
            <a href="level13.php">&larr; Previous Level</a>
            <a href="level15.php">Next Level &rarr;</a>
        </div>
    </div>

    <script>
        function urlEncode() {
            const plain = document.getElementById('plain-text').value;
            const encoded = encodeURIComponent(plain);
            document.getElementById('encoded-text').value = encoded;
        }

        function htmlEncode() {
            const plain = document.getElementById('plain-text').value;
            let encoded = plain
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;')
                .replace(/'/g, '&#39;')
                .replace(/ /g, '&#32;')
                .replace(/=/g, '&#61;');

            // Encode letters to decimal entities
            encoded = encoded.replace(/[A-Za-z]/g, function(match) {
                return '&#' + match.charCodeAt(0) + ';';
            });

            document.getElementById('encoded-text').value = encoded;
        }

        function clearEncoder() {
            document.getElementById('plain-text').value = '';
            document.getElementById('encoded-text').value = '';
        }
    </script>
</body>
</html>

<?php $conn->close(); ?>
