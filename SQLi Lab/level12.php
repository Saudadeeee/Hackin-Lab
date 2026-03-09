<?php
// Level 12: JSON-based SQL Injection
// Goal: Exploit JSON parameter parsing in SQL queries

session_start();

require_once __DIR__ . '/includes/helpers.php';
require_once __DIR__ . '/helpers.php';
$_flag_result = handle_inline_flag_submit(12);
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

if ($_POST) {
    $json_input = $_POST['json_data'] ?? '';

    try {
        // Parse JSON input
        $data = json_decode($json_input, true);

        if ($data === null) {
            $message = "Invalid JSON format!";
        } else {
            $username = $data['username'] ?? '';
            $password = $data['password'] ?? '';
            $role_filter = $data['role'] ?? 'user';

            // VULNERABLE query using JSON parsed data
            $sql = "SELECT * FROM users WHERE username = '$username' AND password = '$password' AND role = '$role_filter'";

            $result = $conn->query($sql);

            if ($result && $result->num_rows > 0) {
                $user_data = $result->fetch_assoc();

                if ($user_data['role'] === 'admin') {
                    $success = true;
                    $flag = get_flag_for_level(12);
                    $message = "Great job! You exploited JSON-based SQL injection.<br>";
                    $message .= "<strong>Flag:</strong> <code>" . htmlspecialchars($flag) . "</code><br>";
                    $message .= "JSON input: <code>" . htmlspecialchars($json_input) . "</code><br>";
                    $message .= "SQL query: <code>" . htmlspecialchars($sql) . "</code><br>";
                    $message .= "Administrator access granted!";
                } else {
                    $message = "Login successful as: " . htmlspecialchars($user_data['username']) . " (" . htmlspecialchars($user_data['role']) . ")";
                    $message .= "<br>You need admin role to get the flag!";
                }
            } else {
                $message = "Authentication failed: no matching user found.";
                $message .= "<br>SQL query: <code>" . htmlspecialchars($sql) . "</code>";
            }
        }

    } catch (Exception $e) {
        $message = "JSON processing error: " . $e->getMessage();
        $message .= "<br>JSON input: <code>" . htmlspecialchars($json_input ?? 'N/A') . "</code>";
    }
}

// Sample JSON for reference
$sample_json = json_encode([
    'username' => 'guest',
    'password' => 'guest123',
    'role' => 'user'
], JSON_PRETTY_PRINT);
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Level 12 - JSON Injection | SQL Injection Lab</title>
    <link rel="stylesheet" href="css/styles.css">

</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Level 12 - JSON Injection</h1>
            <p>Exploit JSON parameter parsing vulnerabilities in API authentication</p>
            <a href="index.php" class="back-btn">&larr; Back to Labs</a>
        </div>

        <div class="challenge-layout">
            <!-- Left: Source Code Panel -->
            <div class="code-panel">
                <h3>Vulnerable Source Code</h3>
                <div class="source-code">
                    <pre><code><span class="php-variable">$data</span> = <span class="php-function">json_decode</span>(<span class="php-variable">$json_input</span>, <span class="php-keyword">true</span>);

<span class="php-variable">$username</span>    = <span class="php-variable">$data</span>[<span class="php-string">'username'</span>] ?? <span class="php-string">''</span>;
<span class="php-variable">$password</span>    = <span class="php-variable">$data</span>[<span class="php-string">'password'</span>] ?? <span class="php-string">''</span>;
<span class="php-variable">$role_filter</span> = <span class="php-variable">$data</span>[<span class="php-string">'role'</span>]     ?? <span class="php-string">'user'</span>;

<span class="php-comment">// VULNERABLE: JSON fields used in raw SQL</span>
<span class="vuln-line"><span class="php-variable">$sql</span> = <span class="php-string">"SELECT * FROM users"</span>
     . <span class="php-string">" WHERE username = '$username'"</span>
     . <span class="php-string">" AND password  = '$password'"</span>
     . <span class="php-string">" AND role      = '$role_filter'"</span>;</span>

<span class="php-variable">$result</span> = <span class="php-variable">$conn</span>-&gt;<span class="php-function">query</span>(<span class="php-variable">$sql</span>);
<span class="php-keyword">if</span> (<span class="php-variable">$result</span>[<span class="php-string">'role'</span>] === <span class="php-string">'admin'</span>) {
    <span class="php-comment">// flag awarded</span>
}</code></pre>
                </div>
                <div class="vuln-annotation">
                    <strong>Vulnerability:</strong>&nbsp; Values extracted from the user-controlled JSON body are placed directly into the SQL query without parameterization. Injecting SQL syntax into any JSON field (e.g. <code>username</code> or <code>role</code>) can break out of the string context and alter query logic.
                </div>
            </div>

            <!-- Right: Challenge Panel -->
            <div class="challenge-panel">
                <h3>Challenge</h3>
                <div class="panel-body">
                    <p>This API endpoint accepts a JSON body for authentication. The fields are extracted and used directly in a SQL query — no parameterization or escaping is applied.</p>
                    <p><strong>Goal:</strong> Manipulate the JSON to authenticate as <code>admin</code> and capture the flag!</p>

                    <div class="json-viewer"><?= htmlspecialchars($sample_json) ?></div>

                    <?php if ($message): ?>
                        <div class="message <?= $success ? 'success' : (stripos($message, 'error') !== false ? 'error' : 'info') ?>">
                            <?= $message ?>
                        </div>
                    <?php endif; ?>

                    <h3>JSON Authentication API</h3>
                    <form method="POST" class="login-form">
                        <div class="form-group">
                            <label for="json_data">JSON Data:</label>
                            <textarea id="json_data" name="json_data"
                                      placeholder="Enter JSON authentication data..." required><?= htmlspecialchars($sample_json) ?></textarea>
                            <button type="button" class="sample-btn" onclick="loadSampleJSON()">Load Sample JSON</button>
                        </div>

                        <button type="submit" class="submit-btn">Authenticate</button>
                    </form>
                </div>
            </div>
        </div>

        <?= render_hint_section(get_level_hints(12), 'Hints for Level 12'); ?>

    <?= render_inline_flag_form(12, $_flag_result) ?>

        <div class="navigation">
            <a href="level11.php">&larr; Previous Level</a>
            <a href="level13.php">Next Level &rarr;</a>
        </div>
    </div>

    <script>
        function loadSampleJSON() {
            document.getElementById('json_data').value = `{
    "username": "guest",
    "password": "guest123",
    "role": "user"
}`;
        }
    </script>
</body>
</html>

<?php $conn->close(); ?>
