<?php
// Level 16: Advanced WAF Bypass - Final Boss Challenge
// Goal: Bypass multiple sophisticated filtering mechanisms

session_start();

require_once __DIR__ . '/includes/helpers.php';
require_once __DIR__ . '/helpers.php';
$_flag_result = handle_inline_flag_submit(16);
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
$blocked_patterns = [];
$waf_bypass_achieved = false;

if ($_POST) {
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';

    // Advanced WAF simulation with multiple filter layers
    $original_input = "Username: $username | Password: $password";

    // Layer 1: Comment filtering
    $comment_patterns = ['--', '#', '/*', '*/'];
    $has_comments = false;
    foreach ($comment_patterns as $pattern) {
        if (stripos($username . $password, $pattern) !== false) {
            $blocked_patterns[] = "Comment: $pattern";
            $has_comments = true;
        }
    }

    // Layer 2: Common SQL keywords
    $sql_keywords = ['UNION', 'SELECT', 'FROM', 'WHERE', 'INSERT', 'UPDATE', 'DELETE', 'DROP'];
    $has_keywords = false;
    foreach ($sql_keywords as $keyword) {
        if (stripos($username . $password, $keyword) !== false) {
            $blocked_patterns[] = "Keyword: $keyword";
            $has_keywords = true;
        }
    }

    // Layer 3: Special characters
    $special_chars = ["'", '"', '=', '<', '>', '(', ')'];
    $has_special = false;
    foreach ($special_chars as $char) {
        if (strpos($username . $password, $char) !== false) {
            $blocked_patterns[] = "Special: $char";
            $has_special = true;
        }
    }

    // Layer 4: Logical operators
    $logical_ops = ['OR', 'AND', 'NOT'];
    $has_logical = false;
    foreach ($logical_ops as $op) {
        if (stripos($username . $password, $op) !== false) {
            $blocked_patterns[] = "Logic: $op";
            $has_logical = true;
        }
    }

    // Layer 5: Space and whitespace
    $has_spaces = false;
    if (preg_match('/\s/', $username . $password)) {
        $blocked_patterns[] = "Whitespace detected";
        $has_spaces = true;
    }

    // Calculate WAF bypass score
    $total_filters = 5;
    $triggered_filters = ($has_comments ? 1 : 0) + ($has_keywords ? 1 : 0) +
                        ($has_special ? 1 : 0) + ($has_logical ? 1 : 0) + ($has_spaces ? 1 : 0);

    if ($triggered_filters > 0) {
        $message = "Advanced WAF protection triggered!<br>";
        $message .= "Blocked patterns: " . implode(', ', $blocked_patterns) . "<br>";
        $message .= "Filters triggered: $triggered_filters/$total_filters<br>";
        $message .= "You must bypass every filter to proceed.<br>";
        $message .= "Try more sophisticated encoding, alternatives, or creative bypasses.";
    } else {
        $waf_bypass_achieved = true;

        // If all filters are bypassed, check for actual injection
        $sql = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";

        try {
            $result = $conn->query($sql);

            if ($result && $result->num_rows > 0) {
                $user_data = $result->fetch_assoc();

                if ($user_data['role'] === 'admin') {
                    $success = true;
                    $flag = get_flag_for_level(16);
                    $message = "Ultimate victory! You defeated the advanced WAF.<br>";
                    $message .= "<strong>Flag:</strong> <code>" . htmlspecialchars($flag) . "</code><br>";
                    $message .= "All WAF filters bypassed successfully.<br>";
                    $message .= "SQL query: <code>" . htmlspecialchars($sql) . "</code><br>";
                    $message .= "Congratulations on completing all 16 levels!";
                } else {
                    $message = "WAF bypass succeeded but the injection did not escalate.<br>";
                    $message .= "Login successful as: " . htmlspecialchars($user_data['username']) . " (" . htmlspecialchars($user_data['role']) . ")<br>";
                    $message .= "You still need the admin role for the final flag.";
                }
            } else {
                $message = "WAF bypass succeeded but authentication failed.<br>";
                $message .= "All filters were bypassed, yet no matching user was found.<br>";
                $message .= "SQL query: <code>" . htmlspecialchars($sql) . "</code><br>";
                $message .= "Adjust your payload until it maps to the admin credentials.";
            }

        } catch (Exception $e) {
            $message = "WAF bypass succeeded but the query errored.<br>";
            $message .= "All filters were bypassed successfully.<br>";
            $message .= "SQL error: " . $e->getMessage() . "<br>";
            $message .= "SQL query: <code>" . htmlspecialchars($sql) . "</code>";
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Level 16 - Advanced WAF Bypass | SQL Injection Lab</title>
    <link rel="stylesheet" href="css/styles.css">

</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Level 16 - Advanced WAF Bypass</h1>
            <p>The ultimate challenge - bypass sophisticated Web Application Firewall</p>
            <a href="index.php" class="back-btn">&larr; Back to Labs</a>
        </div>

        <div class="final-boss">
            FINAL BOSS CHALLENGE<br>
            Advanced WAF Protection System
        </div>

        <div class="challenge-layout">
            <!-- Left: Source Code Panel -->
            <div class="code-panel">
                <h3>Vulnerable Source Code</h3>
                <div class="source-code">
                    <pre><code><span class="php-comment">// Layer 1: --, #, /*, */</span>
<span class="php-comment">// Layer 2: UNION, SELECT, FROM, WHERE …</span>
<span class="php-comment">// Layer 3: ', ", =, &lt;, &gt;, (, )</span>
<span class="php-comment">// Layer 4: OR, AND, NOT</span>
<span class="php-comment">// Layer 5: \s (any whitespace)</span>
<span class="php-variable">$triggered</span> = <span class="php-variable">$layer1</span> + <span class="php-variable">$layer2</span>
            + <span class="php-variable">$layer3</span> + <span class="php-variable">$layer4</span>
            + <span class="php-variable">$layer5</span>;

<span class="php-keyword">if</span> (<span class="php-variable">$triggered</span> &gt; 0) {
    <span class="php-comment">// block all flagged input</span>
} <span class="php-keyword">else</span> {
    <span class="php-comment">// VULNERABLE: all-filter-passing input</span>
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
                    <strong>Vulnerability:</strong>&nbsp; Five independent filter layers each block a different pattern class. The SQL construction is still raw string concatenation — combine encoding, keyword alternatives (<code>||</code> instead of <code>OR</code>), operator substitutes, and whitespace tricks to craft a payload that satisfies every layer simultaneously and still alters the query logic.
                </div>
            </div>

            <!-- Right: Challenge Panel -->
            <div class="challenge-panel">
                <h3>Challenge</h3>
                <div class="panel-body">
                    <p>This is the final boss! The WAF enforces five independent filter layers. Every single layer must be bypassed before your input reaches the underlying SQL query.</p>
                    <p><strong>Goal:</strong> Bypass all 5 WAF layers and authenticate as <code>admin</code> to capture the final flag!</p>

                    <div class="waf-status">
                        ADVANCED WAF PROTECTION ACTIVE<br>
                        Multiple Security Layers Engaged
                    </div>

                    <div class="filter-layers">
                        <h4>Active Security Filters:</h4>

                        <div class="filter-layer">
                            <strong>Layer 1:</strong> Comment Detection (blocks: <code>--</code>, <code>#</code>, <code>/*</code>, <code>*/</code>)
                        </div>

                        <div class="filter-layer">
                            <strong>Layer 2:</strong> SQL Keyword Filtering (blocks: <code>UNION</code>, <code>SELECT</code>, <code>FROM</code>, <code>WHERE</code>, etc.)
                        </div>

                        <div class="filter-layer">
                            <strong>Layer 3:</strong> Special Character Detection (blocks: <code>'</code> <code>"</code> <code>=</code> <code>&lt;</code> <code>&gt;</code> <code>(</code> <code>)</code>)
                        </div>

                        <div class="filter-layer">
                            <strong>Layer 4:</strong> Logical Operator Filtering (blocks: <code>OR</code>, <code>AND</code>, <code>NOT</code>)
                        </div>

                        <div class="filter-layer">
                            <strong>Layer 5:</strong> Whitespace Detection (blocks: spaces, tabs, newlines)
                        </div>
                    </div>

                    <?php if ($message): ?>
                        <div class="message <?= $success ? 'success' : ($waf_bypass_achieved ? 'warning' : 'error') ?>">
                            <?= $message ?>
                        </div>
                    <?php endif; ?>

                    <h3>Ultimate Login Challenge</h3>
                    <form method="POST" class="login-form">
                        <div class="form-group">
                            <label for="username">Username:</label>
                            <input type="text" id="username" name="username" placeholder="Bypass ALL filters..." required>
                        </div>

                        <div class="form-group">
                            <label for="password">Password:</label>
                            <input type="text" id="password" name="password" placeholder="Ultimate challenge awaits..." required>
                        </div>

                        <button type="submit" class="submit-btn">Face the Final Boss</button>
                    </form>
                </div>
            </div>
        </div>

        <?= render_hint_section(get_level_hints(16), 'Hints for Level 16'); ?>

    <?= render_inline_flag_form(16, $_flag_result) ?>

        <div class="navigation">
            <a href="level15.php">&larr; Previous Level</a>
            <span>Final Challenge!</span>
        </div>
    </div>
</body>
</html>

<?php $conn->close(); ?>
