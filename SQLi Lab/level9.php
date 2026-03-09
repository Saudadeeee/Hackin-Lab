<?php
// Level 9: XPATH Injection - XML-based Authentication
// Goal: Bypass XML-based authentication system using XPATH injection

session_start();

require_once __DIR__ . '/includes/helpers.php';
require_once __DIR__ . '/helpers.php';
$_flag_result = handle_inline_flag_submit(9);
$message = "";
$success = false;

// XML user database (simulated)
$xml_data = '<?xml version="1.0"?>
<users>
    <user>
        <username>admin</username>
        <password>secret123</password>
        <role>administrator</role>
        <email>admin@company.com</email>
    </user>
    <user>
        <username>guest</username>
        <password>guest123</password>
        <role>user</role>
        <email>guest@company.com</email>
    </user>
    <user>
        <username>manager</username>
        <password>manage456</password>
        <role>manager</role>
        <email>manager@company.com</email>
    </user>
</users>';

if ($_POST) {
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';

    try {
        // Create XML document
        $xml = new DOMDocument();
        $xml->loadXML($xml_data);

        // Create XPath object
        $xpath = new DOMXPath($xml);

        // VULNERABLE XPATH query - directly concatenating user input
        $query = "//user[username/text()='{$username}' and password/text()='{$password}']";

        // Execute XPATH query
        $users = $xpath->query($query);

        if ($users && $users->length > 0) {
            $user = $users->item(0);
            $role = $xpath->query('role/text()', $user)->item(0)->nodeValue;
            $email = $xpath->query('email/text()', $user)->item(0)->nodeValue;

            if ($role === 'administrator') {
                $success = true;
                $flag = get_flag_for_level(9);
                $message = "Great job! You bypassed the XPath authentication filter.<br>";
                $message .= "<strong>Flag:</strong> <code>" . htmlspecialchars($flag) . "</code><br>";
                $message .= "XPath query: <code>" . htmlspecialchars($query) . "</code><br>";
                $message .= "Administrator access granted! Email: " . htmlspecialchars($email);
            } else {
                $message = "Login successful as: " . htmlspecialchars($username) . " (" . htmlspecialchars($role) . ")";
                $message .= "<br>Email: " . htmlspecialchars($email);
                $message .= "<br>You need administrator role to get the flag!";
            }
        } else {
            $message = " Authentication failed: No matching user found";
            $message .= "<br> XPATH Query: <code>" . htmlspecialchars($query) . "</code>";
        }

    } catch (Exception $e) {
        $message = " XPATH Error: " . $e->getMessage();
        $message .= "<br> XPATH Query: <code>" . htmlspecialchars($query ?? 'N/A') . "</code>";
        $message .= "<br> Error indicates successful injection attempt!";
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Level 9 - XPath Authentication | SQL Injection Lab</title>
    <link rel="stylesheet" href="css/styles.css">

</head>
<body>
    <div class="container">
        <div class="header">
            <h1> Level 9 - XPath Authentication</h1>
            <p>Bypass XML-based authentication using XPATH injection techniques</p>
            <a href="index.php" class="back-btn">&larr; Back to Labs</a>
        </div>

        <div class="challenge-layout">
            <!-- Left: Source Code Panel -->
            <div class="code-panel">
                <h3>Vulnerable Source Code</h3>
                <div class="source-code">
                    <pre><code><span class="php-variable">$username</span> = <span class="php-variable">$_POST</span>[<span class="php-string">'username'</span>] ?? <span class="php-string">''</span>;
<span class="php-variable">$password</span> = <span class="php-variable">$_POST</span>[<span class="php-string">'password'</span>] ?? <span class="php-string">''</span>;

<span class="php-variable">$xml</span> = <span class="php-keyword">new</span> <span class="php-function">DOMDocument</span>();
<span class="php-variable">$xml</span>-&gt;<span class="php-function">loadXML</span>(<span class="php-variable">$xml_data</span>);
<span class="php-variable">$xpath</span> = <span class="php-keyword">new</span> <span class="php-function">DOMXPath</span>(<span class="php-variable">$xml</span>);

<span class="php-comment">// VULNERABLE: user input directly in XPath</span>
<span class="vuln-line"><span class="php-variable">$query</span> = <span class="php-string">"//user[username/text()='<span class="php-variable">{$username}</span>'"</span>
       . <span class="php-string">" and password/text()='<span class="php-variable">{$password}</span>']"</span>;</span>

<span class="php-variable">$users</span> = <span class="php-variable">$xpath</span>-&gt;<span class="php-function">query</span>(<span class="php-variable">$query</span>);
<span class="php-keyword">if</span> (<span class="php-variable">$users</span> &amp;&amp; <span class="php-variable">$users</span>-&gt;length &gt; 0) {
    <span class="php-variable">$role</span> = <span class="php-variable">$xpath</span>-&gt;<span class="php-function">query</span>(<span class="php-string">'role/text()'</span>, ...);
}</code></pre>
                </div>
                <div class="vuln-annotation">
                    <strong>Vulnerability:</strong>&nbsp; <code>$username</code> and <code>$password</code> are interpolated directly into the XPath expression string. An attacker can inject XPath syntax (e.g. <code>' or '1'='1</code>) to alter the predicate logic and match any node, bypassing authentication entirely.
                </div>
            </div>

            <!-- Right: Challenge Panel -->
            <div class="challenge-panel">
                <h3>Challenge</h3>
                <div class="panel-body">
                    <p>This system uses an XML database with XPath queries for authentication. The query is built by directly embedding your credentials into the XPath expression.</p>
                    <p><strong>Goal:</strong> Login as <code>administrator</code> to capture the flag!</p>

                    <div class="xml-viewer">
                        <div class="xml-tag">&lt;users&gt;</div>
                        <div style="margin-left: 1rem;">
                            <div class="xml-tag">&lt;user&gt;</div>
                            <div style="margin-left: 1rem;">
                                <div class="xml-tag">&lt;username&gt;</div><span class="xml-content">admin</span><div class="xml-tag">&lt;/username&gt;</div>
                                <div class="xml-tag">&lt;password&gt;</div><span class="xml-content">secret123</span><div class="xml-tag">&lt;/password&gt;</div>
                                <div class="xml-tag">&lt;role&gt;</div><span class="xml-content">administrator</span><div class="xml-tag">&lt;/role&gt;</div>
                            </div>
                            <div class="xml-tag">&lt;/user&gt;</div>
                            <div class="text-muted" style="margin-top: 0.5rem;">... more users ...</div>
                        </div>
                        <div class="xml-tag">&lt;/users&gt;</div>
                    </div>

                    <?php if ($message): ?>
                        <div class="message <?= $success ? 'success' : (stripos($message, 'error') !== false ? 'error' : 'info') ?>">
                            <?= $message ?>
                        </div>
                    <?php endif; ?>

                    <h3>XML Authentication</h3>
                    <form method="POST" class="login-form">
                        <div class="form-group">
                            <label for="username">Username:</label>
                            <input type="text" id="username" name="username" placeholder="Enter username" required>
                        </div>

                        <div class="form-group">
                            <label for="password">Password:</label>
                            <input type="password" id="password" name="password" placeholder="Enter password" required>
                        </div>

                        <button type="submit" class="submit-btn">Authenticate</button>
                    </form>
                </div>
            </div>
        </div>

        <?= render_hint_section(get_level_hints(9), 'Hints for Level 9'); ?>

    <?= render_inline_flag_form(9, $_flag_result) ?>

        <div class="navigation">
            <a href="level8.php">&larr; Previous Level</a>
            <a href="level10.php">Next Level &rarr;</a>
        </div>
    </div>
</body>
</html>
