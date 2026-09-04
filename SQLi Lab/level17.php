<?php
// Level 17: Error-Based Extraction - Reading data out of the error channel
// Goal: Recover a value the response never prints, using only the error message

session_start();

require_once __DIR__ . '/includes/helpers.php';
require_once __DIR__ . '/helpers.php';
require_once __DIR__ . '/teaching.php';
$_flag_result = handle_inline_flag_submit(17);

$host   = $_ENV['DB_HOST'] ?? 'db';
$user   = $_ENV['DB_USER'] ?? 'webapp';
$pass   = $_ENV['DB_PASS'] ?? 'webapp123';
$dbname = $_ENV['DB_NAME'] ?? 'sqli_lab';

$conn = new mysqli($host, $user, $pass, $dbname);
if ($conn->connect_error) {
    die('Connection failed: ' . $conn->connect_error);
}

/** The value the response never prints. 55 characters, so it does not fit one error. */
function level17_secret(mysqli $conn): string
{
    $st = $conn->prepare('SELECT mvalue FROM meta WHERE mkey = ?');
    $key = 'secret_message';
    $st->bind_param('s', $key);
    $st->execute();
    return (string)($st->get_result()->fetch_row()[0] ?? '');
}

$message   = '';
$success   = false;
$sql       = '';
$blocked   = [];
$lookupHit = null;

/* ── The recovered-value gate ───────────────────────────────────────────── */
if ($_POST && isset($_POST['recovered'])) {
    $answer = trim((string)$_POST['recovered']);
    if ($answer !== '' && hash_equals(level17_secret($conn), $answer)) {
        $success = true;
        $flag    = get_flag_for_level(17);
        $message = "You read a value the page never printed.<br>";
        $message .= "<strong>Flag:</strong> <code>" . htmlspecialchars($flag) . "</code><br>";
        $message .= "Every character of it arrived inside an error message.";
    } elseif ($answer !== '') {
        $message = "That is not the stored value. Remember the error window is 32 characters wide, ";
        $message .= "so a 55-character string takes more than one request to read.";
    }
}

/* ── The vulnerable lookup ──────────────────────────────────────────────── */
if ($_POST && isset($_POST['order_id'])) {
    $orderId = (string)$_POST['order_id'];

    // The only thing this endpoint refuses is a second result set.
    foreach (['union'] as $word) {
        if (stripos($orderId, $word) !== false) {
            $blocked[] = $word;
        }
    }

    if ($blocked) {
        $message = 'Query rejected: <code>' . htmlspecialchars(implode(', ', $blocked)) . '</code> is not allowed here.';
    } else {
        // Numeric context: no quotes to escape, and the result is a count that
        // the page compares but never displays.
        $sql    = "SELECT COUNT(*) FROM users WHERE id = $orderId";
        $result = $conn->query($sql);

        if ($result === false) {
            // The entire channel. The driver's message is returned verbatim.
            $message = 'Lookup failed: ' . htmlspecialchars($conn->error);
        } else {
            $lookupHit = (int)$result->fetch_row()[0];
            $message   = $lookupHit > 0
                ? 'Order found. Status: <strong>shipped</strong>.'
                : 'No order with that reference.';
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Level 17 - Error-Based Extraction | SQL Injection Lab</title>
    <link rel="stylesheet" href="css/styles.css">
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Level 17 - Error-Based Extraction</h1>
            <p>The response never prints a row. The error message does.</p>
            <a href="index.php" class="back-btn">&larr; Back to Labs</a>
        </div>

        <div class="challenge-layout">
            <!-- Left: Source Code Panel -->
            <div class="code-panel">
                <h3>Vulnerable Source Code</h3>
                <div class="source-code">
                    <pre><code><span class="php-comment">// Order status lookup. UNION is refused; nothing else is.</span>
<span class="php-keyword">foreach</span> ([<span class="php-string">'union'</span>] <span class="php-keyword">as</span> <span class="php-variable">$word</span>) {
    <span class="php-keyword">if</span> (<span class="php-function">stripos</span>(<span class="php-variable">$orderId</span>, <span class="php-variable">$word</span>) !== <span class="php-keyword">false</span>) <span class="php-function">reject</span>();
}

<span class="php-comment">// Numeric context — no quote to break out of.</span>
<span class="vuln-line"><span class="php-variable">$sql</span> = <span class="php-string">"SELECT COUNT(*) FROM users WHERE id = <span class="php-variable">$orderId</span>"</span>;</span>
<span class="php-variable">$result</span> = <span class="php-variable">$conn</span>-&gt;<span class="php-function">query</span>(<span class="php-variable">$sql</span>);

<span class="php-keyword">if</span> (<span class="php-variable">$result</span> === <span class="php-keyword">false</span>) {
    <span class="php-comment">// The driver's message goes straight back to the client.</span>
<span class="vuln-line">    <span class="php-keyword">echo</span> <span class="php-string">'Lookup failed: '</span> . <span class="php-variable">$conn</span>-&gt;error;</span>
} <span class="php-keyword">else</span> {
    <span class="php-comment">// The count is compared. It is never printed.</span>
    <span class="php-variable">$hit</span> = <span class="php-variable">$result</span>-&gt;<span class="php-function">fetch_row</span>()[<span class="php-number">0</span>];
    <span class="php-keyword">echo</span> <span class="php-variable">$hit</span> &gt; <span class="php-number">0</span> ? <span class="php-string">'Order found'</span> : <span class="php-string">'No such order'</span>;
}</code></pre>
                </div>
                <div class="vuln-annotation">
                    <strong>Vulnerability:</strong>&nbsp; The injection point is a numeric context, so no quote is
                    needed to reach the parser. What makes this level different is the <em>output</em>: the query
                    selects a <code>COUNT(*)</code> that the page compares and never displays, so a
                    <code>UNION</code> would have nowhere to surface a row even if it were allowed. The one thing
                    that does reach you is <code>$conn-&gt;error</code>, returned verbatim &mdash; which turns the
                    database's own diagnostics into a read primitive.
                </div>
            </div>

            <!-- Right: Challenge Panel -->
            <div class="challenge-panel">
                <h3>Challenge</h3>
                <div class="panel-body">
                    <div class="scenario">
                        <strong>Scenario:</strong> Order status lookup<br>
                        <strong>Objective:</strong> The <code>meta</code> table holds a row where
                        <code>mkey = 'secret_message'</code>. Recover its <code>mvalue</code> in full and submit it
                        below. The page will never print it for you.
                    </div>

                    <?php if ($message): ?>
                        <div class="message <?= $success ? 'success' : (stripos($message, 'failed') !== false || stripos($message, 'rejected') !== false ? 'error' : 'info') ?>">
                            <?= $message ?>
                        </div>
                    <?php endif; ?>

                    <h3>Order Lookup</h3>
                    <form method="POST" class="login-form">
                        <div class="form-group">
                            <label for="order_id">Order reference:</label>
                            <input type="text" id="order_id" name="order_id" placeholder="e.g. 3"
                                   value="<?= htmlspecialchars($_POST['order_id'] ?? '') ?>"
                                   autocomplete="off" spellcheck="false">
                        </div>
                        <button type="submit" class="submit-btn">Look up</button>
                    </form>

                    <h3>Recovered value</h3>
                    <form method="POST" class="login-form">
                        <div class="form-group">
                            <label for="recovered">The full <code>secret_message</code>:</label>
                            <input type="text" id="recovered" name="recovered" placeholder="paste the whole string"
                                   value="<?= htmlspecialchars($_POST['recovered'] ?? '') ?>"
                                   autocomplete="off" spellcheck="false">
                        </div>
                        <button type="submit" class="submit-btn">Submit value</button>
                    </form>
                </div>
            </div>
        </div>

    <?= sqli_teach(17, ['input' => $_POST['order_id'] ?? '', 'filter' => $blocked, 'filter_label' => "stripos(\$orderId, 'union')", 'sql' => $sql, 'error' => (isset($conn) && $conn instanceof mysqli && $conn->error !== '') ? $conn->error : '', 'rows' => $lookupHit, 'solved' => !empty($success) || !empty($_flag_result['already_completed'])]) ?>

        <?= render_hint_section(get_level_hints(17), 'Hints for Level 17'); ?>

    <?= render_inline_flag_form(17, $_flag_result) ?>

        <div class="navigation">
            <a href="level16.php">&larr; Previous Level</a>
            <a href="index.php">All Levels &rarr;</a>
        </div>
    </div>
</body>
</html>

<?php $conn->close(); ?>
