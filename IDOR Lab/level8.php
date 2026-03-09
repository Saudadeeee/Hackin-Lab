<?php
require_once __DIR__ . '/db.php';
require_once __DIR__ . '/helpers.php';

// --- Challenge logic ---
$flagFound     = false;
$resetResult   = '';
$resultType    = '';
$submitted     = false;

function generate_reset_token(string $username): string {
    return md5($username); // VULNERABLE: totally predictable!
}

$username = $_GET['user']  ?? '';
$token    = $_GET['token'] ?? '';

if ($username !== '' && $token !== '') {
    $submitted = true;
    $db        = get_db();
    $expected  = generate_reset_token($username);

    if ($token === $expected) {
        $stmt = $db->prepare("SELECT email, role FROM users WHERE username = ?");
        $stmt->execute([$username]);
        $user = $stmt->fetch();

        if ($user) {
            $resetResult = 'Token valid! Account data for ' . htmlspecialchars($username) . ': '
                         . htmlspecialchars(json_encode($user));
            $resultType  = 'success';
            if ($username === 'admin') {
                $flagFound = true;
            }
        } else {
            $resetResult = 'Token valid but user not found.';
            $resultType  = 'error';
        }
    } else {
        $resetResult = 'Invalid reset token! Expected: ' . htmlspecialchars(substr($expected, 0, 8)) . '...';
        $resultType  = 'error';
    }
}

$_flag_result = handle_inline_flag_submit(8);
html_open('Level 8 — Predictable Reset Token');
render_page_header('Level 8 — Predictable Password Reset Token', 'Computing Reset Tokens for Any User', 8);
?>

<div class="context-bar">
    <div>Target User: <span>admin</span></div>
    <div>Token Algorithm: <span style="color:var(--white);font-weight:700;">md5(username)</span></div>
    <div>Status: <span><?= $submitted ? ($flagFound ? 'Cracked!' : 'Attempt made') : 'Pending' ?></span></div>
</div>

<div class="challenge-layout">

    <!-- Source Code Panel -->
    <div class="code-panel">
        <h3>Vulnerable Source Code — level8.php</h3>
        <div class="source-code"><code><span class="php-keyword">&lt;?php</span>
<span class="php-keyword">require_once</span> <span class="php-string">'db.php'</span>;

<span class="php-variable">$username</span> = <span class="php-variable">$_GET</span>[<span class="php-string">'user'</span>]  ?? <span class="php-string">''</span>;
<span class="php-variable">$token</span>    = <span class="php-variable">$_GET</span>[<span class="php-string">'token'</span>] ?? <span class="php-string">''</span>;

<span class="php-comment">// Generate reset token (VULNERABLE: md5 of username)</span>
<span class="php-keyword">function</span> <span class="php-function">generate_reset_token</span>(<span class="php-keyword">string</span> <span class="php-variable">$username</span>): <span class="php-keyword">string</span> {
<span class="vuln-line">    <span class="php-keyword">return</span> <span class="php-function">md5</span>(<span class="php-variable">$username</span>); <span class="php-comment">// Totally predictable!</span></span>
}

<span class="php-keyword">if</span> (<span class="php-variable">$token</span> && <span class="php-variable">$username</span>) {
    <span class="php-variable">$db</span>       = <span class="php-function">get_db</span>();
    <span class="php-variable">$expected</span> = <span class="php-function">generate_reset_token</span>(<span class="php-variable">$username</span>);

    <span class="php-keyword">if</span> (<span class="php-variable">$token</span> === <span class="php-variable">$expected</span>) {
        <span class="php-variable">$stmt</span> = <span class="php-variable">$db</span>-><span class="php-function">prepare</span>(
            <span class="php-string">"SELECT email, role FROM users WHERE username = ?"</span>
        );
        <span class="php-variable">$stmt</span>-><span class="php-function">execute</span>([<span class="php-variable">$username</span>]);
        <span class="php-variable">$user</span> = <span class="php-variable">$stmt</span>-><span class="php-function">fetch</span>();
        <span class="php-keyword">echo</span> <span class="php-string">"Reset successful for: "</span>
           . <span class="php-function">json_encode</span>(<span class="php-variable">$user</span>);
    } <span class="php-keyword">else</span> {
        <span class="php-keyword">echo</span> <span class="php-string">"Invalid token!"</span>;
    }
}
<span class="php-keyword">?&gt;</span></code></div>
        <div class="message info" style="margin-top:0.75rem;">
            <strong>Vulnerability:</strong> The reset token is <code>md5($username)</code> — a deterministic,
            attacker-computable value. A secure token would be <code>bin2hex(random_bytes(32))</code> stored
            in the database with a short expiry time.
        </div>
    </div>

    <!-- Challenge Panel -->
    <div class="challenge-panel">
        <h3>Password Reset Endpoint</h3>
        <div class="scenario">
            <strong>Scenario:</strong> You found a password reset URL: <code>?user=alice&amp;token=TOKEN</code>.
            The token is generated server-side. Read the code — can you predict the admin's reset token?
        </div>

        <form method="GET" action="level8.php">
            <div class="form-group">
                <label for="user">Username (<code>?user=</code>)</label>
                <input type="text" id="user" name="user" class="form-control"
                       value="<?= htmlspecialchars($username ?: 'admin') ?>"
                       placeholder="admin">
            </div>
            <div class="form-group">
                <label for="token">Reset Token (<code>?token=</code>)</label>
                <input type="text" id="token" name="token" class="form-control"
                       value="<?= htmlspecialchars($token) ?>"
                       placeholder="Compute md5(username) and enter here">
            </div>
            <button type="submit" class="btn btn-primary">Submit Reset Token</button>
        </form>

        <?php if ($submitted): ?>
        <div class="message <?= $resultType ?>">
            <?= $resetResult ?>
        </div>
        <?php if ($flagFound): ?>
        <div class="flag-display"><?= htmlspecialchars(get_flag_for_level(8)) ?></div>
        <?php endif; ?>
        <?php endif; ?>

        <div style="margin-top:1rem;background:var(--bg);border:1px solid var(--border);border-radius:6px;padding:0.75rem 1rem;">
            <p style="font-size:0.85rem;color:var(--text-muted);margin-bottom:0.5rem;">
                <strong style="color:var(--text);">Compute the token in your browser console:</strong>
            </p>
            <code style="display:block;font-size:0.82rem;color:#c9d1d9;background:var(--code-bg);padding:0.5rem;border-radius:4px;margin-bottom:0.75rem;">// JavaScript doesn't have md5 natively.
// Use this precomputed table:</code>
            <table class="data-table">
                <thead><tr><th>Username</th><th>md5(username)</th></tr></thead>
                <tbody>
                    <tr><td>alice</td><td><code>6384e2b2184bcbf58eccf10ca7a6563c</code></td></tr>
                    <tr><td>bob</td><td><code>9f9d51bc70ef21ca5c14f307980a29d8</code></td></tr>
                    <tr><td>admin</td><td><code style="color:var(--white);font-weight:700;">21232f297a57a5a743894a0e4a801fc3</code></td></tr>
                    <tr><td>guest</td><td><code>084e0343a0486ff05530df6c705c8bb4</code></td></tr>
                </tbody>
            </table>
            <div style="margin-top:0.75rem;">
                <button onclick="document.getElementById('token').value='21232f297a57a5a743894a0e4a801fc3'; document.getElementById('user').value='admin';"
                        class="btn btn-outline" style="font-size:0.82rem;">
                    Auto-fill admin token
                </button>
            </div>
        </div>
    </div>

</div>

<?= render_hint_section(get_level_hints(8)) ?>
<?= render_inline_flag_form(8, $_flag_result) ?>

<div class="navigation">
    <a href="level7.php" class="prev-link">&#8592; Level 7</a>
    <a href="index.php" class="nav-link">Lab Home</a>
    <a href="level9.php" class="next-link">Level 9 &rarr;</a>
</div>

<?php html_close(); ?>
