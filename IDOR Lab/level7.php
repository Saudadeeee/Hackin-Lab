<?php
require_once __DIR__ . '/db.php';
require_once __DIR__ . '/helpers.php';

// --- Challenge logic: act as proxy for api.php ---
$apiResponse   = null;
$flagFound     = false;
$submitted     = false;
$rawJson       = '';
$apiError      = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['api_key'])) {
    $submitted  = true;
    $api_key    = trim($_POST['api_key'] ?? '');
    $target_id  = (int)($_POST['user_id'] ?? 1);

    // Simulate calling api.php logic directly (internal proxy)
    $db   = get_db();

    // Validate API key
    $stmt = $db->prepare("SELECT id FROM users WHERE api_key = ?");
    $stmt->execute([$api_key]);
    $caller = $stmt->fetch();

    if (!$caller) {
        $rawJson  = json_encode(['error' => 'Invalid API key']);
        $apiError = 'Invalid API key';
    } else {
        // VULNERABLE: fetch ANY user without ownership check
        $stmt = $db->prepare("SELECT id, username, email, role, api_key FROM users WHERE id = ?");
        $stmt->execute([$target_id]);
        $user = $stmt->fetch();
        if ($user) {
            $rawJson = json_encode($user, JSON_PRETTY_PRINT);
            if ($user['role'] === 'admin') {
                $flagFound = true;
            }
        } else {
            $rawJson  = json_encode(['error' => 'User not found']);
            $apiError = 'User not found';
        }
    }
}

$_flag_result = handle_inline_flag_submit(7);
html_open('Level 7 — API IDOR');
render_page_header('Level 7 — API IDOR (No Ownership Check)', 'IDOR via REST API — Any Valid Key, Any User\'s Data', 7);
?>

<div class="context-bar">
    <div>Your Identity: <span>alice</span></div>
    <div>Your API Key: <span style="font-family:Consolas,monospace;">key_alice_abc123</span></div>
    <div>Role: <span>user</span></div>
</div>

<div class="challenge-layout">

    <!-- Source Code Panel -->
    <div class="code-panel">
        <h3>Vulnerable Source Code — api.php</h3>
        <div class="source-code"><code><span class="php-keyword">&lt;?php</span>
<span class="php-comment">// api.php — REST endpoint</span>
<span class="php-variable">$action</span> = <span class="php-variable">$_GET</span>[<span class="php-string">'action'</span>] ?? <span class="php-string">''</span>;
<span class="php-variable">$body</span>   = <span class="php-function">json_decode</span>(
    <span class="php-function">file_get_contents</span>(<span class="php-string">'php://input'</span>), <span class="php-keyword">true</span>
) ?? [];

<span class="php-keyword">if</span> (<span class="php-variable">$action</span> === <span class="php-string">'getUser'</span>) {
    <span class="php-comment">// Validate API key exists (not whose it is)</span>
    <span class="php-variable">$stmt</span> = <span class="php-variable">$db</span>-><span class="php-function">prepare</span>(
        <span class="php-string">"SELECT id FROM users WHERE api_key = ?"</span>
    );
    <span class="php-variable">$stmt</span>-><span class="php-function">execute</span>([<span class="php-variable">$body</span>[<span class="php-string">'api_key'</span>]]);
    <span class="php-variable">$caller</span> = <span class="php-variable">$stmt</span>-><span class="php-function">fetch</span>();
    <span class="php-keyword">if</span> (!<span class="php-variable">$caller</span>) { <span class="php-function">die</span>(<span class="php-string">'Invalid API key'</span>); }

    <span class="php-comment">// VULNERABLE: fetches ANY user without ownership check</span>
    <span class="vuln-line"><span class="php-variable">$stmt</span> = <span class="php-variable">$db</span>-><span class="php-function">prepare</span>(
        <span class="php-string">"SELECT * FROM users WHERE id = ?"</span>
        <span class="php-comment">// Missing: AND id = $caller['id']</span>
    );</span>
    <span class="vuln-line"><span class="php-variable">$stmt</span>-><span class="php-function">execute</span>([<span class="php-variable">$body</span>[<span class="php-string">'id'</span>]]); <span class="php-comment">// id from request body!</span></span>
    <span class="php-keyword">echo</span> <span class="php-function">json_encode</span>(<span class="php-variable">$stmt</span>-><span class="php-function">fetch</span>());
}
<span class="php-keyword">?&gt;</span></code></div>
        <div class="message info" style="margin-top:0.75rem;">
            <strong>Vulnerability:</strong> The API validates that an API key <em>exists</em> but does not
            check whether the caller is requesting their <em>own</em> data. Any holder of a valid API key
            can enumerate all user records by incrementing the <code>id</code> field.
        </div>
    </div>

    <!-- Challenge Panel -->
    <div class="challenge-panel">
        <h3>API Request Tester</h3>
        <div class="scenario">
            <strong>Scenario:</strong> You have Alice's API key. The <code>/api.php?action=getUser</code>
            endpoint accepts a JSON body with <code>api_key</code> and <code>id</code>. Use Alice's key
            to fetch the admin's data (ID: 4).
        </div>

        <form method="POST" action="level7.php">
            <div class="form-group">
                <label for="api_key">API Key (your key as Alice)</label>
                <input type="text" id="api_key" name="api_key" class="form-control"
                       value="<?= htmlspecialchars($_POST['api_key'] ?? 'key_alice_abc123') ?>">
            </div>
            <div class="form-group">
                <label for="user_id">Target User ID (<code>"id"</code> in JSON body)</label>
                <input type="number" id="user_id" name="user_id" class="form-control"
                       value="<?= htmlspecialchars((string)($_POST['user_id'] ?? 1)) ?>" min="1" max="10">
            </div>
            <button type="submit" class="btn btn-primary">Send API Request</button>
        </form>

        <?php if ($submitted): ?>
        <div style="margin-top:1rem;">
            <p style="font-size:0.82rem;color:var(--text-muted);margin-bottom:0.3rem;">
                Equivalent curl command:
            </p>
            <code style="display:block;font-size:0.78rem;color:#c9d1d9;background:var(--code-bg);padding:0.5rem;border-radius:4px;margin-bottom:0.75rem;white-space:pre-wrap;word-break:break-all;">curl -X POST "http://localhost:8083/api.php?action=getUser" \
  -H "Content-Type: application/json" \
  -d '{"api_key":"<?= htmlspecialchars($_POST['api_key'] ?? '') ?>","id":<?= (int)($_POST['user_id'] ?? 1) ?>}'</code>

            <p style="font-size:0.82rem;color:var(--text-muted);margin-bottom:0.3rem;">API Response:</p>
            <pre style="background:var(--code-bg);border:1px solid var(--border);border-radius:6px;padding:0.75rem;font-size:0.85rem;color:#c9d1d9;white-space:pre-wrap;word-break:break-all;"><?= htmlspecialchars($rawJson) ?></pre>
        </div>
        <?php if ($flagFound): ?>
        <div class="message success">You fetched admin data using a non-admin API key!</div>
        <div class="flag-display"><?= htmlspecialchars(get_flag_for_level(7)) ?></div>
        <?php elseif ($apiError): ?>
        <div class="message error"><?= htmlspecialchars($apiError) ?></div>
        <?php else: ?>
        <div class="message info">Response received. Try changing the target user ID to 4 (admin).</div>
        <?php endif; ?>
        <?php endif; ?>

        <div style="margin-top:1rem;font-size:0.82rem;color:var(--text-muted);">
            <strong>Known API Keys:</strong>
            <table class="data-table" style="margin-top:0.3rem;">
                <thead><tr><th>User</th><th>API Key</th></tr></thead>
                <tbody>
                    <tr><td>alice</td><td><code>key_alice_abc123</code></td></tr>
                    <tr><td>admin</td><td><em style="color:var(--text-muted);">unknown — fetch it!</em></td></tr>
                </tbody>
            </table>
        </div>
    </div>

</div>

<?= render_hint_section(get_level_hints(7)) ?>
<?= render_inline_flag_form(7, $_flag_result) ?>

<div class="navigation">
    <a href="level6.php" class="prev-link">&#8592; Level 6</a>
    <a href="index.php" class="nav-link">Lab Home</a>
    <a href="level8.php" class="next-link">Level 8 &rarr;</a>
</div>

<?php html_close(); ?>
