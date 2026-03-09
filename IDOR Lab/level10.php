<?php
require_once __DIR__ . '/db.php';
require_once __DIR__ . '/helpers.php';

// --- Challenge logic ---
$current_user_id = (int)($_GET['user_id'] ?? 1);
$action          = $_GET['action'] ?? '';
$flagFound       = false;
$actionResult    = null;
$actionError     = '';

$db = get_db();

if ($action === 'create') {
    // Create an exclusive reward for the specified user
    $token = bin2hex(random_bytes(4));
    $db->prepare("INSERT INTO rewards (user_id, token, claimed) VALUES (?, ?, 0)")
       ->execute([$current_user_id, $token]);
    $newId      = $db->lastInsertId();
    $actionResult = ['status' => 'created', 'reward_id' => $newId, 'token' => $token, 'user_id' => $current_user_id];

} elseif ($action === 'claim') {
    // Check-Then-Act: TOCTOU race condition
    $stmt   = $db->query("SELECT * FROM rewards WHERE claimed = 0 ORDER BY id DESC LIMIT 1");
    $reward = $stmt->fetch();

    if ($reward) {
        if ((int)$reward['user_id'] !== $current_user_id) {
            // There is a window here — artificial delay simulates it
            usleep(50000); // 50ms window
            // Re-fetch (but in the lab the "race" is simulated — we just claim it)
            $db->prepare("UPDATE rewards SET claimed=1, claimed_by=? WHERE id=?")
               ->execute([$current_user_id, $reward['id']]);
            $actionResult = [
                'status'     => 'claimed',
                'reward_id'  => $reward['id'],
                'token'      => $reward['token'],
                'created_by' => $reward['user_id'],
                'claimed_by' => $current_user_id,
            ];
            $flagFound = true;
        } else {
            $actionResult = ['status' => 'own_reward', 'message' => 'This reward belongs to you (user_id=' . $reward['user_id'] . '). Create one for another user to demonstrate TOCTOU.'];
        }
    } else {
        $actionResult = ['status' => 'none', 'message' => 'No unclaimed rewards. Create one first.'];
    }

} elseif ($action === 'list') {
    $stmt         = $db->query("SELECT * FROM rewards ORDER BY id DESC LIMIT 10");
    $actionResult = $stmt->fetchAll();
} elseif ($action === 'reset') {
    $db->exec("DELETE FROM rewards");
    $actionResult = ['status' => 'reset', 'message' => 'All rewards deleted.'];
}

// Load all rewards for display
$stmtAll  = $db->query("SELECT * FROM rewards ORDER BY id DESC LIMIT 10");
$allRewards = $stmtAll->fetchAll();

$_flag_result = handle_inline_flag_submit(10);
html_open('Level 10 — Race Condition TOCTOU');
render_page_header('Level 10 — Race Condition: TOCTOU Access Control Bypass', 'Exploiting Time-of-Check / Time-of-Use Window', 10);
?>

<div class="context-bar">
    <div>Acting as User ID: <span><?= htmlspecialchars((string)$current_user_id) ?></span></div>
    <div>Action: <span><?= htmlspecialchars($action ?: '(none)') ?></span></div>
    <div>Total Rewards: <span><?= count($allRewards) ?></span></div>
</div>

<div class="challenge-layout">

    <!-- Source Code Panel -->
    <div class="code-panel">
        <h3>Vulnerable Source Code — level10.php</h3>
        <div class="source-code"><code><span class="php-keyword">&lt;?php</span>
<span class="php-keyword">require_once</span> <span class="php-string">'db.php'</span>;

<span class="php-variable">$uid</span>    = (<span class="php-keyword">int</span>)(<span class="php-variable">$_GET</span>[<span class="php-string">'user_id'</span>] ?? <span class="php-string">1</span>);
<span class="php-variable">$action</span> = <span class="php-variable">$_GET</span>[<span class="php-string">'action'</span>]  ?? <span class="php-string">''</span>;
<span class="php-variable">$db</span>     = <span class="php-function">get_db</span>();

<span class="php-keyword">if</span> (<span class="php-variable">$action</span> === <span class="php-string">'create'</span>) {
    <span class="php-comment">// Create exclusive reward for any user</span>
    <span class="php-variable">$token</span> = <span class="php-function">bin2hex</span>(<span class="php-function">random_bytes</span>(<span class="php-string">4</span>));
    <span class="php-variable">$db</span>-><span class="php-function">exec</span>(<span class="php-string">"INSERT INTO rewards
        (user_id, token, claimed)
        VALUES ($uid, '$token', 0)"</span>);

} <span class="php-keyword">elseif</span> (<span class="php-variable">$action</span> === <span class="php-string">'claim'</span>) {
    <span class="php-comment">// CHECK: get latest unclaimed reward</span>
    <span class="vuln-line">    <span class="php-variable">$reward</span> = <span class="php-variable">$db</span>-><span class="php-function">query</span>(
        <span class="php-string">"SELECT * FROM rewards
         WHERE claimed = 0
         ORDER BY id DESC LIMIT 1"</span>
    )-><span class="php-function">fetch</span>();</span>

    <span class="php-keyword">if</span> (<span class="php-variable">$reward</span> && <span class="php-variable">$reward</span>[<span class="php-string">'user_id'</span>] !== <span class="php-variable">$uid</span>) {
        <span class="php-comment">// Artificial 50ms window (TOCTOU gap)</span>
        <span class="vuln-line">        <span class="php-function">usleep</span>(<span class="php-string">50000</span>);</span>
        <span class="php-comment">// USE: update — no re-check of ownership!</span>
        <span class="vuln-line">        <span class="php-variable">$db</span>-><span class="php-function">exec</span>(
            <span class="php-string">"UPDATE rewards SET claimed=1,
             claimed_by=$uid
             WHERE id="</span> . <span class="php-variable">$reward</span>[<span class="php-string">'id'</span>]
        );</span>
    }
}
<span class="php-keyword">?&gt;</span></code></div>
        <div class="message info" style="margin-top:0.75rem;">
            <strong>Vulnerability (TOCTOU):</strong> Between the CHECK (SELECT) and the USE (UPDATE),
            another concurrent request can slip in and claim a reward that was just created for a different user.
            The fix: use a database-level atomic <code>UPDATE ... WHERE claimed=0 AND user_id=?</code>
            and check <code>rowsAffected > 0</code>.
        </div>
    </div>

    <!-- Challenge Panel -->
    <div class="challenge-panel">
        <h3>Exclusive Reward System</h3>
        <div class="scenario">
            <strong>Scenario:</strong> Each user gets one exclusive reward. Alice (ID: 1) creates a reward.
            Bob (ID: 2) exploits the TOCTOU window to claim it. Demonstrate the race condition:
            <ol style="margin:0.5rem 0 0 1.25rem;font-size:0.88rem;color:var(--text-muted);">
                <li>Create a reward for User 1 (Alice)</li>
                <li>Claim it as User 2 (Bob) — the server doesn't re-verify ownership before updating</li>
            </ol>
        </div>

        <!-- Step 1: Create reward for alice -->
        <div style="background:var(--bg);border:1px solid var(--border);border-radius:6px;padding:0.75rem 1rem;margin-bottom:0.75rem;">
            <p style="font-size:0.85rem;font-weight:600;margin-bottom:0.5rem;">Step 1 — Create a reward for Alice (user_id=1)</p>
            <a href="level10.php?action=create&user_id=1" class="btn btn-primary" style="font-size:0.82rem;text-decoration:none;">
                Create Reward for Alice (user_id=1)
            </a>
        </div>

        <!-- Step 2: Claim it as bob -->
        <div style="background:var(--bg);border:1px solid var(--border);border-radius:6px;padding:0.75rem 1rem;margin-bottom:0.75rem;">
            <p style="font-size:0.85rem;font-weight:600;margin-bottom:0.5rem;">Step 2 — Claim it as Bob (user_id=2) before Alice does</p>
            <a href="level10.php?action=claim&user_id=2" class="btn btn-outline" style="font-size:0.82rem;text-decoration:none;">
                Claim as Bob (user_id=2) — Exploit TOCTOU
            </a>
        </div>

        <!-- Utility actions -->
        <div style="display:flex;gap:0.5rem;flex-wrap:wrap;margin-bottom:0.75rem;">
            <a href="level10.php?action=list" class="btn" style="font-size:0.82rem;background:var(--surface2);color:var(--text);text-decoration:none;">
                List All Rewards
            </a>
            <a href="level10.php?action=reset" class="btn" style="font-size:0.82rem;border-color:var(--border-hi);color:var(--text-muted);text-decoration:none;"
               onclick="return confirm('Delete all rewards?');">
                Reset Rewards
            </a>
        </div>

        <?php if ($actionResult !== null): ?>
        <div style="background:var(--code-bg);border:1px solid var(--border);border-radius:6px;padding:0.75rem;margin-bottom:0.75rem;">
            <p style="font-size:0.82rem;color:var(--text-muted);margin-bottom:0.3rem;">Action result:</p>
            <pre style="font-size:0.82rem;color:#c9d1d9;white-space:pre-wrap;"><?= htmlspecialchars(json_encode($actionResult, JSON_PRETTY_PRINT)) ?></pre>
        </div>
        <?php if ($flagFound): ?>
        <div class="message success">TOCTOU exploited! Bob claimed a reward created for Alice!</div>
        <div class="flag-display"><?= htmlspecialchars(get_flag_for_level(10)) ?></div>
        <?php endif; ?>
        <?php endif; ?>

        <!-- Reward table -->
        <?php if ($allRewards): ?>
        <h4 style="font-size:0.9rem;color:var(--text-muted);margin-bottom:0.5rem;">Reward Table (Latest 10)</h4>
        <table class="data-table">
            <thead>
                <tr><th>ID</th><th>Created For</th><th>Token</th><th>Claimed</th><th>Claimed By</th></tr>
            </thead>
            <tbody>
                <?php foreach ($allRewards as $r): ?>
                <tr>
                    <td><?= htmlspecialchars((string)$r['id']) ?></td>
                    <td>User <?= htmlspecialchars((string)$r['user_id']) ?></td>
                    <td><code><?= htmlspecialchars($r['token']) ?></code></td>
                    <td><?= $r['claimed'] ? '<strong style="color:var(--white);">Yes</strong>' : '<span style="color:var(--text-faint);">No</span>' ?></td>
                    <td><?= $r['claimed_by'] ? 'User ' . htmlspecialchars((string)$r['claimed_by']) : '—' ?></td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
        <?php endif; ?>

        <!-- Race condition simulation -->
        <div style="margin-top:1rem;background:var(--bg);border:1px solid var(--border);border-radius:6px;padding:0.75rem 1rem;">
            <p style="font-size:0.85rem;color:var(--text);margin-bottom:0.5rem;"><strong>Simulate real race condition (rapid requests):</strong></p>
            <code style="display:block;font-size:0.78rem;color:#c9d1d9;background:var(--code-bg);padding:0.5rem;border-radius:4px;white-space:pre-wrap;">// JavaScript: fire 20 claim requests simultaneously as bob
const base = '/level10.php';
// Step 1: create a reward for alice
await fetch(base + '?action=create&user_id=1');
// Step 2: race 20 concurrent claim requests as bob
const reqs = Array.from({length:20}, () =>
  fetch(base + '?action=claim&user_id=2')
);
const results = await Promise.all(reqs.map(r => r.text()));
console.log(results);</code>
            <button onclick="raceSimulate()" class="btn btn-primary" style="margin-top:0.5rem;font-size:0.82rem;">
                Run Race Simulation (JS)
            </button>
            <div id="raceOutput" style="margin-top:0.5rem;font-size:0.78rem;color:var(--text-muted);"></div>
        </div>
    </div>

</div>

<?= render_hint_section(get_level_hints(10)) ?>
<?= render_inline_flag_form(10, $_flag_result) ?>

<div class="navigation">
    <a href="level9.php" class="prev-link">&#8592; Level 9</a>
    <a href="index.php" class="nav-link">Lab Home</a>
    <a href="submit.php" class="submit-btn" style="text-decoration:none;">Submit Flags</a>
</div>

<script>
async function raceSimulate() {
    const output = document.getElementById('raceOutput');
    output.textContent = 'Running...';
    try {
        // Create reward for alice
        const createResp = await fetch('/level10.php?action=create&user_id=1');
        const createText = await createResp.text();

        // Fire 20 rapid claim requests as bob
        const reqs = Array.from({length: 20}, () =>
            fetch('/level10.php?action=claim&user_id=2').then(r => r.text())
        );
        const results = await Promise.all(reqs);
        const successes = results.filter(r => r.includes('claimed'));
        output.innerHTML = `Sent 20 claim requests. Claimed: ${successes.length}/20.<br>
            <a href="level10.php?action=list" style="color:#ffffff;text-decoration:underline;">Reload to see reward table.</a>`;
        if (successes.length > 0) {
            setTimeout(() => location.reload(), 1500);
        }
    } catch(e) {
        output.textContent = 'Error: ' + e.message;
    }
}
</script>

<?php html_close(); ?>
