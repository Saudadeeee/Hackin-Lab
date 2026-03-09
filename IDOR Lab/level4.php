<?php
require_once __DIR__ . '/db.php';
require_once __DIR__ . '/helpers.php';

// --- Challenge logic ---
$current_user_id = 1; // Alice — simulated session
$msg_id          = (int)($_GET['msg_id'] ?? 1);
$msg             = null;
$flagFound       = false;

$db   = get_db();
// VULNERABLE: fetches message without checking recipient
$stmt = $db->prepare("SELECT * FROM messages WHERE id = ?");
$stmt->execute([$msg_id]);
$msg = $stmt->fetch();

if ($msg && str_contains((string)$msg['body'], 'FLAG{')) {
    $flagFound = true;
}

// Alice's inbox (messages where she is recipient)
$stmtInbox = $db->prepare("SELECT id, subject, created_at FROM messages WHERE recipient_id = ?");
$stmtInbox->execute([$current_user_id]);
$inbox = $stmtInbox->fetchAll();

$_flag_result = handle_inline_flag_submit(4);
html_open('Level 4 — Horizontal Privilege Escalation');
render_page_header('Level 4 — Horizontal Privilege Escalation', 'Reading Messages Not Addressed to You', 4);
?>

<div class="context-bar">
    <div>Logged in as: <span>alice</span></div>
    <div>User ID: <span>1</span></div>
    <div>Role: <span>user</span></div>
</div>

<div class="challenge-layout">

    <!-- Source Code Panel -->
    <div class="code-panel">
        <h3>Vulnerable Source Code — level4.php</h3>
        <div class="source-code"><code><span class="php-keyword">&lt;?php</span>
<span class="php-keyword">require_once</span> <span class="php-string">'db.php'</span>;

<span class="php-variable">$current_user_id</span> = <span class="php-string">1</span>; <span class="php-comment">// Alice - simulated session</span>
<span class="php-variable">$msg_id</span> = (<span class="php-keyword">int</span>)(<span class="php-variable">$_GET</span>[<span class="php-string">'msg_id'</span>] ?? <span class="php-string">1</span>);

<span class="php-variable">$db</span> = <span class="php-function">get_db</span>();
<span class="php-comment">// VULNERABLE: fetches message without checking recipient</span>
<span class="vuln-line"><span class="php-variable">$stmt</span> = <span class="php-variable">$db</span>-><span class="php-function">prepare</span>(
    <span class="php-string">"SELECT * FROM messages WHERE id = ?"</span>
    <span class="php-comment">// Missing: AND recipient_id = $current_user_id</span>
);</span>
<span class="php-variable">$stmt</span>-><span class="php-function">execute</span>([<span class="php-variable">$msg_id</span>]);
<span class="php-variable">$msg</span> = <span class="php-variable">$stmt</span>-><span class="php-function">fetch</span>();

<span class="php-keyword">if</span> (<span class="php-variable">$msg</span>) {
    <span class="php-comment">// No check: is current_user_id == msg['recipient_id']?</span>
    <span class="php-keyword">echo</span> <span class="php-variable">$msg</span>[<span class="php-string">'subject'</span>] . <span class="php-string">': '</span> . <span class="php-variable">$msg</span>[<span class="php-string">'body'</span>];
}
<span class="php-keyword">?&gt;</span></code></div>
        <div class="message info" style="margin-top:0.75rem;">
            <strong>Vulnerability:</strong> Horizontal privilege escalation — two users at the same privilege
            level (neither is admin), but one can read the other's private messages by enumerating
            <code>msg_id</code>. The fix: add <code>AND recipient_id = $current_user_id</code>.
        </div>
    </div>

    <!-- Challenge Panel -->
    <div class="challenge-panel">
        <h3>Message Inbox</h3>
        <div class="scenario">
            <strong>Scenario:</strong> You are Alice. Your inbox shows messages sent to you. The message
            viewer loads any message by <code>msg_id</code>. Can you read a message addressed to someone else?
        </div>

        <form method="GET" action="level4.php">
            <div class="form-group">
                <label for="msg_id">Message ID (<code>?msg_id=</code>)</label>
                <input type="number" id="msg_id" name="msg_id" class="form-control"
                       value="<?= htmlspecialchars((string)$msg_id) ?>" min="1" max="10">
            </div>
            <button type="submit" class="btn btn-primary">Read Message</button>
        </form>

        <?php if ($msg): ?>
        <div style="margin-top:1rem;background:var(--bg);border:1px solid var(--border);border-radius:6px;padding:0.75rem 1rem;">
            <div style="font-size:0.8rem;color:var(--text-muted);margin-bottom:0.4rem;">
                Message #<?= htmlspecialchars((string)$msg['id']) ?> &mdash;
                From: User #<?= htmlspecialchars((string)$msg['sender_id']) ?> &mdash;
                To: User #<?= htmlspecialchars((string)$msg['recipient_id']) ?> &mdash;
                <?= htmlspecialchars($msg['created_at']) ?>
            </div>
            <div style="font-weight:600;margin-bottom:0.3rem;"><?= htmlspecialchars($msg['subject']) ?></div>
            <div style="color:var(--text-muted);font-size:0.9rem;"><?= htmlspecialchars($msg['body']) ?></div>
        </div>
        <?php if ($flagFound): ?>
        <div class="message success">You read a private message addressed to another user!</div>
        <div class="flag-display"><?= htmlspecialchars(get_flag_for_level(4)) ?></div>
        <?php elseif ((int)$msg['recipient_id'] !== $current_user_id): ?>
        <div class="message error">Warning: This message was not addressed to you (recipient_id=<?= htmlspecialchars((string)$msg['recipient_id']) ?>)!</div>
        <?php endif; ?>
        <?php else: ?>
        <div class="message error">Message not found.</div>
        <?php endif; ?>

        <div style="margin-top:1rem;">
            <h4 style="font-size:0.9rem;color:var(--text-muted);margin-bottom:0.5rem;">Your Inbox (Alice — Recipient ID: 1)</h4>
            <table class="data-table">
                <thead><tr><th>ID</th><th>Subject</th><th>Date</th></tr></thead>
                <tbody>
                    <?php if ($inbox): foreach ($inbox as $m): ?>
                    <tr>
                        <td><?= htmlspecialchars((string)$m['id']) ?></td>
                        <td><?= htmlspecialchars($m['subject']) ?></td>
                        <td><?= htmlspecialchars($m['created_at']) ?></td>
                    </tr>
                    <?php endforeach; else: ?>
                    <tr><td colspan="3" style="color:var(--text-muted);">No messages in your inbox.</td></tr>
                    <?php endif; ?>
                </tbody>
            </table>
            <p style="font-size:0.8rem;color:var(--text-muted);margin-top:0.5rem;">
                There are 4 messages in total (IDs 1–4). Only ID 1 is addressed to you...
            </p>
        </div>
    </div>

</div>

<?= render_hint_section(get_level_hints(4)) ?>
<?= render_inline_flag_form(4, $_flag_result) ?>

<div class="navigation">
    <a href="level3.php" class="prev-link">&#8592; Level 3</a>
    <a href="index.php" class="nav-link">Lab Home</a>
    <a href="level5.php" class="next-link">Level 5 &rarr;</a>
</div>

<?php html_close(); ?>
