<?php
/**
 * Auth Reset Lab · the learner's mailbox
 * ---------------------------------------------------------------------------
 * This page reads exactly one mailbox: guest@hackinlab.internal, the account
 * the learner owns. The address is a constant in the query, not a parameter,
 * so there is no version of this request that returns somebody else's mail.
 *
 * That restriction is the premise of the whole lab. Every level asks you to
 * get at something in the administrator's mailbox without being able to open
 * it, and each level is a different answer to that question.
 */

require_once __DIR__ . '/helpers.php';

$level = (int)($_GET['level'] ?? 1);
if ($level < 1 || $level > 10) {
    $level = 1;
}
ar_ensure_level($level);

$messages = ar_mailbox($level, AR_GUEST);

ob_start(); ?>
<div class="labs-hero">
    <h2>Mailbox &mdash; <?= lk_esc(AR_GUEST) ?></h2>
    <p>Messages delivered to your own account on level <?= $level ?>. Each level has its own mail store, so a
       message you generated on one level never appears on another.</p>
    <div class="whitebox-note">
        <strong>Not readable here:</strong> <code><?= lk_esc(AR_ADMIN) ?></code>, or any other account. The query
        behind this page is <code>SELECT * FROM mail WHERE level = ? AND to_email = 'guest@hackinlab.internal'</code>
        and the address is not taken from the URL. If a level makes the administrator's mail arrive somewhere you
        control, it arrives at <a href="collector.php">collector.php</a>, not here.
    </div>
</div>

<div class="ar-toolbar">
    <?php foreach (ar_levels() as $n => $m): ?>
        <a class="btn btn-outline<?= $n === $level ? ' btn-primary' : '' ?>" href="mailbox.php?level=<?= $n ?>">L<?= $n ?></a>
    <?php endforeach; ?>
    <a class="btn btn-outline" href="level<?= $level ?>.php">Back to level <?= $level ?> &rarr;</a>
</div>

<?php if (!$messages): ?>
    <div class="message info">No messages on level <?= $level ?> yet. Ask the application to send one.</div>
<?php endif; ?>

<?php foreach ($messages as $m): ?>
    <div class="lk-box">
        <h4><span class="lk-tag">MAIL</span><?= lk_esc($m['subject']) ?></h4>
        <div class="lk-body">
            <table class="lk-kv">
                <tr><td>to</td><td><span class="ar-mono"><?= lk_esc($m['to_email']) ?></span></td></tr>
                <tr><td>received</td><td><?= lk_esc(gmdate('Y-m-d H:i:s', (int)$m['created_at'])) ?> UTC</td></tr>
            </table>
            <div class="output-box" style="margin-top:0.6rem"><pre class="ar-mono" style="white-space:pre-wrap;margin:0"><?= lk_esc($m['body']) ?></pre></div>
            <?php if (!empty($m['link'])): ?>
                <div class="ar-actions">
                    <a class="btn btn-outline" href="<?= lk_esc($m['link']) ?>">Open the link &rarr;</a>
                </div>
            <?php endif; ?>
        </div>
    </div>
<?php endforeach; ?>
<?php
ar_shell('Mailbox', 'Mail for the account you own', (string)ob_get_clean(), $level);
