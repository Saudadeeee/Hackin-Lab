<?php
/**
 * Auth Reset Lab · the reset landing page
 * ---------------------------------------------------------------------------
 * This is the page a reset link points at, and it is written the way the flow
 * is supposed to work:
 *
 *   - the token row is looked up by value,
 *   - the account is taken from the token row and from nowhere else,
 *   - the token must be unredeemed and must not have expired,
 *   - redemption marks the token used.
 *
 * It is here so the links in the mail store lead somewhere real. The weakened
 * versions of these rules live on the individual level pages, which is where
 * you break them.
 */

require_once __DIR__ . '/helpers.php';

/** Tokens are unique across the whole store, so the row tells us its level. */
function ar_token_find_any(string $token): ?array
{
    $st = ar_db()->prepare('SELECT * FROM tokens WHERE token = ? ORDER BY id DESC LIMIT 1');
    $st->execute([$token]);
    $row = $st->fetch();
    return $row ?: null;
}

$token  = trim((string)($_REQUEST['token'] ?? ''));
$row    = $token === '' ? null : ar_token_find_any($token);
$level  = $row ? (int)$row['level'] : 0;
$owner  = $row && $row['user_id'] !== null ? ar_user_by_id($level, (int)$row['user_id']) : null;
$checks = ar_token_checks($row);
$usable = $row !== null && !in_array(false, $checks, true) && $owner !== null;

$body = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && $usable) {
    $new = (string)($_POST['new_password'] ?? '');
    if ($new === '') {
        $body .= ar_err('Enter a new password.');
    } else {
        /** @var array $owner */
        ar_set_password($level, (int)$owner['id'], $new);
        ar_token_mark_used((int)$row['id']);

        // State check, not a payload check: re-read the row and confirm the
        // stored hash really verifies against the string that was submitted.
        $after = ar_user_by_id($level, (int)$owner['id']);
        $ok    = $after !== null && password_verify($new, (string)$after['password_hash']);

        if ($ok && strcasecmp((string)$owner['email'], AR_ADMIN) === 0) {
            ar_mark_win($level, 'reset.php redeemed a token bound to ' . AR_ADMIN);
        }
        $body .= $ok
            ? ar_ok('Password updated for <code>' . lk_esc((string)$owner['email']) . '</code> on level ' . $level
                  . '. <a href="level' . $level . '.php">Return to level ' . $level . ' &rarr;</a>')
            : ar_err('The update did not take effect.');
        $usable = false;
        $checks['not already redeemed'] = false;
    }
}

ob_start(); ?>
<div class="labs-hero">
    <h2>Choose a new password</h2>
    <p>The link you followed carries a reset token. This page decides what that token is allowed to do.</p>
</div>

<?= $body ?>

<?php if ($token === ''): ?>
    <div class="message info">No token in the URL. Reset links look like
        <code>reset.php?token=&hellip;</code> and are delivered by mail.</div>
<?php else: ?>
<div class="lk-box">
    <h4><span class="lk-tag">TOKEN</span>What this page checked</h4>
    <div class="lk-body">
        <table class="ar-table">
            <tr><th>check</th><th>result</th></tr>
            <?php foreach ($checks as $name => $ok): ?>
            <tr><td><?= lk_esc($name) ?></td>
                <td class="<?= $ok ? 'ar-hit' : 'ar-miss' ?>"><?= ar_bool_chip($ok) ?></td></tr>
            <?php endforeach; ?>
        </table>
        <?php if ($row): ?>
        <table class="lk-kv" style="margin-top:0.6rem">
            <tr><td>level</td><td><?= $level ?></td></tr>
            <tr><td>issued to</td><td class="ar-mono"><?= lk_esc((string)$row['email']) ?></td></tr>
            <tr><td>account on the token</td><td class="ar-mono"><?= $owner ? lk_esc((string)$owner['email']) : '(unresolved)' ?></td></tr>
            <tr><td>issued at</td><td><?= lk_esc(gmdate('Y-m-d H:i:s', (int)$row['issued_at'])) ?> UTC</td></tr>
            <tr><td>expires at</td><td><?= $row['expires_at'] === null ? 'never' : lk_esc(gmdate('Y-m-d H:i:s', (int)$row['expires_at'])) . ' UTC' ?></td></tr>
            <tr><td>redeemed at</td><td><?= $row['used_at'] === null ? 'not redeemed' : lk_esc(gmdate('Y-m-d H:i:s', (int)$row['used_at'])) . ' UTC' ?></td></tr>
        </table>
        <?php endif; ?>
    </div>
</div>
<?php endif; ?>

<?php if ($usable): ?>
<div class="flag-form">
    <h3>Set a new password for <?= lk_esc((string)$owner['email']) ?></h3>
    <form method="post">
        <input type="hidden" name="token" value="<?= lk_esc($token) ?>">
        <div class="form-group">
            <label class="form-label">New password</label>
            <input type="text" name="new_password" class="form-control" autocomplete="off" value="">
        </div>
        <button class="btn btn-primary" type="submit">Update password</button>
    </form>
</div>
<?php elseif ($token !== ''): ?>
    <div class="message error">This token cannot be redeemed here. Every check above has to pass, and this page
        takes the account from the token row rather than from anything you send it.</div>
<?php endif; ?>

<div class="ar-toolbar">
    <a class="btn btn-outline" href="index.php">All levels &rarr;</a>
    <?php if ($level > 0): ?><a class="btn btn-outline" href="mailbox.php?level=<?= $level ?>">Your mailbox &rarr;</a><?php endif; ?>
</div>
<?php
ar_shell('Reset password', 'The page a reset link points at', (string)ob_get_clean(), $level);
