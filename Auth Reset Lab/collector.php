<?php
/**
 * Auth Reset Lab · the attacker's web server
 * ---------------------------------------------------------------------------
 * This file plays the part of a machine you control on the internet. It logs
 * every request it receives, with the full query string, and extracts anything
 * that looks like a reset token.
 *
 * Two hostnames in the container resolve to this application and are served
 * entirely by this script: attacker.hackinlab.internal and
 * collector.hackinlab.internal. Any path on those names lands here, which is
 * what a real attacker-owned host would do.
 *
 * If a request arrives with no query string it is treated as you opening your
 * own console rather than as a victim's click.
 */

require_once __DIR__ . '/helpers.php';

$query = (string)($_SERVER['QUERY_STRING'] ?? '');
$uri   = (string)($_SERVER['REQUEST_URI'] ?? '/');
$host  = (string)($_SERVER['HTTP_HOST'] ?? '-');

$isConsole = $query === ''
    || $query === 'view=1'
    || isset($_GET['clear'])
    || (isset($_GET['level']) && count($_GET) === 1);

if (isset($_GET['clear'])) {
    ar_db()->exec('DELETE FROM collected');
    header('Location: collector.php');
    exit;
}

if (!$isConsole) {
    // A victim's browser or mail client just fetched a link that named this
    // host. Log it. The token can be anywhere in the query string, including
    // in a path that was smuggled through the host component of the URL.
    $token = null;
    if (preg_match('#token=([A-Za-z0-9._~-]{6,128})#', rawurldecode($query), $m)) {
        $token = $m[1];
    }
    ar_collect(3, $host, $uri, $query, $token);

    header('Content-Type: text/plain; charset=utf-8');
    echo "logged\n";
    exit;
}

$level = (int)($_GET['level'] ?? 3);
if ($level < 1 || $level > 10) {
    $level = 3;
}
$rows = ar_collected(25);

ob_start(); ?>
<div class="labs-hero">
    <h2>Collector</h2>
    <p>Request log for the host you control. Every request that arrives here is recorded with its full query
       string, and anything matching <code>token=&hellip;</code> is pulled out into its own column.</p>
    <div class="whitebox-note">
        In this container, <code>attacker.hackinlab.internal</code> and <code>collector.hackinlab.internal</code>
        both resolve to 127.0.0.1 and every path on them is served by this script. A link of the form
        <code>http://attacker.hackinlab.internal/reset.php?token=&hellip;</code> therefore reaches you rather than
        the application, exactly as it would if the name pointed at a machine you rented.
    </div>
</div>

<div class="ar-toolbar">
    <a class="btn btn-outline" href="level3.php">Back to level 3 &rarr;</a>
    <a class="btn btn-outline" href="collector.php?clear=1">Clear the log</a>
</div>

<?php if (!$rows): ?>
    <div class="message info">Nothing collected yet. The log fills up when a victim requests a URL whose host is
        one you supplied.</div>
<?php else: ?>
<div class="lk-box">
    <h4><span class="lk-tag lk-tag-red">CAPTURED</span><?= count($rows) ?> request(s)</h4>
    <div class="lk-body">
        <table class="ar-table">
            <tr><th>when</th><th>host</th><th>request</th><th>token</th></tr>
            <?php foreach ($rows as $r): ?>
            <tr>
                <td><?= lk_esc(gmdate('H:i:s', (int)$r['created_at'])) ?></td>
                <td class="ar-mono"><?= lk_esc((string)$r['host']) ?></td>
                <td class="ar-mono"><?= lk_esc((string)$r['uri']) ?></td>
                <td class="ar-mono <?= $r['token'] ? 'ar-hit' : 'ar-miss' ?>">
                    <?= $r['token'] ? lk_esc((string)$r['token']) : '&mdash;' ?>
                </td>
            </tr>
            <?php endforeach; ?>
        </table>
    </div>
</div>
<?php endif; ?>
<?php
ar_shell('Collector', 'Requests that reached the host you control', (string)ob_get_clean(), $level);
