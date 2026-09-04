<?php
/**
 * The endpoints the levels race.
 *
 * Each returns one short line of plain text so the launcher's output stays
 * readable.
 *
 * Note the deliberate split in most levels: the CHECK reads shared state with
 * no lock (racy), while the EFFECT is appended to a ledger (atomic). That is
 * how real code usually looks - `UPDATE t SET n = n + 1` is safe on its own,
 * but the decision to run it came from a SELECT taken a moment earlier. Level 1
 * keeps the unsafe read-modify-write so the lost-update failure is visible too.
 */
require_once __DIR__ . '/lab_kit.php';
require_once __DIR__ . '/race.php';
require_once __DIR__ . '/secrets.php';

header('Content-Type: text/plain; charset=utf-8');

$level = (int)($_REQUEST['level'] ?? 0);
$op    = (string)($_REQUEST['op'] ?? '');
$sid   = race_sid();

// The launcher's warm-up requests must not touch state.
if (isset($_GET['warm'])) {
    echo 'warm';
    exit;
}

switch ($level) {

/* ------------------------------------------------------------------ 1 */
case 1: {
    // Non-atomic increment: read, think, write.
    $s    = race_read(1, ['counter' => 0]);
    $seen = $s['counter'];
    race_log(1, "read counter=$seen");
    race_work(120);
    $s['counter'] = $seen + 1;
    race_write(1, $s);
    race_log(1, "wrote counter={$s['counter']}");

    // The acknowledgement ledger is append-only, so it counts every request
    // that got this far - unlike the counter.
    race_ledger_add(1, 'acks');
    echo "ok counter={$s['counter']}";
    break;
}

/* ------------------------------------------------------------------ 2 */
case 2: {
    // Check-then-act on a boolean.
    $s = race_read(2, ['used' => false]);
    race_log(2, 'check used=' . ($s['used'] ? 'true' : 'false'));
    if ($s['used']) {
        echo 'rejected: coupon already used';
        break;
    }
    race_work(140);                       // validate the code against the promo service
    race_write(2, ['used' => true]);
    race_ledger_add(2, 'applied', '30.00');
    $n = race_ledger_count(2, 'applied');
    race_log(2, "applied discount #$n");
    echo "ok applied=$n";
    break;
}

/* ------------------------------------------------------------------ 3 */
case 3: {
    // Check-then-act on a number.
    $withdrawn = race_ledger_sum(3, 'withdrawals');
    $balance   = 100 - $withdrawn;
    race_log(3, "check balance=$balance");
    if ($balance < 100) {
        echo "rejected: insufficient funds ($balance)";
        break;
    }
    race_work(150);                       // contact the payment rail
    race_ledger_add(3, 'withdrawals', '100');
    $w = race_ledger_sum(3, 'withdrawals');
    race_log(3, 'debited, withdrawn=' . $w);
    echo 'ok withdrawn=' . $w . ' balance=' . (100 - $w);
    break;
}

/* ------------------------------------------------------------------ 4 */
case 4: {
    // Rate limiter that counts AFTER doing the work.
    $hits = race_ledger_count(4, 'hits');
    race_log(4, "limiter sees hits=$hits");
    if ($hits >= 3) {
        echo 'rejected: rate limit (3 per window)';
        break;
    }
    race_work(130);                       // the expensive operation being limited
    race_ledger_add(4, 'hits');
    $n = race_ledger_count(4, 'hits');
    race_log(4, "processed, hits=$n");
    echo "ok processed=$n";
    break;
}

/* ------------------------------------------------------------------ 5 */
case 5: {
    $files = ['notes.txt' => "Reminder: rotate the API keys.\n", 'vault.key' => cl_race_secret()];
    $s = race_read(5, ['file' => 'notes.txt', 'leaked' => false]);

    if ($op === 'select') {
        $to = (string)($_REQUEST['to'] ?? 'notes.txt');
        if (!isset($files[$to])) {
            echo 'unknown file';
            break;
        }
        $s['file'] = $to;
        race_write(5, $s);
        race_log(5, "selected {$to}");
        echo "selected {$to}";
        break;
    }

    // TIME OF CHECK
    $name = $s['file'];
    race_log(5, "check {$name}");
    if (!str_ends_with($name, '.txt')) {
        echo "rejected: only .txt files may be exported ({$name})";
        break;
    }
    race_work(160);                       // render the export, write the audit row

    // TIME OF USE - the name is read again, and it may have changed
    $used = race_read(5, ['file' => 'notes.txt', 'leaked' => false])['file'];
    race_log(5, "export {$used}");
    if ($used === 'vault.key') {
        $st = race_read(5, ['file' => 'notes.txt', 'leaked' => false]);
        $st['leaked'] = true;
        race_write(5, $st);
    }
    echo "exported {$used}: " . trim($files[$used] ?? '');
    break;
}

/* ------------------------------------------------------------------ 6 */
case 6: {
    // Same shape as level 2, but the endpoint calls session_start(), which
    // takes an exclusive lock on the session file for the whole request.
    // An empty token means "give me a session of my own" - which is what a
    // second browser, a mobile app or a fresh login would produce.
    $token = (string)($_REQUEST['token'] ?? '');
    $clean = substr(preg_replace('/[^a-z0-9]/', '', $token), 0, 32);
    session_id($clean !== '' ? $clean : bin2hex(random_bytes(8)));
    session_start();

    $s = race_read(6, ['used' => false], $sid);
    race_log(6, 'session ' . session_id() . ' check used=' . ($s['used'] ? 'true' : 'false'), $sid);
    if ($s['used']) {
        echo 'rejected: reward already claimed';
        break;
    }
    race_work(150);
    race_write(6, ['used' => true], $sid);
    race_ledger_add(6, 'claims', session_id(), $sid);
    $n = race_ledger_count(6, 'claims', $sid);
    race_log(6, 'session ' . session_id() . " claimed=$n", $sid);
    echo "ok claimed=$n session=" . session_id();
    break;
}

/* ------------------------------------------------------------------ 7 */
case 7: {
    // Two endpoints, one state machine, no lock between them.
    $s = race_read(7, ['status' => 'pending', 'refunded' => false, 'shipped' => false]);

    if ($op === 'cancel') {
        race_log(7, "cancel sees status={$s['status']}");
        if ($s['status'] !== 'pending') {
            echo "rejected: order is {$s['status']}";
            break;
        }
        race_work(150);                   // call the payment provider
        $s = race_read(7, ['status' => 'pending', 'refunded' => false, 'shipped' => false]);
        $s['status']   = 'cancelled';
        $s['refunded'] = true;
        race_write(7, $s);
        race_log(7, 'refund issued');
        echo 'ok refunded';
        break;
    }

    race_log(7, "ship sees status={$s['status']}");
    if ($s['status'] !== 'pending') {
        echo "rejected: order is {$s['status']}";
        break;
    }
    race_work(150);                       // reserve stock, print the label
    $s = race_read(7, ['status' => 'pending', 'refunded' => false, 'shipped' => false]);
    $s['status']  = 'shipped';
    $s['shipped'] = true;
    race_write(7, $s);
    race_log(7, 'shipment created');
    echo 'ok shipped';
    break;
}

/* ------------------------------------------------------------------ 8 */
case 8: {
    // Arrival times are appended, never overwritten, so the count is honest.
    // The challenge is purely one of delivery.
    $now = microtime(true);
    race_ledger_add(8, 'arrivals', sprintf('%.6f', $now));
    $best = race_best_window(race_ledger_rows(8, 'arrivals'), 0.025);
    race_log(8, sprintf('arrived, best window now %d', $best));
    echo sprintf('arrived best=%d', $best);
    break;
}

/* ------------------------------------------------------------------ 9 */
case 9: {
    // Optimistic locking with a non-atomic compare-and-swap.
    $spent   = 50 * race_ledger_count(9, 'purchases');
    $balance = 100 - $spent;
    $s       = race_read(9, ['version' => 1]);
    $version = (int)$s['version'];
    race_log(9, "read balance=$balance version=$version");

    race_work(140);                       // build the order, call the gateway

    $cur = race_read(9, ['version' => 1]);
    if ((int)$cur['version'] !== $version) {          // the CHECK
        race_log(9, "conflict: version now {$cur['version']}");
        echo 'rejected: someone else modified the row';
        break;
    }
    race_work(40);                        // the gap between the CHECK and the WRITE

    race_ledger_add(9, 'purchases', '50');            // the WRITE
    race_write(9, ['version' => $version + 1]);
    $spent = 50 * race_ledger_count(9, 'purchases');
    race_log(9, "wrote purchase, spent=$spent version=" . ($version + 1));
    echo "ok spent=$spent balance=" . (100 - $spent);
    break;
}

/* ------------------------------------------------------------------ 10 */
case 10: {
    $balance = 50 + race_ledger_sum(10, 'balance');
    $credits = (int)race_ledger_sum(10, 'credits');

    if ($op === 'refund') {
        // Gated on holding a credit, but the check and the consumption are
        // separate steps, so concurrent refunds all see the same credit.
        race_log(10, "refund check credits=$credits balance=$balance");
        if ($credits < 1) {
            echo 'rejected: no credit to refund';
            break;
        }
        race_work(150);                   // call the payment provider
        race_ledger_add(10, 'balance', '50');
        race_ledger_add(10, 'credits', '-1');
        $b = 50 + race_ledger_sum(10, 'balance');
        race_log(10, "refunded, balance=$b");
        echo "ok refunded balance=$b";
        break;
    }

    // buy: spend 50, gain one credit
    race_log(10, "buy check balance=$balance");
    if ($balance < 50) {
        echo "rejected: insufficient balance ($balance)";
        break;
    }
    race_work(150);
    race_ledger_add(10, 'balance', '-50');
    race_ledger_add(10, 'credits', '1');
    $b = 50 + race_ledger_sum(10, 'balance');
    $c = (int)race_ledger_sum(10, 'credits');
    race_log(10, "bought, balance=$b credits=$c");
    echo "ok credits=$c balance=$b";
    break;
}

default:
    http_response_code(400);
    echo 'unknown level';
}
