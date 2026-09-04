<?php
/**
 * Self-test: drives the intended solution for every level against the live
 * app and reports whether the flag came back. Run inside the container:
 *
 *   docker compose exec web php /var/www/html/solve_check.php
 *
 * Business-logic levels are stateful, so this file does two things the other
 * labs' self-tests do not need. It carries a cookie jar, because the shop
 * keys every balance and order on a session cookie; and it resets each level
 * before solving it, so the run is idempotent.
 *
 * Not part of the challenge - it exists so the lab can be regression-tested.
 */
require_once __DIR__ . '/helpers.php';

$BASE    = 'http://localhost';
$COOKIES = [];
$pass    = 0;
$fail    = 0;

/** POST a form body, carrying and collecting cookies. */
function req(string $path, array $fields = []): string
{
    global $BASE, $COOKIES;

    $header = "Content-Type: application/x-www-form-urlencoded\r\n";
    if ($COOKIES) {
        $jar = [];
        foreach ($COOKIES as $k => $v) {
            $jar[] = $k . '=' . $v;
        }
        $header .= 'Cookie: ' . implode('; ', $jar) . "\r\n";
    }

    $ctx = stream_context_create(['http' => [
        'method'        => 'POST',
        'header'        => $header,
        'content'       => http_build_query($fields),
        'timeout'       => 20,
        'ignore_errors' => true,
    ]]);

    $body = (string)@file_get_contents($BASE . $path, false, $ctx);

    foreach ($http_response_header ?? [] as $h) {
        if (stripos($h, 'Set-Cookie:') === 0) {
            $pair = explode(';', trim(substr($h, 11)))[0];
            [$k, $v] = array_pad(explode('=', $pair, 2), 2, '');
            if ($k !== '') {
                $COOKIES[$k] = $v;
            }
        }
    }
    return $body;
}

/** Drop a level back to its starting state so the run repeats cleanly. */
function reset_level(int $level): void
{
    req("/level$level.php", ['bl_action' => 'reset']);
}

function check(int $level, string $body): void
{
    global $pass, $fail;
    $want = biz_flag($level);
    if (strpos($body, $want) !== false) {
        $pass++;
        echo "  PASS  level $level  $want\n";
    } else {
        $fail++;
        echo "  FAIL  level $level  (expected $want)\n";
    }
}

echo "Business Logic Lab self-test\n----------------------------\n";

/* 1 - a negative quantity turns the checkout subtraction into an addition */
reset_level(1);
req('/level1.php', ['bl_action' => 'add', 'item' => 'laptop', 'qty' => '-1']);
check(1, req('/level1.php', ['bl_action' => 'checkout']));

/* 2 - the unit price came back from the browser, so choose it */
reset_level(2);
check(2, req('/level2.php', [
    'bl_action' => 'buy', 'item' => 'ent-support', 'qty' => '1', 'unit_price' => '1.00',
]));

/* 3 - five first-order coupons, all validated before any is recorded as used */
reset_level(3);
check(3, req('/level3.php', [
    'bl_action' => 'checkout',
    'codes'     => 'FIRST10, WELCOME15, NEWBIE20, SPRING25, LOYAL30',
]));

/* 4 - one unit per line: round(0.336, 2) = 0.34, three hundred times over */
reset_level(4);
check(4, req('/level4.php', ['bl_action' => 'refund', 'per_line' => '1', 'lines' => '300']));

/* 5 - a quantity the web tier allows and the 32-bit warehouse field cannot hold */
reset_level(5);
check(5, req('/level5.php', ['bl_action' => 'buy', 'item' => 'giftcard', 'qty' => '2147483648']));

/* 6 - confirm only checks that an order exists, so skip address and payment */
reset_level(6);
req('/level6.php', ['step' => 'start', 'item' => 'desk']);
check(6, req('/level6.php', ['step' => 'confirm']));

/* 7 - fields the form never rendered are still keys in the merge */
reset_level(7);
check(7, req('/level7.php', [
    'bl_action'       => 'place',
    'item'            => 'headset',
    'qty'             => '1',
    'discount_tier'   => 'staff',      // 90% internal rate
    'internal_credit' => '100',        // dollars off, straight from the request
]));

/* 8 - each refund is checked against the line, never against the running total */
reset_level(8);
req('/level8.php', ['bl_action' => 'refund', 'line' => '1', 'amount' => '329.00']);
check(8, req('/level8.php', ['bl_action' => 'refund', 'line' => '1', 'amount' => '329.00']));

/* 9 - the loyalty round trip doubles: 50 points out at $0.02, 100 back in per $1 */
reset_level(9);
$body = '';
$points = 100;
for ($loop = 0; $loop < 5; $loop++) {
    $body   = req('/level9.php', ['bl_action' => 'redeem', 'points' => (string)$points]);
    $credit = number_format($points / 50, 2, '.', '');
    $body   = req('/level9.php', ['bl_action' => 'spend', 'spend' => $credit]);
    $points = $points * 2;                       // 100 -> 200 -> ... -> 3200
}
check(9, req('/level9.php', ['bl_action' => 'redeem', 'points' => (string)$points]));

/* 10 - the coupon engine writes a subtotal into the tier ledger for free,
        which opens the platinum gate on an item you can then buy at list price */
reset_level(10);
req('/level10.php', [
    'bl_action' => 'checkout', 'item' => 'rack', 'qty' => '12',
    'codes'     => 'FIRST10, WELCOME15, NEWBIE20, SPRING25, LOYAL30',
]);
check(10, req('/level10.php', ['bl_action' => 'checkout', 'item' => 'founders', 'qty' => '1']));

echo "----------------------------\n$pass passed, $fail failed\n";
exit($fail === 0 ? 0 : 1);
