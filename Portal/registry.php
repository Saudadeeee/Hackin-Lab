<?php
/**
 * Hackin-Lab Portal · the lab registry.
 *
 * One place that knows every lab: where it listens, how many levels it has,
 * which cookie holds its progress, and where it sits in the suggested order.
 *
 * Progress works across ports because a cookie's scope is the host, not the
 * port - every lab on localhost writes into the same jar, so the portal can
 * read all of them.
 */

function portal_phases(): array
{
    return [
        0 => [
            'title' => 'Warm-up',
            'lead'  => 'Learn the page, not the payload.',
            'why'   => 'Read the source panel, run the three probes, predict what the trace will say, then send
                        your payload and check the prediction. That loop is the method; everything after this is
                        practice at it. Two levels is enough.',
        ],
        1 => [
            'title' => 'Data becoming syntax',
            'lead'  => 'One root cause, four grammars.',
            'why'   => 'HTML, SQL, a filesystem path and a shell command line are four different grammars with the
                        same defect: a value crosses into a position where it is read as structure. By the fourth
                        lab the question should already be "where does my input end up, and what is structural
                        there".',
        ],
        2 => [
            'title' => 'The same bug in less familiar grammars',
            'lead'  => 'Transfer the habit, not the payload.',
            'why'   => 'XPath, LDAP filters, Mongo query documents, template expressions and XML entities. None of
                        these look like SQL, and all of them are assembled by string concatenation.',
        ],
        3 => [
            'title' => 'Trust and identity',
            'lead'  => 'Who says you are who you say you are.',
            'why'   => 'Do JWT strictly in order: the key you crack in level 4 is still valid in levels 9 and 10,
                        which is the lesson rather than an oversight.',
        ],
        4 => [
            'title' => 'The browser as the boundary',
            'lead'  => 'Origins, allowlists and who is allowed to ask.',
            'why'   => 'CORS and CSP teach how a browser decides what may talk to what. SSRF then walks the same
                        allowlist reasoning back to the server side, where the parser is different but the mistake
                        is identical.',
        ],
        5 => [
            'title' => 'Nothing to fuzz',
            'lead'  => 'No payload syntax to discover.',
            'why'   => 'These are read-the-logic labs. In the Race lab do levels 2 and 3, then jump to 6 - it
                        explains why your earlier races may not have reproduced, which saves a lot of time in 7 to
                        10.',
        ],
        6 => [
            'title' => 'Correct primitives, wrong construction',
            'lead'  => 'AES is not broken. The construction is.',
            'why'   => 'Strictly in order: each level assumes the one before it. The habit being trained is asking
                        what a construction lets you observe and what it lets you change.',
        ],
    ];
}

/**
 * @return array<int, array{
 *   dir:string, name:string, port:int, levels:int, cookie:string,
 *   class:string, phase:int, note:string, tools:array<string,string>
 * }>
 */
function portal_labs(): array
{
    return [
        ['dir' => 'XSS Lab', 'name' => 'XSS', 'port' => 8081, 'levels' => 10,
         'cookie' => 'xss_lab_progress', 'phase' => 0, 'order' => 1,
         'class' => 'Cross-site scripting',
         'note'  => 'Reflected, stored, DOM, then filters. Levels 1-2 are the warm-up; the rest belong to phase 1.',
         'tools' => []],

        ['dir' => 'SQLi Lab', 'name' => 'SQL Injection', 'port' => 8080, 'levels' => 17,
         'cookie' => 'completed_levels', 'phase' => 1, 'order' => 2,
         'class' => 'SQL injection',
         'note'  => 'Levels 1-8 here, 9-17 in phase 2. The trace prints the assembled statement, so you never have to imagine the query.',
         'tools' => []],

        ['dir' => 'Path Traversal Lab', 'name' => 'Path Traversal', 'port' => 8082, 'levels' => 10,
         'cookie' => 'pt_lab_progress', 'phase' => 1, 'order' => 3,
         'class' => 'Path traversal and LFI',
         'note'  => 'A filesystem path is a grammar too. Wrappers, encodings, and filters that normalise in the wrong order.',
         'tools' => []],

        ['dir' => 'OSCommand Injection', 'name' => 'OS Command Injection', 'port' => 8084, 'levels' => 10,
         'cookie' => 'oscommand_lab_progress', 'phase' => 1, 'order' => 4,
         'class' => 'Command injection',
         'note'  => 'The trace shows the exact command handed to the shell, and makes newlines and null bytes visible.',
         'tools' => []],

        ['dir' => 'XPath LDAP Lab', 'name' => 'XPath &amp; LDAP', 'port' => 8100, 'levels' => 10,
         'cookie' => 'xpathldap_lab_progress', 'phase' => 2, 'order' => 5,
         'class' => 'XPath and LDAP filter injection',
         'note'  => 'Real XPath via DOMXPath, plus a hand-written RFC 4515 filter parser, so the injections are genuine rather than simulated.',
         'tools' => []],

        ['dir' => 'NoSQL Injection Lab', 'name' => 'NoSQL Injection', 'port' => 8090, 'levels' => 10,
         'cookie' => 'nosql_lab_progress', 'phase' => 2, 'order' => 6,
         'class' => 'NoSQL injection',
         'note'  => 'Operator injection and type confusion, where the payload is a data structure rather than a string.',
         'tools' => []],

        ['dir' => 'SSTI Lab', 'name' => 'Template Injection', 'port' => 8086, 'levels' => 10,
         'cookie' => 'ssti_lab_progress', 'phase' => 2, 'order' => 7,
         'class' => 'Server-side template injection',
         'note'  => 'From expression evaluation to remote code execution, one sandbox gap at a time.',
         'tools' => []],

        ['dir' => 'XXE Lab', 'name' => 'XXE', 'port' => 8087, 'levels' => 10,
         'cookie' => 'xxe_lab_progress', 'phase' => 2, 'order' => 8,
         'class' => 'XML external entities',
         'note'  => 'Out-of-band and error-based exfiltration, XInclude, and parameter-entity chaining.',
         'tools' => []],

        ['dir' => 'JWT Lab', 'name' => 'JWT &amp; Token Forgery', 'port' => 8093, 'levels' => 10,
         'cookie' => 'jwt_lab_progress', 'phase' => 3, 'order' => 9,
         'class' => 'Token verification failures',
         'note'  => 'Strictly in order. Six steps of a correct verification, one broken per level.',
         'tools' => ['JWT Workbench' => 'tools.php', 'JWKS' => 'jwks.php', 'Paste' => 'paste.php']],

        ['dir' => 'Auth Reset Lab', 'name' => 'Auth &amp; Password Reset', 'port' => 8099, 'levels' => 10,
         'cookie' => 'authreset_lab_progress', 'phase' => 3, 'order' => 10,
         'class' => 'Account recovery',
         'note'  => 'Sign in as guest@hackinlab.internal / guest123 and take over admin@hackinlab.internal.',
         'tools' => ['Mailbox' => 'mailbox.php', 'Collector' => 'collector.php']],

        ['dir' => 'IDOR Lab', 'name' => 'IDOR', 'port' => 8083, 'levels' => 10,
         'cookie' => 'idor_lab_progress', 'phase' => 3, 'order' => 11,
         'class' => 'Broken access control',
         'note'  => 'Object references, mass assignment, and a check that runs before the state it is checking.',
         'tools' => []],

        ['dir' => 'CORS CSP Lab', 'name' => 'CORS &amp; CSP', 'port' => 8095, 'levels' => 10,
         'cookie' => 'browserpolicy_lab_progress', 'phase' => 4, 'order' => 12,
         'class' => 'Browser policy bypass',
         'note'  => 'Levels 1-5 are CORS allowlists, 6-10 are CSP. The CSP levels send the real header, so the payload genuinely runs or genuinely does not.',
         'tools' => []],

        ['dir' => 'CSRF Lab', 'name' => 'CSRF', 'port' => 8091, 'levels' => 10,
         'cookie' => 'csrf_lab_progress', 'phase' => 4, 'order' => 13,
         'class' => 'Cross-site request forgery',
         'note'  => 'Token binding, SameSite, referer checks, and double-submit done wrong.',
         'tools' => []],

        ['dir' => 'Open Redirect Lab', 'name' => 'Open Redirect', 'port' => 8092, 'levels' => 10,
         'cookie' => 'redirect_lab_progress', 'phase' => 4, 'order' => 14,
         'class' => 'Open redirect',
         'note'  => 'Every place a string can hide inside a URL, and why only parsing settles it.',
         'tools' => []],

        ['dir' => 'SSRF Lab', 'name' => 'SSRF', 'port' => 8085, 'levels' => 10,
         'cookie' => 'ssrf_lab_progress', 'phase' => 4, 'order' => 15,
         'class' => 'Server-side request forgery',
         'note'  => 'Cloud metadata, scheme abuse, and parser confusion between the validator and the fetcher.',
         'tools' => []],

        ['dir' => 'Business Logic Lab', 'name' => 'Business Logic', 'port' => 8097, 'levels' => 10,
         'cookie' => 'bizlogic_lab_progress', 'phase' => 5, 'order' => 16,
         'class' => 'Business logic',
         'note'  => 'A working shop whose rules are wrong. The trace shows the money arithmetic with your numbers in it.',
         'tools' => []],

        ['dir' => 'Race Condition Lab', 'name' => 'Race Conditions &amp; TOCTOU', 'port' => 8094, 'levels' => 10,
         'cookie' => 'race_lab_progress', 'phase' => 5, 'order' => 17,
         'class' => 'Concurrency',
         'note'  => 'Do 2 and 3, then 6. Every level prints a server-side log of how your requests actually interleaved.',
         'tools' => []],

        ['dir' => 'File Upload Lab', 'name' => 'File Upload', 'port' => 8088, 'levels' => 10,
         'cookie' => 'upload_lab_progress', 'phase' => 5, 'order' => 18,
         'class' => 'Unrestricted upload',
         'note'  => 'Extension, MIME and magic-byte checks, and the ways a web server decides what to execute.',
         'tools' => []],

        ['dir' => 'PHP Object Injection', 'name' => 'Object Injection', 'port' => 8089, 'levels' => 10,
         'cookie' => 'poi_lab_progress', 'phase' => 5, 'order' => 19,
         'class' => 'Insecure deserialization',
         'note'  => 'POP chains, phar streams, and the magic methods that run before you get a say.',
         'tools' => []],

        ['dir' => 'GraphQL Lab', 'name' => 'GraphQL', 'port' => 8098, 'levels' => 10,
         'cookie' => 'graphql_lab_progress', 'phase' => 5, 'order' => 20,
         'class' => 'GraphQL security',
         'note'  => 'A hand-written engine, so introspection, aliases, batching and depth limits all behave for real.',
         'tools' => []],

        ['dir' => 'Crypto Oracle Lab', 'name' => 'Crypto Oracle', 'port' => 8096, 'levels' => 10,
         'cookie' => 'crypto_lab_progress', 'phase' => 6, 'order' => 21,
         'class' => 'Cryptographic misuse',
         'note'  => 'Strictly in order. Each level assumes the one before it.',
         'tools' => ['Crypto Workbench' => 'tools.php', 'Oracle endpoints' => 'oracle.php']],
    ];
}

/** Levels solved for one lab, read from its progress cookie. */
function portal_solved(string $cookie): array
{
    $raw = $_COOKIE[$cookie] ?? '';
    if ($raw === '') {
        return [];
    }
    $decoded = json_decode($raw, true);
    if (!is_array($decoded)) {
        return [];
    }
    $out = [];
    foreach ($decoded as $v) {
        if (is_int($v) || (is_string($v) && ctype_digit($v))) {
            $out[] = (int)$v;
        }
    }
    sort($out);
    return array_values(array_unique($out));
}

/**
 * Liveness for every lab, checked in parallel so the page stays fast.
 *
 * The portal runs in its own container, so it reaches the other labs through
 * the Docker host gateway rather than through localhost.
 */
function portal_status(array $labs, float $timeout = 0.6): array
{
    $host = getenv('LAB_HOST') ?: 'host.docker.internal';
    if (!function_exists('curl_multi_init')) {
        return [];
    }
    $mh = curl_multi_init();
    $hs = [];
    foreach ($labs as $i => $lab) {
        $ch = curl_init(sprintf('http://%s:%d/index.php', $host, $lab['port']));
        curl_setopt_array($ch, [
            CURLOPT_NOBODY         => true,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT_MS     => (int)($timeout * 1000),
            CURLOPT_CONNECTTIMEOUT_MS => (int)($timeout * 1000),
        ]);
        curl_multi_add_handle($mh, $ch);
        $hs[$i] = $ch;
    }
    $active = null;
    do {
        curl_multi_exec($mh, $active);
        curl_multi_select($mh, 0.05);
    } while ($active > 0);

    $out = [];
    foreach ($hs as $i => $ch) {
        $code = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        $out[$labs[$i]['port']] = $code >= 200 && $code < 400;
        curl_multi_remove_handle($mh, $ch);
        curl_close($ch);
    }
    curl_multi_close($mh);
    return $out;
}
