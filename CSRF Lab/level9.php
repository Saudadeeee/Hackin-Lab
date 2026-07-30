<?php
require_once __DIR__ . '/helpers.php';

$levelId = 9;
$p     = csrf_level_prepare($levelId);
$state = $p['state'];

$source = <<<'SRC'
<span class="php-keyword">&lt;?php</span>
<span class="php-comment">// promote.php  (level 9) — double-submit cookie pattern</span>
<span class="php-variable">$cookieTok</span> = <span class="php-variable">$_COOKIE</span>[<span class="php-string">'csrf_token'</span>] ?? <span class="php-string">''</span>;
<span class="php-variable">$bodyTok</span>   = <span class="php-variable">$_POST</span>[<span class="php-string">'csrf_token'</span>] ?? <span class="php-string">''</span>;

<span class="php-comment">// Only checks that the two MATCH — never that the server issued them.</span>
<span class="vuln-line"><span class="php-keyword">if</span> (<span class="php-variable">$cookieTok</span> === <span class="php-string">''</span> || <span class="php-variable">$cookieTok</span> !== <span class="php-variable">$bodyTok</span>) {</span>
    <span class="php-function">http_response_code</span>(<span class="php-string">403</span>); <span class="php-keyword">exit</span>;
}
<span class="php-function">promote_to_admin</span>(<span class="php-variable">$_POST</span>[<span class="php-string">'user'</span>] ?? <span class="php-string">''</span>);   <span class="php-comment">// state change</span>
SRC;

$scaffold = "<!-- Target: promote.php  |  Method: POST  |  Protection: double-submit cookie -->\n<!-- The csrf_token cookie is NOT HttpOnly. Set it from script, and match it in the body. -->\n";

csrf_render_level([
    'id'            => $levelId,
    'title'         => 'Double-Submit Cookie Flaw',
    'difficulty'    => 'Hard',
    'endpoint'      => 'promote.php',
    'method_label'  => 'POST',
    'defense_label' => 'Double-submit cookie',
    'samesite'      => 'None',
    'source_html'   => $source,
    'vuln_annotation' => '<strong>Vulnerability:</strong>&nbsp; Double-submit only proves the cookie and the body carry the same value — not that the server issued it. Because the <code>csrf_token</code> cookie is not <code>HttpOnly</code> (and is <code>SameSite=None</code>), the attacker sets both sides to a value they choose.',
    'scenario_html' => '<p>The promote endpoint uses the double-submit cookie pattern: it accepts the request when the <code>csrf_token</code> cookie equals the body <code>csrf_token</code>.</p><p>Set the cookie yourself, match it in the form body, and deliver the PoC.</p>',
    'console_rows'  => [
        "User '" . CSRF_TARGET_USER . "' role" => $state['target_role'],
        'Attacker goal'                        => 'promote ' . CSRF_TARGET_USER . ' to admin',
    ],
    'scaffold'      => $scaffold,
    'result'        => $p['result'],
    'solved'        => $p['solved'],
    'flag'          => $p['flag'],
    'hints'         => $p['hints'],
    'flag_form'     => $p['flag_form'],
    'prev'          => 8,
    'next'          => 10,
]);
