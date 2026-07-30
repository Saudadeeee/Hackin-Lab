<?php
require_once __DIR__ . '/helpers.php';

$levelId = 4;
$p     = csrf_level_prepare($levelId);
$state = $p['state'];

$source = <<<'SRC'
<span class="php-keyword">&lt;?php</span>
<span class="php-comment">// promote.php  (level 4)</span>
<span class="vuln-line"><span class="php-keyword">define</span>(<span class="php-string">'CSRF_TOKEN'</span>, <span class="php-string">'a1b2c3d4'</span>);        <span class="php-comment">// hardcoded, same for everyone</span></span>

<span class="php-variable">$token</span> = <span class="php-variable">$_POST</span>[<span class="php-string">'csrf_token'</span>] ?? <span class="php-string">''</span>;
<span class="php-keyword">if</span> (<span class="php-variable">$token</span> !== <span class="php-keyword">CSRF_TOKEN</span>) {                <span class="php-comment">// predictable — attacker knows it</span>
    <span class="php-function">http_response_code</span>(<span class="php-string">403</span>); <span class="php-keyword">exit</span>;
}
<span class="php-function">promote_to_admin</span>(<span class="php-variable">$_POST</span>[<span class="php-string">'user'</span>] ?? <span class="php-string">''</span>);   <span class="php-comment">// state change</span>
SRC;

$scaffold = "<!-- Target: promote.php  |  Method: POST  |  Protection: static token -->\n<!-- The expected token is hardcoded in the source above. Reuse it. -->\n";

csrf_render_level([
    'id'            => $levelId,
    'title'         => 'Static / Predictable Token',
    'difficulty'    => 'Medium',
    'endpoint'      => 'promote.php',
    'method_label'  => 'POST',
    'defense_label' => 'Static token',
    'samesite'      => 'None',
    'source_html'   => $source,
    'vuln_annotation' => '<strong>Vulnerability:</strong>&nbsp; The token is a compile-time constant (<code>a1b2c3d4</code>), identical for every user and session. A token only defends against CSRF when the attacker cannot guess it — here it is printed in the source.',
    'scenario_html' => '<p>The <code>promote.php</code> endpoint grants admin rights and now validates a token. But the token is hardcoded, so you already know it.</p><p>Forge a POST that promotes <strong>' . htmlspecialchars(CSRF_TARGET_USER) . '</strong> using the known token, then deliver it.</p>',
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
    'prev'          => 3,
    'next'          => 5,
]);
