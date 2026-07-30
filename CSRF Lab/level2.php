<?php
require_once __DIR__ . '/helpers.php';

$levelId = 2;
$p     = csrf_level_prepare($levelId);
$state = $p['state'];

$source = <<<'SRC'
<span class="php-keyword">&lt;?php</span>
<span class="php-comment">// change_email.php  (level 2)</span>
<span class="php-keyword">if</span> (<span class="php-variable">$_SERVER</span>[<span class="php-string">'REQUEST_METHOD'</span>] !== <span class="php-string">'POST'</span>) {
    <span class="php-function">http_response_code</span>(<span class="php-string">405</span>); <span class="php-keyword">exit</span>;
}
<span class="php-variable">$email</span> = <span class="php-variable">$_POST</span>[<span class="php-string">'email'</span>] ?? <span class="php-string">''</span>;

<span class="php-comment">// Requires POST — but a cross-site &lt;form&gt; can POST too, and there is no token.</span>
<span class="vuln-line"><span class="php-function">change_admin_email</span>(<span class="php-variable">$email</span>);            <span class="php-comment">// state change on an untokened POST</span></span>
SRC;

$scaffold = "<!-- Target: change_email.php  |  Method: POST  |  Protection: none -->\n<!-- An <img> only sends GET. You need a self-submitting cross-site form. -->\n";

csrf_render_level([
    'id'            => $levelId,
    'title'         => 'No-Token POST Form',
    'difficulty'    => 'Easy',
    'endpoint'      => 'change_email.php',
    'method_label'  => 'POST',
    'defense_label' => 'None',
    'samesite'      => 'None',
    'source_html'   => $source,
    'vuln_annotation' => '<strong>Vulnerability:</strong>&nbsp; Requiring <code>POST</code> is <em>not</em> a CSRF defense. A hidden auto-submitting <code>&lt;form&gt;</code> hosted anywhere sends a cross-site POST carrying the admin cookie — and there is still no token.',
    'scenario_html' => '<p>The developer "fixed" CSRF by only accepting POST. The admin cookie is still sent on cross-site POSTs, and no token is validated.</p><p>Build an auto-submitting form PoC and deliver it to the admin.</p>',
    'console_rows'  => [
        'Admin account email' => $state['admin_email'],
        'Attacker goal'       => 'change it to ' . CSRF_ATTACKER_EMAIL,
    ],
    'scaffold'      => $scaffold,
    'result'        => $p['result'],
    'solved'        => $p['solved'],
    'flag'          => $p['flag'],
    'hints'         => $p['hints'],
    'flag_form'     => $p['flag_form'],
    'prev'          => 1,
    'next'          => 3,
]);
