<?php
require_once __DIR__ . '/helpers.php';

$levelId = 3;
$p     = csrf_level_prepare($levelId);
$state = $p['state'];

$source = <<<'SRC'
<span class="php-keyword">&lt;?php</span>
<span class="php-comment">// change_email.php  (level 3)</span>
<span class="php-variable">$email</span> = <span class="php-variable">$_POST</span>[<span class="php-string">'email'</span>] ?? <span class="php-string">''</span>;
<span class="php-variable">$token</span> = <span class="php-variable">$_POST</span>[<span class="php-string">'csrf_token'</span>] ?? <span class="php-string">''</span>;     <span class="php-comment">// token IS read...</span>

<span class="php-comment">// if ($token !== $_SESSION['csrf_token']) {     // ...but the compare</span>
<span class="php-comment">//     http_response_code(403); exit;            //    line was left</span>
<span class="php-comment">// }                                             //    commented out!</span>

<span class="vuln-line"><span class="php-function">change_admin_email</span>(<span class="php-variable">$email</span>);            <span class="php-comment">// runs regardless of the token</span></span>
SRC;

$scaffold = "<!-- Target: change_email.php  |  Method: POST  |  Protection: token field that is never validated -->\n<!-- The csrf_token field can be any value (or absent). -->\n";

csrf_render_level([
    'id'            => $levelId,
    'title'         => 'Unvalidated CSRF Token',
    'difficulty'    => 'Medium',
    'endpoint'      => 'change_email.php',
    'method_label'  => 'POST',
    'defense_label' => 'Token (never checked)',
    'samesite'      => 'None',
    'source_html'   => $source,
    'vuln_annotation' => '<strong>Vulnerability:</strong>&nbsp; The form ships a <code>csrf_token</code> field and the handler even reads it — but the comparison against the session token was commented out. A token that is generated but never validated protects nothing.',
    'scenario_html' => '<p>The email form now includes a <code>csrf_token</code> hidden field, so it looks defended. Read the handler: the validation line is missing.</p><p>Forge a POST — with any token value, or none — and deliver it.</p>',
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
    'prev'          => 2,
    'next'          => 4,
]);
