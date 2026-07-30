<?php
require_once __DIR__ . '/helpers.php';

$levelId = 5;
$p     = csrf_level_prepare($levelId);
$state = $p['state'];

$source = <<<'SRC'
<span class="php-keyword">&lt;?php</span>
<span class="php-comment">// change_email.php  (level 5)</span>
<span class="php-variable">$token</span> = <span class="php-variable">$_POST</span>[<span class="php-string">'csrf_token'</span>] ?? <span class="php-string">''</span>;

<span class="php-comment">// Validates the FORMAT of the token, but never compares it to the</span>
<span class="php-comment">// token stored in the admin's session — so any 32-hex value passes.</span>
<span class="vuln-line"><span class="php-keyword">if</span> (!<span class="php-function">preg_match</span>(<span class="php-string">'/^[a-f0-9]{32}$/i'</span>, <span class="php-variable">$token</span>)) {   <span class="php-comment">// format only!</span></span>
    <span class="php-function">http_response_code</span>(<span class="php-string">403</span>); <span class="php-keyword">exit</span>;
}
<span class="php-function">change_admin_email</span>(<span class="php-variable">$_POST</span>[<span class="php-string">'email'</span>] ?? <span class="php-string">''</span>);   <span class="php-comment">// state change</span>
SRC;

$scaffold = "<!-- Target: change_email.php  |  Method: POST  |  Protection: token format check only -->\n<!-- Supply any 32 hex-character csrf_token; it is never bound to the session. -->\n";

csrf_render_level([
    'id'            => $levelId,
    'title'         => 'Token Not Bound to Session',
    'difficulty'    => 'Medium',
    'endpoint'      => 'change_email.php',
    'method_label'  => 'POST',
    'defense_label' => 'Token (format only)',
    'samesite'      => 'None',
    'source_html'   => $source,
    'vuln_annotation' => '<strong>Vulnerability:</strong>&nbsp; The handler checks that the token <em>looks</em> right (32 hex chars) but never compares it to the value stored in the admin\'s session. Any well-formed string you invent is accepted.',
    'scenario_html' => '<p>The token now looks random and malformed values are rejected — but validating a <em>format</em> is not the same as validating <em>authenticity</em>.</p><p>Forge a POST with a self-chosen 32-hex token and deliver it.</p>',
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
    'prev'          => 4,
    'next'          => 6,
]);
