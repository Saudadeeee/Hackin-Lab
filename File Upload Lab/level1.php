<?php
$levelId    = 1;
$levelTitle = 'No Validation Upload';
$difficulty = 'Easy';

$scenario = <<<'HTML'
<p>A basic file uploader saves your file verbatim into <code>uploads/level1/</code> and lets you open it.
There are <strong>zero</strong> checks on the name, type, or content.</p>
<p>Upload a PHP web shell and browse it to read the server secret at
<code>/var/secret/level1_flag.txt</code>.</p>
HTML;

$vulnNote = <<<'HTML'
<strong>Vulnerability:</strong>&nbsp; The upload is written into a web-served directory that executes
PHP, using the attacker-supplied filename and bytes. No extension, MIME, or content validation exists,
so a <code>.php</code> web shell runs on the server.
HTML;

$sourceCode = <<<'HTML'
<span class="php-keyword">&lt;?php</span>
<span class="php-comment">// level1.php — no validation of any kind</span>
<span class="php-variable">$u</span> = <span class="php-function">get_upload_input</span>();   <span class="php-comment">// filename + bytes, both attacker-controlled</span>

<span class="php-keyword">function</span> <span class="php-function">filter_level1</span>(<span class="php-keyword">array</span> <span class="php-variable">$u</span>): <span class="php-keyword">array</span> {
    <span class="php-keyword">return</span> [<span class="php-keyword">true</span>, <span class="php-string">'Accepted - no validation applied.'</span>];
}

<span class="php-comment">// Whatever is uploaded is written into the web root and served back:</span>
<span class="vuln-line"><span class="php-function">file_put_contents</span>(<span class="php-string">"uploads/level1/"</span> . <span class="php-variable">$u</span>[<span class="php-string">'name'</span>], <span class="php-variable">$u</span>[<span class="php-string">'content'</span>]);</span>
<span class="php-comment">// uploads/ runs PHP -> browse uploads/level1/shell.php to execute it.</span>
HTML;

require __DIR__ . '/render_level.php';
