<?php
/**
 * XSS Lab · teaching layer
 * ---------------------------------------------------------------------------
 * Adds, underneath the existing two-panel challenge, the things a learner needs
 * in order to stop guessing:
 *
 *   - a trace of THEIR input through the SAME filter code the level runs
 *   - the exact string the browser receives, with the injection highlighted
 *   - how the browser parses that specific context, and where it can be escaped
 *   - probes: one question each, never a finished exploit
 *   - on success, why that payload beat that filter
 *   - the fix, vulnerable line beside correct line
 *
 * Nothing here changes challenge behaviour or flag values.
 */

require_once __DIR__ . '/lab_kit.php';

/* =========================================================================
 * Per-level static content
 * ===================================================================== */

function xss_teach_content(int $level): array
{
    $c = [];

    $c[1] = [
        'model_title' => 'Context: element text',
        'model' => '<p>Your value lands between an opening and a closing tag, where the HTML parser is in
            <strong>data state</strong>. In that state exactly one character is structural: <code>&lt;</code>.
            It starts a tag. Everything else is text.</p>
            <p>So the question for this context is only ever "does <code>&lt;</code> survive?". If it does, you can
            open any element you like, and from there you have the whole HTML grammar available. If it is encoded to
            <code>&amp;lt;</code>, nothing else you do to the string matters.</p>
            <p><code>&lt;script&gt;</code> is one option, not the option. An element with an event handler
            (<code>&lt;img onerror&gt;</code>, <code>&lt;svg onload&gt;</code>, <code>&lt;details ontoggle open&gt;</code>)
            is often more useful, because filters that block the word "script" usually stop there.</p>',
        'why' => '<p>Nothing stood between your input and the parser. The value was concatenated into the HTML
            string, so the <code>&lt;</code> you sent opened a real element and the browser built a real DOM node
            from it.</p>
            <p>This is the baseline every other level is measured against: it establishes that the sink is HTML and
            that the context is element text. The remaining nine levels change one thing each.</p>',
        'fix_bad' => 'echo "<div>Hello, " . $name . "</div>";',
        'fix_good' => '// Encode for the context you are writing into. For element text
// that means the four HTML metacharacters, always.
echo "<div>Hello, "
   . htmlspecialchars($name, ENT_QUOTES | ENT_SUBSTITUTE, \'UTF-8\')
   . "</div>";

// ENT_QUOTES covers both quote characters, so the same call stays
// correct if this value is later moved into an attribute.
// ENT_SUBSTITUTE replaces invalid UTF-8 instead of returning an
// empty string, which is what turns an encoding bug into a blank page.',
        'fix_note' => 'Templating engines do this for you (Twig, Blade, React). The bug almost always appears at the
            point where someone opts out: <code>|raw</code>, <code>{!! !!}</code>, <code>dangerouslySetInnerHTML</code>.',
        'param' => 'name',
        'probes' => [
            ['q' => 'Does the less-than sign survive?', 'payload' => '<b>bold</b>',
             'learn' => 'If the text renders in bold, <code>&lt;</code> reached the parser as a tag opener. If you see the literal characters, it was encoded and this context is closed.'],
            ['q' => 'Is the value reflected verbatim, or normalised?', 'payload' => 'a"b\'c<d>e&f',
             'learn' => 'View the page source and compare byte for byte. This one probe tells you what every filter in the pipeline did, for all five characters that matter.'],
            ['q' => 'Does an element that is not a script tag also work?', 'payload' => '<u>underline</u>',
             'learn' => 'Confirms the parser is building arbitrary elements rather than a small allowlist. Once that is true, event handlers are available.'],
        ],
    ];

    $c[2] = [
        'model_title' => 'Context: double-quoted attribute value',
        'model' => '<p>Your value is written inside <code>value="&hellip;"</code>. In an attribute value the parser
            is looking for one thing: the matching quote character that ends it. Until that appears, everything
            including <code>&lt;</code> is literal attribute text.</p>
            <p>So the structural character here is <code>"</code>, not <code>&lt;</code>. Inject one and you are back
            in the tag, where the parser accepts more attributes separated by whitespace - and an event handler
            attribute is executable code.</p>
            <table class="lk-kv">
                <tr><td>ENT_NOQUOTES</td><td>encodes <code>&amp; &lt; &gt;</code> only. Both quote characters pass through.</td></tr>
                <tr><td>ENT_COMPAT (default)</td><td>also encodes <code>"</code>. Single quotes still pass.</td></tr>
                <tr><td>ENT_QUOTES</td><td>encodes both. This is the flag you want, always.</td></tr>
            </table>
            <p>The flag argument, not the function name, is what decides whether this context is safe.</p>',
        'why' => '<p><code>ENT_NOQUOTES</code> left your <code>"</code> intact, so it closed <code>value="</code>
            early. The parser then read the rest of your input as further attributes on the same
            <code>&lt;input&gt;</code> element, and an event handler among them became executable.</p>
            <p>Note what did not need to happen: no <code>&lt;</code> was required. The angle brackets were
            correctly encoded the whole time, and it made no difference, because the escape route in an attribute is
            the quote.</p>',
        'fix_bad' => '$safe = htmlspecialchars($search, ENT_NOQUOTES);
echo \'<input type="text" value="\' . $safe . \'">\';',
        'fix_good' => '// One call, correct in every HTML context that takes a text value.
$safe = htmlspecialchars($search, ENT_QUOTES | ENT_SUBSTITUTE, \'UTF-8\');
echo \'<input type="text" value="\' . $safe . \'">\';

// Two further habits that make this class of bug hard to reintroduce:
//   - always quote attributes; an unquoted value ends at the first
//     space, so even a fully-escaped value can grow new attributes
//   - never place user input in an event handler or a style
//     attribute, where the value is parsed as code, not as text',
        'fix_note' => 'Escaping is context-dependent. HTML encoding is correct for element text and quoted attribute
            values, and <em>not sufficient</em> inside <code>&lt;script&gt;</code>, inside a URL, or inside an event
            handler - those need JSON encoding, URL encoding, and not doing it at all, respectively.',
        'param' => 'q',
        'probes' => [
            ['q' => 'Which characters does this filter actually encode?', 'payload' => 'a"b\'c<d>e&f',
             'learn' => 'Read the trace below. Anything still present after the filter stage is a character you can build with.'],
            ['q' => 'Can I get out of the attribute at all?', 'payload' => '" x="y',
             'learn' => 'If the rendered input element gains an attribute called <code>x</code>, the quote broke out. Inspect the live output element to check.'],
            ['q' => 'Are angle brackets really closed off?', 'payload' => '<b>test',
             'learn' => 'Expect this to be encoded. Confirming what is <em>not</em> available is how you avoid wasting attempts on it.'],
        ],
    ];

    $c[3] = [
        'model_title' => 'Stored: the sink runs for someone else',
        'model' => '<p>The difference from reflected XSS is not the payload, it is the delivery. Your comment is
            written to <code>stored_comments.json</code> and re-rendered for <em>every</em> visitor, with no
            encoding at output time. You do not need to persuade a victim to click a crafted URL.</p>
            <p>Two encoding decisions exist and only one of them matters. Encoding on input is fragile: the same
            stored value may later be written into HTML, into a JSON API, into a CSV export and into an email, and
            each of those needs a different encoding. Encoding at output, in the template, is correct because it is
            the only place that knows the destination context.</p>
            <p>The code here does neither. <code>$c[\'text\']</code> is concatenated straight into a
            <code>&lt;div&gt;</code>, so the stored bytes are parsed as markup.</p>',
        'why' => '<p>The comment was stored verbatim and echoed verbatim. Because the output context is element
            text, your <code>&lt;</code> opened a tag exactly as in level 1 - the only change is that the payload now
            lives on the server and fires for every visitor to this page.</p>
            <p>That change is what moves the severity. A reflected payload needs a delivery mechanism; a stored one
            already has the application as its delivery mechanism.</p>',
        'fix_bad' => 'foreach ($comments as $c) {
    echo "<div class=\'comment\'>"
       . "<strong>" . $c[\'author\'] . "</strong>"
       . "<p>" . $c[\'text\'] . "</p>"
       . "</div>";
}',
        'fix_good' => '// Store raw, encode at output, where the context is known.
foreach ($comments as $c) {
    $author = htmlspecialchars($c[\'author\'], ENT_QUOTES | ENT_SUBSTITUTE, \'UTF-8\');
    $text   = htmlspecialchars($c[\'text\'],   ENT_QUOTES | ENT_SUBSTITUTE, \'UTF-8\');
    echo "<div class=\'comment\'><strong>{$author}</strong><p>{$text}</p></div>";
}

// If the comment must support formatting, do not write your own
// sanitiser. Parse to a known-good subset with a real library
// (HTML Purifier, DOMPurify) and render the parse result, never
// the original string.',
        'fix_note' => 'A stored payload also reaches contexts you did not think about: an admin moderation panel, a
            search-results page, a notification email. Encoding at each output point is what makes those safe too.',
        'param' => 'comment',
        'probes' => [
            ['q' => 'Is the author field encoded when the comment field is not?', 'payload' => '<i>italic</i>',
             'learn' => 'Post this once as the author and once as the comment. Different behaviour between two fields on the same page is common, and it tells you which template line is missing its call.'],
            ['q' => 'Does the stored value survive a round trip through JSON?', 'payload' => 'quote:" slash:\\ tag:<i>',
             'learn' => 'JSON escaping happens at storage time and is undone at read time, so it protects nothing at output. The trace shows the value before and after that round trip.'],
            ['q' => 'Does the payload fire for a fresh visitor, not just for me?', 'payload' => '<b>persisted</b>',
             'learn' => 'Reload the page in a private window. That is the difference between reflected and stored, stated as an experiment.'],
        ],
    ];

    $c[4] = [
        'model_title' => 'DOM XSS: the server never sees the payload',
        'model' => '<p>The value flows from <code>location.search</code> to <code>element.innerHTML</code> without
            ever leaving the browser. Server-side encoding cannot help, because the server is not in the path - in a
            real target the payload can even sit in the fragment (<code>#</code>), which is never transmitted.</p>
            <p><code>innerHTML</code> invokes the HTML parser on the string you assign. That parser builds real
            elements and, crucially, <strong>runs event handlers</strong>. What it does <em>not</em> do is execute
            <code>&lt;script&gt;</code> elements inserted this way - the HTML specification marks them
            "already started" so they are parsed and then ignored.</p>
            <p>Hence the standard vectors here are event-handler based:
            <code>&lt;img src=x onerror=&hellip;&gt;</code>, <code>&lt;svg onload=&hellip;&gt;</code>,
            <code>&lt;details open ontoggle=&hellip;&gt;</code>. If a <code>&lt;script&gt;</code> payload "does
            nothing", that is the reason, and it is a property of the sink rather than of a filter.</p>',
        'why' => '<p>Your string was handed to <code>innerHTML</code>, which parsed it as HTML and attached the
            event handler you supplied to a real element. The handler then fired on its own trigger - an image that
            fails to load, an SVG that finishes loading, a <code>&lt;details&gt;</code> that opens.</p>
            <p>The server-side verifier on this page only awards the flag; it plays no part in the vulnerability.
            The whole bug lives in one JavaScript assignment.</p>',
        'fix_bad' => 'const msg = new URLSearchParams(location.search).get("msg");
document.getElementById("out").innerHTML = "Message: " + msg;',
        'fix_good' => '// textContent assigns a text node. There is no parser involved,
// so there is nothing to inject into.
const msg = new URLSearchParams(location.search).get("msg");
document.getElementById("out").textContent = "Message: " + msg;

// If markup genuinely has to be rendered, sanitise with a parser
// that produces a DOM you control:
//   el.innerHTML = DOMPurify.sanitize(msg);
//
// The other sinks in this family, all of which parse or execute:
//   outerHTML, insertAdjacentHTML, document.write,
//   eval, Function, setTimeout("string"), location = "javascript:"',
        'fix_note' => 'Trusted Types (<code>require-trusted-types-for \'script\'</code>) turns every one of those
            sinks into a runtime error unless the value passed a named policy, which converts this class of bug from
            "audit every assignment" into "audit the policies".',
        'param' => 'msg',
        'probes' => [
            ['q' => 'Does a script tag inserted through innerHTML run?', 'payload' => '<script>window.__x=1</script>',
             'learn' => 'It will not. Confirming this once saves you from concluding the sink is filtered when it is behaving exactly as specified.'],
            ['q' => 'Does innerHTML build real elements?', 'payload' => '<b>bold</b>',
             'learn' => 'Bold text means the parser ran and produced a DOM node. From there, event handlers are the vector.'],
            ['q' => 'Which event handlers fire without user interaction?', 'payload' => '<img src=x onerror=window.__p=1>',
             'learn' => 'A broken image fires <code>onerror</code> immediately. Check <code>window.__p</code> in the console - a probe you can verify without an alert box.'],
        ],
    ];

    $c[5] = [
        'model_title' => 'Context: single-quoted attribute value',
        'model' => '<p>Same shape as level 2, one character different. The attribute is delimited with
            <code>\'</code>, and <code>htmlspecialchars()</code> called with no second argument uses
            <code>ENT_COMPAT</code>, which encodes the double quote and leaves the single quote alone.</p>
            <p>The lesson is that the correctness of an escaping call depends on a match between two things a long
            way apart in the file: the flags passed to the encoder, and the quote character chosen in the template.
            Change either one and the other becomes wrong.</p>
            <p>Since PHP 8.1 the default is <code>ENT_QUOTES | ENT_SUBSTITUTE</code>, which closes this by default -
            but only for code that omits the argument entirely. Code that passes <code>ENT_COMPAT</code> explicitly,
            or runs on an older version, still has this bug.</p>',
        'why' => '<p><code>ENT_COMPAT</code> does not encode <code>\'</code>, and the template chose single quotes
            for the delimiter. Your quote therefore closed <code>value=\'</code>, put the parser back into the tag,
            and the attribute you appended after it was accepted as part of the element.</p>
            <p>Adding <code>autofocus</code> is what makes it fire without interaction: the element takes focus on
            load, which triggers <code>onfocus</code>.</p>',
        'fix_bad' => '$safe = htmlspecialchars($bio);            // ENT_COMPAT on PHP < 8.1
echo "<input type=\'text\' value=\'{$safe}\' />";',
        'fix_good' => '// Be explicit. Never rely on the default matching the quote
// character someone else picked in the template.
$safe = htmlspecialchars($bio, ENT_QUOTES | ENT_SUBSTITUTE, \'UTF-8\');
echo \'<input type="text" value="\' . $safe . \'">\';

// PHP 8.1 changed the default to ENT_QUOTES|ENT_SUBSTITUTE, so new
// code that omits the argument is safe - but an explicit
// ENT_COMPAT, or an older runtime, still leaves the single quote.',
        'fix_note' => 'When reviewing, grep for <code>htmlspecialchars(</code> with exactly one argument and for
            <code>ENT_COMPAT</code>, then check the quote character used at each call site.',
        'param' => 'bio',
        'probes' => [
            ['q' => 'Is the single quote encoded?', 'payload' => 'it\'s',
             'learn' => 'Read the filter stage in the trace. A surviving <code>\'</code> is the entire finding for this level.'],
            ['q' => 'Is the double quote encoded?', 'payload' => 'say "hi"',
             'learn' => 'Expect <code>&amp;quot;</code>. Knowing which of the two survives tells you which delimiter you can break, before you write a payload.'],
            ['q' => 'Can I add an attribute after breaking out?', 'payload' => '\' data-x=\'1',
             'learn' => 'Inspect the rendered element. A <code>data-x</code> attribute proves the parser accepted new attributes - the step before adding a handler.'],
        ],
    ];

    $c[6] = [
        'model_title' => 'A filter that removes rather than encodes',
        'model' => '<p>The filter is two <code>str_replace()</code> calls, and both properties of that function
            matter here:</p>
            <ul>
                <li>It is <strong>case-sensitive</strong>. <code>&lt;SCRIPT&gt;</code> and <code>&lt;ScRiPt&gt;</code>
                    are different strings and are not touched.</li>
                <li>It <strong>removes</strong> rather than encodes, and it makes a single pass. Removing a substring
                    can create a new one out of what remains:
                    <code>&lt;scr&lt;script&gt;ipt&gt;</code> becomes <code>&lt;script&gt;</code> after the deletion.</li>
            </ul>
            <p>Beyond both of those, the filter names one tag out of the hundred-odd that can execute code. It says
            nothing about <code>&lt;img&gt;</code>, <code>&lt;svg&gt;</code>, <code>&lt;details&gt;</code>, or about
            any event handler attribute.</p>
            <p>The general principle: a blacklist has to enumerate every dangerous input, and the enumeration is
            never complete. An encoder has to handle five characters, and the list does not grow.</p>',
        'why' => '<p>Your payload survived the two replacements. The trace shows what the filter actually did to
            your bytes - either it matched nothing at all, or the deletion left behind a string that the parser
            still reads as a tag.</p>
            <p>Note that no exotic knowledge was required. Changing the case, or picking a different element, is
            enough, because the filter never described the dangerous thing - it described one spelling of one
            example of it.</p>',
        'fix_bad' => '$filtered = str_replace(\'<script>\',  \'\', $input);
$filtered = str_replace(\'</script>\', \'\', $filtered);
echo $filtered;',
        'fix_good' => '// Do not remove markup. Encode it, so it is displayed rather
// than parsed, and the question of "which tags are dangerous"
// never has to be answered.
echo htmlspecialchars($input, ENT_QUOTES | ENT_SUBSTITUTE, \'UTF-8\');

// If the feature genuinely requires user-supplied HTML, parse it
// into a DOM and rebuild it from an allowlist of elements and
// attributes (HTML Purifier server-side, DOMPurify in the browser).
// An allowlist over a parse tree is sound; a blacklist over a
// string is not.',
        'fix_note' => 'Any single-pass removal filter can be defeated by nesting the removed token inside itself.
            If a filter must delete, it has to loop until the string stops changing - and that is still a blacklist.',
        'param' => 'input',
        'probes' => [
            ['q' => 'Is the filter case-sensitive?', 'payload' => '<SCRIPT>x</SCRIPT>',
             'learn' => 'Compare the raw and filtered values in the trace. If they are identical, <code>str_replace</code> matched nothing, and case is the whole bypass.'],
            ['q' => 'What exactly does the filter delete?', 'payload' => '<script>keep</script>',
             'learn' => 'Lowercase and exact. The trace shows only the tags removed and the content left behind, which tells you the match is on the literal tag text.'],
            ['q' => 'Does the filter touch anything other than script tags?', 'payload' => '<b onmouseover=1>x</b>',
             'learn' => 'It does not. Confirming that an entire category is unhandled is worth one request.'],
        ],
    ];

    $c[7] = [
        'model_title' => 'Context: URL, not text',
        'model' => '<p>Your value becomes the <code>href</code> of a link. HTML-encoding it would not help, because
            the danger is not in the markup - it is in the <em>scheme</em>. A URL beginning
            <code>javascript:</code> executes its body in the page origin when the link is followed.</p>
            <p>So the check that matters here is a scheme allowlist, and it has to be done after normalisation.
            Browsers strip leading whitespace and control characters and treat the scheme case-insensitively, so all
            of <code>javascript:</code>, <code>JaVaScRiPt:</code>, <code>&nbsp;javascript:</code> and
            <code>java&#0;script:</code> reach the same handler.</p>
            <p>Related sinks with the same property: <code>src</code>, <code>action</code>, <code>formaction</code>,
            <code>xlink:href</code>, <code>window.location</code>, and <code>data:text/html</code> URLs, which
            execute in their own origin and are therefore useful for a different set of attacks.</p>',
        'why' => '<p>No scheme validation ran, so <code>javascript:</code> stayed in the <code>href</code>. The
            browser treats that scheme as executable, and following the link ran your code in this origin, with
            access to this page\'s DOM and cookies.</p>
            <p>Encoding would not have changed anything: every character in <code>javascript:alert(1)</code> is
            already an ordinary character. This is a validation problem rather than an escaping one, which is why
            "we escape all output" does not cover it.</p>',
        'fix_bad' => 'echo \'<a href="\' . $url . \'">Visit Profile</a>\';',
        'fix_good' => '// Allowlist the scheme, then encode for the attribute.
$parts  = parse_url($url);
$scheme = strtolower($parts[\'scheme\'] ?? \'\');

if (!in_array($scheme, [\'http\', \'https\', \'mailto\'], true)) {
    $url = \'#\';                       // reject, do not try to clean
}
echo \'<a href="\' . htmlspecialchars($url, ENT_QUOTES, \'UTF-8\') . \'">Visit</a>\';

// Two further notes:
//   - a relative URL has no scheme; decide deliberately whether
//     you accept one, and reject "//evil.example" if you do
//   - add rel="noopener noreferrer" to any target="_blank" link',
        'fix_note' => 'Do not attempt to strip <code>javascript:</code> from the string. Between whitespace, control
            characters, HTML entities and case, there are too many spellings. Parse the URL and compare the scheme.',
        'param' => 'url',
        'probes' => [
            ['q' => 'Is any scheme validation happening?', 'payload' => 'ftp://example.test/file',
             'learn' => 'An unusual but harmless scheme. If it appears unchanged in the rendered href, there is no allowlist and the level is open.'],
            ['q' => 'Is the value HTML-encoded inside the attribute?', 'payload' => 'https://a.test/?x="y',
             'learn' => 'Two different defences can apply to an href. This separates "the attribute is escaped" from "the scheme is checked" - they fail independently.'],
            ['q' => 'Does a relative URL survive?', 'payload' => '/index.php',
             'learn' => 'Establishes the baseline behaviour, so you can tell a rejected payload from an unchanged one.'],
        ],
    ];

    $c[8] = [
        'model_title' => 'JSON is not an HTML encoder',
        'model' => '<p>The endpoint returns your value inside a JSON document, and the page then does
            <code>el.innerHTML = data.message</code>. Two encodings are in play and only one of them is applied.</p>
            <p><code>json_encode()</code> escapes what would break <em>JSON</em>: quotes, backslashes, control
            characters. HTML metacharacters are not JSON metacharacters, so <code>&lt;img onerror=&hellip;&gt;</code>
            travels through the JSON layer untouched, and <code>JSON.parse</code> hands the browser exactly the
            string you sent.</p>
            <p>The bug is at the point of use, not in the transport. An API that returns raw data is behaving
            correctly; the client that assigns that data to <code>innerHTML</code> is not.</p>
            <p>Separately, when JSON is embedded directly into a <code>&lt;script&gt;</code> block, the sequence
            <code>&lt;/script&gt;</code> inside a string ends the block early - which is what the
            <code>JSON_HEX_TAG</code> family of flags exists to prevent.</p>',
        'why' => '<p>Your markup passed through <code>json_encode</code> unchanged, because none of its characters
            are special to JSON. The client parsed the response and assigned the string to <code>innerHTML</code>,
            at which point the HTML parser ran and built your element.</p>
            <p>Worth carrying forward: data that has crossed an encoding boundary is not thereby sanitised. Each
            boundary needs the encoding for the context on its far side.</p>',
        'fix_bad' => '// server
echo json_encode([\'message\' => $msg]);
// client
el.innerHTML = data.message;',
        'fix_good' => '// client - the fix belongs here, at the sink
el.textContent = data.message;

// If the API response is embedded into a script block rather than
// fetched, encode for that context too:
echo \'<script>const data = \'
   . json_encode($payload, JSON_HEX_TAG | JSON_HEX_AMP
                         | JSON_HEX_APOS | JSON_HEX_QUOT)
   . \';</script>\';
// Without JSON_HEX_TAG, a "</script>" inside any string value
// closes the block early and everything after it is markup.',
        'fix_note' => 'A useful review question for any API: what does the client do with each field? A field that is
            only ever displayed as text is safe; the same field assigned to <code>innerHTML</code> anywhere in the
            codebase is not.',
        'param' => 'message',
        'probes' => [
            ['q' => 'Does JSON encoding touch HTML metacharacters?', 'payload' => '<b>x</b> & "y"',
             'learn' => 'Open <code>?_api=1&amp;message=&lt;b&gt;x&lt;/b&gt;</code> directly and read the raw JSON. Only the quote is escaped, and only because it is a JSON metacharacter.'],
            ['q' => 'Does the client use innerHTML or textContent?', 'payload' => '<b>bold</b>',
             'learn' => 'Bold rendering means <code>innerHTML</code>. This one observation decides whether the level is exploitable at all.'],
            ['q' => 'Do the JSON escapes survive parsing?', 'payload' => 'quote:" backslash:\\',
             'learn' => 'They do not - <code>JSON.parse</code> undoes them, so the client receives your original bytes. Escaping that is undone before the sink protects nothing.'],
        ],
    ];

    $c[9] = [
        'model_title' => 'Blacklist: four strings, unbounded input space',
        'model' => '<p>The filter rejects an input containing any of four substrings, case-insensitively:
            <code>&lt;script</code>, <code>javascript:</code>, <code>onload=</code>, <code>onclick=</code>.</p>
            <p>Two of those four are event handlers. HTML defines well over a hundred, and browsers add more with
            each new API - <code>onerror</code>, <code>onmouseover</code>, <code>onfocus</code>,
            <code>ontoggle</code>, <code>onpointerenter</code>, <code>onanimationstart</code>,
            <code>onwheel</code>, <code>oncontextmenu</code>. Enumerating them is a losing position by
            construction, because the list is defined by someone else and grows without your involvement.</p>
            <p>The blacklist is also written against one spelling. HTML permits whitespace and a newline between an
            attribute name and its <code>=</code>, so <code>onload =</code> and <code>onload\\n=</code> are the same
            attribute to the parser and different strings to <code>stripos</code>.</p>',
        'why' => '<p>Your payload contained none of the four blacklisted strings and still produced a working
            vector. The check was accurate about what it checked - it simply described a tiny part of the space of
            executable HTML.</p>
            <p>This is the argument for encoding over filtering, stated as an experiment: an encoder handles five
            characters and is complete; this blacklist handles four strings and is not.</p>',
        'fix_bad' => 'foreach ([\'<script\', \'javascript:\', \'onload=\', \'onclick=\'] as $bad) {
    if (stripos($input, $bad) !== false) {
        die(\'XSS detected\');
    }
}
echo $input;',
        'fix_good' => '// Encode. The set of characters that are structural in HTML is
// fixed and small; the set of dangerous inputs is neither.
echo htmlspecialchars($input, ENT_QUOTES | ENT_SUBSTITUTE, \'UTF-8\');

// If a WAF-style filter is required in addition, treat it as
// defence in depth and monitoring - never as the control that
// makes the output safe.',
        'fix_note' => 'A blacklist tells an attacker what the developer thought of. The absences are the map: four
            entries covering two handlers means every other handler is untested.',
        'param' => 'xss',
        'probes' => [
            ['q' => 'Is the check case-insensitive?', 'payload' => '<ScRiPt',
             'learn' => 'It uses <code>stripos</code>, so expect a block. Confirming this rules out the level-6 bypass and saves you repeating it.'],
            ['q' => 'Which handler names are actually listed?', 'payload' => '<b onmouseover=1>x</b>',
             'learn' => 'Not blocked. Each probe that passes marks one more region of the input space the filter never described.'],
            ['q' => 'Does whitespace before the equals sign defeat the match?', 'payload' => '<b onload =1>x</b>',
             'learn' => 'The blacklist matches <code>onload=</code> exactly. HTML allows the space; <code>stripos</code> does not know that.'],
        ],
    ];

    $c[10] = [
        'model_title' => 'Three layers, each precise, none complete',
        'model' => '<p>Read the layers as a set of claims about the input, and then ask what each one leaves
            uncovered:</p>
            <table class="lk-kv">
                <tr><td>Layer 1</td><td><code>preg_replace(\'/&lt;script[\\s\\S]*?&lt;\\/script&gt;/i\')</code> - removes complete script <em>blocks</em>. An unpaired opening tag does not match, and no other element is considered.</td></tr>
                <tr><td>Layer 2</td><td><code>str_ireplace</code> over six handler names. Every other handler passes, and so does any spelling with whitespace before the <code>=</code>.</td></tr>
                <tr><td>Layer 3</td><td>Removes HTML comments. This affects an old comment-splitting trick and nothing else.</td></tr>
            </table>
            <p>Stacking filters multiplies the effort of writing them and does not close the gap, because each one
            is still a blacklist. Worse, deletion filters interact: a string removed by layer 2 can join the two
            halves either side of it into something layer 1 already finished inspecting.</p>
            <p>Order matters and is worth tracing. Layers run once, in sequence, and none of them re-runs after a
            later layer has modified the string.</p>',
        'why' => '<p>The trace shows your input at each of the three layers. Whatever survived to the end was
            something none of the three described - most likely a handler outside the six-name list, on an element
            that is not <code>&lt;script&gt;</code>.</p>
            <p>The instructive part is that every layer did exactly what it was written to do. The defence failed
            not through a coding mistake but through its choice of strategy: enumerating bad inputs, in a language
            whose set of bad inputs is defined elsewhere and keeps growing.</p>',
        'fix_bad' => '$x = preg_replace(\'/<script[\\s\\S]*?<\\/script>/i\', \'\', $input);
foreach ([\'onerror=\', \'onload=\', \'onclick=\',
          \'onfocus=\', \'onmouseover=\', \'javascript:\'] as $b) {
    $x = str_ireplace($b, \'\', $x);
}
$x = preg_replace(\'/<!--[\\s\\S]*?-->/\', \'\', $x);
echo $x;',
        'fix_good' => '// One line replaces all three layers and is complete.
echo htmlspecialchars($input, ENT_QUOTES | ENT_SUBSTITUTE, \'UTF-8\');

// Where user HTML is a product requirement, sanitise over a parse
// tree with an allowlist, and add a Content-Security-Policy so a
// missed sink is not immediately an executed script:
//
//   Content-Security-Policy:
//     default-src \'self\';
//     script-src \'nonce-<random>\' \'strict-dynamic\';
//     object-src \'none\'; base-uri \'none\';
//
// CSP is a second line of defence, not a substitute for encoding.',
        'fix_note' => 'When you meet a stack of filters in a real codebase, trace one input through all of them in
            order and write down what each one changed. The gaps are usually visible after a single pass, and they
            are more informative than any payload list.',
        'param' => 'payload',
        'probes' => [
            ['q' => 'Does layer 1 need a closing tag to match?', 'payload' => '<script>x',
             'learn' => 'The pattern requires <code>&lt;/script&gt;</code>. An unpaired opening tag survives layer 1 - which is a fact about the regex, not about the browser.'],
            ['q' => 'Which six handlers does layer 2 name?', 'payload' => '<b onerror= onpointerenter=>x</b>',
             'learn' => 'Compare the value before and after layer 2 in the trace. One of these is deleted and one is not, in a single request.'],
            ['q' => 'Does deletion in layer 2 join what is left?', 'payload' => 'onerroronerror=r=x',
             'learn' => 'Removing the inner match can leave a new one behind. Watch the layer-2 stage to see what the single pass produced.'],
        ],
    ];

    return $c[$level] ?? [];
}

/* =========================================================================
 * Per-level pipeline + sink, computed from the learner's real input
 * ===================================================================== */

function xss_teach_pipeline(int $level, array $ctx): array
{
    $in = (string)($ctx['input'] ?? '');
    if ($in === '') {
        return [];
    }

    switch ($level) {
        case 1:
            return [
                ['label' => '$_GET[\'name\']', 'value' => $in],
                ['label' => 'no filter of any kind is applied', 'value' => $in,
                 'note'  => 'The value reaches the HTML string exactly as received.', 'verdict' => 'pass'],
            ];

        case 2:
            $safe = htmlspecialchars($in, ENT_NOQUOTES);
            return [
                ['label' => '$_GET[\'q\']', 'value' => $in],
                ['label' => 'htmlspecialchars($search, ENT_NOQUOTES)', 'value' => $safe,
                 'note'  => 'Double quotes present after the filter: <strong>' . substr_count($safe, '"') . '</strong>. '
                          . 'ENT_NOQUOTES encodes only <code>&amp; &lt; &gt;</code>.',
                 'verdict' => strpos($safe, '"') !== false ? 'pass' : 'block'],
            ];

        case 3:
            return [
                ['label' => '$_POST[\'comment\']', 'value' => $in],
                ['label' => 'json_encode(...) -> stored_comments.json', 'value' => json_encode($in),
                 'note'  => 'JSON escaping is a transport concern. It is undone by json_decode on the way out.'],
                ['label' => 'json_decode(...) at render time', 'value' => $in,
                 'note'  => 'Back to the original bytes, with no HTML encoding anywhere in the path.',
                 'verdict' => 'pass'],
            ];

        case 4:
            return [
                ['label' => '$_GET[\'msg\'] (server side, verification only)', 'value' => $in],
                ['label' => 'new URLSearchParams(location.search).get("msg")', 'value' => $in,
                 'note'  => 'Read in the browser. The server is not in this path at all.'],
                ['label' => 'element.innerHTML = "Message: " + msg', 'value' => 'Message: ' . $in,
                 'note'  => 'innerHTML invokes the HTML parser. Event handlers run; a &lt;script&gt; element inserted this way does not.',
                 'verdict' => 'pass'],
            ];

        case 5:
            $safe = htmlspecialchars($in, ENT_COMPAT);
            return [
                ['label' => '$_GET[\'bio\']', 'value' => $in],
                ['label' => 'htmlspecialchars($bio)  // ENT_COMPAT', 'value' => $safe,
                 'note'  => 'Single quotes present after the filter: <strong>' . substr_count($safe, "'") . '</strong>, '
                          . 'double quotes: <strong>' . substr_count($safe, '"') . '</strong>.',
                 'verdict' => strpos($safe, "'") !== false ? 'pass' : 'block'],
            ];

        case 6:
            $s1 = str_replace('<script>', '', $in);
            $s2 = str_replace('</script>', '', $s1);
            return [
                ['label' => '$_GET[\'input\']', 'value' => $in],
                ['label' => "str_replace('<script>', '', \$input)", 'value' => $s1,
                 'note'  => $s1 === $in
                    ? 'Nothing matched. <code>str_replace</code> is case-sensitive and matches the literal lowercase tag only.'
                    : 'Removed ' . (substr_count($in, '<script>')) . ' occurrence(s). Deletion can leave a new token behind.'],
                ['label' => "str_replace('</script>', '', \$filtered)", 'value' => $s2,
                 'note'  => 'One pass, in this order. Neither call runs again after the other has modified the string.',
                 'verdict' => 'pass'],
            ];

        case 7:
            $scheme = strtolower((string)parse_url($in, PHP_URL_SCHEME));
            return [
                ['label' => '$_GET[\'url\']', 'value' => $in],
                ['label' => 'scheme, as the browser will read it',
                 'value' => $scheme !== '' ? $scheme : '(none - relative URL)',
                 'note'  => 'No allowlist is applied. Whatever scheme is here is the scheme the browser honours.',
                 'verdict' => $scheme === 'javascript' ? 'pass' : null],
                ['label' => 'written into href="..."', 'value' => $in,
                 'note'  => 'HTML encoding would not change the scheme, so it would not help here.'],
            ];

        case 8:
            $json = json_encode(['status' => 'ok', 'message' => $in]);
            return [
                ['label' => '$_GET[\'message\']', 'value' => $in],
                ['label' => 'json_encode([...])', 'value' => (string)$json,
                 'note'  => 'HTML metacharacters are not JSON metacharacters, so they pass through unchanged.'],
                ['label' => 'client: JSON.parse(...).message', 'value' => $in,
                 'note'  => 'The JSON escaping is undone here, before the value reaches the sink.'],
                ['label' => 'client: element.innerHTML = data.message', 'value' => $in,
                 'note'  => 'The HTML parser runs on this string.', 'verdict' => 'pass'],
            ];

        case 9:
            $blacklist = ['<script', 'javascript:', 'onload=', 'onclick='];
            $stages = [['label' => '$_GET[\'xss\']', 'value' => $in]];
            $hit = null;
            foreach ($blacklist as $bad) {
                if (stripos($in, $bad) !== false) {
                    $hit = $bad;
                    break;
                }
            }
            $stages[] = [
                'label'   => "foreach (['<script','javascript:','onload=','onclick='] as \$bad) stripos(...)",
                'value'   => $hit === null ? 'no entry matched' : 'matched: ' . $hit,
                'note'    => $hit === null
                    ? 'Four strings checked, case-insensitively. Everything else in the input space is unexamined.'
                    : 'The request is terminated here. Note which entry matched - the other three are still untested.',
                'verdict' => $hit === null ? 'pass' : 'block',
            ];
            if ($hit === null) {
                $stages[] = ['label' => 'echo $xss_input;', 'value' => $in,
                             'note' => 'No encoding is applied on the way out.'];
            }
            return $stages;

        case 10:
            $l1 = preg_replace('/<script[\s\S]*?<\/script>/i', '', $in);
            $l2 = $l1;
            $removed = [];
            foreach (['onerror=', 'onload=', 'onclick=', 'onfocus=', 'onmouseover=', 'javascript:'] as $b) {
                $before = $l2;
                $l2 = str_ireplace($b, '', $l2);
                if ($l2 !== $before) {
                    $removed[] = $b;
                }
            }
            $l3 = preg_replace('/<!--[\s\S]*?-->/', '', $l2);
            return [
                ['label' => '$_GET[\'payload\']', 'value' => $in],
                ['label' => "Layer 1: preg_replace('/<script[\\s\\S]*?<\\/script>/i', '')", 'value' => (string)$l1,
                 'note'  => $l1 === $in
                    ? 'No complete script block matched. The pattern needs both tags.'
                    : 'A complete script block was removed.'],
                ['label' => 'Layer 2: str_ireplace over six handler names', 'value' => $l2,
                 'note'  => $removed
                    ? 'Removed: <code>' . implode('</code>, <code>', $removed) . '</code>. The other names in HTML are untouched.'
                    : 'None of the six names appeared. There are well over a hundred more.'],
                ['label' => "Layer 3: preg_replace('/<!--[\\s\\S]*?-->/', '')", 'value' => (string)$l3,
                 'note'  => 'Whatever is shown here is what the browser parses.',
                 'verdict' => 'pass'],
            ];
    }
    return [];
}

/** The exact string the browser receives, injection highlighted. */
function xss_teach_sink(int $level, array $ctx): string
{
    $in = (string)($ctx['input'] ?? '');
    if ($in === '') {
        return '';
    }

    switch ($level) {
        case 1:
            return lk_sink('HTML written to the page', '<div class="xss-output-box">Hello, ', $in, '</div>');
        case 2:
            return lk_sink('HTML written to the page', '<input type="text" name="q" value="',
                htmlspecialchars($in, ENT_NOQUOTES), '">');
        case 3:
            return lk_sink('HTML written for every visitor', '<div class="comment"><p>', $in, '</p></div>');
        case 4:
            return lk_sink('JavaScript executed in the browser', 'document.getElementById("out").innerHTML = "Message: ',
                $in, '";');
        case 5:
            return lk_sink('HTML written to the page', "<input type='text' name='bio' value='",
                htmlspecialchars($in, ENT_COMPAT), "'>");
        case 6:
            $f = str_replace('</script>', '', str_replace('<script>', '', $in));
            return lk_sink('HTML written to the page', '<div class="xss-output-box">', $f, '</div>');
        case 7:
            return lk_sink('HTML written to the page', '<a class="user-link" href="', $in, '">Visit Profile</a>');
        case 8:
            return lk_sink('JavaScript executed in the browser', 'out.innerHTML = data.message;   // data.message = ',
                $in, '');
        case 9:
            return lk_sink('HTML written to the page', '<div class="xss-output-box">', $in, '</div>');
        case 10:
            $x = preg_replace('/<script[\s\S]*?<\/script>/i', '', $in);
            foreach (['onerror=', 'onload=', 'onclick=', 'onfocus=', 'onmouseover=', 'javascript:'] as $b) {
                $x = str_ireplace($b, '', $x);
            }
            $x = preg_replace('/<!--[\s\S]*?-->/', '', $x);
            return lk_sink('HTML written to the page', '<div class="xss-output-box">', (string)$x, '</div>');
    }
    return '';
}

/* =========================================================================
 * Assembly
 * ===================================================================== */

/**
 * @param array $ctx {input: string, solved: bool}
 */
function xss_teach(int $level, array $ctx): string
{
    $c = xss_teach_content($level);
    if (!$c) {
        return '';
    }
    $in     = (string)($ctx['input'] ?? '');
    $solved = !empty($ctx['solved']);

    $out  = '<div class="xss-teach">';
    $out .= lk_model($c['model_title'], $c['model']);

    $pipeline = xss_teach_pipeline($level, $ctx);
    if ($pipeline) {
        $out .= lk_pipeline($pipeline);
        $out .= xss_teach_sink($level, $ctx);
    } else {
        $out .= '<div class="lk-box lk-pipeline"><h4><span class="lk-tag">TRACE</span>What the server did to your '
              . 'input</h4><div class="lk-body"><p class="text-muted">Send something and this will show your value at '
              . 'every stage of the filter, plus the exact string the browser receives. A rejected payload is worth '
              . 'as much as an accepted one, as long as you read what happened to it.</p></div></div>';
    }

    if ($solved) {
        $out .= lk_why($c['why']);
    }

    $method = $level === 3 ? 'POST' : 'GET';
    $out .= lk_probes($c['probes'], $c['param'], $method, 'level' . $level . '.php');
    $out .= lk_fix($c['fix_bad'], $c['fix_good'], $c['fix_note']);

    return $out . '</div>';
}
