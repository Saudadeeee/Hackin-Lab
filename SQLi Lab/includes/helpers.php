<?php
declare(strict_types=1);

/**
 * Return the canonical flag string for a given level.
 */
function get_flag_for_level(int $levelId): string
{
    static $flags = [
        1 => 'FLAG{error_based}',
        2 => 'FLAG{union_based}',
        3 => 'FLAG{stacked_queries}',
        4 => 'FLAG{waf_bypass}',
        5 => 'FLAG{boolean_blind}',
        6 => 'FLAG{time_based}',
        7 => 'FLAG{oob_file_write}',
        8 => 'FLAG{second_order}',
        9 => 'FLAG{xpath_injection}',
        10 => 'FLAG{insert_injection}',
        11 => 'FLAG{update_injection}',
        12 => 'FLAG{json_injection}',
        13 => 'FLAG{comment_bypass}',
        14 => 'FLAG{encoding_bypass}',
        15 => 'FLAG{space_bypass}',
        16 => 'FLAG{advanced_waf_bypass}',
    ];

    return $flags[$levelId] ?? 'FLAG{unknown_level}';
}

/**
 * Return the progressive hints for a given level.
 *
 * @return array<int, string>
 */
function get_level_hints(int $levelId): array
{
    static $hints = [
        1 => [
            '<strong>Start simple:</strong> try a payload such as <code>\' OR \'1\'=\'1</code> to force a true condition.',
            '<strong>Read the errors:</strong> database error messages reveal the structure of the query.',
            '<strong>Trim the password check:</strong> append <code>-- </code> or <code>#</code> to comment out trailing SQL.',
            '<strong>Target the admin user:</strong> payloads like <code>admin\'--</code> ensure you retrieve the admin row.',
        ],
        2 => [
            '<strong>Integer injection:</strong> the user ID is concatenated without quotes.',
            '<strong>Count the columns:</strong> use <code>ORDER BY</code> or <code>UNION SELECT NULL,...</code> to find the correct layout.',
            '<strong>Inject your own row:</strong> supply values for id, username, and role to fabricate an admin record.',
            '<strong>Shortcut:</strong> <code>999 UNION SELECT 1,\'admin\',\'admin\'</code> bypasses the role check once the columns align.',
        ],
        3 => [
            '<strong>Stacked queries:</strong> end the original statement with <code>;</code> and supply your own SQL after it.',
            '<strong>Promote a user:</strong> <code>test\'; UPDATE users SET role=\'admin\' WHERE username=\'test\';--</code> escalates privileges.',
            '<strong>Reset credentials:</strong> overwrite a known password before signing in.',
            '<strong>Create a backdoor:</strong> insert a fresh admin account in the same payload so you always have access.',
        ],
        4 => [
            '<strong>Case variation:</strong> mix uppercase and lowercase letters to dodge naive keyword filters.',
            '<strong>Encode critical words:</strong> hex strings like <code>0x61646d696e</code> can stand in for <code>admin</code>.',
            '<strong>Break the pattern:</strong> split blocked keywords with comments such as <code>/**/</code>.',
            '<strong>Swap operators and spaces:</strong> use <code>||</code>/<code>&&</code> and encodings like <code>%20</code> when literals are blocked.',
        ],
        5 => [
            '<strong>Measure time:</strong> wrap conditions in <code>SLEEP()</code> to gather boolean answers from delays.',
            '<strong>Check existence:</strong> <code>AND IF((SELECT COUNT(*) FROM users WHERE username=\'admin\')>0,SLEEP(3),0)</code> validates targets.',
            '<strong>Find the length:</strong> use <code>LENGTH()</code> tests to determine password size.',
            '<strong>Extract characters:</strong> binary search with <code>SUBSTR()</code> and <code>ASCII()</code> to recover each byte.',
        ],
        6 => [
            '<strong>Into outfile:</strong> use <code>UNION SELECT ... INTO OUTFILE</code> to dump query results to disk.',
            '<strong>Check paths:</strong> writable locations such as <code>/tmp</code> or <code>/var/lib/mysql-files</code> are common.',
            '<strong>Concatenate data:</strong> combine username and password columns to log credentials per line.',
            '<strong>Look for errors:</strong> permission denials still prove your syntax works - adjust the target path accordingly.',
        ],
        7 => [
            '<strong>Second-order setup:</strong> store the payload in step one, then trigger it later.',
            '<strong>Meta storage:</strong> registration saves input that is reused in the vulnerable query.',
            '<strong>Reference by key:</strong> choose a key you can retrieve later (for example <code>flag7</code>).',
            '<strong>Final trigger:</strong> load the page that consumes the stored value so it executes inside the query.',
        ],
        8 => [
            '<strong>Two-step attack:</strong> register the payload first, then authenticate to fire it.',
            '<strong>Email field:</strong> the stored email is embedded directly in the second query.',
            '<strong>Force admin count:</strong> inject a UNION that returns <code>admin</code> for the role comparison.',
            '<strong>Remember quotes:</strong> close the string properly before adding your injected SQL.',
        ],
        9 => [
            '<strong>XML structure:</strong> credentials are stored in an XML document parsed via XPath.',
            '<strong>XPath injection:</strong> break out of the predicate with <code>\']</code> and append new conditions.',
            '<strong>Use logical OR:</strong> payloads like <code>\'] | //user[role=\'administrator\']</code> bypass role checks.',
            '<strong>Beware encoding:</strong> XML reserves characters such as <code>&lt;</code> and <code>&amp;</code>; encode or escape them as needed.',
        ],
        10 => [
            '<strong>INSERT abuse:</strong> control the <code>VALUES</code> clause to change inserted data.',
            '<strong>Close then continue:</strong> finish the first tuple and append another admin tuple.',
            '<strong>Override roles:</strong> inject <code>\'admin\'</code> into the role field to avoid the default <code>user</code> role.',
            '<strong>Terminate the query:</strong> comment out the remainder with <code>--</code> or <code>#</code>.',
        ],
        11 => [
            '<strong>UPDATE injection:</strong> user input is concatenated into the <code>SET</code> clause.',
            '<strong>Add extra assignments:</strong> inject <code>, role=\'admin\'</code> to escalate privileges.',
            '<strong>Balance quotes:</strong> close the current string before adding your payload.',
            '<strong>Double-check IDs:</strong> ensure the <code>WHERE</code> clause still points to your user record.',
        ],
        12 => [
            '<strong>JSON parsing:</strong> values from the JSON body land directly in the SQL statement.',
            '<strong>Manipulate role:</strong> overwrite the <code>role</code> value to bypass the final comparison.',
            '<strong>Inject via username:</strong> payloads like <code>admin\' OR \'1\'=\'1</code> still work inside JSON.',
            '<strong>Keep JSON valid:</strong> watch commas, quotes, and braces so the payload parses correctly.',
        ],
        13 => [
            '<strong>Comment filters:</strong> keywords are blocked unless you split them up.',
            '<strong>Inline comments:</strong> use <code>/**/</code> to break prohibited words (for example <code>UN/**/ION</code>).',
            '<strong>Alternative comment styles:</strong> mix <code>--</code> and <code>#</code> to cut the remainder of the query.',
            '<strong>Vary casing:</strong> combine case changes with comments to evade basic string matching.',
        ],
        14 => [
            '<strong>Encoding hurdles:</strong> the filter expects specific byte patterns.',
            '<strong>Use URL or hex encoding:</strong> convert payload characters before submission.',
            '<strong>Double encode:</strong> encode the encoded string to slip past decoding once.',
            '<strong>Focus on keywords:</strong> encode operators such as <code>OR</code> to avoid direct matches.',
        ],
        15 => [
            '<strong>Space restrictions:</strong> literal spaces are blocked or stripped.',
            '<strong>Alternative whitespace:</strong> use comments, tabs (<code>%09</code>), or line breaks.',
            '<strong>Concatenate tokens:</strong> rely on functions like <code>/**/</code> to separate keywords.',
            '<strong>Squeeze payloads:</strong> remove unnecessary spaces and rely on SQL tolerance for token separation.',
        ],
        16 => [
            '<strong>Ultimate restrictions:</strong> filters target both spaces and common bypass tricks.',
            '<strong>Leverage inline comments:</strong> <code>/*!SELECT*/</code> style payloads survive aggressive filters.',
            '<strong>Use binary or hex:</strong> encode identifiers and strings to minimize blocked characters.',
            '<strong>Combine techniques:</strong> stack encoding, comments, and alternative whitespace to land a valid query.',
        ],
    ];

    return $hints[$levelId] ?? [];
}

/**
 * Render a progressive hint section. Each click reveals the next hint.
 *
 * @param array<int, string> $hints
 * @param string             $title
 */
function render_hint_section(array $hints, string $title = 'Hints'): string
{
    if (empty($hints)) {
        return '';
    }

    static $scriptRendered = false;
    $id = uniqid('hint_', false);

    ob_start();
    ?>
    <div class="hints">
        <h3><?= htmlspecialchars($title, ENT_QUOTES, 'UTF-8') ?></h3>
        <button type="button" class="hint-btn" data-hint-target="<?= htmlspecialchars($id, ENT_QUOTES, 'UTF-8') ?>">
            Show next hint
        </button>
        <ul id="<?= htmlspecialchars($id, ENT_QUOTES, 'UTF-8') ?>" class="hint-list">
            <?php foreach ($hints as $hint): ?>
                <li class="hint-item" hidden><?= $hint ?></li>
            <?php endforeach; ?>
        </ul>
    </div>
    <?php if (!$scriptRendered): ?>
        <script>
        (function () {
            "use strict";
            document.addEventListener("click", function (event) {
                if (!event.target.matches(".hint-btn")) {
                    return;
                }

                var button = event.target;
                var targetId = button.getAttribute("data-hint-target");
                if (!targetId) {
                    return;
                }

                var list = document.getElementById(targetId);
                if (!list) {
                    return;
                }

                var nextHint = list.querySelector(".hint-item[hidden]");
                if (nextHint) {
                    nextHint.hidden = false;
                }

                if (!list.querySelector(".hint-item[hidden]")) {
                    button.disabled = true;
                    button.textContent = "All hints shown";
                }
            });
        }());
        </script>
    <?php
        $scriptRendered = true;
    endif;

    return ob_get_clean();
}


