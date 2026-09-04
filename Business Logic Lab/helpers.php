<?php
/**
 * Business Logic Lab · lab metadata, flags, hints and shared level UI.
 */

require_once __DIR__ . '/lab_kit.php';
require_once __DIR__ . '/shop.php';

function bizlab(): array
{
    return [
        'slug'    => 'bizlogic',
        'name'    => 'Business Logic Lab',
        'icon'    => 'LOGIC',
        'total'   => 10,
        'tagline' => 'Ten shops where every line of code works and every rule is wrong',
    ];
}

function biz_flag(int $level): string
{
    $flags = [
        1  => 'FLAG{quantity_had_no_lower_bound}',
        2  => 'FLAG{the_client_does_not_know_the_price}',
        3  => 'FLAG{validated_all_then_applied_all}',
        4  => 'FLAG{rounded_each_line_before_summing}',
        5  => 'FLAG{the_cap_was_wider_than_the_field}',
        6  => 'FLAG{confirm_never_checked_payment}',
        7  => 'FLAG{the_request_wrote_fields_the_form_never_showed}',
        8  => 'FLAG{each_refund_was_checked_alone}',
        9  => 'FLAG{the_round_trip_was_net_positive}',
        10 => 'FLAG{tier_credit_ignored_the_discount}',
    ];
    return $flags[$level] ?? '';
}

function biz_levels(): array
{
    return [
        1 => [
            'title'      => 'Negative Quantity',
            'difficulty' => 'Easy',
            'skill'      => 'Ranges that are bounded on one side only',
            'desc'       => 'The cart clamps quantity at ten. Nobody wrote the other half of the range check, so a line can subtract from the order instead of adding to it.',
        ],
        2 => [
            'title'      => 'The Price Came From the Browser',
            'difficulty' => 'Easy',
            'skill'      => 'Trusting the client for a value only the server knows',
            'desc'       => 'The product form carries the unit price in a hidden field and the checkout bills whatever came back. Buy the item you were never meant to afford.',
        ],
        3 => [
            'title'      => 'Coupon Stacking',
            'difficulty' => 'Medium',
            'skill'      => 'Time-of-check to time-of-use inside one request',
            'desc'       => 'Every coupon is single use and first-order only. Validation runs in one loop and application runs in another, so several codes are all still the first order.',
        ],
        4 => [
            'title'      => 'Rounding in the Wrong Direction',
            'difficulty' => 'Medium',
            'skill'      => 'Where in the sum you round, and who keeps the fraction',
            'desc'       => 'Refunds are rounded to whole cents per line before the lines are added up. Choose how the return is split and the rounding pays you.',
        ],
        5 => [
            'title'      => 'Integer Overflow in the Cart',
            'difficulty' => 'Medium',
            'skill'      => 'A validated range wider than the field it is stored in',
            'desc'       => 'The web tier accepts quantities up to five billion. The warehouse protocol stores quantity in a signed 32-bit field. Those two facts do not fit together.',
        ],
        6 => [
            'title'      => 'Skipping a Step',
            'difficulty' => 'Hard',
            'skill'      => 'State machines enforced by the UI instead of the server',
            'desc'       => 'Checkout runs cart, address, payment, confirm. The confirm endpoint checks that an order exists and nothing else. The buttons enforce the order; the server does not.',
        ],
        7 => [
            'title'      => 'Mass Assignment at Checkout',
            'difficulty' => 'Hard',
            'skill'      => 'Hydrating an object from the request array',
            'desc'       => 'The order is built by merging the POST body into a defaults array. Fields the form never rendered are still fields, and they are still writable.',
        ],
        8 => [
            'title'      => 'Refund More Than You Paid',
            'difficulty' => 'Hard',
            'skill'      => 'Per-request limits on a cumulative quantity',
            'desc'       => 'Each partial refund is checked against the line it belongs to. Nothing checks the running total, so the same line can be refunded again and again.',
        ],
        9 => [
            'title'      => 'The Loyalty Loop',
            'difficulty' => 'Expert',
            'skill'      => 'Two exchange rates that do not agree',
            'desc'       => 'Points buy credit at one rate and credit earns points at another. Work out the round trip before you click anything: it multiplies.',
        ],
        10 => [
            'title'      => 'Chain',
            'difficulty' => 'Expert',
            'skill'      => 'Composing two correct-looking rules into a privilege',
            'desc'       => 'A membership tier nobody can legitimately reach guards an item nobody can legitimately buy. Two of the shop rules you have already met combine to open it.',
        ],
    ];
}

/* =========================================================================
 * Hints (5 per level: concept -> observation -> technique -> shape -> answer)
 * ===================================================================== */

function biz_hints(int $level): array
{
    $h = [
        1 => [
            'Fuzzing does not help here. There is no payload syntax to find, only a rule the developer did not finish writing. Read the range check and ask what it does <em>not</em> reject.',
            'The check in the source is <code>if ($qty &gt; 10)</code>. One comparison, one direction. Ask yourself what the smallest quantity the shop will accept actually is.',
            'The line total is <code>$qty * $price</code> with no sign handling anywhere downstream, and checkout does <code>$balance -= $total</code>. Follow a negative number through those two statements on paper.',
            'A single line with a negative quantity produces a negative line total, which makes the order total negative, which makes the subtraction at checkout an addition.',
            'Add <code>Refurbished Laptop</code> with quantity <code>-1</code>, then check out. Your balance goes from $25.00 to $924.99.',
        ],
        2 => [
            'A price is a fact the server owns. Anything the browser sends back is a request, not a fact - even when the browser only sent it because the server put it there first.',
            'Look at line 6 of the source: <code>$unit = (float)$_POST[\'unit_price\']</code>. The catalogue is never consulted after the page is rendered.',
            'View the page source, or open the request-body editor under the buy form. The field is called <code>unit_price</code> and it is sitting right next to <code>item</code>.',
            'Select the restricted item, keep its <code>item</code> id, and replace the <code>unit_price</code> that came with it with a number your $25.00 balance covers.',
            'Send <code>item=ent-support</code> with <code>unit_price=1.00</code> and <code>qty=1</code>. The order is billed at $1.00 and the contract is yours.',
        ],
        3 => [
            'Single use and first order only are rules about <em>history</em>. History only changes when something is written down. Ask when this code writes anything down.',
            'There are two loops. The first decides which codes are valid; the second applies them and only then appends to <code>$used</code>. Both loops read the same unchanged history.',
            'So the question is not whether a code can be reused - it cannot. It is whether several different codes can each be the first one, in the same request.',
            'Submit more than one code at once. Every percentage is taken against the original subtotal, not against the running total, so the percentages add rather than compound.',
            'The subtotal is $240.00 and the five codes are 10 + 15 + 20 + 25 + 30 = 100%. Enter <code>FIRST10, WELCOME15, NEWBIE20, SPRING25, LOYAL30</code> and check out at $0.00.',
        ],
        4 => [
            'Money is not a real number. Every arithmetic step either keeps a fraction of a cent or throws it away, and whoever the rounding favours collects the difference.',
            'The refund code is <code>$refund += round($qty * $unit, 2)</code> inside the loop over lines. The rounding happens per line, before the addition, not once at the end.',
            'The unit price is $0.336. Work out <code>round(n * 0.336, 2)</code> for small values of <code>n</code> and compare each result with the exact value <code>n * 0.336</code>.',
            'You have 300 units to return and you choose how they are split into lines. Pick the quantity per line whose exact value rounds <em>up</em>, then use as many lines as the units allow.',
            'One unit per line: <code>round(0.336, 2) = 0.34</code>, four tenths of a cent above the true price. 300 lines of quantity 1 refunds $102.00 against an order of $100.80.',
        ],
        5 => [
            'A validation says which values are allowed. A storage type says which values can exist. When the first is wider than the second, the values in between do not get rejected - they get transformed.',
            'The web tier rejects <code>$qty &lt; 1</code> and <code>$qty &gt; 5000000000</code>. Five billion. Then the quantity is written into the warehouse message.',
            'The warehouse field is <code>signed 32-bit</code>. Its range is -2,147,483,648 to 2,147,483,647. Anything above that top value wraps around to the bottom.',
            'You need a quantity that the web tier accepts and that the 32-bit field cannot hold. The smallest such value is one past the signed 32-bit maximum.',
            'Buy the <code>Digital Gift Card</code> with quantity <code>2147483648</code>. The warehouse reads it back as -2147483648 and the order total becomes -$21,474,836,480.00.',
        ],
        6 => [
            'A checkout is a state machine. Drawing it is the whole job: list the states, list the transitions, then ask which transitions the server actually verifies.',
            'The states are <code>cart</code>, <code>address_set</code>, <code>authorised</code>, <code>paid</code>. Three of the four handlers check the state they are coming from. Find the one that does not.',
            'The confirm handler is three lines: load the order, set the status to paid, ship it. The only thing it verifies is that an order exists at all.',
            'The buttons for steps you have not reached are disabled in the HTML. Disabled is a rendering decision made in your browser; the endpoint never learns about it.',
            'Start an order for the Standing Desk, then send <code>step=confirm</code> directly using the request panel. The order reaches <code>paid</code> with <code>amount_paid</code> still $0.00.',
        ],
        7 => [
            'An order object has more fields than an order form. The gap between those two lists is the attack surface of every framework that hydrates a model from request data.',
            'The source builds the order with <code>array_merge($defaults, $_POST)</code>. Read the defaults array: it is the complete list of keys you are allowed to write.',
            'The order dump in the state panel prints every field the object carries, including the ones no input rendered. That dump is your field list.',
            'Send a key that the form never shows. <code>discount_tier</code> is looked up in a tier table, and <code>internal_credit</code> is subtracted from the total in dollars.',
            'Post <code>item=headset&amp;qty=1&amp;discount_tier=staff&amp;internal_credit=100</code>. The 90% staff rate takes $249.00 to $24.90 and the credit takes it to $0.00.',
        ],
        8 => [
            'A limit that is checked once per request is not a limit on the total. It is a limit on one request. The difference only shows up when you send the request twice.',
            'The validation is <code>if ($amount &gt; $line[\'total\'])</code>. It compares your amount with the line, and never with <code>array_sum($order[\'refunds\'])</code>.',
            'Nothing here is a race condition. The requests can be strictly sequential; the state is written correctly each time. The rule being enforced is the wrong rule.',
            'Issue the largest refund the per-line check allows, then issue it again. Watch the running total in the state panel climb past the order total.',
            'Refund $329.00 against line 1 twice. The order was $354.00; you have now been paid $658.00 for it.',
        ],
        9 => [
            'Two exchange rates between the same pair of currencies only make sense if you can only travel one way. If both directions are open, one of the rates is a machine for printing money.',
            'Redeem is 50 points for $1.00 of credit. Earn is 100 points for every $1.00 of credit spent. Write both as a price per point: you are selling points at two cents and buying them back at one.',
            'Follow 100 points around the loop on paper before you click anything. Redeem gives $2.00; spending $2.00 gives 200 points. The loop is not leaky, it is multiplicative.',
            'Each full loop doubles your points, so after <code>n</code> loops you hold <code>100 * 2^n</code> points, worth <code>$2.00 * 2^n</code>. Solve for the smallest <code>n</code> that clears the target.',
            'Five loops takes 100 points to 3,200. Redeem those without spending them and you hold $64.00 of credit against a $50.00 target.',
        ],
        10 => [
            'Nothing in this level is new. Both halves are rules you have already broken; the level is about noticing that one of them produces the input the other one needs.',
            'The gate is <code>tier === \'platinum\'</code> and the tier comes from <code>lifetime_spend</code>. Read the checkout code and find which of the three money figures is added to that ledger.',
            'The ledger is credited with the <strong>subtotal</strong>, before discounts, while your balance is charged the <strong>total</strong>, after them. Those two numbers do not have to be close to each other.',
            'The coupon engine from level 3 was never fixed, and it still stacks to 100%. So you can record an arbitrarily large subtotal while paying nothing at all.',
            'Buy 12 Server Rack Units ($12,000.00 subtotal) with all five coupon codes. You are charged $0.00, your lifetime spend records $12,000.00, your tier becomes platinum, and the Founders Edition Hoodie unlocks for its list price of $19.00.',
        ],
    ];
    return $h[$level] ?? [];
}

/* =========================================================================
 * Shared level UI
 * ===================================================================== */

/**
 * POST keys the lab itself owns. Level 7 hydrates an order object straight
 * from the request, so it has to know which keys belong to the page furniture
 * rather than to the order.
 */
function biz_control_keys(): array
{
    return ['bl_action', '_flag_submit', 'submitted_flag'];
}

/** True when the learner pressed "Reset this level". */
function biz_handle_reset(int $level): bool
{
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['bl_action'] ?? '') === 'reset') {
        shop_reset($level);
        return true;
    }
    return false;
}

/** Two-column key/value block, used for balances and order status. */
function biz_kv(array $rows): string
{
    $out = '<table class="lk-kv">';
    foreach ($rows as $k => $v) {
        $out .= '<tr><td>' . $k . '</td><td>' . $v . '</td></tr>';
    }
    return $out . '</table>';
}

/** Wide table, used for carts, line items and ledgers. */
function biz_table(array $head, array $rows, string $empty = 'nothing here yet'): string
{
    if (!$rows) {
        return '<p class="text-muted" style="margin:0.35rem 0 0">' . lk_esc($empty) . '</p>';
    }
    $out = '<table class="data-table"><thead><tr>';
    foreach ($head as $h) {
        $out .= '<th>' . $h . '</th>';
    }
    $out .= '</tr></thead><tbody>';
    foreach ($rows as $r) {
        $out .= '<tr>';
        foreach ($r as $cell) {
            $out .= '<td>' . $cell . '</td>';
        }
        $out .= '</tr>';
    }
    return $out . '</tbody></table>';
}

/** The "where you are right now" panel every level shows above its form. */
function biz_state_box(string $title, string $html): string
{
    return '<div class="lk-box biz-state"><h4><span class="lk-tag">STATE</span>' . lk_esc($title) . '</h4>'
         . '<div class="lk-body">' . $html . '</div></div>';
}

/**
 * Reset button. Business-logic levels are stateful and can be driven into
 * corners that no further request can get out of, so every level has one.
 */
function biz_reset_form(string $label = 'Reset this level'): string
{
    return '<form method="post" class="biz-reset">'
         . '<input type="hidden" name="bl_action" value="reset">'
         . '<button type="submit" class="btn btn-outline">' . lk_esc($label) . '</button>'
         . '<span class="text-muted">state lives in a per-browser JSON file; this drops it back to the defaults</span>'
         . '</form>';
}

/** Standard success / failure banner for a shop operation. */
function biz_notice(string $kind, string $html): string
{
    return '<div class="message ' . lk_esc($kind) . '">' . $html . '</div>';
}

/**
 * A visible editor for the raw request body. Business-logic testing normally
 * happens in a proxy; this is the smallest honest substitute, and it makes the
 * point that the form is a suggestion and the endpoint is the contract.
 */
function biz_raw_form(string $prefill, string $note = ''): string
{
    ob_start(); ?>
    <details class="biz-raw">
        <summary>Send a raw request body (what a proxy would let you edit)</summary>
        <?php if ($note !== ''): ?><p class="lk-hintline"><?= $note ?></p><?php endif; ?>
        <form method="post" action="">
            <textarea name="__raw" class="form-control biz-raw-ta" rows="3" spellcheck="false"><?= lk_esc($prefill) ?></textarea>
            <button class="btn btn-primary" type="submit" style="margin-top:0.5rem">Send</button>
        </form>
    </details>
    <?php
    return ob_get_clean();
}

/**
 * Merge a raw urlencoded body from the editor into $_POST so the level handler
 * only has to read one place. Called at the top of the levels that offer it.
 */
function biz_apply_raw_body(): void
{
    $raw = trim((string)($_POST['__raw'] ?? ''));
    unset($_POST['__raw']);
    if ($raw === '') {
        return;
    }
    $parsed = [];
    parse_str($raw, $parsed);
    foreach ($parsed as $k => $v) {
        $_POST[$k] = $v;
    }
}

function biz_extra_head(): string
{
    return '<style>
        .biz-state .lk-body { padding-top: 0.35rem; }
        .biz-state .data-table { margin-top: 0.5rem; }
        .biz-reset { display: flex; align-items: center; gap: 0.75rem; flex-wrap: wrap;
                     margin: 0.9rem 0 0.25rem; }
        .biz-reset .text-muted { font-size: 0.74rem; }
        .biz-raw { margin: 0.75rem 0 0.25rem; font-size: 0.8rem; }
        .biz-raw summary { cursor: pointer; color: var(--text-muted); }
        .biz-raw-ta { font-family: "JetBrains Mono", ui-monospace, monospace; font-size: 0.76rem;
                      margin-top: 0.5rem; }
        .biz-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
                    gap: 0.6rem; margin-bottom: 0.6rem; }
        .biz-steps { display: flex; flex-wrap: wrap; gap: 0.4rem; margin: 0.5rem 0; }
        .biz-steps button[disabled] { opacity: 0.4; cursor: not-allowed; }
        .biz-calc { font-family: "JetBrains Mono", ui-monospace, monospace; font-size: 0.78rem; }
        .biz-big { font-size: 1.05rem; font-weight: 600; }
    </style>';
}
