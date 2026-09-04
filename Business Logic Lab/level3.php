<?php
require_once __DIR__ . '/helpers.php';

$L    = 3;
$meta = biz_levels()[$L];

shop_sid();
biz_handle_reset($L);

$catalog = shop_catalog($L);
$coupons = shop_coupons();
$state   = shop_state($L);

$flag     = '';
$result   = '';
$pipeline = [];

/* ── The cart the shop built for this basket. ───────────────────────────── */
$subtotal = 0.0;
$cartRows = [];
foreach ($state['cart'] as $ln) {
    $it    = $catalog[$ln['item']];
    $line  = $ln['qty'] * $it['price'];
    $subtotal += $line;
    $cartRows[] = [lk_esc($it['name']), (int)$ln['qty'], shop_money($it['price']), shop_money($line)];
}
$subtotal = shop_cents($subtotal);

$submitted = trim((string)($_POST['codes'] ?? ''));

/* =========================================================================
 * Checkout with coupons.
 *
 * Two loops. The first decides which codes are usable; the second applies
 * them and records that they have been used. Both loops read the same
 * history, and the history does not change until the second loop is done.
 * ===================================================================== */

if (($_POST['bl_action'] ?? '') === 'checkout' || $submitted !== '') {
    $codes = array_values(array_filter(array_map(
        static fn ($c) => strtoupper(trim($c)),
        preg_split('/[,\s]+/', $submitted) ?: []
    )));

    $ordersPlaced = count($state['orders']);
    $used         = $state['used_codes'];

    // ── Loop 1: validation ────────────────────────────────────────────────
    $valid  = [];
    $vNotes = [];
    foreach ($codes as $c) {
        if (!isset($coupons[$c])) {
            $vNotes[] = $c . ' -> unknown code';
            continue;
        }
        if ($ordersPlaced > 0) {                    // first-order rule
            $vNotes[] = $c . ' -> rejected, not your first order';
            continue;
        }
        if (in_array($c, $used, true)) {            // single-use rule
            $vNotes[] = $c . ' -> rejected, already used';
            continue;
        }
        $valid[]  = $c;
        $vNotes[] = $c . ' -> valid (orders placed so far: ' . $ordersPlaced
                  . ', codes used so far: ' . (count($used) ?: 0) . ')';
    }
    $valid = array_values(array_unique($valid));

    // ── Loop 2: application ───────────────────────────────────────────────
    $discount = 0.0;
    $aNotes   = [];
    foreach ($valid as $c) {
        $cp   = $coupons[$c];
        $cut  = $cp['type'] === 'pct' ? $subtotal * $cp['value'] : $cp['value'];
        $discount += $cut;
        $used[]    = $c;                            // written only now
        $aNotes[]  = $c . ': ' . ($cp['type'] === 'pct'
            ? (int)round($cp['value'] * 100) . '% of subtotal ' . shop_money($subtotal)
            : 'flat') . ' = -' . shop_money($cut) . '   running discount ' . shop_money($discount);
    }

    $discount = shop_cents($discount);
    $total    = shop_cents($subtotal - $discount);

    $pipeline = [
        ['label' => 'codes submitted', 'value' => $codes ? implode(', ', $codes) : '(none)'],
        ['label' => 'loop 1 - validate every code against the account history',
         'value' => $vNotes ? implode("\n", $vNotes) : '(nothing to validate)',
         'note'  => 'Both rules are questions about the past: how many orders have you placed, and which codes '
                  . 'have you already spent. At this point in the request the answers are still 0 and none, '
                  . 'and they stay that way for every iteration of this loop.',
         'verdict' => $valid ? 'pass' : 'block'],
        ['label' => 'loop 2 - apply every valid code, then record it as used',
         'value' => $aNotes ? implode("\n", $aNotes) : '(no discount applied)',
         'note'  => 'Each percentage is taken against <code>$subtotal</code>, the original figure, not against the '
                  . 'running total. That is why five codes add to 100% instead of compounding down to about 66%.'],
        ['label' => '$total = $subtotal - $discount',
         'value' => shop_money($subtotal) . ' - ' . shop_money($discount) . ' = ' . shop_money($total),
         'verdict' => $total <= 0.0 ? 'pass' : null],
    ];

    if (!$codes) {
        $result = biz_notice('error', 'Enter at least one coupon code.');
    } else {
        $state['used_codes'] = array_values(array_unique($used));
        $state['orders'][]   = ['subtotal' => $subtotal, 'discount' => $discount, 'total' => $total,
                                'codes' => $valid];
        shop_put($L, $state);
        $result = biz_notice($total <= 0.0 ? 'success' : 'info',
            'Order placed. Subtotal ' . shop_money($subtotal) . ', discount ' . shop_money($discount)
            . ', charged <strong>' . shop_money($total) . '</strong>.');
    }
}

/* ── Flag: an order was actually placed whose charged total is zero or less. */
foreach ($state['orders'] as $o) {
    if ((float)$o['total'] <= 0.0) {
        $flag = biz_flag($L);
    }
}

/* =========================================================================
 * Panels
 * ===================================================================== */

$couponRows = [];
foreach ($coupons as $code => $cp) {
    $couponRows[] = [
        '<code>' . lk_esc($code) . '</code>',
        lk_esc($cp['label']),
        'single use, first order only',
        in_array($code, $state['used_codes'], true) ? 'spent' : 'available',
    ];
}

$orderRows = [];
foreach ($state['orders'] as $i => $o) {
    $orderRows[] = [
        '#' . ($i + 1),
        shop_money($o['subtotal']),
        '-' . shop_money($o['discount']),
        shop_money($o['total']),
        $o['codes'] ? lk_esc(implode(', ', $o['codes'])) : '&mdash;',
    ];
}

$stateHtml = biz_kv([
    'Cart subtotal'  => '<span class="biz-big">' . shop_money($subtotal) . '</span>',
    'Orders placed'  => count($state['orders']),
    'Codes spent'    => $state['used_codes'] ? lk_esc(implode(', ', $state['used_codes'])) : 'none',
    'Target'         => 'place an order charged ' . shop_money(0.00) . ' or less',
])
. biz_table(['Item', 'Qty', 'Unit', 'Line total'], $cartRows)
. '<p class="lk-hintline" style="margin-top:0.7rem">Coupon wallet</p>'
. biz_table(['Code', 'Offer', 'Terms', 'Status'], $couponRows)
. ($orderRows ? '<p class="lk-hintline" style="margin-top:0.7rem">Order history</p>'
              . biz_table(['#', 'Subtotal', 'Discount', 'Charged', 'Codes'], $orderRows) : '');

ob_start(); ?>
<form method="post" action="">
    <input type="hidden" name="bl_action" value="checkout">
    <div class="form-group">
        <label class="form-label">Coupon codes</label>
        <input type="text" name="codes" class="form-control" value="<?= lk_esc($submitted) ?>"
               placeholder="FIRST10" autocomplete="off" spellcheck="false">
    </div>
    <button class="btn btn-primary" type="submit">Apply coupons and check out</button>
</form>
<?= biz_reset_form() ?>
<?php
$form = biz_state_box('This basket', $stateHtml) . ob_get_clean();

$code = <<<'PHP'
// POST /checkout
$codes        = array_map('strtoupper', explode(',', $_POST['codes']));
$ordersPlaced = count($customer['orders']);
$used         = $customer['used_codes'];

// 1. work out which codes this customer may use
$valid = [];
foreach ($codes as $c) {
    $coupon = COUPONS[$c] ?? null;
    if (!$coupon)                          continue;   // unknown code
    if ($coupon['first_order'] && $ordersPlaced > 0) continue;
    if (in_array($c, $used, true))         continue;   // single use
    $valid[] = $c;
}

// 2. apply them
$discount = 0.0;
foreach ($valid as $c) {
    $coupon    = COUPONS[$c];
    $discount += $coupon['type'] === 'pct'
        ? $subtotal * $coupon['value']     // always the ORIGINAL subtotal
        : $coupon['value'];
    $used[] = $c;                          // history written here, not above
}

$total = $subtotal - $discount;
charge($customer, $total);
$customer['used_codes'] = $used;
$customer['orders'][]   = $order;
PHP;

$fixBad = <<<'PHP'
foreach ($codes as $c) { /* validate against unchanged history */ }
foreach ($valid as $c) { /* apply, then append to history */ }
PHP;

$fixGood = <<<'PHP'
// One coupon per order, decided once, and the decision is made by the same
// code that applies it - so there is no window between the two.
$code   = strtoupper(trim($_POST['code'] ?? ''));
$coupon = COUPONS[$code] ?? null;
if (!$coupon) {
    return error('unknown code');
}

// Reserve the code inside the transaction that creates the order. A unique
// index on (customer_id, code) makes the single-use rule a fact about the
// data rather than a hope about the control flow.
$db->transaction(function () use ($customer, $code, $coupon, $subtotal) {
    $db->insert('coupon_redemptions', [
        'customer_id' => $customer->id,
        'code'        => $code,
    ]);                                    // UNIQUE(customer_id, code)

    $discount = min(
        $coupon['type'] === 'pct' ? $subtotal * $coupon['value'] : $coupon['value'],
        $subtotal                          // a discount can never exceed the basket
    );
    create_order($customer, $subtotal, $discount);
});
PHP;

lk_page([
    'lab'        => bizlab(),
    'level'      => $L,
    'title'      => $meta['title'],
    'difficulty' => $meta['difficulty'],
    'extra_head' => biz_extra_head(),

    'code'       => $code,
    'vuln_lines' => [7, 8, 9, 10, 11, 12, 13, 14, 24],
    'annotation' => 'Both coupon rules are questions about history - "is this your first order" and "have you
        spent this code" - and both are asked in a loop that runs entirely before any history is written. Every
        code in one request therefore sees the same empty past, and every one of them is the first.',

    'theory' => '<p>This is time-of-check to time-of-use, but with no concurrency anywhere in it. The check and the
        use are separated by nothing more exotic than a loop boundary in a single-threaded request. People associate
        TOCTOU with races because that is where it is dramatic; the ordinary version is far more common and needs no
        timing at all.</p>
        <p>The structural smell is a two-pass design over shared mutable state: <em>validate everything, then apply
        everything</em>. It reads well and it is easy to test, because each pass does one job. It is also wrong
        whenever applying an item changes the facts the validation depended on. The first pass is answering a
        question about a world the second pass is busy demolishing.</p>
        <p>There is a second bug stacked on top of the first, and it is worth separating them. Each percentage is
        taken against <code>$subtotal</code> rather than against the running total. Applied to the running total,
        five discounts would compound - 10% then 15% then 20% then 25% then 30% leaves about 34% of the basket
        standing. Applied to the original, they add, and five of them reach exactly nothing. Whether discounts
        compound or add is a business decision; the point is that nobody made it here.</p>',

    'fix' => [
        'bad'  => $fixBad,
        'good' => $fixGood,
        'note' => 'Two independent repairs. Make the redemption a uniquely-indexed row written inside the same
            transaction as the order, so "single use" is enforced by the database rather than by the order of two
            loops. And clamp the discount at the basket value, so that even a stacking bug can only ever reach
            zero, never below it.',
    ],

    'scenario' => '<strong>Scenario:</strong> a promotional campaign went out with five welcome codes in it. Each
        one is marked single use and first order only, and the terms are enforced - you can check. Your basket is
        <strong>' . shop_money(240.00) . '</strong>.
        <br><strong>Goal:</strong> place an order whose charged total is ' . shop_money(0.00) . ' or less.',

    'model' => [
        'title' => 'What each loop knows',
        'html'  => '<table class="lk-kv">
            <tr><td>loop 1 reads</td><td><code>$ordersPlaced</code> and <code>$used</code> - both still empty</td></tr>
            <tr><td>loop 1 writes</td><td>nothing</td></tr>
            <tr><td>loop 2 reads</td><td><code>$valid</code>, computed above</td></tr>
            <tr><td>loop 2 writes</td><td><code>$discount</code>, and appends to <code>$used</code></td></tr>
        </table>
        <p>The single-use rule works perfectly <em>across</em> requests: spend a code today and it is gone tomorrow.
        It does nothing <em>within</em> one request, because the list it consults is only updated after the
        decisions that consult it.</p>
        <table class="lk-kv" style="margin-top:0.6rem">
            <tr><td>subtotal</td><td>' . shop_money(240.00) . '</td></tr>
            <tr><td>discounts add</td><td>each one is <code>$subtotal x rate</code>, independent of the others</td></tr>
            <tr><td>so the question is</td><td>which set of rates sums to 1.00</td></tr>
        </table>',
    ],

    'form'     => $form,
    'result'   => $result,
    'flag'     => $flag,
    // Stateful levels can be reset after a solve, so the inline submit box
    // keeps accepting this level's flag even once the winning state is gone.
    'expected_flag' => biz_flag($L),
    'flag_msg' => 'An order exists in your history with a charged total of zero.',
    'why'      => '<p>Read the two trace steps side by side. Step 2 lists every code as valid and prints the
        history it consulted: nought orders, no codes spent. Step 3 then applies all of them and appends to that
        same list, long after every decision that depended on it has been made.</p>
        <p>The flag is awarded for the <strong>charged total of a placed order</strong>. Sending five codes is not
        what wins; reaching a state where the shop has recorded an order it collected no money for is.</p>
        <p>Look for this shape wherever a request handles a collection: bulk invite acceptance, batch refunds,
        multi-item redemptions, "apply to all" buttons. The single-item path is usually correct and the batch path
        usually validates the whole batch against the state that existed before any of it ran.</p>',

    'pipeline' => $pipeline,
    'probes'   => [
        'param'  => 'codes',
        'method' => 'POST',
        'action' => 'level3.php',
        'items'  => [
            ['q' => 'Is a single code enforced correctly?',
             'payload' => 'FIRST10',
             'learn'   => 'Establishes the baseline: one code, one discount, and the code is marked spent afterwards. Reset the level before you go further so the history is clean again.'],
            ['q' => 'Does the same code twice in one request count twice?',
             'payload' => 'FIRST10, FIRST10',
             'learn'   => 'A different question from stacking two <em>different</em> codes. The answer tells you whether the guard is deduplicating the list or genuinely consulting history.'],
            ['q' => 'Is an unknown code rejected quietly or loudly?',
             'payload' => 'NOTACODE',
             'learn'   => 'Cheap, and it confirms the validation loop is really running rather than being skipped when the input looks unusual.'],
        ],
    ],
    'hints' => biz_hints($L),
]);
