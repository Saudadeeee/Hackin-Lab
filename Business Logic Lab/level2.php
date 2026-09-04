<?php
require_once __DIR__ . '/helpers.php';

$L    = 2;
$meta = biz_levels()[$L];

shop_sid();
biz_handle_reset($L);
biz_apply_raw_body();          // the raw-body editor writes into $_POST

$catalog = shop_catalog($L);
$state   = shop_state($L);

$flag     = '';
$result   = '';
$pipeline = [];

/* =========================================================================
 * The shop. One operation: buy.
 *
 * The product page renders a hidden field carrying the unit price so the
 * "order summary" widget can show a running total without another round trip.
 * The checkout then bills whatever came back in that field.
 * ===================================================================== */

if (($_POST['bl_action'] ?? '') === 'buy' || isset($_POST['unit_price'])) {
    $itemId  = (string)($_POST['item'] ?? 'cable');
    $rawUnit = (string)($_POST['unit_price'] ?? '');
    $rawQty  = (string)($_POST['qty'] ?? '1');

    $item = $catalog[$itemId] ?? null;
    $qty  = max(1, (int)$rawQty);

    // ── The bug, in one statement. The catalogue is not consulted. ────────
    $unit  = (float)$rawUnit;
    $total = shop_cents($qty * $unit);

    $before     = (float)$state['balance'];
    $affordable = $total <= $before;

    $pipeline = [
        ['label' => '$_POST["item"]', 'value' => $itemId,
         'note'  => $item ? 'Catalogue name: <strong>' . lk_esc($item['name']) . '</strong>, list price '
                          . shop_money($item['price']) . '.'
                          : 'Not a catalogue id.',
         'verdict' => $item ? 'pass' : 'block'],
        ['label' => '$_POST["unit_price"] (raw)', 'value' => $rawUnit,
         'note'  => 'This value made the round trip: the server rendered it into a hidden field and the browser '
                  . 'handed it back. Nothing about that journey makes it trustworthy on return.'],
        ['label' => '$unit = (float)$_POST["unit_price"]', 'value' => number_format($unit, 2, '.', ''),
         'note'  => $item && abs($unit - (float)$item['price']) > 0.001
            ? 'Catalogue says ' . shop_money($item['price']) . '. The server is about to bill '
              . shop_money($unit) . ' and will not notice the difference.'
            : 'Matches the catalogue price.'],
        ['label' => '$total = $qty * $unit',
         'value' => $qty . ' x ' . shop_money($unit) . ' = ' . shop_money($total)],
        ['label' => 'if ($total > $balance) reject("insufficient funds")',
         'value' => $affordable ? 'passed' : 'rejected - ' . shop_money($total) . ' > ' . shop_money($before),
         'note'  => 'The only remaining guard. It compares your balance against a number you supplied.',
         'verdict' => $affordable ? 'pass' : 'block'],
    ];

    if (!$item) {
        $result = biz_notice('error', 'Unknown item.');
    } elseif ($unit <= 0) {
        $result = biz_notice('error', 'Unit price must be greater than zero.');
    } elseif (!$affordable) {
        $result = biz_notice('error', 'Insufficient funds: order total ' . shop_money($total)
                . ', balance ' . shop_money($before) . '.');
    } else {
        $state['balance'] = shop_cents($before - $total);
        $state['orders'][] = [
            'item'   => $itemId,
            'name'   => $item['name'],
            'qty'    => $qty,
            'unit'   => $unit,
            'total'  => $total,
            'list'   => (float)$item['price'],
        ];
        shop_put($L, $state);
        $result = biz_notice('success', 'Order placed: ' . (int)$qty . ' x ' . lk_esc($item['name'])
                . ' at ' . shop_money($unit) . ' each, billed ' . shop_money($total) . '.');
    }
}

/* ── Flag: you own the restricted item. Not "you sent a low price" - the
 *    order has to exist in your history for the item you were priced out of. */
foreach ($state['orders'] as $o) {
    if ($o['item'] === 'ent-support') {
        $flag = biz_flag($L);
    }
}

/* =========================================================================
 * Panels
 * ===================================================================== */

$orderRows = [];
foreach ($state['orders'] as $o) {
    $orderRows[] = [
        lk_esc($o['name']),
        (int)$o['qty'],
        shop_money($o['list']),
        shop_money($o['unit']),
        shop_money($o['total']),
    ];
}

$stateHtml = biz_kv([
    'Store credit' => '<span class="biz-big">' . shop_money($state['balance']) . '</span>',
    'Target'       => 'own an <code>ent-support</code> order',
]) . biz_table(['Item', 'Qty', 'List price', 'Billed unit', 'Charged'], $orderRows, 'no orders yet');

$radios = '';
foreach ($catalog as $id => $it) {
    $radios .= '<label class="biz-item"><input type="radio" name="item" value="' . lk_esc($id) . '"'
             . ($id === 'cable' ? ' checked' : '') . '> '
             . lk_esc($it['name']) . ' <span class="text-muted">' . shop_money($it['price'])
             . (!empty($it['note']) ? ' &middot; ' . lk_esc($it['note']) : '') . '</span>'
             . '<input type="hidden" name="unit_price_' . lk_esc($id) . '" value="'
             . number_format((float)$it['price'], 2, '.', '') . '"></label>';
}

ob_start(); ?>
<form method="post" action="" id="buyForm">
    <input type="hidden" name="bl_action" value="buy">
    <div class="form-group">
        <label class="form-label">Product</label>
        <?= $radios ?>
    </div>
    <div class="biz-grid">
        <div class="form-group">
            <label class="form-label">Quantity</label>
            <input type="text" name="qty" class="form-control" value="1" autocomplete="off">
        </div>
    </div>
    <!-- rendered by the product template so the summary widget can price the
         order without another round trip; updated by the radio buttons -->
    <input type="hidden" name="unit_price" value="12.00">
    <button class="btn btn-primary" type="submit">Buy now</button>
</form>
<script>
// Keeps the hidden price in step with the selected radio, exactly as the real
// product page does. Everything here runs in your browser.
document.querySelectorAll('#buyForm input[name="item"]').forEach(function (r) {
    r.addEventListener('change', function () {
        var f = document.getElementById('buyForm');
        f.querySelector('input[name="unit_price"]').value =
            f.querySelector('input[name="unit_price_' + r.value + '"]').value;
    });
});
</script>
<?= biz_raw_form('bl_action=buy&item=cable&qty=1&unit_price=12.00',
        'This is the exact body the button above submits. Edit any field and send it.') ?>
<?= biz_reset_form() ?>
<?php
$form = biz_state_box('Your account', $stateHtml) . ob_get_clean();

$code = <<<'PHP'
// views/product.php renders the price into the form so the order summary
// widget can total the cart without another round trip:
//     <input type="hidden" name="unit_price" value="9999.00">

// POST /checkout
$item = catalog_lookup($_POST['item']);
$qty  = max(1, (int)$_POST['qty']);
$unit = (float)$_POST['unit_price'];   // <- came back from the browser
$total = $qty * $unit;

if ($total > $customer['balance']) {
    return error('insufficient funds');
}
$customer['balance'] -= $total;
place_order($item, $qty, $unit, $total);
PHP;

$fixBad = <<<'PHP'
$item  = catalog_lookup($_POST['item']);
$unit  = (float)$_POST['unit_price'];
$total = $qty * $unit;
PHP;

$fixGood = <<<'PHP'
// The request names the product. The server prices it. There is no third
// option, and no hidden field to tamper with because none is ever read.
$item  = catalog_lookup($_POST['item']);
$total = $qty * $item['price'];

// If the client genuinely needs to show a price it computed, treat the
// client's number as a claim to be confirmed, never as the amount to bill:
$quoted = (float)($_POST['quoted_total'] ?? $total);
if (abs($quoted - $total) > 0.001) {
    // The price changed between page load and submit. Show the new price
    // and make the customer confirm it - do not silently bill either one.
    return price_changed($item, $total);
}
PHP;

lk_page([
    'lab'        => bizlab(),
    'level'      => $L,
    'title'      => $meta['title'],
    'difficulty' => $meta['difficulty'],
    'extra_head' => biz_extra_head() . '<style>
        .biz-item { display:block; padding:0.3rem 0; font-size:0.85rem; }
        .biz-item input[type=radio] { margin-right:0.5rem; }
    </style>',

    'code'       => $code,
    'vuln_lines' => [3, 8, 9],
    'annotation' => 'The unit price makes a round trip through the browser and the checkout bills whatever comes
        back. The catalogue lookup on line 6 fetches the product but its <code>price</code> is never read again,
        so the server has a correct price in a variable and chooses the customer&rsquo;s instead.',

    'theory' => '<p>The reason this keeps happening is that the hidden field is not obviously input. The developer
        wrote both ends: the template that emits the value and the handler that reads it. From inside that story
        the value looks like a variable being passed between two of their own functions, and HTTP looks like nothing
        more than an unusually verbose way of passing it.</p>
        <p>It is not. Everything between <code>echo</code> and <code>$_POST</code> is under someone else&rsquo;s
        control. Hidden fields, disabled inputs, <code>readonly</code> attributes, values in a JWT the client can
        decode, query parameters in a signed-looking URL, prices in a cart object kept in <code>localStorage</code>
        - all of these are round trips through the attacker, and all of them come back as ordinary request
        parameters.</p>
        <p>The rule that survives every framework: <strong>if the server knows the answer, do not ask the
        client.</strong> Send the identifier, look up the fact. When the client legitimately needs to display a
        computed value, the client&rsquo;s copy is a claim to be reconciled, not a figure to be trusted - and a
        mismatch is a user-visible "the price has changed" flow, not a silent acceptance of either number.</p>',

    'fix' => [
        'bad'  => $fixBad,
        'good' => $fixGood,
        'note' => 'The same reasoning applies to quantity discounts, shipping bands, tax rates, currency codes and
            loyalty multipliers. Each one is a fact the server owns. Each one turns into a bug the moment it is
            rendered into a form and read back.',
    ],

    'scenario' => '<strong>Scenario:</strong> the same store, a week later. Someone added an Enterprise Support
        Contract at ' . shop_money(9999.00) . ' that is meant to be sold by the sales team, not self-served. You
        still have ' . shop_money(25.00) . ' of store credit.
        <br><strong>Goal:</strong> end up with an order for <code>ent-support</code> in your history.',

    'model' => [
        'title' => 'Which side of the wire knows what',
        'html'  => '<table class="lk-kv">
            <tr><td>server knows</td><td>the catalogue - <code>ent-support</code> costs ' . shop_money(9999.00) . '</td></tr>
            <tr><td>server asks the client for</td><td><code>item</code>, <code>qty</code>, <code>unit_price</code></td></tr>
            <tr><td>server bills</td><td><code>qty x unit_price</code></td></tr>
            <tr><td>server never checks</td><td>that <code>unit_price</code> equals the catalogue price</td></tr>
        </table>
        <p>Two of those three request fields are legitimately the customer&rsquo;s to choose. The third is not, and
        it is sitting in the same POST body as the other two with nothing marking it different.</p>
        <p>Use the request-body editor under the form. It shows the exact bytes the Buy button sends, which is what
        a proxy would show you, and it is editable - because in the real world so is the form.</p>',
    ],

    'form'     => $form,
    'result'   => $result,
    'flag'     => $flag,
    // Stateful levels can be reset after a solve, so the inline submit box
    // keeps accepting this level's flag even once the winning state is gone.
    'expected_flag' => biz_flag($L),
    'flag_msg' => 'The order exists, for the restricted product, at a price you chose.',
    'why'      => '<p>The trace shows the catalogue lookup succeeding on step 1 - the server had the real price of
        ' . shop_money(9999.00) . ' in hand. Step 3 then overwrote the price that mattered with yours, and step 5
        checked your balance against your own number.</p>
        <p>The flag was awarded because an order for <code>ent-support</code> exists in your history, not because
        you sent a particular price. Any price your balance covers reaches the same state, which is the honest
        definition of the bug: the amount charged is unconstrained.</p>
        <p>When you review a checkout, list every field in the request body and write next to each one who owns
        that fact. Any field owned by the server that appears in the list is the finding.</p>',

    'pipeline' => $pipeline,
    'probes'   => [
        'param'  => 'unit_price',
        'method' => 'POST',
        'action' => 'level2.php',
        'items'  => [
            ['q' => 'Does the server compare the submitted price with the catalogue at all?',
             'payload' => '11.00',
             'learn'   => 'A dollar off the USB-C cable. Harmless, cheap, and it answers the only question that matters before you go any further.'],
            ['q' => 'Is there a floor, or is any positive number accepted?',
             'payload' => '0.01',
             'learn'   => 'Tells you whether a minimum-price rule exists somewhere. Sends the default item, so nothing restricted is involved.'],
            ['q' => 'Is a negative price rejected?',
             'payload' => '-5.00',
             'learn'   => 'Combines this level with level 1. If a negative unit price were accepted, buying would pay you - worth knowing which of the two guards is present.'],
        ],
    ],
    'hints' => biz_hints($L),
]);
