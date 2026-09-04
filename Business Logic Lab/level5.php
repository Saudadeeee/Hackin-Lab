<?php
require_once __DIR__ . '/helpers.php';

$L    = 5;
$meta = biz_levels()[$L];

shop_sid();
biz_handle_reset($L);

$catalog = shop_catalog($L);
$state   = shop_state($L);

$flag     = '';
$result   = '';
$pipeline = [];

const BIZ_QTY_CEILING = 5000000000;      // the web tier's idea of "too many"

/* =========================================================================
 * The shop. One operation: buy N of something.
 *
 * The web tier validates the quantity in PHP, where integers are 64-bit.
 * The order is then handed to the fulfilment service, whose wire format
 * stores quantity in a signed 32-bit field - and the price is computed from
 * the quantity the fulfilment service echoed back.
 * ===================================================================== */

if (($_POST['bl_action'] ?? '') === 'buy' || isset($_POST['qty'])) {
    $itemId = (string)($_POST['item'] ?? 'giftcard');
    $rawQty = (string)($_POST['qty'] ?? '');
    $item   = $catalog[$itemId] ?? null;
    $price  = $item ? (float)$item['price'] : 0.0;

    $qty = (int)$rawQty;                                   // 64-bit here

    // ── Web-tier validation. Both bounds present. Level 1 was fixed. ──────
    $rejected = null;
    if (!$item) {
        $rejected = 'unknown item';
    } elseif ($qty < 1) {
        $rejected = 'quantity must be at least 1';
    } elseif ($qty > BIZ_QTY_CEILING) {
        $rejected = 'quantity may not exceed ' . number_format(BIZ_QTY_CEILING);
    }

    // ── Hand-off to the warehouse: an int32 field on the wire. ────────────
    $effective = shop_warehouse_qty($qty);
    $total     = shop_cents($effective * $price);

    $before     = (float)$state['balance'];
    $affordable = $total <= $before;

    $pipeline = [
        ['label' => '$_POST["qty"] (raw)', 'value' => $rawQty],
        ['label' => '$qty = (int)$_POST["qty"]  // PHP int, 64-bit',
         'value' => number_format($qty),
         'note'  => 'PHP_INT_MAX on this machine is ' . number_format(PHP_INT_MAX)
                  . ', so nothing has been lost yet.'],
        ['label' => 'if ($qty < 1 || $qty > 5,000,000,000) reject',
         'value' => $rejected === null ? 'accepted' : 'rejected - ' . $rejected,
         'note'  => 'Both bounds are present this time. The ceiling was chosen to be generously above any real '
                  . 'order, and it was chosen in a language where that number fits comfortably in an integer.',
         'verdict' => $rejected === null ? 'pass' : 'block'],
        ['label' => 'warehouse wire format: unpack("l", pack("l", $qty))',
         'value' => number_format($qty) . '  ->  ' . number_format($effective),
         'note'  => $effective !== $qty
            ? 'The four bytes that fit were kept and reinterpreted as signed. '
              . number_format($qty) . ' is above the signed 32-bit maximum of '
              . number_format(2147483647) . ', so it comes back as '
              . number_format($effective) . '. No error was raised anywhere, because from the field\'s point of '
              . 'view nothing went wrong - it stored a perfectly valid int32.'
            : 'Fits in 32 bits, so the value survives the round trip unchanged.',
         'verdict' => $effective !== $qty ? 'pass' : null],
        ['label' => '$total = $effectiveQty * $price',
         'value' => number_format($effective) . ' x ' . shop_money($price) . ' = ' . shop_money($total),
         'note'  => $total < 0 ? 'A negative order total, produced without ever sending a negative number.' : ''],
        ['label' => 'if ($total > $balance) reject("insufficient funds")',
         'value' => $affordable ? 'passed' : 'rejected',
         'verdict' => $affordable ? 'pass' : 'block'],
    ];

    if ($rejected !== null) {
        $result = biz_notice('error', 'Rejected: ' . lk_esc($rejected) . '.');
    } elseif (!$affordable) {
        $result = biz_notice('error', 'Insufficient funds: order total ' . shop_money($total)
                . ', balance ' . shop_money($before) . '.');
    } else {
        $state['balance'] = shop_cents($before - $total);
        $state['orders'][] = ['item' => $itemId, 'name' => $item['name'], 'requested' => $qty,
                              'effective' => $effective, 'total' => $total];
        shop_put($L, $state);
        $result = biz_notice($total < 0 ? 'success' : 'info',
            'Order placed. Warehouse quantity ' . number_format($effective) . ', total '
            . shop_money($total) . '. Balance is now ' . shop_money($state['balance']) . '.');
    }
}

/* ── Flag: the balance actually reached, not the number that was typed. ── */
if ((float)$state['balance'] >= 1000000.00) {
    $flag = biz_flag($L);
}

/* =========================================================================
 * Panels
 * ===================================================================== */

$orderRows = [];
foreach ($state['orders'] as $o) {
    $orderRows[] = [
        lk_esc($o['name']),
        number_format((int)$o['requested']),
        number_format((int)$o['effective']),
        shop_money($o['total']),
    ];
}

$stateHtml = biz_kv([
    'Store credit' => '<span class="biz-big">' . shop_money($state['balance']) . '</span>',
    'Target'       => 'store credit of ' . shop_money(1000000.00) . ' or more',
    'Quantity ceiling (web tier)' => number_format(BIZ_QTY_CEILING),
    'Quantity field (warehouse)'  => 'signed 32-bit: ' . number_format(-2147483648) . ' to '
                                   . number_format(2147483647),
]) . biz_table(['Item', 'Requested qty', 'Warehouse qty', 'Order total'], $orderRows, 'no orders yet');

$options = '';
foreach ($catalog as $id => $it) {
    $options .= '<option value="' . lk_esc($id) . '">' . lk_esc($it['name']) . ' - '
              . shop_money($it['price']) . '</option>';
}

ob_start(); ?>
<form method="post" action="">
    <input type="hidden" name="bl_action" value="buy">
    <div class="biz-grid">
        <div class="form-group">
            <label class="form-label">Item</label>
            <select name="item" class="form-control"><?= $options ?></select>
        </div>
        <div class="form-group">
            <label class="form-label">Quantity</label>
            <input type="text" name="qty" class="form-control" value="1" autocomplete="off" spellcheck="false">
        </div>
    </div>
    <button class="btn btn-primary" type="submit">Place order</button>
</form>
<?= biz_reset_form() ?>
<?php
$form = biz_state_box('Your account', $stateHtml) . ob_get_clean();

$code = <<<'PHP'
// POST /order  - web tier (PHP, 64-bit integers)
$qty = (int)$_POST['qty'];
if ($qty < 1 || $qty > 5_000_000_000) {      // level 1's bug: fixed
    return error('invalid quantity');
}

// Hand the order to fulfilment. Their wire format is fixed-width binary and
// the quantity field is a signed 32-bit integer; the client library packs it.
$message   = pack('l', $qty);                // four bytes, silently truncated
$accepted  = warehouse_submit($message);
$effective = unpack('l', $accepted)[1];      // what the warehouse will ship

// Price the order from the quantity that was actually accepted.
$total = $effective * $item['price'];
if ($total > $customer['balance']) {
    return error('insufficient funds');
}
$customer['balance'] -= $total;
PHP;

$fixBad = <<<'PHP'
if ($qty < 1 || $qty > 5_000_000_000) {   // range chosen in a 64-bit language
    return error('invalid quantity');
}
$message = pack('l', $qty);               // stored in a 32-bit field
PHP;

$fixGood = <<<'PHP'
// The validation bound belongs to the narrowest type in the pipeline, not to
// the language the validation happens to be written in. Better still: pick a
// bound the business can defend, which is always far smaller than any type.
const MAX_LINE_QTY = 1000;                   // fulfilment cannot pick more

if ($qty < 1 || $qty > MAX_LINE_QTY) {
    return error('quantity must be between 1 and ' . MAX_LINE_QTY);
}

// And make the truncation impossible to ignore rather than silent. If the
// value cannot be represented, that is an error, not a different value.
if ($qty !== unpack('l', pack('l', $qty))[1]) {
    throw new RangeException('quantity does not fit the fulfilment field');
}

// Finally, an invariant next to the money: an order the customer places can
// never have a total below zero, whatever arithmetic produced it.
if ($total < 0) {
    throw new LogicException('negative order total');
}
PHP;

lk_page([
    'lab'        => bizlab(),
    'level'      => $L,
    'title'      => $meta['title'],
    'difficulty' => $meta['difficulty'],
    'extra_head' => biz_extra_head(),

    'code'       => $code,
    'vuln_lines' => [3, 4, 5, 9],
    'annotation' => 'The web tier validates the quantity against a ceiling of five billion, which is a fine number
        for a 64-bit PHP integer and impossible for the signed 32-bit field the fulfilment protocol stores it in.
        Every value between 2,147,483,648 and the ceiling passes validation and then becomes a different number -
        often a negative one - before it is priced.',

    'theory' => '<p>A validation says which values are permitted. A type says which values can exist. When the
        permitted range is wider than the representable range, the values in the gap are not rejected: they are
        <em>transformed</em>, quietly, into values that were never validated at all. Whatever check ran upstream is
        now a statement about a number that no longer exists.</p>
        <p>The reason this survives review is that the two facts live in different documents. The ceiling is in the
        API validation layer, written by someone thinking about plausible order sizes in a language with 64-bit
        integers. The field width is in a protocol definition, an IDL file, a database column, or a downstream
        service written in a language where <code>int</code> means 32 bits. Neither author is wrong on their own
        page.</p>
        <p>The same mismatch produces a long family of bugs: an <code>INT</code> column behind a <code>bigint</code>
        API, a JavaScript client that loses precision above 2^53 talking to a 64-bit backend, a
        <code>smallint</code> stock level, a C service reading a length field. The question to ask at every service
        boundary is not "is this value valid" but "is this value representable on the other side, and what happens
        if it is not".</p>',

    'fix' => [
        'bad'  => $fixBad,
        'good' => $fixGood,
        'note' => 'Bound the input by the narrowest type it will pass through, and pick a business limit far below
            even that. Then make truncation loud: comparing the value with its own round trip through the field is
            two lines and turns a silent wrap into an exception.',
    ],

    'scenario' => '<strong>Scenario:</strong> the merch store again, after level 1 was reported and fixed.
        Quantities below 1 are rejected properly now, and there is a generous upper bound. The gift-card SKU costs
        ' . shop_money(10.00) . ' and you have ' . shop_money(25.00) . ' of store credit.
        <br><strong>Goal:</strong> reach a store credit balance of ' . shop_money(1000000.00) . ' or more.',

    'model' => [
        'title' => 'Two different ideas of how large a number can be',
        'html'  => '<table class="lk-kv">
            <tr><td>PHP integer</td><td>64-bit: up to ' . number_format(PHP_INT_MAX) . '</td></tr>
            <tr><td>web-tier ceiling</td><td>' . number_format(BIZ_QTY_CEILING) . '</td></tr>
            <tr><td>warehouse field</td><td>signed 32-bit: ' . number_format(-2147483648) . ' to '
                . number_format(2147483647) . '</td></tr>
            <tr><td>the gap</td><td>' . number_format(2147483648) . ' to ' . number_format(BIZ_QTY_CEILING)
                . ' - accepted upstream, unrepresentable downstream</td></tr>
        </table>
        <p>Values in that gap keep only their low 32 bits, and those bits are then read back as a <em>signed</em>
        number. Anything with the top bit set comes back negative. The smallest such value is one past the signed
        maximum, which is where the wrap begins.</p>
        <p>You already know from level 1 what a negative quantity does to <code>$balance -= $total</code>. This
        level is that same ending reached without ever sending a negative number - which is exactly why the
        level-1 fix does not stop it.</p>',
    ],

    'form'     => $form,
    'result'   => $result,
    'flag'     => $flag,
    // Stateful levels can be reset after a solve, so the inline submit box
    // keeps accepting this level's flag even once the winning state is gone.
    'expected_flag' => biz_flag($L),
    'flag_msg' => 'You never sent a negative quantity. The wire format produced one for you.',
    'why'      => '<p>Trace step 3 shows the validation passing honestly: your quantity was above 1 and below the
        five-billion ceiling. Step 4 then shows the same number arriving at the warehouse as a negative one,
        because the four bytes that fit were reinterpreted as signed. Step 5 priced the order from that.</p>
        <p>Notice which check would have caught this and which would not. A stricter lower bound does nothing here.
        A stricter <em>upper</em> bound - one below 2,147,483,647 - fixes it completely, and so does asserting the
        order total is not negative. Two independent guards, either of which is enough, which is the usual sign
        that neither was thought about.</p>
        <p>When you map an application, note the type of every numeric field at every hop: HTTP, JSON, the ORM, the
        column, the queue message, the downstream service. The narrowest one governs, and it is rarely the one the
        validation was written against.</p>',

    'pipeline' => $pipeline,
    'probes'   => [
        'param'  => 'qty',
        'method' => 'POST',
        'action' => 'level5.php',
        'items'  => [
            ['q' => 'Was the level-1 bug actually fixed here?',
             'payload' => '-1',
             'learn'   => 'Rules out the easy answer in one request. If this is rejected, the negative number has to come from somewhere other than your keyboard.'],
            ['q' => 'Where exactly does the warehouse field stop?',
             'payload' => '2147483647',
             'learn'   => 'The signed 32-bit maximum. Trace step 4 shows it surviving the round trip intact, which pins down the boundary without spending anything - the balance check rejects the order afterwards.'],
            ['q' => 'Is the ceiling in the error message the real ceiling?',
             'payload' => '5000000001',
             'learn'   => 'One past the advertised limit. Confirms the upper bound is enforced and tells you the exact width of the window you have to work in.'],
        ],
    ],
    'hints' => biz_hints($L),
]);
