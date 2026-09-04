<?php
require_once __DIR__ . '/helpers.php';

$L    = 1;
$meta = biz_levels()[$L];

shop_sid();
biz_handle_reset($L);

$catalog = shop_catalog($L);
$state   = shop_state($L);

$flag     = '';
$result   = '';
$pipeline = [];

/* =========================================================================
 * The shop. Two operations: add a line to the cart, and check out.
 * ===================================================================== */

// A bare POST carrying only `qty` (what the probe buttons send) is treated as
// an add, so a single-question probe does not need the rest of the form.
$action = (string)($_POST['bl_action'] ?? '');
if ($action === '' && isset($_POST['qty'])) {
    $action = 'add';
}

if ($action === 'add') {
    $itemId = (string)($_POST['item'] ?? 'mug');
    $rawQty = (string)($_POST['qty'] ?? '');
    $qty    = (int)$rawQty;                       // "-1" and "1" cast the same way

    $item  = $catalog[$itemId] ?? null;
    $price = $item ? (float)$item['price'] : 0.0;
    $line  = $qty * $price;

    // ── The stock rule, as written. One comparison. One direction. ────────
    $rejected = null;
    if (!$item) {
        $rejected = 'unknown item';
    } elseif ($qty > 10) {
        $rejected = 'maximum 10 per line';
    }

    $pipeline = [
        ['label' => '$_POST["qty"] (raw)', 'value' => $rawQty],
        ['label' => '$qty = (int)$_POST["qty"]', 'value' => (string)$qty,
         'note'  => 'A cast, not a validation. It happily produces negative integers.'],
        ['label' => 'if ($qty > 10) reject("maximum 10 per line")',
         'value' => $qty > 10 ? 'rejected' : 'accepted',
         'note'  => 'The rule the business wrote was "nobody buys more than ten". The rule the code enforces is '
                  . '"nobody buys <em>more</em> than ten" - it says nothing at all about the other end of the range.',
         'verdict' => $qty > 10 ? 'block' : 'pass'],
        ['label' => '$line = $qty * $price',
         'value' => $qty . ' x ' . shop_money($price) . ' = ' . shop_money($line),
         'note'  => $line < 0
            ? 'A negative line total. Nothing downstream treats this as unusual, because nothing downstream was told it could happen.'
            : 'An ordinary line total.'],
    ];

    if ($rejected !== null) {
        $result = biz_notice('error', 'Not added: ' . lk_esc($rejected) . '.');
    } else {
        $state['cart'][] = ['item' => $itemId, 'qty' => $qty, 'price' => $price, 'line' => shop_cents($line)];
        shop_put($L, $state);
        $result = biz_notice('info', 'Added ' . (int)$qty . ' x ' . lk_esc($item['name'])
                . ' - line total ' . shop_money($line) . '.');
    }
}

if ($action === 'checkout') {
    $total = 0.0;
    $steps = [];
    foreach ($state['cart'] as $i => $ln) {
        $total  += (float)$ln['line'];
        $steps[] = 'line ' . ($i + 1) . ': ' . $ln['qty'] . ' x ' . shop_money($ln['price'])
                 . ' = ' . shop_money($ln['line']) . '   running total ' . shop_money($total);
    }
    $total  = shop_cents($total);
    $before = (float)$state['balance'];

    // ── Checkout. The only guard is "can you afford it", which a negative
    //    total passes trivially, and then the subtraction runs regardless.
    $affordable = $total <= $before;

    $pipeline = [
        ['label' => 'sum of cart lines', 'value' => $steps ? implode("\n", $steps) : '(empty cart)'],
        ['label' => '$total', 'value' => shop_money($total)],
        ['label' => 'if ($total > $balance) reject("insufficient funds")',
         'value' => $affordable ? 'passed - ' . shop_money($total) . ' <= ' . shop_money($before) : 'rejected',
         'note'  => $total < 0
            ? 'A negative total is comfortably less than your balance, so the affordability check waves it through.'
            : 'Ordinary affordability check.',
         'verdict' => $affordable ? 'pass' : 'block'],
        ['label' => '$balance -= $total',
         'value' => shop_money($before) . ' - (' . shop_money($total) . ') = ' . shop_money($before - $total),
         'note'  => $total < 0
            ? 'Subtracting a negative number adds it. The shop has paid you to place an order.'
            : ''],
    ];

    if (!$state['cart']) {
        $result = biz_notice('error', 'Your cart is empty.');
    } elseif (!$affordable) {
        $result = biz_notice('error', 'Insufficient funds: order total ' . shop_money($total)
                . ', balance ' . shop_money($before) . '.');
    } else {
        $state['balance'] = shop_cents($before - $total);
        $state['orders'][] = ['total' => $total, 'lines' => count($state['cart'])];
        $state['cart']     = [];
        shop_put($L, $state);
        $result = biz_notice($total < 0 ? 'success' : 'info',
            'Order placed for ' . shop_money($total) . '. Balance is now ' . shop_money($state['balance']) . '.');
    }
}

/* ── The flag is awarded for the balance, not for the input that produced it. */
if ((float)$state['balance'] >= 100.00) {
    $flag = biz_flag($L);
}

/* =========================================================================
 * Panels
 * ===================================================================== */

$cartRows = [];
foreach ($state['cart'] as $ln) {
    $cartRows[] = [
        lk_esc($catalog[$ln['item']]['name'] ?? $ln['item']),
        (int)$ln['qty'],
        shop_money($ln['price']),
        shop_money($ln['line']),
    ];
}
$cartTotal = 0.0;
foreach ($state['cart'] as $ln) {
    $cartTotal += (float)$ln['line'];
}

$stateHtml = biz_kv([
    'Store credit'     => '<span class="biz-big">' . shop_money($state['balance']) . '</span>',
    'Orders placed'    => count($state['orders']),
    'Cart total'       => shop_money($cartTotal),
    'Target'           => 'store credit of ' . shop_money(100.00) . ' or more',
]) . biz_table(['Item', 'Qty', 'Unit', 'Line total'], $cartRows, 'cart is empty');

$options = '';
foreach ($catalog as $id => $it) {
    $options .= '<option value="' . lk_esc($id) . '">' . lk_esc($it['name']) . ' - '
              . shop_money($it['price']) . '</option>';
}

ob_start(); ?>
<form method="post" action="">
    <input type="hidden" name="bl_action" value="add">
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
    <button class="btn btn-primary" type="submit">Add to cart</button>
</form>
<form method="post" action="" style="margin-top:0.6rem">
    <input type="hidden" name="bl_action" value="checkout">
    <button class="btn btn-outline" type="submit">Check out (<?= count($state['cart']) ?> line<?= count($state['cart']) === 1 ? '' : 's' ?>)</button>
</form>
<?= biz_reset_form() ?>
<?php
$form = biz_state_box('Your account', $stateHtml) . ob_get_clean();

$code = <<<'PHP'
// POST /cart/add
$item = catalog_lookup($_POST['item']);
$qty  = (int)$_POST['qty'];

// Stock rule agreed with the merchandising team: "no more than ten per line".
if ($qty > 10) {
    return error('maximum 10 per line');
}

$cart[] = [
    'item'  => $item['id'],
    'qty'   => $qty,
    'price' => $item['price'],
    'line'  => $qty * $item['price'],   // sign is never considered
];

// POST /checkout
$total = 0.0;
foreach ($cart as $line) {
    $total += $line['line'];
}
if ($total > $customer['balance']) {
    return error('insufficient funds');
}
$customer['balance'] -= $total;         // subtracting a negative adds it
place_order($cart, $total);
PHP;

$fixBad = <<<'PHP'
$qty = (int)$_POST['qty'];
if ($qty > 10) {
    return error('maximum 10 per line');
}
PHP;

$fixGood = <<<'PHP'
// Bound the range on both sides, and reject anything that was not a whole
// number to begin with rather than letting the cast invent one.
$raw = $_POST['qty'] ?? '';
if (!is_string($raw) || !preg_match('/^[0-9]{1,3}$/', $raw)) {
    return error('quantity must be a whole number');
}
$qty = (int)$raw;
if ($qty < 1 || $qty > 10) {
    return error('quantity must be between 1 and 10');
}

// And enforce the invariant again where the money is, not only where the
// input is. A line total below zero is a bug in this shop, so say so:
$line = $qty * $item['price'];
if ($line < 0) {
    throw new LogicException('negative line total for order ' . $orderId);
}
PHP;

lk_page([
    'lab'        => bizlab(),
    'level'      => $L,
    'title'      => $meta['title'],
    'difficulty' => $meta['difficulty'],
    'extra_head' => biz_extra_head(),

    'code'       => $code,
    'vuln_lines' => [6, 7, 8, 15],
    'annotation' => 'The quantity is bounded above and not below. A negative quantity produces a negative line
        total, a negative order total, and a checkout that runs <code>$balance -= $total</code> on a negative
        number. Every individual statement is correct; the set of values they were written for was never
        written down.',

    'theory' => '<p>This is the simplest business-logic bug there is, and it is still found in production every
        year. There is no injection, no parser, no encoding. The developer had a rule in their head - "a customer
        buys between one and ten of a thing" - and expressed half of it.</p>
        <p>The reason a scanner does not find it is that nothing about the request is malformed. <code>qty=-1</code>
        is a perfectly well-typed integer arriving at a field that expects an integer. There is no anomaly to
        detect at the boundary. The anomaly is <em>semantic</em>: the value is legal for the type and illegal for
        the domain, and only the domain knows the difference.</p>
        <p>Generalise it and you have a review question worth asking of every numeric input in an application:
        the code checks that this value is not too big, so what stops it being too small, or zero, or fractional,
        or larger than the field it will eventually be stored in? Each of those is its own level later in this
        lab.</p>',

    'fix' => [
        'bad'  => $fixBad,
        'good' => $fixGood,
        'note' => 'Two habits worth keeping. Validate the range on both sides at the boundary, and then assert the
            invariant again next to the money. Boundary validation stops the bad request; the assertion next to the
            money catches the day someone adds a second code path that skips the boundary.',
    ],

    'scenario' => '<strong>Scenario:</strong> the merch store. You have <strong>' . shop_money(25.00) . '</strong>
        of store credit and there is nothing in the catalogue you can afford. Quantities are capped at ten per
        line, and checkout refuses to run if the order costs more than your balance.
        <br><strong>Goal:</strong> place an order and come out of it with a store credit balance of
        <strong>' . shop_money(100.00) . '</strong> or more.',

    'model' => [
        'title' => 'The three statements the money passes through',
        'html'  => '<table class="lk-kv">
            <tr><td>1. cast</td><td><code>$qty = (int)$_POST["qty"]</code> - accepts any integer, sign included</td></tr>
            <tr><td>2. rule</td><td><code>if ($qty &gt; 10) reject</code> - upper bound only</td></tr>
            <tr><td>3. money</td><td><code>$line = $qty * $price</code>, then <code>$balance -= $total</code></td></tr>
        </table>
        <p>Read those three lines as a single expression and substitute a value of your choosing for
        <code>$qty</code>. That substitution is the entire level; the shop below is only there so you can watch it
        happen to a real balance.</p>
        <p>The trace under the form prints each of the three steps with your number in it, including the sign, so
        a rejected attempt tells you which of the three stopped you.</p>',
    ],

    'form'     => $form,
    'result'   => $result,
    'flag'     => $flag,
    // Stateful levels can be reset after a solve, so the inline submit box
    // keeps accepting this level's flag even once the winning state is gone.
    'expected_flag' => biz_flag($L),
    'flag_msg' => 'Your balance went up because the shop subtracted a negative number from it.',
    'why'      => '<p>The order total was negative, so <code>$total &gt; $balance</code> was false and the
        affordability check passed. Then <code>$balance -= $total</code> executed exactly as written, and
        subtracting a negative is addition.</p>
        <p>Notice what the flag was awarded for: the <strong>balance in your account</strong>, not the string you
        typed. That is the only sound way to grade a logic bug. The input is unremarkable - it is the state the
        application ends up in that is impossible.</p>
        <p>The same shape turns up outside carts: a transfer amount, a stock adjustment, a leave-days request, a
        loyalty redemption. Anywhere a number is multiplied by money, ask what the smallest accepted value is.</p>',

    'pipeline' => $pipeline,
    'probes'   => [
        'param'  => 'qty',
        'method' => 'POST',
        'action' => 'level1.php',
        'items'  => [
            ['q' => 'Is the upper bound real, or is the message decorative?',
             'payload' => '11',
             'learn'   => 'Confirms the one rule that exists is actually enforced. Knowing which checks are real narrows where the flaw can be.'],
            ['q' => 'Does the field accept a value that is not a positive integer at all?',
             'payload' => '0',
             'learn'   => 'Zero is harmless and tells you whether anything rejects non-positive quantities. If zero is accepted, the lower bound is missing entirely.'],
            ['q' => 'Does a non-numeric string get rejected or cast?',
             'payload' => '3abc',
             'learn'   => 'PHP casts this to 3 rather than refusing it. Worth knowing before you assume any string input is being validated as a number.'],
        ],
    ],
    'hints' => biz_hints($L),
]);
