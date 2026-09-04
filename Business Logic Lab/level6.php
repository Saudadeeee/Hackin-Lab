<?php
require_once __DIR__ . '/helpers.php';

$L    = 6;
$meta = biz_levels()[$L];

shop_sid();
biz_handle_reset($L);
biz_apply_raw_body();

$catalog = shop_catalog($L);
$state   = shop_state($L);

$flag     = '';
$result   = '';
$pipeline = [];

/**
 * The checkout state machine.
 *   cart -> address_set -> authorised -> paid
 * Three handlers check the state they are coming from. One does not.
 */
$FLOW = ['cart' => 'address', 'address_set' => 'payment', 'authorised' => 'confirm', 'paid' => null];

$step   = (string)($_POST['step'] ?? '');
$order  = is_array($state['order']) ? $state['order'] : null;

if ($step !== '') {
    $from   = $order['status'] ?? '(no order)';
    $stages = [['label' => 'requested step', 'value' => $step],
               ['label' => 'order status before the request', 'value' => (string)$from]];
    $err    = null;

    switch ($step) {
        case 'start':
            $itemId = (string)($_POST['item'] ?? 'desk');
            $item   = $catalog[$itemId] ?? null;
            if (!$item) {
                $err = 'unknown item';
                break;
            }
            $order = [
                'id'          => 'ORD-' . strtoupper(substr(bin2hex(random_bytes(3)), 0, 6)),
                'item'        => $itemId,
                'name'        => $item['name'],
                'total'       => shop_cents((float)$item['price']),
                'status'      => 'cart',
                'address'     => '',
                'amount_paid' => 0.00,
            ];
            $stages[] = ['label' => 'order created', 'value' => $order['id'] . ' - ' . $order['name']
                       . ' - ' . shop_money($order['total']), 'verdict' => 'pass'];
            break;

        case 'address':
            // guard present
            if (!$order)                        { $err = 'no order in progress'; break; }
            if ($order['status'] !== 'cart')    { $err = 'order is not in the cart state'; break; }
            $order['address'] = trim((string)($_POST['address'] ?? '')) ?: '221B Baker Street, London';
            $order['status']  = 'address_set';
            $stages[] = ['label' => 'if ($order["status"] !== "cart") deny',
                         'value' => 'passed - status was cart', 'verdict' => 'pass'];
            break;

        case 'payment':
            // guard present
            if (!$order)                            { $err = 'no order in progress'; break; }
            if ($order['status'] !== 'address_set') { $err = 'no delivery address on this order'; break; }
            $stages[] = ['label' => 'if ($order["status"] !== "address_set") deny',
                         'value' => 'passed - status was address_set', 'verdict' => 'pass'];
            if ((float)$order['total'] > (float)$state['balance']) {
                $err = 'card declined: balance ' . shop_money($state['balance'])
                     . ' does not cover ' . shop_money($order['total']);
                $stages[] = ['label' => 'authorise ' . shop_money($order['total']),
                             'value' => 'declined', 'verdict' => 'block'];
                break;
            }
            $state['balance']     = shop_cents((float)$state['balance'] - (float)$order['total']);
            $order['amount_paid'] = shop_cents((float)$order['total']);
            $order['status']      = 'authorised';
            $stages[] = ['label' => 'authorise ' . shop_money($order['total']),
                         'value' => 'approved, amount_paid = ' . shop_money($order['amount_paid']),
                         'verdict' => 'pass'];
            break;

        case 'confirm':
            // ── The handler with no guard. Three lines, as shipped. ───────
            if (!$order) {
                $err = 'no order in progress';
                break;
            }
            $stages[] = ['label' => 'if (!$order) redirect("/cart")',
                         'value' => 'an order exists, so we continue',
                         'note'  => 'That is the whole check. The handler never asks which state the order is in, '
                                  . 'and never looks at <code>amount_paid</code>.',
                         'verdict' => 'pass'];
            $order['status']    = 'paid';
            $order['placed_at'] = date('H:i:s');
            $stages[] = ['label' => '$order["status"] = "paid"; ship($order)',
                         'value' => 'status is now paid, amount_paid is ' . shop_money($order['amount_paid']),
                         'verdict' => (float)$order['amount_paid'] < (float)$order['total'] ? 'pass' : null];
            break;

        default:
            $err = 'unknown step';
    }

    if ($err !== null) {
        $stages[] = ['label' => 'result', 'value' => 'denied - ' . $err, 'verdict' => 'block'];
        $result   = biz_notice('error', 'Step <code>' . lk_esc($step) . '</code> denied: ' . lk_esc($err) . '.');
    } else {
        $state['order']     = $order;
        $state['history'][] = ['step' => $step, 'status' => $order['status'], 'at' => date('H:i:s')];
        shop_put($L, $state);
        $result = biz_notice($order['status'] === 'paid' && (float)$order['amount_paid'] <= 0.0 ? 'success' : 'info',
            'Step <code>' . lk_esc($step) . '</code> accepted. Order ' . lk_esc($order['id'])
            . ' is now <strong>' . lk_esc($order['status']) . '</strong>.');
    }
    $pipeline = $stages;
    $order    = is_array($state['order']) ? $state['order'] : null;
}

/* ── Flag: an order in the paid state that nobody paid for. ────────────── */
if ($order && $order['status'] === 'paid' && (float)$order['amount_paid'] < (float)$order['total']) {
    $flag = biz_flag($L);
}

/* =========================================================================
 * Panels
 * ===================================================================== */

$status = $order['status'] ?? '(none)';
$stateHtml = biz_kv([
    'Store credit' => '<span class="biz-big">' . shop_money($state['balance']) . '</span>',
    'Order'        => $order ? lk_esc($order['id']) . ' &middot; ' . lk_esc($order['name'])
                             . ' &middot; ' . shop_money($order['total']) : 'no order in progress',
    'Status'       => '<code>' . lk_esc($status) . '</code>',
    'Address'      => $order && $order['address'] !== '' ? lk_esc($order['address']) : '&mdash;',
    'Amount paid'  => $order ? shop_money($order['amount_paid']) : '&mdash;',
    'Target'       => 'status <code>paid</code> with <code>amount_paid</code> below the order total',
]);

$histRows = [];
foreach ($state['history'] as $h) {
    $histRows[] = [lk_esc($h['at']), '<code>' . lk_esc($h['step']) . '</code>', '<code>' . lk_esc($h['status']) . '</code>'];
}
$stateHtml .= '<p class="lk-hintline" style="margin-top:0.7rem">Steps taken</p>'
            . biz_table(['Time', 'Step', 'Resulting status'], $histRows, 'no steps taken yet');

/** A step button, disabled by the template when the flow says it is not next. */
$btn = function (string $s, string $label) use ($order, $FLOW): string {
    $expected = $order ? ($FLOW[$order['status']] ?? null) : 'start';
    if (!$order && $s !== 'start') {
        $expected = 'start';
    }
    $enabled = ($s === $expected) || ($s === 'start' && !$order);
    return '<form method="post" action="" style="display:inline">'
         . '<input type="hidden" name="step" value="' . lk_esc($s) . '">'
         . '<button class="btn ' . ($enabled ? 'btn-primary' : 'btn-outline') . '" type="submit"'
         . ($enabled ? '' : ' disabled') . '>' . lk_esc($label) . '</button></form>';
};

ob_start(); ?>
<form method="post" action="">
    <input type="hidden" name="step" value="start">
    <div class="biz-grid">
        <div class="form-group">
            <label class="form-label">Start a new order for</label>
            <select name="item" class="form-control">
                <?php foreach ($catalog as $id => $it): ?>
                    <option value="<?= lk_esc($id) ?>"<?= $id === 'desk' ? ' selected' : '' ?>>
                        <?= lk_esc($it['name']) ?> - <?= shop_money($it['price']) ?>
                    </option>
                <?php endforeach; ?>
            </select>
        </div>
    </div>
    <button class="btn btn-primary" type="submit">1. Add to cart</button>
</form>
<div class="biz-steps">
    <?= $btn('address', '2. Save address') ?>
    <?= $btn('payment', '3. Pay') ?>
    <?= $btn('confirm', '4. Confirm order') ?>
</div>
<?= biz_raw_form('step=address', 'The step buttons above are disabled by the page template when the flow says '
        . 'they are not next. That decision is made in your browser. This box posts whatever you type.') ?>
<?= biz_reset_form() ?>
<?php
$form = biz_state_box('Checkout ' . ($order['id'] ?? ''), $stateHtml) . ob_get_clean();

$code = <<<'PHP'
// POST /checkout/address
$order = current_order();
if (!$order)                            return redirect('/cart');
if ($order['status'] !== 'cart')        return deny('wrong step');
$order['address'] = validate_address($_POST['address']);
$order['status']  = 'address_set';

// POST /checkout/payment
$order = current_order();
if (!$order)                            return redirect('/cart');
if ($order['status'] !== 'address_set') return deny('wrong step');
$auth = gateway_authorise($order['total'], $_POST['card']);
if (!$auth->approved)                   return deny('card declined');
$order['amount_paid'] = $order['total'];
$order['status']      = 'authorised';

// POST /checkout/confirm
$order = current_order();
if (!$order)                            return redirect('/cart');
$order['status']      = 'paid';          // <- the payment step ran. Did it?
$order['placed_at']   = now();
fulfilment_dispatch($order);
PHP;

$fixBad = <<<'PHP'
// confirm
$order = current_order();
if (!$order) return redirect('/cart');
$order['status'] = 'paid';
PHP;

$fixGood = <<<'PHP'
// Every transition states where it may be entered from, and the money is
// checked against the gateway rather than against a field the app set itself.
const TRANSITIONS = [
    'cart'        => ['address_set'],
    'address_set' => ['authorised'],
    'authorised'  => ['paid', 'cancelled'],
    'paid'        => ['shipped', 'refunded'],
];

function transition(array &$order, string $to): void
{
    $from = $order['status'];
    if (!in_array($to, TRANSITIONS[$from] ?? [], true)) {
        throw new IllegalTransition("$from -> $to");
    }
    $order['status'] = $to;
}

// POST /checkout/confirm
$order = current_order() ?? redirect('/cart');
$auth  = gateway_fetch_authorisation($order['id']);   // ask the gateway
if (!$auth || $auth->amount < $order['total']) {
    return deny('not paid');
}
transition($order, 'paid');
PHP;

lk_page([
    'lab'        => bizlab(),
    'level'      => $L,
    'title'      => $meta['title'],
    'difficulty' => $meta['difficulty'],
    'extra_head' => biz_extra_head(),

    'code'       => $code,
    'vuln_lines' => [19, 20, 21, 22, 23],
    'annotation' => 'The address and payment handlers each verify the state they are being entered from. The
        confirm handler verifies only that an order exists. It marks the order paid and dispatches it to
        fulfilment without ever consulting <code>status</code> or <code>amount_paid</code>, because the developer
        writing it knew that the payment step ran immediately before - in the browser.',

    'theory' => '<p>A checkout is a state machine, and the safe way to build one is to write down the states and
        the permitted transitions in a single place. What usually happens instead is that each page is written as
        a page: it knows what it does, it knows what the previous page was, and the guard it carries is whatever
        the author remembered while writing that file. Guards accumulate unevenly, and the last step - the one
        that runs after everything important has already happened - is the one most likely to be written as if it
        could not be reached out of order.</p>
        <p>The UI reinforces the illusion. Buttons are hidden or disabled, wizard steps grey out, the router
        redirects. All of that is presentation, evaluated in a browser the server does not control, and none of it
        is reflected in the handler. A request is not a click. Any endpoint can be called at any time, in any
        order, any number of times, by anyone who holds the session.</p>
        <p>The second half of the lesson is about who is authoritative for payment. Here the order is marked paid
        by the application setting its own field. The only party that knows whether money moved is the payment
        gateway, and the only sound confirmation is to ask it - by webhook or by a server-to-server lookup keyed on
        the order id. An application that trusts its own <code>amount_paid</code> field has replaced a payment
        check with a bookkeeping entry it wrote itself.</p>',

    'fix' => [
        'bad'  => $fixBad,
        'good' => $fixGood,
        'note' => 'One transition table, consulted by every handler, so adding a state cannot silently leave a
            handler unguarded. And confirm the payment with the gateway, not with a local field - the local field
            is the thing being attacked.',
    ],

    'scenario' => '<strong>Scenario:</strong> a four-step checkout - cart, address, payment, confirm. The Standing
        Desk costs ' . shop_money(649.00) . ' and you have ' . shop_money(25.00) . ' of store credit, so the
        payment step is closed to you. The Desk Mat at ' . shop_money(19.00) . ' is affordable if you want to
        watch the honest flow work first.
        <br><strong>Goal:</strong> get an order into the <code>paid</code> state with <code>amount_paid</code>
        still below its total.',

    'model' => [
        'title' => 'The state machine, and which edges are checked',
        'html'  => '<table class="data-table">
            <thead><tr><th>Handler</th><th>Requires status</th><th>Sets status</th></tr></thead>
            <tbody>
                <tr><td><code>start</code></td><td>no order yet</td><td><code>cart</code></td></tr>
                <tr><td><code>address</code></td><td><code>cart</code></td><td><code>address_set</code></td></tr>
                <tr><td><code>payment</code></td><td><code>address_set</code></td><td><code>authorised</code></td></tr>
                <tr><td><code>confirm</code></td><td><em>only that an order exists</em></td><td><code>paid</code></td></tr>
            </tbody>
        </table>
        <p>Three rows name a specific predecessor. One does not. That table is the level; everything below it is
        only a way of sending the request.</p>
        <p>The step buttons are rendered disabled when the flow says they are not next. <code>disabled</code> is an
        attribute on an element in your browser - the server never sees it, and the endpoint has no idea a button
        existed. Use the raw request box to send a step name directly.</p>',
    ],

    'form'     => $form,
    'result'   => $result,
    'flag'     => $flag,
    // Stateful levels can be reset after a solve, so the inline submit box
    // keeps accepting this level's flag even once the winning state is gone.
    'expected_flag' => biz_flag($L),
    'flag_msg' => 'The order is marked paid and dispatched. No money moved.',
    'why'      => '<p>The trace shows the confirm handler doing exactly what it was written to do: it checked that
        an order existed, found one, and set the status. It never asked what state the order was in, so the fact
        that it had never been through payment was not information the handler had.</p>
        <p>The flag was awarded for the pair (<code>status = paid</code>, <code>amount_paid</code> below the
        total). That combination is impossible on the intended path and is the honest signature of the bug - much
        better than looking for a particular request, because several orderings reach it.</p>
        <p>When you test a multi-step flow, complete it once legitimately and write down every endpoint and the
        state each one expects. Then replay them out of order: skip one, repeat one, run the last one first. The
        step that produces the valuable state change while checking the least is where to look.</p>',

    'pipeline' => $pipeline,
    'probes'   => [
        'param'  => 'step',
        'method' => 'POST',
        'action' => 'level6.php',
        'items'  => [
            ['q' => 'Does the address step check where it is coming from?',
             'payload' => 'address',
             'learn'   => 'Send it before creating an order. The denial message names the state the handler expected, which tells you the guard exists and what shape it has.'],
            ['q' => 'Does the payment step check the same way?',
             'payload' => 'payment',
             'learn'   => 'Same question, next handler. Two handlers with guards establishes the pattern, so the one without a guard stands out.'],
            ['q' => 'What does an unrecognised step do?',
             'payload' => 'ship',
             'learn'   => 'Confirms there is a default branch and that the router is not silently accepting anything. Harmless, and it rules out a whole class of guesses.'],
        ],
    ],
    'hints' => biz_hints($L),
]);
