<?php
require_once __DIR__ . '/helpers.php';

$L    = 8;
$meta = biz_levels()[$L];

shop_sid();
biz_handle_reset($L);

$state = shop_state($L);
$order = $state['order'];

$flag     = '';
$result   = '';
$pipeline = [];

$refundedSoFar = 0.0;
foreach ($state['refunds'] as $r) {
    $refundedSoFar += (float)$r['amount'];
}
$refundedSoFar = shop_cents($refundedSoFar);

/* =========================================================================
 * The refunds desk. One operation: refund an amount against a line.
 *
 * The validation compares the requested amount with the line it belongs to.
 * It never compares anything with what has already been refunded.
 * ===================================================================== */

if (($_POST['bl_action'] ?? '') === 'refund' || isset($_POST['amount'])) {
    $lineNo = (int)($_POST['line'] ?? 1);
    $amount = round((float)($_POST['amount'] ?? 0), 2);
    $line   = $order['lines'][$lineNo - 1] ?? null;

    // ── Per-request validation. Correct, and about the wrong quantity. ────
    $err = null;
    if (!$line) {
        $err = 'no such line on this order';
    } elseif ($amount <= 0) {
        $err = 'refund amount must be positive';
    } elseif ($amount > (float)$line['total']) {
        $err = 'refund of ' . shop_money($amount) . ' exceeds the line total of '
             . shop_money($line['total']);
    }

    $lineRefunded = 0.0;
    foreach ($state['refunds'] as $r) {
        if ((int)$r['line'] === $lineNo) {
            $lineRefunded += (float)$r['amount'];
        }
    }

    $pipeline = [
        ['label' => 'requested refund',
         'value' => 'line ' . $lineNo . ' - ' . shop_money($amount)
                  . ($line ? '  (' . $line['item'] . ', line total ' . shop_money($line['total']) . ')' : '')],
        ['label' => 'if ($amount > $line["total"]) reject',
         'value' => $line && $amount > (float)$line['total']
                  ? 'rejected - ' . shop_money($amount) . ' > ' . shop_money($line['total'])
                  : 'passed - ' . shop_money($amount) . ' <= ' . shop_money($line['total'] ?? 0),
         'note'  => 'This is the only ceiling in the handler, and it compares your amount with the line. It is '
                  . 'evaluated afresh on every request, against a value that never changes.',
         'verdict' => ($line && $amount <= (float)$line['total'] && $amount > 0) ? 'pass' : 'block'],
        ['label' => 'already refunded against line ' . $lineNo . ' (never consulted)',
         'value' => shop_money($lineRefunded) . ' before this request',
         'note'  => 'The handler computes nothing like this figure. It is shown here only so you can watch it '
                  . 'climb past the number the check is comparing against.'],
        ['label' => 'already refunded against the whole order (never consulted)',
         'value' => shop_money($refundedSoFar) . ' of an order worth ' . shop_money($order['total'])],
        ['label' => '$customer["balance"] += $amount',
         'value' => $err === null
                  ? shop_money($state['balance']) . ' + ' . shop_money($amount) . ' = '
                    . shop_money(shop_cents((float)$state['balance'] + $amount))
                  : '(not reached)',
         'verdict' => $err === null && shop_cents($refundedSoFar + $amount) > (float)$order['total'] ? 'pass' : null],
    ];

    if ($err !== null) {
        $result = biz_notice('error', 'Refund declined: ' . lk_esc($err) . '.');
    } else {
        $state['balance']  = shop_cents((float)$state['balance'] + $amount);
        $state['refunds'][] = ['line' => $lineNo, 'item' => $line['item'], 'amount' => $amount,
                               'at' => date('H:i:s')];
        shop_put($L, $state);
        $refundedSoFar = shop_cents($refundedSoFar + $amount);
        $result = biz_notice($refundedSoFar > (float)$order['total'] ? 'success' : 'info',
            'Refund approved: ' . shop_money($amount) . ' credited. Total refunded against '
            . lk_esc($order['id']) . ' is now <strong>' . shop_money($refundedSoFar) . '</strong>.');
    }
}

/* ── Flag: more money has left the shop than the order was ever worth. ─── */
if ($refundedSoFar > (float)$order['total']) {
    $flag = biz_flag($L);
}

/* =========================================================================
 * Panels
 * ===================================================================== */

$lineRows = [];
foreach ($order['lines'] as $i => $ln) {
    $paidBack = 0.0;
    foreach ($state['refunds'] as $r) {
        if ((int)$r['line'] === $i + 1) {
            $paidBack += (float)$r['amount'];
        }
    }
    $lineRows[] = [
        (string)($i + 1),
        lk_esc($ln['item']),
        (int)$ln['qty'],
        shop_money($ln['unit']),
        shop_money($ln['total']),
        shop_money($paidBack),
    ];
}

$refundRows = [];
foreach ($state['refunds'] as $i => $r) {
    $refundRows[] = ['#' . ($i + 1), lk_esc($r['at']), 'line ' . (int)$r['line'],
                     lk_esc($r['item']), shop_money($r['amount'])];
}

$stateHtml = biz_kv([
    'Order'              => '<code>' . lk_esc($order['id']) . '</code>',
    'Order total'        => shop_money($order['total']),
    'Customer paid'      => shop_money($order['paid']),
    'Refunded so far'    => '<span class="biz-big">' . shop_money($refundedSoFar) . '</span>',
    'Net to the shop'    => shop_money(shop_cents((float)$order['paid'] - $refundedSoFar)),
    'Your balance'       => shop_money($state['balance']),
    'Target'             => 'refunded total above ' . shop_money((float)$order['total']),
])
. '<p class="lk-hintline" style="margin-top:0.7rem">Order lines</p>'
. biz_table(['#', 'Item', 'Qty', 'Unit', 'Line total', 'Refunded against it'], $lineRows)
. '<p class="lk-hintline" style="margin-top:0.7rem">Refund ledger</p>'
. biz_table(['#', 'Time', 'Line', 'Item', 'Amount'], $refundRows, 'no refunds issued yet');

ob_start(); ?>
<form method="post" action="">
    <input type="hidden" name="bl_action" value="refund">
    <div class="biz-grid">
        <div class="form-group">
            <label class="form-label">Line</label>
            <select name="line" class="form-control">
                <?php foreach ($order['lines'] as $i => $ln): ?>
                    <option value="<?= $i + 1 ?>"><?= $i + 1 ?> &mdash; <?= lk_esc($ln['item']) ?>
                        (<?= shop_money($ln['total']) ?>)</option>
                <?php endforeach; ?>
            </select>
        </div>
        <div class="form-group">
            <label class="form-label">Refund amount</label>
            <input type="text" name="amount" class="form-control" value="329.00" autocomplete="off">
        </div>
    </div>
    <button class="btn btn-primary" type="submit">Issue partial refund</button>
</form>
<?= biz_reset_form() ?>
<?php
$form = biz_state_box('Refund console', $stateHtml) . ob_get_clean();

$code = <<<'PHP'
// POST /support/refund
// Partial refunds exist because a customer often returns one item from a
// multi-item order, so the agent picks the line and the amount.
$order  = load_order($_POST['order_id']);
$line   = $order['lines'][(int)$_POST['line'] - 1] ?? null;
$amount = round((float)$_POST['amount'], 2);

if (!$line)                        return error('no such line');
if ($amount <= 0)                  return error('amount must be positive');
if ($amount > $line['total'])      return error('refund exceeds line total');

$gateway->refund($order['payment_id'], $amount);
$customer['balance'] += $amount;

$order['refunds'][] = ['line' => $_POST['line'], 'amount' => $amount];
save_order($order);
PHP;

$fixBad = <<<'PHP'
if ($amount > $line['total']) {
    return error('refund exceeds line total');
}
PHP;

$fixGood = <<<'PHP'
// The limit is on the cumulative total, so the check has to read the ledger.
$alreadyLine  = sum_refunds_for_line($order, $lineNo);
$alreadyOrder = sum_refunds($order);

if ($amount > $line['total'] - $alreadyLine) {
    return error('exceeds the remaining refundable amount on this line');
}
if ($amount > $order['amount_captured'] - $alreadyOrder) {
    return error('exceeds the amount collected for this order');
}

// Then make the invariant structural rather than procedural. Insert the
// refund row and the new total inside one transaction, with a constraint
// the database enforces whatever the application code does:
//
//   ALTER TABLE orders ADD CONSTRAINT refunds_within_capture
//     CHECK (refunded_total <= amount_captured);
//
// A rule about a running total belongs where the running total lives.
PHP;

lk_page([
    'lab'        => bizlab(),
    'level'      => $L,
    'title'      => $meta['title'],
    'difficulty' => $meta['difficulty'],
    'extra_head' => biz_extra_head(),

    'code'       => $code,
    'vuln_lines' => [11, 13, 14],
    'annotation' => 'The ceiling on a refund is the line total, and the line total is a constant. Nothing in the
        handler reads the refunds that have already been issued, so the check gives the same answer on the first
        request and on the twentieth. It is a limit on one refund, not a limit on refunding.',

    'theory' => '<p>The distinction here is between a limit on a <em>request</em> and a limit on a
        <em>quantity</em>. A per-request check answers "is this one amount reasonable". A per-quantity check
        answers "does this amount still fit inside what remains". They look nearly identical in code and they
        differ completely in what they guarantee, and the second one is the only one that means anything when the
        request can be repeated.</p>
        <p>It is worth being precise about what this is not. This is not a race condition. The requests here are
        strictly sequential, every write lands cleanly, and adding a lock or a transaction changes nothing at all.
        Concurrency defences protect a correct rule from interleaving; they cannot repair a rule that was the wrong
        rule to begin with. If you reach for a mutex here you will end up with a very well synchronised
        overpayment.</p>
        <p>The same shape appears anywhere a budget is spent in instalments: gift-card redemption, partial
        captures, referral bounties, API quota top-ups, expense claims against a receipt, loyalty point redemption
        against a single order. In each case, find the ledger and ask whether the check reads it. If the check only
        reads the request and a constant, the limit is not a limit.</p>',

    'fix' => [
        'bad'  => $fixBad,
        'good' => $fixGood,
        'note' => 'Check against the remaining balance, not the original amount, and back it with a database
            constraint on the running total. An application-level check protects one code path; a
            <code>CHECK</code> constraint protects every path, including the admin tool nobody remembered.',
    ],

    'scenario' => '<strong>Scenario:</strong> order <code>ORD-88412</code> was placed and paid: a monitor at
        ' . shop_money(329.00) . ' and two cables at ' . shop_money(12.50) . ', ' . shop_money(354.00) . ' in
        total. The support console lets you issue partial refunds line by line.
        <br><strong>Goal:</strong> have more than ' . shop_money(354.00) . ' refunded against this order.',

    'model' => [
        'title' => 'What the check reads, and what it does not',
        'html'  => '<table class="lk-kv">
            <tr><td>the check reads</td><td><code>$amount</code> (your request) and <code>$line["total"]</code> (a constant)</td></tr>
            <tr><td>the check ignores</td><td>the refund ledger, which is where every previous refund is recorded</td></tr>
            <tr><td>therefore</td><td>the answer is the same every time you ask, no matter what has already been paid out</td></tr>
        </table>
        <table class="data-table" style="margin-top:0.6rem">
            <thead><tr><th>Line</th><th>Item</th><th>Line total</th><th>Max per request</th><th>Max in total</th></tr></thead>
            <tbody>
                <tr><td>1</td><td>27-inch Monitor</td><td>' . shop_money(329.00) . '</td><td>' . shop_money(329.00) . '</td><td>unbounded</td></tr>
                <tr><td>2</td><td>USB-C Cable</td><td>' . shop_money(25.00) . '</td><td>' . shop_money(25.00) . '</td><td>unbounded</td></tr>
            </tbody>
        </table>
        <p>The state panel prints the refunded total and the net position of the shop after every request, so you
        can watch the moment the order stops being profitable and starts being a payout.</p>',
    ],

    'form'     => $form,
    'result'   => $result,
    'flag'     => $flag,
    // Stateful levels can be reset after a solve, so the inline submit box
    // keeps accepting this level's flag even once the winning state is gone.
    'expected_flag' => biz_flag($L),
    'flag_msg' => 'More has now been refunded against this order than was ever collected for it.',
    'why'      => '<p>Trace step 2 shows the ceiling being enforced honestly on each request. Steps 3 and 4 show
        the two figures that would have caught this - the running total per line and per order - and both are
        marked as never consulted, because the handler does not compute them.</p>
        <p>The flag is awarded for the refunded total exceeding the order total. Not for a repeated request, not
        for a particular amount: for the shop having paid out more than it took in, which is the state the rule was
        supposed to make impossible.</p>
        <p>Test for this by finding any operation that draws down an allowance and repeating it. If the second
        attempt behaves exactly like the first, the allowance is not being tracked, and the third attempt will not
        behave differently either.</p>',

    'pipeline' => $pipeline,
    'probes'   => [
        'param'  => 'amount',
        'method' => 'POST',
        'action' => 'level8.php',
        'items'  => [
            ['q' => 'Is the per-line ceiling real?',
             'payload' => '400.00',
             'learn'   => 'More than line 1 is worth. A rejection confirms the check exists and tells you exactly which number it is comparing against.'],
            ['q' => 'Are amounts below the line total accepted without any other condition?',
             'payload' => '1.00',
             'learn'   => 'A dollar back on line 1. Small, reversible with the reset button, and it puts one row in the ledger so you can see whether the next request notices it.'],
            ['q' => 'Is a refund on line 2 bounded by line 2 or by the order?',
             'payload' => '25.00',
             'learn'   => 'Line 2 is worth ' . shop_money(25.00) . ' and the default line in the form is line 1, so send this from the form with line 2 selected. It tells you whether the ceiling is per line or per order.'],
        ],
    ],
    'hints' => biz_hints($L),
]);
