<?php
require_once __DIR__ . '/helpers.php';

$L    = 10;
$meta = biz_levels()[$L];

shop_sid();
biz_handle_reset($L);

$catalog = shop_catalog($L);
$coupons = shop_coupons();
$state   = shop_state($L);

$flag     = '';
$result   = '';
$pipeline = [];

$tier = shop_tier_for((float)$state['lifetime_spend']);

/* =========================================================================
 * Checkout.
 *
 * Same coupon engine as level 3 - it was never fixed, only inherited. The
 * new part is the membership ledger: `lifetime_spend` decides the tier, and
 * the tier decides which items may be bought.
 * ===================================================================== */

if (($_POST['bl_action'] ?? '') === 'checkout' || isset($_POST['item'])) {
    $itemId = (string)($_POST['item'] ?? '');
    $qty    = (int)($_POST['qty'] ?? 1);
    $raw    = trim((string)($_POST['codes'] ?? ''));
    $item   = $catalog[$itemId] ?? null;

    $codes = array_values(array_filter(array_map(
        static fn ($c) => strtoupper(trim($c)),
        $raw === '' ? [] : (preg_split('/[,\s]+/', $raw) ?: [])
    )));

    $err = null;
    if (!$item) {
        $err = 'unknown item';
    } elseif ($qty < 1 || $qty > 20) {
        $err = 'quantity must be between 1 and 20';
    } elseif (!empty($item['gate']) && $tier !== $item['gate']) {
        $err = $item['name'] . ' is reserved for ' . $item['gate'] . ' members. Your tier is ' . $tier;
    }

    $subtotal = $item ? shop_cents($qty * (float)$item['price']) : 0.0;

    // ── The inherited coupon engine: validate all, then apply all. ────────
    $ordersPlaced = count($state['orders']);
    $used         = $state['used_codes'];
    $valid        = [];
    foreach ($codes as $c) {
        if (!isset($coupons[$c]))            continue;
        if ($ordersPlaced > 0)               continue;   // first order only
        if (in_array($c, $used, true))       continue;   // single use
        $valid[] = $c;
    }
    $valid = array_values(array_unique($valid));

    $discount = 0.0;
    foreach ($valid as $c) {
        $discount += $subtotal * $coupons[$c]['value'];
        $used[]    = $c;
    }
    $discount = shop_cents(min($discount, $subtotal));
    $charged  = shop_cents($subtotal - $discount);

    $before     = (float)$state['balance'];
    $affordable = $charged <= $before;

    $lifeBefore = (float)$state['lifetime_spend'];
    $lifeAfter  = shop_cents($lifeBefore + $subtotal);
    $tierAfter  = shop_tier_for($lifeAfter);

    $pipeline = [
        ['label' => 'membership gate on this item',
         'value' => empty($item['gate'])
            ? 'none - open to every tier'
            : 'requires ' . $item['gate'] . ', you are ' . $tier,
         'note'  => 'The gate reads your current tier, which is derived from <code>lifetime_spend</code>. It is '
                  . 'the only thing standing between you and the item.',
         'verdict' => $err !== null && str_contains((string)$err, 'reserved') ? 'block' : 'pass'],
        ['label' => '$subtotal = $qty * $item["price"]',
         'value' => $qty . ' x ' . shop_money($item['price'] ?? 0) . ' = ' . shop_money($subtotal)],
        ['label' => 'coupons applied (same engine as level 3)',
         'value' => $valid
            ? implode(' + ', array_map(
                static fn ($c) => $c . ' (' . (int)round($coupons[$c]['value'] * 100) . '%)', $valid))
              . ' = -' . shop_money($discount)
            : 'none applied',
         'note'  => $valid
            ? 'Every rate is taken against the subtotal, and all of them were validated before any of them was '
              . 'recorded as used. Nothing about this engine changed since level 3.'
            : ''],
        ['label' => '$charged = $subtotal - $discount',
         'value' => shop_money($subtotal) . ' - ' . shop_money($discount) . ' = ' . shop_money($charged)],
        ['label' => 'if ($charged > $balance) reject',
         'value' => $affordable ? 'passed - ' . shop_money($charged) . ' <= ' . shop_money($before)
                                : 'rejected - ' . shop_money($charged) . ' > ' . shop_money($before),
         'verdict' => $affordable ? 'pass' : 'block'],
        ['label' => '$customer["lifetime_spend"] += $subtotal',
         'value' => shop_money($lifeBefore) . ' + ' . shop_money($subtotal) . ' = ' . shop_money($lifeAfter),
         'note'  => 'The ledger is credited with the <strong>subtotal</strong>, before discounts, while your '
                  . 'balance was charged the <strong>total</strong>, after them. Those are two different numbers '
                  . 'and the gap between them is whatever the coupon engine allows.',
         'verdict' => $lifeAfter > $lifeBefore && $charged <= 0.0 ? 'pass' : null],
        ['label' => 'tier = tier_for($lifetime_spend)',
         'value' => shop_money($lifeAfter) . ' -> ' . $tierAfter
                  . ($tierAfter !== $tier ? '  (was ' . $tier . ')' : ''),
         'verdict' => $tierAfter === 'platinum' && $tier !== 'platinum' ? 'pass' : null],
    ];

    if ($err !== null) {
        $result = biz_notice('error', 'Order refused: ' . lk_esc($err) . '.');
    } elseif (!$affordable) {
        $result = biz_notice('error', 'Insufficient funds: ' . shop_money($charged) . ' due, balance '
                . shop_money($before) . '.');
    } else {
        $state['balance']        = shop_cents($before - $charged);
        $state['lifetime_spend'] = $lifeAfter;
        $state['used_codes']     = array_values(array_unique($used));
        $state['orders'][]       = ['item' => $itemId, 'name' => $item['name'], 'qty' => $qty,
                                    'subtotal' => $subtotal, 'discount' => $discount, 'charged' => $charged];
        if (!in_array($itemId, $state['owned'], true)) {
            $state['owned'][] = $itemId;
        }
        shop_put($L, $state);
        $tier   = shop_tier_for((float)$state['lifetime_spend']);
        $result = biz_notice($itemId === 'founders' ? 'success' : 'info',
            'Order placed: ' . (int)$qty . ' x ' . lk_esc($item['name']) . '. Subtotal '
            . shop_money($subtotal) . ', charged <strong>' . shop_money($charged)
            . '</strong>. Lifetime spend is now ' . shop_money($state['lifetime_spend'])
            . ' and your tier is <strong>' . lk_esc($tier) . '</strong>.');
    }
}

/* ── Flag: you own the gated item. ─────────────────────────────────────── */
if (in_array('founders', $state['owned'], true)) {
    $flag = biz_flag($L);
}

/* =========================================================================
 * Panels
 * ===================================================================== */

$ladder = [];
foreach (shop_tiers() as $row) {
    $ladder[] = [
        ($row['tier'] === $tier ? '<strong>' . lk_esc($row['tier']) . '</strong>' : lk_esc($row['tier'])),
        'lifetime spend ' . shop_money($row['min']) . '+',
        $row['tier'] === $tier ? 'you are here' : '&mdash;',
    ];
}

$orderRows = [];
foreach ($state['orders'] as $i => $o) {
    $orderRows[] = ['#' . ($i + 1), lk_esc($o['name']), (int)$o['qty'], shop_money($o['subtotal']),
                    '-' . shop_money($o['discount']), shop_money($o['charged'])];
}

$stateHtml = biz_kv([
    'Store credit'   => '<span class="biz-big">' . shop_money($state['balance']) . '</span>',
    'Lifetime spend' => '<span class="biz-big">' . shop_money($state['lifetime_spend']) . '</span>',
    'Membership tier' => '<code>' . lk_esc($tier) . '</code>',
    'Owned'          => $state['owned'] ? lk_esc(implode(', ', $state['owned'])) : 'nothing yet',
    'Codes spent'    => $state['used_codes'] ? lk_esc(implode(', ', $state['used_codes'])) : 'none',
    'Target'         => 'own <code>founders</code>',
])
. '<p class="lk-hintline" style="margin-top:0.7rem">Membership ladder</p>'
. biz_table(['Tier', 'Requires', ''], $ladder)
. ($orderRows ? '<p class="lk-hintline" style="margin-top:0.7rem">Order history</p>'
              . biz_table(['#', 'Item', 'Qty', 'Subtotal', 'Discount', 'Charged'], $orderRows) : '');

$options = '';
foreach ($catalog as $id => $it) {
    $options .= '<option value="' . lk_esc($id) . '">' . lk_esc($it['name']) . ' - ' . shop_money($it['price'])
              . (!empty($it['note']) ? ' (' . lk_esc($it['note']) . ')' : '') . '</option>';
}

$couponRows = [];
foreach ($coupons as $code => $cp) {
    $couponRows[] = ['<code>' . lk_esc($code) . '</code>', lk_esc($cp['label']),
                     in_array($code, $state['used_codes'], true) ? 'spent' : 'available'];
}

ob_start(); ?>
<form method="post" action="">
    <input type="hidden" name="bl_action" value="checkout">
    <div class="biz-grid">
        <div class="form-group">
            <label class="form-label">Item</label>
            <select name="item" class="form-control"><?= $options ?></select>
        </div>
        <div class="form-group">
            <label class="form-label">Quantity (max 20)</label>
            <input type="text" name="qty" class="form-control" value="1" autocomplete="off">
        </div>
    </div>
    <div class="form-group">
        <label class="form-label">Coupon codes</label>
        <input type="text" name="codes" class="form-control" placeholder="FIRST10" autocomplete="off"
               spellcheck="false">
    </div>
    <button class="btn btn-primary" type="submit">Check out</button>
</form>
<?= biz_table(['Code', 'Offer', 'Status'], $couponRows) ?>
<?= biz_reset_form() ?>
<?php
$form = biz_state_box('Membership account', $stateHtml) . ob_get_clean();

$code = <<<'PHP'
// POST /checkout
$item = catalog_lookup($_POST['item']);
$qty  = (int)$_POST['qty'];

// Some SKUs are reserved for a membership tier.
$tier = tier_for($customer['lifetime_spend']);   // platinum at $10,000
if ($item['gate'] && $tier !== $item['gate']) {
    return error($item['name'] . ' is reserved for ' . $item['gate'] . ' members');
}

$subtotal = $qty * $item['price'];
$discount = apply_coupons($_POST['codes'], $subtotal);   // unchanged since v1
$total    = $subtotal - $discount;

if ($total > $customer['balance']) {
    return error('insufficient funds');
}
$customer['balance'] -= $total;

// Tier credit is awarded on merchandise value. Finance treats promotional
// discount as a marketing cost, not as a reduction in what the customer
// bought, so the loyalty ledger records the gross figure.
$customer['lifetime_spend'] += $subtotal;
PHP;

$fixBad = <<<'PHP'
$customer['balance']        -= $total;      // what the customer paid
$customer['lifetime_spend'] += $subtotal;   // what the customer "spent"
PHP;

$fixGood = <<<'PHP'
// Whatever the accounting policy is, the ledger that grants privilege must be
// driven by money that was actually collected - and by a figure the customer
// cannot inflate for free.
$customer['lifetime_spend'] += $amountCaptured;   // from the payment gateway

// Then stop deriving the privilege from a number at all, and derive it from
// the event that is supposed to grant it. A tier change is a decision, so
// record it as one, with the evidence attached:
TierLedger::record($customer, [
    'reason'      => 'order ' . $order->id,
    'captured'    => $amountCaptured,
    'evaluated_at'=> now(),
]);

// And bound the discount engine independently, so a stacking bug can never
// produce a large subtotal at a zero charge:
if ($discount > $subtotal * MAX_TOTAL_DISCOUNT_RATE) {
    return error('discount exceeds the maximum for one order');
}
PHP;

lk_page([
    'lab'        => bizlab(),
    'level'      => $L,
    'title'      => $meta['title'],
    'difficulty' => $meta['difficulty'],
    'extra_head' => biz_extra_head(),

    'code'       => $code,
    'vuln_lines' => [12, 13, 22],
    'annotation' => 'Two rules, each defensible. Tier credit is recorded on the subtotal, because finance treats a
        discount as a marketing cost rather than as a smaller purchase. The coupon engine still stacks, because
        nobody fixed level 3. Together they let you write any figure you like into the ledger that grants
        privilege, for no money at all.',

    'theory' => '<p>Chained findings are where business-logic testing pays for itself. Neither half of this level
        is a vulnerability by itself. A ledger recording gross merchandise value is an accounting choice with a
        real justification behind it. A coupon that stacks is a discount bug worth a few hundred dollars. Put them
        in the same request and the discount bug stops being about money and becomes a privilege escalation, which
        is a different severity and a different conversation.</p>
        <p>The composition works because the two rules share a variable. <code>$subtotal</code> is an input to the
        pricing path and an input to the entitlement path, and the two paths have different threat models. Pricing
        is guarded - there is a balance check downstream. Entitlement is not, because whoever wrote the tier logic
        assumed <code>$subtotal</code> was a proxy for money received. It is a proxy for money received only while
        the discount engine is correct.</p>
        <p>That is the pattern worth carrying away. When one computed value feeds two subsystems, the weaker
        guarantee governs both. Look for the variables that cross a boundary like this: an order total that also
        drives fraud scoring, a request count that also drives rate limiting, a file size that also drives quota, a
        role string that is both displayed and enforced. Then ask what the value looks like when the subsystem you
        already know how to break is the one producing it.</p>',

    'fix' => [
        'bad'  => $fixBad,
        'good' => $fixGood,
        'note' => 'Drive the entitlement ledger from money actually captured, cap the total discount on an order
            independently of how many codes were applied, and record tier changes as auditable events rather than
            deriving them from a running number that several code paths can write.',
    ],

    'scenario' => '<strong>Scenario:</strong> the Founders Edition Hoodie costs ' . shop_money(19.00) . ' - well
        inside your ' . shop_money(25.00) . ' balance - and is reserved for <code>platinum</code> members.
        Platinum requires ' . shop_money(10000.00) . ' of lifetime spend. You have spent nothing, and no honest
        sequence of purchases on a ' . shop_money(25.00) . ' balance will ever get you there.
        <br><strong>Goal:</strong> own the Founders Edition Hoodie.',

    'model' => [
        'title' => 'Three money figures, and which one grants the tier',
        'html'  => '<table class="lk-kv">
            <tr><td><code>$subtotal</code></td><td>quantity x list price, before any discount</td></tr>
            <tr><td><code>$discount</code></td><td>whatever the coupon engine allows</td></tr>
            <tr><td><code>$total</code></td><td><code>$subtotal - $discount</code> - this is what your balance pays</td></tr>
        </table>
        <table class="lk-kv" style="margin-top:0.6rem">
            <tr><td>balance is charged</td><td><code>$total</code></td></tr>
            <tr><td>lifetime spend records</td><td><code>$subtotal</code></td></tr>
            <tr><td>so the ledger grows by</td><td>a number you can inflate without paying for it</td></tr>
        </table>
        <p>The catalogue has a Server Rack Unit at ' . shop_money(1000.00) . ' and allows up to 20 per line, so the
        largest subtotal one order can carry is ' . shop_money(20000.00) . '. The platinum threshold is
        ' . shop_money(10000.00) . '.</p>
        <p>The coupon engine is byte-for-byte the one from level 3. The wallet under the form shows the same five
        codes and the same terms; the trace prints them applied against your subtotal. You already know what
        happens when all five arrive in one request.</p>',
    ],

    'form'     => $form,
    'result'   => $result,
    'flag'     => $flag,
    // Stateful levels can be reset after a solve, so the inline submit box
    // keeps accepting this level's flag even once the winning state is gone.
    'expected_flag' => biz_flag($L),
    'flag_msg' => 'A tier no legitimate customer on this balance can reach, and the item it was guarding.',
    'why'      => '<p>Read trace steps 4, 6 and 7 together. Step 4 charged your balance the discounted total. Step
        6 credited the membership ledger with the undiscounted subtotal. Step 7 read that ledger and moved you to
        platinum. Every one of those statements is doing exactly what its author intended.</p>
        <p>The flag was awarded for owning the gated item - the state the tier check exists to prevent - not for
        the request that got you there. The second order was an ordinary purchase at list price from a balance that
        could afford it, and it was allowed because by then the gate genuinely opened.</p>
        <p>This is the level to remember when you write a report. The coupon bug on its own is a discount abuse
        finding. Chained into the tier ladder it becomes access to gated inventory, and if the platinum tier also
        carried a support channel, an API scope or a pricing agreement, it would keep going. Always ask what the
        state you reached is an input to.</p>',

    'pipeline' => $pipeline,
    'probes'   => [
        'param'  => 'item',
        'method' => 'POST',
        'action' => 'level10.php',
        'items'  => [
            ['q' => 'What exactly does the gate say, and which value does it read?',
             'payload' => 'founders',
             'learn'   => 'The refusal names the required tier and your current one, which tells you the gate is a comparison against a derived value rather than a flag on your account.'],
            ['q' => 'Does an ordinary purchase move the lifetime-spend ledger at all?',
             'payload' => 'keyboard',
             'learn'   => 'An ' . shop_money(89.00) . ' keyboard you can afford. Watch the lifetime-spend row in the state panel: it establishes that the ledger tracks purchases and by how much.'],
            ['q' => 'Is the quantity cap on a line real?',
             'payload' => 'rack',
             'learn'   => 'Sent with quantity 1, so it costs ' . shop_money(1000.00) . ' you do not have and is refused for funds rather than for quantity. The refusal message tells you which check ran first.'],
        ],
    ],
    'hints' => biz_hints($L),
]);
