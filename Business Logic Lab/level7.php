<?php
require_once __DIR__ . '/helpers.php';

$L    = 7;
$meta = biz_levels()[$L];

shop_sid();
biz_handle_reset($L);
biz_apply_raw_body();

$catalog = shop_catalog($L);
$state   = shop_state($L);

$flag     = '';
$result   = '';
$pipeline = [];

/** Discount rates the pricing engine knows about. `staff` is an internal rate. */
$TIERS = ['standard' => 0.00, 'silver' => 0.05, 'gold' => 0.12, 'staff' => 0.90];

/** Every field an order carries. The form renders four of them. */
function biz7_defaults(): array
{
    return [
        'item'            => 'headset',
        'qty'             => 1,
        'ship_speed'      => 'standard',
        'gift_wrap'       => 'no',
        'discount_tier'   => 'standard',
        'internal_credit' => 0.00,
        'status'          => 'pending',
        'staff_note'      => '',
    ];
}

$defaults = biz7_defaults();
$body     = $_POST;
foreach (biz_control_keys() as $k) {              // page furniture, not order fields
    unset($body[$k]);
}
// Anything that names an order field counts as a checkout attempt, so a
// single-field probe reaches the same code path the form does.
$isCheckout = ($_POST['bl_action'] ?? '') === 'place'
           || (bool)array_intersect(array_keys($body), array_keys($defaults));

if ($isCheckout) {

    // ── The order object, hydrated from the request. ─────────────────────
    $order = array_merge($defaults, $body);       // <- every key in $body wins

    $extra = array_values(array_diff(array_keys($body), ['item', 'qty', 'ship_speed', 'gift_wrap']));
    $wrote = array_values(array_intersect(array_keys($body), array_keys($defaults)));

    $item  = $catalog[(string)$order['item']] ?? null;
    $qty   = max(1, (int)$order['qty']);
    $price = $item ? (float)$item['price'] : 0.0;

    $subtotal = shop_cents($qty * $price);
    $tierName = (string)$order['discount_tier'];
    $tierPct  = $TIERS[$tierName] ?? 0.00;
    $afterTier = shop_cents($subtotal * (1 - $tierPct));
    $credit    = (float)$order['internal_credit'];
    $charge    = shop_cents(max(0.0, $afterTier - $credit));

    $shipping = $order['ship_speed'] === 'express' ? 9.00 : 0.00;
    $charge   = shop_cents($charge + ($charge > 0 ? $shipping : 0.0));

    $before     = (float)$state['balance'];
    $affordable = $charge <= $before;

    $pipeline = [
        ['label' => 'request body keys', 'value' => implode(', ', array_keys($body)) ?: '(empty)'],
        ['label' => '$order = array_merge($defaults, $_POST)',
         'value' => 'wrote: ' . (implode(', ', $wrote) ?: 'nothing'),
         'note'  => 'The defaults array is the list of fields an order has. The merge lets the request set any of '
                  . 'them, whether or not the form ever rendered an input for it.'
                  . ($extra ? ' Fields set here that the form does not render: <strong>'
                            . lk_esc(implode(', ', $extra)) . '</strong>.' : ''),
         'verdict' => $extra ? 'pass' : null],
        ['label' => '$subtotal = $qty * $item["price"]',
         'value' => $qty . ' x ' . shop_money($price) . ' = ' . shop_money($subtotal)],
        ['label' => '$pct = TIERS[$order["discount_tier"]] ?? 0.00',
         'value' => $tierName . ' -> ' . (int)round($tierPct * 100) . '%',
         'note'  => isset($TIERS[$tierName])
            ? 'A key in the rate table. The table does not distinguish rates customers may ask for from rates only '
              . 'staff tooling was ever meant to set.'
            : 'Not in the rate table, so the null-coalesce falls back to 0%.'],
        ['label' => '$afterTier = $subtotal * (1 - $pct)',
         'value' => shop_money($subtotal) . ' x ' . number_format(1 - $tierPct, 2) . ' = ' . shop_money($afterTier)],
        ['label' => '$charge = max(0, $afterTier - $order["internal_credit"])',
         'value' => shop_money($afterTier) . ' - ' . shop_money($credit) . ' = ' . shop_money($charge),
         'note'  => $credit > 0
            ? 'The credit field is a dollar amount subtracted from the total. It exists so support agents can apply '
              . 'goodwill without a refund, and it has no owner, no ceiling and no audit trail.'
            : '',
         'verdict' => $charge <= 0.0 && $subtotal > 0 ? 'pass' : null],
        ['label' => 'if ($charge > $balance) reject',
         'value' => $affordable ? 'passed' : 'rejected - ' . shop_money($charge) . ' > ' . shop_money($before),
         'verdict' => $affordable ? 'pass' : 'block'],
    ];

    // The hydrated object is kept whatever happens next, because building it is
    // what the merge did - the affordability check comes afterwards. This is
    // also the payload the order confirmation renders.
    $order['subtotal'] = $subtotal;
    $order['charged']  = $charge;
    $order['name']     = $item['name'] ?? '(unknown)';
    $state['last']     = $order;

    if (!$item) {
        $result = biz_notice('error', 'Unknown item.');
        shop_put($L, $state);
    } elseif (!$affordable) {
        $result = biz_notice('error', 'Insufficient funds: ' . shop_money($charge)
                . ' due, balance ' . shop_money($before) . '. The order object above was still built from '
                . 'your request.');
        shop_put($L, $state);
    } else {
        $state['balance']  = shop_cents($before - $charge);
        $state['orders'][] = $order;
        shop_put($L, $state);
        $result = biz_notice($charge <= 0.0 && $subtotal > 0 ? 'success' : 'info',
            'Order placed. Subtotal ' . shop_money($subtotal) . ', charged <strong>'
            . shop_money($charge) . '</strong>.');
    }
}

/* ── Flag: a real order, with a real subtotal, that cost nothing. ──────── */
foreach ($state['orders'] as $o) {
    if ((float)($o['subtotal'] ?? 0) > 0 && (float)($o['charged'] ?? 0) <= 0.0) {
        $flag = biz_flag($L);
    }
}

/* =========================================================================
 * Panels
 * ===================================================================== */

/**
 * The order confirmation dump. Real applications leak this list constantly:
 * a JSON API response, an admin view, a webhook payload, a debug header.
 */
$last = is_array($state['last']) ? $state['last'] : biz7_defaults();
$rows = [];
foreach ($last as $k => $v) {
    $rows[] = ['<code>' . lk_esc((string)$k) . '</code>', lk_esc(is_scalar($v) ? (string)$v : json_encode($v))];
}

$stateHtml = biz_kv([
    'Store credit' => '<span class="biz-big">' . shop_money($state['balance']) . '</span>',
    'Orders placed' => count($state['orders']),
    'Target'       => 'an order with a subtotal above ' . shop_money(0.00) . ' that charged ' . shop_money(0.00),
])
. '<p class="lk-hintline" style="margin-top:0.7rem">Order object as stored '
. ($state['last'] ? '(your last checkout attempt)' : '(defaults, before any request)') . '</p>'
. biz_table(['Field', 'Value'], $rows);

ob_start(); ?>
<form method="post" action="">
    <input type="hidden" name="bl_action" value="place">
    <div class="biz-grid">
        <div class="form-group">
            <label class="form-label">Item</label>
            <select name="item" class="form-control">
                <?php foreach ($catalog as $id => $it): ?>
                    <option value="<?= lk_esc($id) ?>"><?= lk_esc($it['name']) ?> - <?= shop_money($it['price']) ?></option>
                <?php endforeach; ?>
            </select>
        </div>
        <div class="form-group">
            <label class="form-label">Quantity</label>
            <input type="text" name="qty" class="form-control" value="1" autocomplete="off">
        </div>
        <div class="form-group">
            <label class="form-label">Shipping</label>
            <select name="ship_speed" class="form-control">
                <option value="standard">Standard - free</option>
                <option value="express">Express - $9.00</option>
            </select>
        </div>
        <div class="form-group">
            <label class="form-label">Gift wrap</label>
            <select name="gift_wrap" class="form-control">
                <option value="no">No</option>
                <option value="yes">Yes</option>
            </select>
        </div>
    </div>
    <button class="btn btn-primary" type="submit">Place order</button>
</form>
<?= biz_raw_form('bl_action=place&item=headset&qty=1&ship_speed=standard&gift_wrap=no',
        'The four fields the form renders. The order object has more.') ?>
<?= biz_reset_form() ?>
<?php
$form = biz_state_box('Your account', $stateHtml) . ob_get_clean();

$code = <<<'PHP'
// app/Order.php - the fields an order carries
const DEFAULTS = [
    'item'            => null,
    'qty'             => 1,
    'ship_speed'      => 'standard',
    'gift_wrap'       => 'no',
    'discount_tier'   => 'standard',   // set by the CRM sync job
    'internal_credit' => 0.00,         // set by support agents
    'status'          => 'pending',    // set by the fulfilment worker
    'staff_note'      => '',
];

// POST /checkout - "so we do not have to touch this when we add a field"
$order = array_merge(DEFAULTS, $_POST);

// pricing/engine.php
$subtotal  = $order['qty'] * catalog_price($order['item']);
$pct       = TIER_RATES[$order['discount_tier']] ?? 0.00;
$afterTier = $subtotal * (1 - $pct);
$charge    = max(0, $afterTier - $order['internal_credit']);

charge_customer($customer, $charge);
save_order($order);
PHP;

$fixBad = <<<'PHP'
$order = array_merge(DEFAULTS, $_POST);
PHP;

$fixGood = <<<'PHP'
// Name the fields the customer owns. Anything else in the body is ignored,
// because it was never read in the first place.
final class PlaceOrderRequest
{
    public function __construct(
        public readonly string $item,
        public readonly int    $qty,
        public readonly string $shipSpeed,
        public readonly bool   $giftWrap,
    ) {}

    public static function fromPost(array $post): self
    {
        return new self(
            item:      (string)($post['item'] ?? ''),
            qty:       max(1, min(10, (int)($post['qty'] ?? 1))),
            shipSpeed: in_array($post['ship_speed'] ?? '', ['standard', 'express'], true)
                           ? $post['ship_speed'] : 'standard',
            giftWrap:  ($post['gift_wrap'] ?? 'no') === 'yes',
        );
    }
}

// The server-owned fields are set by the server, from server-side facts.
$order = Order::create($request, [
    'discount_tier'   => $customer->tierFromLifetimeSpend(),
    'internal_credit' => CreditLedger::availableFor($customer),
    'status'          => 'pending',
]);
PHP;

lk_page([
    'lab'        => bizlab(),
    'level'      => $L,
    'title'      => $meta['title'],
    'difficulty' => $meta['difficulty'],
    'extra_head' => biz_extra_head(),

    'code'       => $code,
    'vuln_lines' => [14, 17, 18, 19, 20],
    'annotation' => 'One line hydrates the order from the request body. The defaults array documents eight fields;
        the form renders four. The other four - <code>discount_tier</code>, <code>internal_credit</code>,
        <code>status</code>, <code>staff_note</code> - are set by internal systems and are every bit as writable as
        the rest, because <code>array_merge</code> does not know which is which.',

    'theory' => '<p>Every framework offers a way to build a model from request data in one line, because writing
        the assignments out by hand is tedious and gets stale. Rails calls the resulting bug mass assignment,
        Laravel guards against it with <code>$fillable</code>, .NET calls it over-posting, and every one of those
        names exists because the shortcut is genuinely convenient and genuinely unsafe.</p>
        <p>What makes it a business-logic bug rather than a coding mistake is the gap it exploits. An entity has
        more fields than any one form. Some are set by other subsystems - a CRM sync, a support console, a
        fulfilment worker, a fraud engine. Each of those is a different trust level writing to the same row. The
        form is a view over a subset; the merge exposes the whole row.</p>
        <p>The defence is an allowlist, and the important part is <em>where</em> it lives. A denylist of forbidden
        keys rots the moment somebody adds a field. Binding to a typed request object cannot rot, because a field
        nobody named is a field nobody read. The corollary is worth stating on its own: server-owned values must be
        set from server-side facts. <code>discount_tier</code> should be computed from the customer record, not
        accepted from anywhere - including from a hidden input the server itself rendered.</p>',

    'fix' => [
        'bad'  => $fixBad,
        'good' => $fixGood,
        'note' => 'Allowlist, not denylist, and set server-owned fields from server-side facts. Then look for the
            other half of this bug: the order confirmation, the API response and the webhook payload are all
            printing that field list to whoever asks.',
    ],

    'scenario' => '<strong>Scenario:</strong> the checkout renders four inputs - item, quantity, shipping and gift
        wrap. The Pro Headset is ' . shop_money(249.00) . ' and you have ' . shop_money(25.00) . '.
        <br><strong>Goal:</strong> place an order with a real subtotal that charges you ' . shop_money(0.00) . '.',

    'model' => [
        'title' => 'Four fields rendered, eight fields writable',
        'html'  => '<table class="data-table">
            <thead><tr><th>Field</th><th>Rendered by the form</th><th>Meant to be set by</th></tr></thead>
            <tbody>
                <tr><td><code>item</code></td><td>yes</td><td>the customer</td></tr>
                <tr><td><code>qty</code></td><td>yes</td><td>the customer</td></tr>
                <tr><td><code>ship_speed</code></td><td>yes</td><td>the customer</td></tr>
                <tr><td><code>gift_wrap</code></td><td>yes</td><td>the customer</td></tr>
                <tr><td><code>discount_tier</code></td><td>no</td><td>the CRM sync job</td></tr>
                <tr><td><code>internal_credit</code></td><td>no</td><td>a support agent</td></tr>
                <tr><td><code>status</code></td><td>no</td><td>the fulfilment worker</td></tr>
                <tr><td><code>staff_note</code></td><td>no</td><td>a support agent</td></tr>
            </tbody>
        </table>
        <p>The state panel prints the stored order object with all eight fields and their current values. That dump
        is not a hint bolted onto the lab - it is the ordinary order-confirmation payload, and in real applications
        it is where this field list comes from.</p>
        <p>Two of the four hidden fields reach the money. <code>discount_tier</code> is a key into a rate table;
        <code>internal_credit</code> is a dollar amount subtracted from the total. The trace prints both with your
        values substituted.</p>',
    ],

    'form'     => $form,
    'result'   => $result,
    'flag'     => $flag,
    // Stateful levels can be reset after a solve, so the inline submit box
    // keeps accepting this level's flag even once the winning state is gone.
    'expected_flag' => biz_flag($L),
    'flag_msg' => 'The order is real, the subtotal is real, and the amount charged is zero.',
    'why'      => '<p>Trace step 2 lists the keys your request wrote into the order object and names the ones the
        form does not render. Steps 4 and 6 then show those values reaching the pricing engine, which applied them
        without asking where they came from - because by the time the engine sees the order, there is nothing left
        to distinguish a field the customer set from a field the CRM set.</p>
        <p>The flag is awarded for an order that has a genuine subtotal and charged nothing. That state is
        reachable by more than one route - the staff rate alone leaves ' . shop_money(24.90) . ' to cover, the
        credit field alone can cover the lot, and together they overshoot. Any of them is the same finding.</p>
        <p>To find this in a live application, get the entity to print its own field list: an API response, an
        order confirmation, an export, a validation error naming an unknown attribute. Then send each field back
        and watch which ones stick.</p>',

    'pipeline' => $pipeline,
    'probes'   => [
        'param'  => 'staff_note',
        'method' => 'POST',
        'action' => 'level7.php',
        'items'  => [
            ['q' => 'Does a field the form never renders survive into the stored order?',
             'payload' => 'hello',
             'learn'   => 'The most harmless field on the list - it touches no money at all. If it appears in the order dump afterwards, the merge is writable and every other field on the list is too.'],
            ['q' => 'Is an unknown field kept, or dropped?',
             'payload' => 'x',
             'learn'   => 'Compare the key list in trace step 1 with the fields in the stored order. Knowing whether the merge filters at all tells you if there is an allowlist somewhere you have not found.'],
            ['q' => 'What does a tier the rate table does not know do?',
             'payload' => 'nonsense',
             'learn'   => 'Sent as <code>staff_note</code>, so nothing is priced differently - but hint 4 names the field that <em>is</em> a rate-table key, and the same question is worth asking of it.'],
        ],
    ],
    'hints' => biz_hints($L),
]);
