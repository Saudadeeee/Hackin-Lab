<?php
/**
 * SQLi Lab · trace, sink and assembly for the teaching layer.
 *
 * Every stage below is derived from a value the level page already computed, so
 * the trace can never disagree with what actually ran. No statement is
 * re-executed from this file.
 */

/**
 * Per-level notes for the trace, keyed by stage name so the generic builder
 * stays short while each level still says something specific.
 */
function sqli_stage_notes(int $level): array
{
    $notes = [
        1  => ['filter' => 'No escaping of any kind runs on this path. The value reaches the statement as received.'],
        2  => ['filter' => 'Nothing is escaped. What constrains a UNION here is the column count of the SELECT, not a filter.'],
        3  => ['filter' => 'Nothing is escaped. Note which driver call executes the statement - that is what decides whether a second statement runs at all.'],
        4  => ['filter' => 'The WAF matched against a fixed list. Anything it did not name reached the parser unchanged.'],
        5  => ['db'     => 'This level returns only a count, so the response carries one bit. That bit is the whole channel.'],
        6  => ['db'     => 'The response body is identical either way. The elapsed time is the channel.'],
        7  => ['db'     => 'The interesting effect of this statement is on disk rather than in the response.'],
        8  => ['filter' => 'Statement 1 stores the value; statement 2 reads it back and concatenates it again. The second concatenation is the sink.'],
        9  => ['filter' => 'No escaping. The expression is XPath, so the parser and the available operators differ from SQL - the injection shape does not.'],
        10 => ['filter' => 'No escaping. There is no WHERE clause to make true here; what you control is the row that gets written.'],
        11 => ['filter' => 'No escaping. Your value lands in a SET list, so the grammar you are injecting into is assignment.'],
        12 => ['filter' => 'json_decode guarantees the document is well formed and says nothing about the contents of a string.'],
        13 => ['filter' => 'Four comment markers checked, case-insensitively. Quotes, keywords, operators and whitespace were not examined.'],
        14 => ['filter' => 'The check ran on the bytes as received. The decoders run next, so this is not the string the statement will contain.',
               'decode' => 'This is the value the query receives. Compare it with the stage above - the filter judged a different string.'],
        15 => ['filter' => 'One character checked with strpos: the ASCII space. Tabs, newlines and inline comments were not.'],
        16 => ['filter' => 'Five lists, all matched against username concatenated with password. The response names every layer that fired.'],
    ];
    return $notes[$level] ?? [];
}

/**
 * @param array $ctx input, input2, filter, filter_label, decoded, sql,
 *                   sql_label, error, rows, observed, solved
 */
function sqli_teach_pipeline(int $level, array $ctx): array
{
    $in = (string)($ctx['input'] ?? '');
    if ($in === '' && (string)($ctx['sql'] ?? '') === '') {
        return [];
    }
    $notes  = sqli_stage_notes($level);
    $stages = [];

    $stages[] = ['label' => 'your input, as the request delivered it', 'value' => $in];

    if (!empty($ctx['input2'])) {
        $stages[] = ['label' => 'second field', 'value' => (string)$ctx['input2']];
    }

    if (array_key_exists('filter', $ctx)) {
        $blocked = $ctx['filter'];
        $hit     = is_array($blocked) ? implode(', ', $blocked) : (string)$blocked;
        $stages[] = [
            'label'   => (string)($ctx['filter_label'] ?? 'input filter'),
            'value'   => $hit === '' ? 'no entry matched' : 'matched: ' . $hit,
            'note'    => $notes['filter'] ?? '',
            'verdict' => $hit === '' ? 'pass' : 'block',
        ];
    } elseif (isset($notes['filter'])) {
        $stages[] = ['label' => 'escaping or filtering applied', 'value' => 'none',
                     'note'  => $notes['filter']];
    }

    if (array_key_exists('decoded', $ctx)) {
        $stages[] = ['label' => 'urldecode() then html_entity_decode()',
                     'value' => (string)$ctx['decoded'],
                     'note'  => $notes['decode'] ?? ''];
    }

    if (!empty($ctx['sql'])) {
        $stages[] = ['label' => (string)($ctx['sql_label'] ?? 'the statement that was executed'),
                     'value' => (string)$ctx['sql']];
    }

    if (!empty($ctx['error'])) {
        $stages[] = ['label'   => 'MySQL response',
                     'value'   => (string)$ctx['error'],
                     'note'    => 'A parse error is information: it proves your bytes reached the parser, and it '
                                . 'shows where the statement stopped making sense.',
                     'verdict' => 'block'];
    } elseif (array_key_exists('rows', $ctx) && $ctx['rows'] !== null) {
        $stages[] = ['label'   => 'rows returned',
                     'value'   => (string)$ctx['rows'],
                     'note'    => $notes['db'] ?? '',
                     'verdict' => (int)$ctx['rows'] > 0 ? 'pass' : null];
    } elseif (isset($notes['db'])) {
        $stages[] = ['label' => 'observable result',
                     'value' => (string)($ctx['observed'] ?? '(see the result panel above)'),
                     'note'  => $notes['db']];
    }

    return $stages;
}

/** Highlight the controlled span inside the assembled statement. */
function sqli_teach_sink(int $level, array $ctx): string
{
    $sql = (string)($ctx['sql'] ?? '');
    $in  = (string)($ctx['input'] ?? '');
    if ($sql === '') {
        return '';
    }
    $label = $level === 9 ? 'XPath expression evaluated' : 'SQL statement handed to the driver';

    if ($in !== '') {
        $pos = strpos($sql, $in);
        if ($pos !== false) {
            return lk_sink($label, substr($sql, 0, $pos), $in, substr($sql, $pos + strlen($in)));
        }
    }
    return lk_sink($label, $sql, '', '');
}

function sqli_teach(int $level, array $ctx): string
{
    $c = sqli_teach_content($level);
    if (!$c) {
        return '';
    }
    $out  = '<div class="sqli-teach">';
    $out .= lk_model($c['model_title'], $c['model']);

    $pipeline = sqli_teach_pipeline($level, $ctx);
    if ($pipeline) {
        $out .= lk_pipeline($pipeline);
        $out .= sqli_teach_sink($level, $ctx);
    } else {
        $out .= '<div class="lk-box lk-pipeline"><h4><span class="lk-tag">TRACE</span>What the server did to your '
              . 'input</h4><div class="lk-body"><p class="text-muted">Submit something and this will show your '
              . 'value at each stage, the statement that was assembled from it, and what the database answered. '
              . 'A rejected attempt is worth as much as a successful one, as long as you read what happened to '
              . 'it.</p></div></div>';
    }

    if (!empty($ctx['solved'])) {
        $out .= lk_why($c['why']);
    }

    $out .= lk_probes($c['probes'], $c['param'], 'POST', 'level' . $level . '.php');
    $out .= lk_fix($c['fix_bad'], $c['fix_good'], $c['fix_note']);

    return $out . '</div>';
}
