<?php
/**
 * XPath & LDAP Lab · RFC 4515 filter engine
 * ---------------------------------------------------------------------------
 * There is no LDAP server in this lab. There is something better for teaching:
 * a real parser and a real evaluator, written out in full, so that every
 * injection in levels 6-10 works for the same reason it works against a
 * directory server - the parser genuinely reads the attacker's bytes as filter
 * structure.
 *
 * Nothing in this file pattern-matches on payloads. A filter string is turned
 * into a tree, and the tree is evaluated against entries. If a level says a
 * filter matched, a filter matched.
 *
 * Grammar implemented (RFC 4515 section 2, with the RFC 4515 section 3 escape
 * rules):
 *
 *   filter     = "(" filtercomp ")"
 *   filtercomp = and / or / not / item
 *   and        = "&" filterlist
 *   or         = "|" filterlist
 *   not        = "!" filter
 *   filterlist = 1*filter
 *   item       = simple / present / substring
 *   simple     = attr filtertype assertionvalue
 *   filtertype = "=" / "~=" / ">=" / "<="
 *   present    = attr "=*"
 *   substring  = attr "=" [initial] "*" *(any "*") [final]
 *
 * Assertion values may not contain a raw "(", ")", "*" or NUL. Those bytes are
 * written as "\28", "\29", "\2a" and "\00". IMPORTANT and load-bearing for
 * level 10: a correct parser decides where a value ENDS before it unescapes
 * anything, which is exactly why "\28" inside a value is an inert byte and not
 * an open parenthesis.
 */

/** Thrown for any filter the parser refuses. The message names the offset. */
class LdapFilterError extends RuntimeException
{
}

/* =========================================================================
 * Escaping / unescaping
 * ===================================================================== */

/**
 * RFC 4515 section 3 unescaping of ONE assertion value.
 * Only ever called on text the parser has already carved out of the filter.
 */
function ldap_unescape(string $value): string
{
    return (string)preg_replace_callback(
        '/\\\\([0-9A-Fa-f]{2})/',
        static function (array $m): string {
            return chr((int)hexdec($m[1]));
        },
        $value
    );
}

/**
 * The correct escaper: backslash FIRST, then the three filter metacharacters,
 * then NUL. strtr() with a map does a single left-to-right pass and never
 * re-examines what it has already written, so "(" cannot become "\5c28".
 */
function ldap_escape_value(string $value): string
{
    return strtr($value, [
        '\\'   => '\\5c',
        '('    => '\\28',
        ')'    => '\\29',
        '*'    => '\\2a',
        "\x00" => '\\00',
    ]);
}

/**
 * A single left-to-right unescape pass over an ENTIRE filter string.
 *
 * This is not part of RFC 4515 and it is not how a correct client works. It
 * models a real implementation shortcut - "normalise the filter, then parse
 * it" - and it is the whole subject of level 10. Applied here, "\28" stops
 * being a byte inside a value and becomes an opening parenthesis in the
 * grammar.
 */
function ldap_unescape_whole_filter(string $filter): string
{
    return ldap_unescape($filter);
}

/* =========================================================================
 * Parser
 * ===================================================================== */

final class LdapFilterParser
{
    private string $s;
    private int $i = 0;
    private int $n;

    public function __construct(string $filter)
    {
        $this->s = $filter;
        $this->n = strlen($filter);
    }

    public function offset(): int
    {
        return $this->i;
    }

    public function atEnd(): bool
    {
        return $this->i >= $this->n;
    }

    /** filter = "(" filtercomp ")" */
    public function parseFilter(): array
    {
        $this->expect('(');
        $node = $this->parseComp();
        $this->expect(')');
        return $node;
    }

    private function parseComp(): array
    {
        if ($this->atEnd()) {
            throw new LdapFilterError('filter ended after "(" - nothing to parse');
        }
        $c = $this->s[$this->i];

        if ($c === '&' || $c === '|') {
            $this->i++;
            $children = $this->parseFilterList();
            if (!$children) {
                throw new LdapFilterError(
                    ($c === '&' ? 'AND' : 'OR') . ' group at offset ' . ($this->i - 1)
                    . ' contains no filters'
                );
            }
            return ['type' => $c === '&' ? 'and' : 'or', 'children' => $children];
        }

        if ($c === '!') {
            $this->i++;
            return ['type' => 'not', 'child' => $this->parseFilter()];
        }

        return $this->parseItem();
    }

    /** filterlist = 1*filter */
    private function parseFilterList(): array
    {
        $out = [];
        while (!$this->atEnd() && $this->s[$this->i] === '(') {
            $out[] = $this->parseFilter();
        }
        return $out;
    }

    private function parseItem(): array
    {
        $attr = $this->readAttr();
        $op   = $this->readOperator();
        $raw  = $this->readRawValue();

        if ($op !== '=') {
            $map = ['>=' => 'ge', '<=' => 'le', '~=' => 'approx'];
            return ['type' => $map[$op], 'attr' => $attr, 'value' => ldap_unescape($raw)];
        }

        // "(attr=*)" is a presence test, not a substring test.
        if ($raw === '*') {
            return ['type' => 'present', 'attr' => $attr];
        }

        // Escaped asterisks are written "\2a" and therefore do not appear as a
        // literal "*" here - splitting on "*" only ever splits on STRUCTURAL
        // asterisks. That is the difference between a wildcard and the
        // character.
        if (strpos($raw, '*') === false) {
            return ['type' => 'eq', 'attr' => $attr, 'value' => ldap_unescape($raw)];
        }

        $parts   = explode('*', $raw);
        $initial = ldap_unescape((string)array_shift($parts));
        $final   = ldap_unescape((string)array_pop($parts));
        $any     = [];
        foreach ($parts as $p) {
            if ($p !== '') {
                $any[] = ldap_unescape($p);
            }
        }
        return ['type' => 'substr', 'attr' => $attr, 'initial' => $initial, 'any' => $any, 'final' => $final];
    }

    private function readAttr(): string
    {
        $start = $this->i;
        while (!$this->atEnd() && preg_match('/[A-Za-z0-9;.\-]/', $this->s[$this->i]) === 1) {
            $this->i++;
        }
        if ($this->i === $start) {
            throw new LdapFilterError('expected an attribute name at offset ' . $start
                . $this->found());
        }
        return substr($this->s, $start, $this->i - $start);
    }

    private function readOperator(): string
    {
        $two = substr($this->s, $this->i, 2);
        if ($two === '>=' || $two === '<=' || $two === '~=') {
            $this->i += 2;
            return $two;
        }
        if (!$this->atEnd() && $this->s[$this->i] === '=') {
            $this->i++;
            return '=';
        }
        throw new LdapFilterError('expected "=", ">=", "<=" or "~=" at offset ' . $this->i . $this->found());
    }

    /**
     * Read an assertion value. Structure is decided HERE, before any
     * unescaping: the value ends at the first unescaped ")".
     */
    private function readRawValue(): string
    {
        $out = '';
        while (!$this->atEnd()) {
            $c = $this->s[$this->i];

            if ($c === ')') {
                break;                                   // end of this item
            }
            if ($c === '(') {
                throw new LdapFilterError('unescaped "(" inside an assertion value at offset '
                    . $this->i . ' - write it as \\28');
            }
            if ($c === "\x00") {
                throw new LdapFilterError('NUL byte inside an assertion value at offset ' . $this->i);
            }
            if ($c === '\\') {
                $hex = substr($this->s, $this->i + 1, 2);
                if (preg_match('/^[0-9A-Fa-f]{2}$/', $hex) !== 1) {
                    throw new LdapFilterError('"\\" at offset ' . $this->i
                        . ' must be followed by two hex digits (RFC 4515 section 3)');
                }
                $out .= '\\' . $hex;                     // keep escaped; unescape per segment later
                $this->i += 3;
                continue;
            }
            $out .= $c;
            $this->i++;
        }
        return $out;
    }

    private function expect(string $ch): void
    {
        if ($this->atEnd() || $this->s[$this->i] !== $ch) {
            throw new LdapFilterError('expected "' . $ch . '" at offset ' . $this->i . $this->found());
        }
        $this->i++;
    }

    private function found(): string
    {
        return $this->atEnd()
            ? ', found end of filter'
            : ', found "' . $this->s[$this->i] . '"';
    }
}

/* =========================================================================
 * Parser entry points
 * ===================================================================== */

/**
 * Strict parse: the whole string must be exactly one filter.
 * Used by the levels whose "client" validates what it sends.
 */
function ldap_parse(string $filter): array
{
    $p    = new LdapFilterParser($filter);
    $tree = $p->parseFilter();
    if (!$p->atEnd()) {
        throw new LdapFilterError('trailing input after the filter, at offset ' . $p->offset()
            . ': ' . substr($filter, $p->offset()));
    }
    return $tree;
}

/**
 * Parse the FIRST complete filter and report what was left over.
 *
 * Plenty of client libraries do exactly this: they read one filter off the
 * front of the string and never look at the rest. That behaviour is why the
 * textbook LDAP injection payloads end with an orphaned "(|(uid=*" - the tail
 * exists only to keep the discarded remainder syntactically plausible.
 *
 * @return array{tree:array, consumed:string, trailing:string}
 */
function ldap_parse_first(string $filter): array
{
    $p    = new LdapFilterParser($filter);
    $tree = $p->parseFilter();
    return [
        'tree'     => $tree,
        'consumed' => substr($filter, 0, $p->offset()),
        'trailing' => substr($filter, $p->offset()),
    ];
}

/**
 * Decompose a string into a sequence of complete filters, consuming every
 * byte. Throws if anything is left dangling. This is the "is the filter I
 * built still well formed?" check a cautious developer writes - and level 8
 * shows that passing it is not the same as being safe.
 *
 * @return array<int,array> one parse tree per filter found
 */
function ldap_split_filters(string $s): array
{
    $p    = new LdapFilterParser($s);
    $out  = [];
    while (!$p->atEnd()) {
        $out[] = $p->parseFilter();
    }
    if (!$out) {
        throw new LdapFilterError('empty filter string');
    }
    return $out;
}

/* =========================================================================
 * Rendering
 * ===================================================================== */

/** Canonical re-serialisation of a parse tree. Values are escaped correctly. */
function ldap_filter_to_string(array $n): string
{
    switch ($n['type']) {
        case 'and':
        case 'or':
            $op = $n['type'] === 'and' ? '&' : '|';
            $s  = '';
            foreach ($n['children'] as $c) {
                $s .= ldap_filter_to_string($c);
            }
            return '(' . $op . $s . ')';
        case 'not':
            return '(!' . ldap_filter_to_string($n['child']) . ')';
        case 'present':
            return '(' . $n['attr'] . '=*)';
        case 'eq':
            return '(' . $n['attr'] . '=' . ldap_escape_value($n['value']) . ')';
        case 'ge':
            return '(' . $n['attr'] . '>=' . ldap_escape_value($n['value']) . ')';
        case 'le':
            return '(' . $n['attr'] . '<=' . ldap_escape_value($n['value']) . ')';
        case 'approx':
            return '(' . $n['attr'] . '~=' . ldap_escape_value($n['value']) . ')';
        case 'substr':
            $v = ldap_escape_value($n['initial']) . '*';
            foreach ($n['any'] as $a) {
                $v .= ldap_escape_value($a) . '*';
            }
            return '(' . $n['attr'] . '=' . $v . ldap_escape_value($n['final']) . ')';
    }
    return '(?)';
}

/** Indented, human-readable parse tree. Plain text; escape before printing. */
function ldap_tree_pretty(array $n, int $depth = 0): string
{
    $pad = str_repeat('    ', $depth);
    switch ($n['type']) {
        case 'and':
        case 'or':
            $out = $pad . ($n['type'] === 'and' ? 'AND  (&)' : 'OR   (|)') . "\n";
            foreach ($n['children'] as $c) {
                $out .= ldap_tree_pretty($c, $depth + 1);
            }
            return $out;
        case 'not':
            return $pad . "NOT  (!)\n" . ldap_tree_pretty($n['child'], $depth + 1);
        case 'present':
            return $pad . 'PRESENT    ' . $n['attr'] . " = *\n";
        case 'eq':
            return $pad . 'EQUAL      ' . $n['attr'] . ' = "' . $n['value'] . "\"\n";
        case 'ge':
            return $pad . 'GREATER-EQ ' . $n['attr'] . ' >= "' . $n['value'] . "\"\n";
        case 'le':
            return $pad . 'LESS-EQ    ' . $n['attr'] . ' <= "' . $n['value'] . "\"\n";
        case 'approx':
            return $pad . 'APPROX     ' . $n['attr'] . ' ~= "' . $n['value'] . "\"\n";
        case 'substr':
            $bits = [];
            $bits[] = 'initial="' . $n['initial'] . '"';
            $bits[] = 'any=[' . implode(', ', array_map(static fn($a) => '"' . $a . '"', $n['any'])) . ']';
            $bits[] = 'final="' . $n['final'] . '"';
            return $pad . 'SUBSTRING  ' . $n['attr'] . '  ' . implode('  ', $bits) . "\n";
    }
    return $pad . "?\n";
}

/* =========================================================================
 * Evaluation
 * ===================================================================== */

/**
 * Attribute lookup. LDAP attribute descriptions are case insensitive, so
 * "uid", "UID" and "Uid" are the same attribute.
 *
 * @return array<int,string> every value of the attribute (attributes are multi-valued)
 */
function ldap_attr_values(array $entry, string $attr): array
{
    foreach ($entry['attrs'] as $name => $values) {
        if (strcasecmp($name, $attr) === 0) {
            return $values;
        }
    }
    return [];
}

/** caseIgnoreOrderingMatch, with a numeric shortcut for numeric attributes. */
function ldap_ordering(string $a, string $b): int
{
    if (is_numeric($a) && is_numeric($b)) {
        return (float)$a <=> (float)$b;
    }
    return strcasecmp($a, $b);
}

/** initial + any* + final, all case insensitive. */
function ldap_substring_match(string $value, array $n): bool
{
    $v   = strtolower($value);
    $pos = 0;

    if ($n['initial'] !== '') {
        $i = strtolower($n['initial']);
        if (strncmp($v, $i, strlen($i)) !== 0) {
            return false;
        }
        $pos = strlen($i);
    }
    foreach ($n['any'] as $a) {
        $a = strtolower($a);
        $p = strpos($v, $a, $pos);
        if ($p === false) {
            return false;
        }
        $pos = $p + strlen($a);
    }
    if ($n['final'] !== '') {
        $f = strtolower($n['final']);
        if (strlen($v) - $pos < strlen($f)) {
            return false;
        }
        if (substr($v, -strlen($f)) !== $f) {
            return false;
        }
    }
    return true;
}

/** Does one entry satisfy one parse tree? */
function ldap_eval(array $n, array $entry): bool
{
    switch ($n['type']) {
        case 'and':
            foreach ($n['children'] as $c) {
                if (!ldap_eval($c, $entry)) {
                    return false;
                }
            }
            return true;

        case 'or':
            foreach ($n['children'] as $c) {
                if (ldap_eval($c, $entry)) {
                    return true;
                }
            }
            return false;

        case 'not':
            return !ldap_eval($n['child'], $entry);

        case 'present':
            return ldap_attr_values($entry, $n['attr']) !== [];

        case 'eq':
            foreach (ldap_attr_values($entry, $n['attr']) as $v) {
                if (strcasecmp($v, $n['value']) === 0) {
                    return true;
                }
            }
            return false;

        case 'approx':
            $want = strtolower(preg_replace('/\s+/', ' ', trim($n['value'])));
            foreach (ldap_attr_values($entry, $n['attr']) as $v) {
                if (strtolower(preg_replace('/\s+/', ' ', trim($v))) === $want) {
                    return true;
                }
            }
            return false;

        case 'ge':
            foreach (ldap_attr_values($entry, $n['attr']) as $v) {
                if (ldap_ordering($v, $n['value']) >= 0) {
                    return true;
                }
            }
            return false;

        case 'le':
            foreach (ldap_attr_values($entry, $n['attr']) as $v) {
                if (ldap_ordering($v, $n['value']) <= 0) {
                    return true;
                }
            }
            return false;

        case 'substr':
            foreach (ldap_attr_values($entry, $n['attr']) as $v) {
                if (ldap_substring_match($v, $n)) {
                    return true;
                }
            }
            return false;
    }
    return false;
}

/**
 * Evaluate a parse tree against every entry, in directory order.
 *
 * @param array<int,array> $entries
 * @return array<int,array> the matching entries, order preserved
 */
function ldap_search(array $entries, array $tree): array
{
    $out = [];
    foreach ($entries as $e) {
        if (ldap_eval($tree, $e)) {
            $out[] = $e;
        }
    }
    return $out;
}
