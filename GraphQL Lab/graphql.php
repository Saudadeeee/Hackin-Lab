<?php
/**
 * GraphQL Lab · a small GraphQL executor written by hand
 * ---------------------------------------------------------------------------
 * There is no Composer in this repo, so this file is the engine every level
 * runs on. It is small but it is not a mock: it lexes, parses, validates and
 * executes a real query document against a schema described as a PHP array,
 * and it returns the standard {"data":…,"errors":[…]} envelope.
 *
 * A request travels through these stages, in this order:
 *   1. lex        - characters become tokens
 *   2. parse      - tokens become a document AST (operations + fragments)
 *   3. select     - one operation is chosen (by name, or the only one present)
 *   4. measure    - depth and complexity are counted, optionally enforced
 *   5. validate   - every field is checked against the type it is selected on
 *   6. execute    - resolvers are called, results are completed by type
 *
 * Almost every level in this lab attacks the gap between two of those stages.
 * The engine therefore records what it did at each one (see GqlTrace) so the
 * level page can print the difference between "the query was validated" and
 * "the data was authorised".
 *
 * Left out on purpose, to stay readable: subscriptions, interfaces and unions,
 * custom scalars, directive execution (@skip/@include are parsed then ignored)
 * and input-object type checking.
 */

/* =========================================================================
 * Errors and tracing
 * ===================================================================== */

/** Thrown by the parser and by resolvers. Becomes an entry in "errors". */
class GqlError extends Exception
{
    /** @var string[] response path of the field that failed */
    public array $path;

    public function __construct(string $message, array $path = [])
    {
        parent::__construct($message);
        $this->path = $path;
    }
}

/**
 * Ordered record of what the engine did. An event has the same shape as a
 * lk_pipeline() stage, so a level hands the events straight to the renderer.
 */
class GqlTrace
{
    public array $events = [];

    public function add(string $label, string $value, string $note = '', ?string $verdict = null): void
    {
        $this->events[] = ['label' => $label, 'value' => $value, 'note' => $note, 'verdict' => $verdict];
    }
}

/* =========================================================================
 * 1. Lexer
 * ===================================================================== */

/**
 * Turn source text into tokens. Commas and comments are ignored: in GraphQL a
 * comma really is whitespace.
 *
 * @return array<int,array{t:string,v:string,p:int}>
 */
function gql_lex(string $src): array
{
    $tokens = [];
    $i      = 0;
    $n      = strlen($src);
    $punct  = ['!', '$', '(', ')', ':', '=', '@', '[', ']', '{', '}', '|', '&'];

    while ($i < $n) {
        $c = $src[$i];

        if ($c === ' ' || $c === "\t" || $c === "\n" || $c === "\r" || $c === ',' || $c === "\xef"
            || $c === "\xbb" || $c === "\xbf") {
            $i++;                                    // whitespace, commas, stray BOM bytes
            continue;
        }
        if ($c === '#') {                            // comment runs to end of line
            while ($i < $n && $src[$i] !== "\n") {
                $i++;
            }
            continue;
        }
        if (substr($src, $i, 3) === '...') {
            $tokens[] = ['t' => 'punct', 'v' => '...', 'p' => $i];
            $i       += 3;
            continue;
        }
        if (in_array($c, $punct, true)) {
            $tokens[] = ['t' => 'punct', 'v' => $c, 'p' => $i];
            $i++;
            continue;
        }
        if ($c === '"') {
            $start = $i;
            [$str, $i] = gql_lex_string($src, $i);
            $tokens[]  = ['t' => 'string', 'v' => $str, 'p' => $start];
            continue;
        }
        if (preg_match('/-?(?:0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?/A', $src, $m, 0, $i)) {
            $isFloat  = (isset($m[1]) && $m[1] !== '') || (isset($m[2]) && $m[2] !== '');
            $tokens[] = ['t' => $isFloat ? 'float' : 'int', 'v' => $m[0], 'p' => $i];
            $i       += strlen($m[0]);
            continue;
        }
        if (preg_match('/[_A-Za-z][_0-9A-Za-z]*/A', $src, $m, 0, $i)) {
            $tokens[] = ['t' => 'name', 'v' => $m[0], 'p' => $i];
            $i       += strlen($m[0]);
            continue;
        }
        throw new GqlError('Syntax error: unexpected character "' . $c . '" at offset ' . $i . '.');
    }
    $tokens[] = ['t' => 'eof', 'v' => '', 'p' => $n];
    return $tokens;
}

/** Read a "simple" or """block""" string starting at $i. @return array{0:string,1:int} */
function gql_lex_string(string $src, int $i): array
{
    $n = strlen($src);
    if (substr($src, $i, 3) === '"""') {
        $end = strpos($src, '"""', $i + 3);
        if ($end === false) {
            throw new GqlError('Syntax error: unterminated block string.');
        }
        return [trim(substr($src, $i + 3, $end - $i - 3)), $end + 3];
    }
    $i++;                                            // step over the opening quote
    $out = '';
    while ($i < $n && $src[$i] !== '"') {
        if ($src[$i] === "\n") {
            throw new GqlError('Syntax error: unterminated string.');
        }
        if ($src[$i] === '\\') {
            $esc = $src[$i + 1] ?? '';
            $map = ['n' => "\n", 't' => "\t", 'r' => "\r", 'b' => "\x08", 'f' => "\x0c",
                    '"' => '"', '\\' => '\\', '/' => '/'];
            if ($esc === 'u') {
                $out .= html_entity_decode('&#x' . substr($src, $i + 2, 4) . ';', ENT_QUOTES, 'UTF-8');
                $i   += 6;
                continue;
            }
            if (!isset($map[$esc])) {
                throw new GqlError('Syntax error: bad escape sequence \\' . $esc . '.');
            }
            $out .= $map[$esc];
            $i   += 2;
            continue;
        }
        $out .= $src[$i];
        $i++;
    }
    if ($i >= $n) {
        throw new GqlError('Syntax error: unterminated string.');
    }
    return [$out, $i + 1];
}

/* =========================================================================
 * 2. Parser (recursive descent)
 * ===================================================================== */

class GqlParser
{
    private array $t;
    private int $i = 0;

    public function __construct(string $source)
    {
        $this->t = gql_lex($source);
    }

    private function peek(): array
    {
        return $this->t[$this->i];
    }

    private function next(): array
    {
        return $this->t[$this->i++];
    }

    private function isPunct(string $v): bool
    {
        return $this->t[$this->i]['t'] === 'punct' && $this->t[$this->i]['v'] === $v;
    }

    private function isName(?string $v = null): bool
    {
        return $this->t[$this->i]['t'] === 'name' && ($v === null || $this->t[$this->i]['v'] === $v);
    }

    private function expectPunct(string $v): void
    {
        if (!$this->isPunct($v)) {
            throw new GqlError('Syntax error: expected "' . $v . '" but found "' . $this->peek()['v'] . '".');
        }
        $this->i++;
    }

    private function expectName(): string
    {
        if (!$this->isName()) {
            throw new GqlError('Syntax error: expected a name but found "' . $this->peek()['v'] . '".');
        }
        return $this->next()['v'];
    }

    /** @return array{operations:array,fragments:array} */
    public function parseDocument(): array
    {
        $ops   = [];
        $frags = [];
        while ($this->peek()['t'] !== 'eof') {
            if ($this->isPunct('{') || $this->isName('query') || $this->isName('mutation')) {
                $ops[] = $this->parseOperation();
            } elseif ($this->isName('fragment')) {
                $f                 = $this->parseFragment();
                $frags[$f['name']] = $f;
            } else {
                throw new GqlError('Syntax error: unexpected "' . $this->peek()['v'] . '" at top level.');
            }
        }
        if (!$ops) {
            throw new GqlError('The document contains no operation to run.');
        }
        return ['operations' => $ops, 'fragments' => $frags];
    }

    private function parseOperation(): array
    {
        $type = 'query';
        $name = null;
        $vars = [];
        if (!$this->isPunct('{')) {                  // not the "{ … }" shorthand
            $type = $this->expectName();
            if ($type !== 'query' && $type !== 'mutation') {
                throw new GqlError('Unsupported operation type "' . $type . '".');
            }
            if ($this->isName()) {
                $name = $this->next()['v'];
            }
            if ($this->isPunct('(')) {
                $vars = $this->parseVariableDefinitions();
            }
            $this->skipDirectives();
        }
        return ['type' => $type, 'name' => $name, 'vars' => $vars,
                'selections' => $this->parseSelectionSet()];
    }

    private function parseFragment(): array
    {
        $this->next();                               // "fragment"
        $name = $this->expectName();
        if (!$this->isName('on')) {
            throw new GqlError('Syntax error: fragment "' . $name . '" needs an "on Type" condition.');
        }
        $this->next();
        $on = $this->expectName();
        $this->skipDirectives();
        return ['name' => $name, 'on' => $on, 'selections' => $this->parseSelectionSet()];
    }

    private function parseVariableDefinitions(): array
    {
        $this->expectPunct('(');
        $defs = [];
        while (!$this->isPunct(')')) {
            $this->expectPunct('$');
            $vn = $this->expectName();
            $this->expectPunct(':');
            $type = $this->parseTypeRef();
            $def  = null;
            if ($this->isPunct('=')) {
                $this->next();
                $def = $this->parseValue();
            }
            $defs[$vn] = ['type' => $type, 'default' => $def];
        }
        $this->expectPunct(')');
        return $defs;
    }

    /** Type references keep their source text: "Int", "[User!]!". */
    private function parseTypeRef(): string
    {
        if ($this->isPunct('[')) {
            $this->next();
            $out = '[' . $this->parseTypeRef() . ']';
            $this->expectPunct(']');
        } else {
            $out = $this->expectName();
        }
        if ($this->isPunct('!')) {
            $this->next();
            $out .= '!';
        }
        return $out;
    }

    private function parseSelectionSet(): array
    {
        $this->expectPunct('{');
        $sels = [];
        while (!$this->isPunct('}')) {
            if ($this->peek()['t'] === 'eof') {
                throw new GqlError('Syntax error: unclosed selection set.');
            }
            $sels[] = $this->parseSelection();
        }
        $this->expectPunct('}');
        if (!$sels) {
            throw new GqlError('Syntax error: a selection set cannot be empty.');
        }
        return $sels;
    }

    private function parseSelection(): array
    {
        if ($this->isPunct('...')) {
            $this->next();
            if ($this->isName() && !$this->isName('on')) {
                $spread = $this->next()['v'];
                $this->skipDirectives();
                return ['kind' => 'spread', 'name' => $spread];
            }
            $on = null;
            if ($this->isName('on')) {
                $this->next();
                $on = $this->expectName();
            }
            $this->skipDirectives();
            return ['kind' => 'inline', 'on' => $on, 'selections' => $this->parseSelectionSet()];
        }

        $name  = $this->expectName();
        $alias = $name;
        if ($this->isPunct(':')) {                   // "alias: field"
            $this->next();
            $name = $this->expectName();
        }
        $args = $this->isPunct('(') ? $this->parseArguments() : [];
        $this->skipDirectives();
        $sub = $this->isPunct('{') ? $this->parseSelectionSet() : [];

        return ['kind' => 'field', 'alias' => $alias, 'name' => $name, 'args' => $args, 'selections' => $sub];
    }

    private function parseArguments(): array
    {
        $this->expectPunct('(');
        $args = [];
        while (!$this->isPunct(')')) {
            $an = $this->expectName();
            $this->expectPunct(':');
            $args[$an] = $this->parseValue();
        }
        $this->expectPunct(')');
        return $args;
    }

    /** Value nodes stay symbolic so $variables can be substituted at execution. */
    private function parseValue(): array
    {
        $tok = $this->peek();
        if ($this->isPunct('$')) {
            $this->next();
            return ['kind' => 'variable', 'name' => $this->expectName()];
        }
        if ($tok['t'] === 'int') {
            $this->next();
            return ['kind' => 'int', 'value' => (int)$tok['v']];
        }
        if ($tok['t'] === 'float') {
            $this->next();
            return ['kind' => 'float', 'value' => (float)$tok['v']];
        }
        if ($tok['t'] === 'string') {
            $this->next();
            return ['kind' => 'string', 'value' => $tok['v']];
        }
        if ($this->isPunct('[')) {
            $this->next();
            $items = [];
            while (!$this->isPunct(']')) {
                $items[] = $this->parseValue();
            }
            $this->expectPunct(']');
            return ['kind' => 'list', 'values' => $items];
        }
        if ($this->isPunct('{')) {
            $this->next();
            $fields = [];
            while (!$this->isPunct('}')) {
                $fn = $this->expectName();
                $this->expectPunct(':');
                $fields[$fn] = $this->parseValue();
            }
            $this->expectPunct('}');
            return ['kind' => 'object', 'fields' => $fields];
        }
        if ($tok['t'] === 'name') {
            $this->next();
            if ($tok['v'] === 'true' || $tok['v'] === 'false') {
                return ['kind' => 'boolean', 'value' => $tok['v'] === 'true'];
            }
            if ($tok['v'] === 'null') {
                return ['kind' => 'null', 'value' => null];
            }
            return ['kind' => 'enum', 'value' => $tok['v']];
        }
        throw new GqlError('Syntax error: "' . $tok['v'] . '" is not a value.');
    }

    /** Directives are parsed so they do not break the grammar, then dropped. */
    private function skipDirectives(): void
    {
        while ($this->isPunct('@')) {
            $this->next();
            $this->expectName();
            if ($this->isPunct('(')) {
                $this->parseArguments();
            }
        }
    }
}

/** Resolve a parsed value node into a PHP value, substituting variables. */
function gql_value(array $node, array $vars)
{
    switch ($node['kind']) {
        case 'variable':
            return $vars[$node['name']] ?? null;
        case 'list':
            return array_map(static fn($v) => gql_value($v, $vars), $node['values']);
        case 'object':
            $out = [];
            foreach ($node['fields'] as $k => $v) {
                $out[$k] = gql_value($v, $vars);
            }
            return $out;
        default:
            return $node['value'] ?? null;
    }
}

/* =========================================================================
 * Type references
 * ===================================================================== */

/** "[User!]!" -> ['list'=>true,'name'=>'User','nonNull'=>true] */
function gql_ref(string $ref): array
{
    $ref     = trim($ref);
    $nonNull = false;
    if (substr($ref, -1) === '!') {
        $nonNull = true;
        $ref     = substr($ref, 0, -1);
    }
    if ($ref !== '' && $ref[0] === '[') {
        $inner            = gql_ref(substr($ref, 1, -1));
        $inner['list']    = true;
        $inner['nonNull'] = $nonNull;
        return $inner;
    }
    return ['list' => false, 'name' => $ref, 'nonNull' => $nonNull];
}

function gql_is_object(array $schema, string $typeName): bool
{
    return isset($schema['types'][$typeName])
        && ($schema['types'][$typeName]['kind'] ?? 'OBJECT') === 'OBJECT';
}

/* =========================================================================
 * 3. Field suggestions ("Did you mean …")
 * ===================================================================== */

/**
 * The whole point of level 2: a helpful error message is a schema oracle.
 * Ranking is edit distance with a large bonus for substring containment, so
 * "pin" finds "onCallPin" the way a real suggestion list does.
 */
function gql_suggest(string $needle, array $candidates, int $limit = 3): array
{
    $scored = [];
    foreach ($candidates as $c) {
        if ($c === $needle || strpos((string)$c, '__') === 0) {
            continue;
        }
        $d = levenshtein(strtolower($needle), strtolower((string)$c));
        if (stripos((string)$c, $needle) !== false || stripos($needle, (string)$c) !== false) {
            $d = min($d, 1);
        }
        if ($d <= 2) {            // 2 keeps the list short; containment already scored 1
            $scored[$c] = $d;
        }
    }
    asort($scored);
    return array_slice(array_keys($scored), 0, $limit);
}

function gql_unknown_field_message(string $field, string $type, array $candidates, bool $suggest): string
{
    $msg = 'Cannot query field "' . $field . '" on type "' . $type . '".';
    if (!$suggest) {
        return $msg;
    }
    $hits = gql_suggest($field, $candidates);
    if (!$hits) {
        return $msg;
    }
    $quoted = array_map(static fn($h) => '"' . $h . '"', $hits);
    $last   = array_pop($quoted);
    return $msg . ' Did you mean ' . ($quoted ? implode(', ', $quoted) . ' or ' . $last : $last) . '?';
}

/* =========================================================================
 * 4. Depth and complexity
 * ===================================================================== */

/**
 * Maximum nesting of a selection set.
 *
 * $expand controls the behaviour level 8 turns into a bug. With $expand=false
 * a fragment spread is counted as a leaf, which is what a limiter that walks
 * the operation AST does. With $expand=true the fragment's own selections are
 * followed, which is what execution actually does.
 */
function gql_depth(array $selections, array $fragments, bool $expand, array $seen = []): int
{
    $max = 0;
    foreach ($selections as $s) {
        if ($s['kind'] === 'field') {
            $d = 1 + ($s['selections'] ? gql_depth($s['selections'], $fragments, $expand, $seen) : 0);
        } elseif ($s['kind'] === 'inline') {
            $d = gql_depth($s['selections'], $fragments, $expand, $seen);   // inline fragments are transparent
        } elseif (!$expand || !isset($fragments[$s['name']]) || isset($seen[$s['name']])) {
            $d = 1;                                                          // counted as a leaf
        } else {
            $seen[$s['name']] = true;
            $d = gql_depth($fragments[$s['name']]['selections'], $fragments, true, $seen);
        }
        $max = max($max, $d);
    }
    return $max;
}

/** Number of field nodes the executor will visit once fragments are expanded. */
function gql_complexity(array $selections, array $fragments, array $seen = []): int
{
    $n = 0;
    foreach ($selections as $s) {
        if ($s['kind'] === 'field') {
            $n += 1 + ($s['selections'] ? gql_complexity($s['selections'], $fragments, $seen) : 0);
        } elseif ($s['kind'] === 'inline') {
            $n += gql_complexity($s['selections'], $fragments, $seen);
        } elseif (isset($fragments[$s['name']]) && !isset($seen[$s['name']])) {
            $seen[$s['name']] = true;
            $n += gql_complexity($fragments[$s['name']]['selections'], $fragments, $seen);
        }
    }
    return $n;
}

/* =========================================================================
 * 5. Validation
 * ===================================================================== */

/**
 * Walk the selection set against the schema. This answers exactly one
 * question - "does every selected field exist on the type it is selected on"
 * - and no other. It is the stage people mistake for authorisation.
 */
function gql_validate(
    array $schema,
    array $selections,
    string $typeName,
    array $fragments,
    bool $suggest,
    array &$errors,
    array $seen = []
): void {
    $fields = $schema['types'][$typeName]['fields'] ?? [];
    foreach ($selections as $s) {
        if ($s['kind'] === 'spread') {
            if (!isset($fragments[$s['name']])) {
                $errors[] = ['message' => 'Unknown fragment "' . $s['name'] . '".'];
                continue;
            }
            if (isset($seen[$s['name']])) {
                continue;                                   // cycle: execution stops there too
            }
            $seen[$s['name']] = true;
            $frag             = $fragments[$s['name']];
            gql_validate($schema, $frag['selections'], $frag['on'] ?: $typeName,
                $fragments, $suggest, $errors, $seen);
            continue;
        }
        if ($s['kind'] === 'inline') {
            gql_validate($schema, $s['selections'], $s['on'] ?: $typeName,
                $fragments, $suggest, $errors, $seen);
            continue;
        }
        if ($s['name'] === '__typename') {
            continue;
        }
        if (!isset($fields[$s['name']])) {
            $errors[] = ['message' => gql_unknown_field_message($s['name'], $typeName, array_keys($fields), $suggest)];
            continue;
        }
        if ($s['selections']) {
            $ref = gql_ref($fields[$s['name']]['type']);
            if (gql_is_object($schema, $ref['name'])) {
                gql_validate($schema, $s['selections'], $ref['name'], $fragments, $suggest, $errors, $seen);
            } else {
                $errors[] = ['message' => 'Field "' . $s['name'] . '" of type "' . $fields[$s['name']]['type']
                                        . '" must not have a selection set.'];
            }
        }
    }
}

/* =========================================================================
 * 6. Introspection
 * ===================================================================== */

/**
 * One node of the __Type chain for a reference such as "[User!]!".
 * Wrapper types have name = null and carry ofType, exactly as the real
 * introspection schema does.
 */
function gql_type_node(string $ref, array $schema): array
{
    $ref = trim($ref);
    if (substr($ref, -1) === '!') {
        return ['name' => null, 'kind' => 'NON_NULL', 'description' => null,
                'fields' => null, 'ofType' => gql_type_node(substr($ref, 0, -1), $schema)];
    }
    if ($ref !== '' && $ref[0] === '[') {
        return ['name' => null, 'kind' => 'LIST', 'description' => null,
                'fields' => null, 'ofType' => gql_type_node(substr($ref, 1, -1), $schema)];
    }
    return ['name' => $ref, 'kind' => $schema['types'][$ref]['kind'] ?? 'SCALAR',
            'description' => $schema['types'][$ref]['desc'] ?? null, 'fields' => null, 'ofType' => null];
}

/**
 * Build the plain arrays that the __schema / __type resolvers return.
 * Only the entries in the top-level "types" list carry their field list; a
 * type reached through a field's type node reports name and kind only, which
 * keeps the structure finite without a lazy resolver.
 */
function gql_introspection_data(array $schema): array
{
    $types = [];
    foreach ($schema['types'] as $name => $def) {
        $fields = null;
        if (($def['kind'] ?? 'OBJECT') === 'OBJECT') {
            $fields = [];
            foreach ($def['fields'] ?? [] as $fn => $fd) {
                $args = [];
                foreach ($fd['args'] ?? [] as $an => $ad) {
                    $args[] = ['name' => $an, 'type' => gql_type_node($ad['type'] ?? 'String', $schema),
                               'defaultValue' => isset($ad['default']) ? json_encode($ad['default']) : null];
                }
                $fields[] = ['name' => $fn, 'description' => $fd['desc'] ?? null,
                             'args' => $args, 'type' => gql_type_node($fd['type'], $schema)];
            }
        }
        $types[] = ['name' => $name, 'kind' => $def['kind'] ?? 'OBJECT',
                    'description' => $def['desc'] ?? null, 'fields' => $fields, 'ofType' => null];
    }
    foreach (['String', 'Int', 'Float', 'Boolean', 'ID'] as $scalar) {
        $types[] = ['name' => $scalar, 'kind' => 'SCALAR', 'description' => null,
                    'fields' => null, 'ofType' => null];
    }
    $byName = [];
    foreach ($types as $t) {
        $byName[$t['name']] = $t;
    }
    return [
        'queryType'    => $byName[$schema['query']] ?? null,
        'mutationType' => isset($schema['mutation']) ? ($byName[$schema['mutation']] ?? null) : null,
        'types'        => $types,
        '_byName'      => $byName,
    ];
}

/**
 * Add the meta types and the __schema / __type root fields. A level that keeps
 * introspection off never calls this, and those fields then fail validation
 * like any other unknown field.
 */
function gql_with_introspection(array $schema): array
{
    $data = gql_introspection_data($schema);

    $schema['types']['__Schema'] = ['kind' => 'OBJECT', 'fields' => [
        'queryType'    => ['type' => '__Type'],
        'mutationType' => ['type' => '__Type'],
        'types'        => ['type' => '[__Type]'],
    ]];
    $schema['types']['__Type'] = ['kind' => 'OBJECT', 'fields' => [
        'name'        => ['type' => 'String'],
        'kind'        => ['type' => 'String'],
        'description' => ['type' => 'String'],
        'fields'      => ['type' => '[__Field]'],
        'ofType'      => ['type' => '__Type'],
    ]];
    $schema['types']['__Field'] = ['kind' => 'OBJECT', 'fields' => [
        'name'        => ['type' => 'String'],
        'description' => ['type' => 'String'],
        'args'        => ['type' => '[__InputValue]'],
        'type'        => ['type' => '__Type'],
    ]];
    $schema['types']['__InputValue'] = ['kind' => 'OBJECT', 'fields' => [
        'name'         => ['type' => 'String'],
        'type'         => ['type' => '__Type'],
        'defaultValue' => ['type' => 'String'],
    ]];

    $schema['types'][$schema['query']]['fields']['__schema'] = [
        'type'    => '__Schema',
        'resolve' => static fn() => $data,
    ];
    $schema['types'][$schema['query']]['fields']['__type'] = [
        'type'    => '__Type',
        'args'    => ['name' => ['type' => 'String!']],
        'resolve' => static fn($root, $args) => $data['_byName'][(string)($args['name'] ?? '')] ?? null,
    ];
    return $schema;
}

/* =========================================================================
 * 7. Execution
 * ===================================================================== */

/**
 * Run one document.
 *
 * @param array $opts operationName, variables, context, introspection (bool),
 *                    suggestions (bool), max_depth (int, 0 = off),
 *                    max_complexity (int, 0 = off), trace (GqlTrace)
 * @return array{result:array,trace:GqlTrace,operation:?array,depth:int,
 *               depth_expanded:int,complexity:int,resolvers:array,ok:bool}
 */
function gql_execute(array $schema, string $source, array $opts = []): array
{
    $trace     = $opts['trace'] ?? new GqlTrace();
    $vars      = (array)($opts['variables'] ?? []);
    $ctx       = (array)($opts['context'] ?? []);
    $suggest   = (bool)($opts['suggestions'] ?? false);
    $opName    = $opts['operationName'] ?? null;
    $resolvers = [];

    $report = [
        'result'    => ['data' => null], 'trace' => $trace, 'operation' => null,
        'depth'     => 0, 'depth_expanded' => 0, 'complexity' => 0,
        'resolvers' => [], 'ok' => false,
    ];

    $trace->add('raw document received', trim($source) === '' ? '(empty)' : $source,
        'Bytes as they arrived. Nothing has been parsed yet, so nothing has been authorised yet.');

    /* --- parse -------------------------------------------------------- */
    try {
        $doc = (new GqlParser($source))->parseDocument();
    } catch (GqlError $e) {
        $trace->add('parse', $e->getMessage(), '', 'block');
        $report['result'] = ['data' => null, 'errors' => [['message' => $e->getMessage()]]];
        return $report;
    }

    /* --- choose the operation ----------------------------------------- */
    $op = null;
    if ($opName !== null && $opName !== '') {
        foreach ($doc['operations'] as $candidate) {
            if ($candidate['name'] === $opName) {
                $op = $candidate;
            }
        }
        if ($op === null) {
            $msg              = 'Unknown operation named "' . $opName . '".';
            $trace->add('operation selection', $msg, '', 'block');
            $report['result'] = ['data' => null, 'errors' => [['message' => $msg]]];
            return $report;
        }
    } else {
        $op = $doc['operations'][0];
    }
    $report['operation'] = ['name' => $op['name'], 'type' => $op['type']];
    $trace->add('parsed operation', $op['type'] . ' ' . ($op['name'] ?? '(anonymous)'),
        'The document carries its own operation type and name. Whether the request body <em>also</em> carried an
         <code>operationName</code> field is a different question, answered by a different piece of code.');

    /* --- measure ------------------------------------------------------- */
    $frags                    = $doc['fragments'];
    $depth                    = gql_depth($op['selections'], $frags, false);
    $expanded                 = gql_depth($op['selections'], $frags, true);
    $complexity               = gql_complexity($op['selections'], $frags);
    $report['depth']          = $depth;
    $report['depth_expanded'] = $expanded;
    $report['complexity']     = $complexity;

    $maxDepth = (int)($opts['max_depth'] ?? 0);
    $maxCost  = (int)($opts['max_complexity'] ?? 0);
    if ($maxDepth > 0 || $maxCost > 0) {
        $tooDeep = ($maxDepth > 0 && $depth > $maxDepth) || ($maxCost > 0 && $complexity > $maxCost);
        $trace->add(
            'depth / complexity counted on the operation AST',
            'depth(counted) = ' . $depth . '   depth(after fragment expansion) = ' . $expanded
            . '   complexity = ' . $complexity
            . ($maxDepth > 0 ? '   [limit: depth <= ' . $maxDepth . ']' : ''),
            'The limiter enforces the <em>counted</em> value. A fragment spread was treated as a leaf, so the two
             numbers only agree when the document has no fragments.',
            $tooDeep ? 'block' : 'pass'
        );
    }
    if ($maxDepth > 0 && $depth > $maxDepth) {
        $msg              = 'Query is too deep: ' . $depth . ' exceeds the maximum depth of ' . $maxDepth . '.';
        $report['result'] = ['data' => null, 'errors' => [['message' => $msg]]];
        return $report;
    }
    if ($maxCost > 0 && $complexity > $maxCost) {
        $msg              = 'Query is too complex: ' . $complexity . ' exceeds the maximum of ' . $maxCost . '.';
        $report['result'] = ['data' => null, 'errors' => [['message' => $msg]]];
        return $report;
    }

    /* --- introspection -------------------------------------------------- */
    if (!empty($opts['introspection'])) {
        $schema = gql_with_introspection($schema);
    }

    /* --- validate ------------------------------------------------------- */
    $rootType = $op['type'] === 'mutation' ? ($schema['mutation'] ?? '') : $schema['query'];
    if ($rootType === '' || !isset($schema['types'][$rootType])) {
        $msg              = 'This endpoint does not support ' . $op['type'] . ' operations.';
        $trace->add('root type lookup', $msg, '', 'block');
        $report['result'] = ['data' => null, 'errors' => [['message' => $msg]]];
        return $report;
    }
    $errors = [];
    gql_validate($schema, $op['selections'], $rootType, $frags, $suggest, $errors);
    if ($errors) {
        $trace->add('validation against the schema',
            count($errors) . ' error(s): ' . implode(' | ', array_column($errors, 'message')),
            'Validation asks whether the <em>shape</em> of the query is legal. It never asks who is asking.',
            'block');
        $report['result'] = ['data' => null, 'errors' => $errors];
        return $report;
    }
    $trace->add('validation against the schema', 'ok - every selected field exists on its type',
        'Shape approved. Authorisation, if there is any, happens inside the resolvers below.', 'pass');

    /* --- execute --------------------------------------------------------- */
    $ctx['trace'] = $trace;
    $data         = gql_execute_selections(
        $schema, $op['selections'], $rootType, $ctx['root'] ?? null,
        $ctx, $frags, $vars, $errors, [], $resolvers
    );

    $report['result']    = $errors ? ['data' => $data, 'errors' => $errors] : ['data' => $data];
    $report['ok']        = !$errors;
    $report['resolvers'] = $resolvers;
    $trace->add('resolvers invoked', $resolvers ? implode(', ', $resolvers) : '(none)',
        'One entry per resolver call, in execution order. A field listed here ran; whether it checked anything
         is entirely up to its own code.');
    return $report;
}

/** Flatten fragments into a plain list of field selections for one type. */
function gql_collect_fields(array $selections, string $typeName, array $fragments, array &$seen): array
{
    $out = [];
    foreach ($selections as $s) {
        if ($s['kind'] === 'field') {
            $out[] = $s;
        } elseif ($s['kind'] === 'inline') {
            if ($s['on'] === null || $s['on'] === $typeName) {
                foreach (gql_collect_fields($s['selections'], $typeName, $fragments, $seen) as $f) {
                    $out[] = $f;
                }
            }
        } elseif (isset($fragments[$s['name']]) && !isset($seen[$s['name']])) {
            $frag = $fragments[$s['name']];
            if ($frag['on'] === $typeName || $frag['on'] === '') {
                $seen[$s['name']] = true;
                foreach (gql_collect_fields($frag['selections'], $typeName, $fragments, $seen) as $f) {
                    $out[] = $f;
                }
                unset($seen[$s['name']]);
            }
        }
    }
    return $out;
}

function gql_execute_selections(
    array $schema,
    array $selections,
    string $typeName,
    $parent,
    array $ctx,
    array $fragments,
    array $vars,
    array &$errors,
    array $path,
    array &$resolvers
): array {
    $seen   = [];
    $fields = gql_collect_fields($selections, $typeName, $fragments, $seen);
    $defs   = $schema['types'][$typeName]['fields'] ?? [];
    $out    = [];

    foreach ($fields as $f) {
        $key      = $f['alias'];
        $here     = array_merge($path, [$key]);
        $pathText = implode('.', $here);

        if ($f['name'] === '__typename') {
            $out[$key] = $typeName;
            continue;
        }
        $def = $defs[$f['name']] ?? null;
        if ($def === null) {                                  // unreachable after validation
            $errors[]  = ['message' => 'Cannot query field "' . $f['name'] . '" on type "' . $typeName . '".',
                          'path' => $here];
            $out[$key] = null;
            continue;
        }

        $args = [];
        foreach ($def['args'] ?? [] as $an => $ad) {
            if (array_key_exists('default', $ad)) {
                $args[$an] = $ad['default'];
            }
        }
        foreach ($f['args'] as $an => $node) {
            $args[$an] = gql_value($node, $vars);
        }

        $resolvers[] = $pathText;
        try {
            if (isset($def['resolve'])) {
                $value = ($def['resolve'])($parent, $args, $ctx, ['field' => $f['name'], 'path' => $here]);
            } elseif (is_array($parent) && array_key_exists($f['name'], $parent)) {
                $value = $parent[$f['name']];
            } else {
                $value = null;
            }
        } catch (GqlError $e) {
            $errors[]  = ['message' => $e->getMessage(), 'path' => $here];
            $out[$key] = null;
            continue;
        } catch (Throwable $e) {
            $errors[]  = ['message' => 'Resolver "' . $f['name'] . '" failed: ' . $e->getMessage(),
                          'path' => $here];
            $out[$key] = null;
            continue;
        }

        $out[$key] = gql_complete(
            $schema, $def['type'], $value, $f['selections'], $ctx, $fragments, $vars, $errors, $here, $resolvers
        );
    }
    return $out;
}

/** Coerce a resolver's return value to its declared type, recursing into objects. */
function gql_complete(
    array $schema,
    string $ref,
    $value,
    array $selections,
    array $ctx,
    array $fragments,
    array $vars,
    array &$errors,
    array $path,
    array &$resolvers
) {
    $t = gql_ref($ref);
    if ($value === null) {
        return null;
    }
    if ($t['list']) {
        $inner = $t['name'] === '' ? 'String' : $t['name'];
        $out   = [];
        foreach ((array)$value as $i => $item) {
            $out[] = gql_complete($schema, $inner, $item, $selections, $ctx, $fragments, $vars,
                $errors, array_merge($path, [(string)$i]), $resolvers);
        }
        return $out;
    }
    if (gql_is_object($schema, $t['name'])) {
        if (!$selections) {
            $errors[] = ['message' => 'Field of type "' . $t['name'] . '" must have a selection set.',
                         'path' => $path];
            return null;
        }
        return gql_execute_selections($schema, $selections, $t['name'], $value, $ctx,
            $fragments, $vars, $errors, $path, $resolvers);
    }
    switch ($t['name']) {
        case 'Int':
            return (int)$value;
        case 'Float':
            return (float)$value;
        case 'Boolean':
            return (bool)$value;
        default:
            return is_scalar($value) ? (string)$value : $value;
    }
}

/* =========================================================================
 * Presentation helpers used by the level pages
 * ===================================================================== */

/** The envelope as a client would see it. */
function gql_json(array $result): string
{
    return (string)json_encode($result, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
}

/**
 * Did the response actually carry the secret? Flags are awarded on this and
 * never on the text of the query: the learner has to make the server hand the
 * value over, not merely ask for it in a plausible shape.
 */
function gql_data_contains(array $result, string $secret): bool
{
    if ($secret === '' || !isset($result['data'])) {
        return false;
    }
    return strpos((string)json_encode($result['data']), $secret) !== false;
}
