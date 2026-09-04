# Building a Hackin-Lab lab

Every lab in this repo is a self-contained Docker service with 10 progressive levels.
The newer labs are built on `lab_kit.php`, which supplies the page shell and the
teaching primitives. **JWT Lab is the reference implementation — read it before
building anything.**

## The teaching contract

The point of these labs is *not* to be solvable. It is to be **explainable**.
A learner who finishes a level must be able to answer "why did that work?" without
looking at the hints. Concretely, every level must let them:

1. **Read the real code** that runs — the left panel shows the actual sink.
2. **Watch their own input travel through it** — the `pipeline` trace prints the
   value at each transformation, so a *rejected* payload teaches as much as a
   winning one.
3. **Test one hypothesis at a time** — `probes` are single questions with a
   payload attached, never finished exploits.
4. **See why the winner won** — the `why` block, shown only on success.
5. **See how it should have been written** — the `fix` diff.

Anti-goals: black-box guessing, wordlist spraying, "try payloads until green".
If a level can be solved faster by fuzzing than by reading, it is a bad level.

## Layout (fixed — do not restructure)

```
source code panel (left)          challenge panel (right)
  vulnerable code + line numbers     scenario
  vulnerability annotation           mental model
  theory: root cause                 the interaction form
  the fix (bad vs patched)           result / flag / why
                                     pipeline trace
                                     sink string
                                     probes
--------------------------------------------------------
hints (5, progressive)  ·  flag submit  ·  prev / index / next
```

## Files per lab

```
<Lab Name>/
  css/styles.css        base theme + kit.css   (created by _kit/scaffold.sh)
  lab_kit.php           copy of _kit/lab_kit.php (created by scaffold.sh)
  docker-compose.yml    unique port            (created by scaffold.sh)
  Dockerfile            FROM php:8.2-apache, COPY . /var/www/html/
  helpers.php           lab meta, flags, level table, 5 hints per level
  index.php             lk_index_page(...)
  submit.php            lk_submit_page(...)
  level1.php … level10.php
  solve_check.php       runs the intended solution for all 10 levels
  README.md
```

Scaffold with:

```bash
./_kit/scaffold.sh "<Lab Name>" <slug> <port>
```

## helpers.php shape

```php
require_once __DIR__ . '/lab_kit.php';

function xxlab(): array   { return ['slug'=>'xx','name'=>'…','icon'=>'…','total'=>10,'tagline'=>'…']; }
function xx_flag(int $l): string  { … 'FLAG{snake_case_lesson}' … }   // the flag names the LESSON
function xx_levels(): array {
    return [1 => ['title'=>…, 'difficulty'=>'Easy|Medium|Hard|Expert', 'skill'=>…, 'desc'=>…], …];
}
function xx_hints(int $l): array {  // exactly 5, in this order:
    // 1 concept   2 observation about THIS code   3 technique
    // 4 the shape of the payload   5 a working payload
}
```

## levelN.php shape

```php
<?php
require_once __DIR__ . '/helpers.php';

$L = 7; $meta = xx_levels()[$L];

// 1. challenge logic — the real vulnerable code, running for real
// 2. build $pipeline stages from the learner's actual input
// 3. set $flag when the exploit genuinely succeeded (never a string match
//    on the payload — check the EFFECT: a row read, a state reached, a
//    signature accepted)

lk_page([
    'lab' => xxlab(), 'level' => $L,
    'title' => $meta['title'], 'difficulty' => $meta['difficulty'],
    'code' => $code, 'vuln_lines' => [6,7],
    'annotation' => '…one paragraph: what exactly is wrong…',
    'theory'     => '…2-3 paragraphs: the CLASS of bug, why it generalises…',
    'fix'        => ['bad'=>…, 'good'=>…, 'note'=>…],
    'scenario'   => '<strong>Scenario:</strong> … <br><strong>Goal:</strong> …',
    'model'      => ['title'=>…, 'html'=>'…how the sink parses; a table works well…'],
    'form'       => '…html…',
    'result'     => $result,
    'flag'       => $flag, 'flag_msg' => '…', 'why' => '…shown on success…',
    'pipeline'   => $pipeline,
    'sink'       => ['label'=>…, 'before'=>…, 'injected'=>$userInput, 'after'=>…],  // optional
    'probes'     => ['param'=>'q','method'=>'GET','action'=>'level7.php','items'=>[…]],
    'hints'      => xx_hints($L),
]);
```

### Kit API

| function | purpose |
|---|---|
| `lk_page($cfg)` | whole level page |
| `lk_index_page($lab,$levels,$intro,$note)` | level grid |
| `lk_submit_page($lab,$levels,$flagFn)` | flag submit + progress |
| `lk_code($src,$vulnLines,$lang)` | line-numbered highlighted source |
| `lk_pipeline($stages,$title)` | filter trace; stage = `['label','value','note','verdict'=>'pass'\|'block']` |
| `lk_sink($label,$before,$injected,$after)` | final string with injection highlighted |
| `lk_probes($items,$param,$method,$action)` | hypothesis probes; item = `['q','payload','learn']` |
| `lk_model/lk_theory/lk_why/lk_fix` | teaching boxes |
| `lk_esc($s)` / `lk_visible($s)` | escape / show control chars and spaces |
| `lk_completed($slug)` / `lk_mark_complete($slug,$n)` | progress cookie |

CSS available: `.message .success/.error/.info`, `.output-box`, `.lk-kv` (2-col table),
`.lk-split`, `.form-control`, `.form-label`, `.btn .btn-primary/.btn-outline`,
`.scenario`, `.data-table`.

## Writing rules

- **Flags** name the lesson: `FLAG{decode_is_not_verify}`, not `FLAG{level3_done}`.
- **Prose is plain and specific.** No "simply", no "just", no exclamation marks.
  Say what happens and why, in the fewest words that stay precise.
- **Probes must not solve the level.** They answer one question with a harmless
  payload (e.g. `role=user`, not `role=admin`). The learner assembles the exploit.
- **Difficulty curve:** 1–3 Easy, 4–6 Medium, 7–8 Hard, 9–10 Expert. Later levels
  should *reuse* what earlier ones taught (a key cracked in level 4 still works in 9).
- **Filters must be real code**, visible in the panel, and the trace must show the
  learner's input passing through each stage of that same filter.
- **Never award a flag for a payload matching a regex.** Award it for the effect.

## Verifying

```bash
cd "<Lab Name>"
for f in *.php; do php -l "$f"; done
docker compose up --build -d
MSYS_NO_PATHCONV=1 docker compose exec -T web php //var/www/html/solve_check.php
```

`solve_check.php` must exercise the *intended* solution for all ten levels and
print `10 passed, 0 failed`.

## Port registry

| port | lab |
|------|-----|
| 8080–8092 | the original thirteen labs |
| 8093 | JWT Lab |
| 8094 | Race Condition Lab |
| 8095 | CORS CSP Lab |
| 8096 | Crypto Oracle Lab |
| 8097 | Business Logic Lab |
| 8098 | GraphQL Lab |
| 8099 | Auth Reset Lab |
| 8100 | XPath LDAP Lab |

## Retrofitting an existing lab

Older labs keep their own page structure. Do not restructure them — add the
teaching layer as a full-width block beneath the existing two panels, directly
above the hints. `XSS Lab` is the reference retrofit.

```bash
cd "<Lab Name>"
cp ../_kit/lab_kit.php lab_kit.php
cat ../_kit/kit.css >> css/styles.css      # append, do not overwrite
```

Then create `teaching.php` with three parts:

```php
require_once __DIR__ . '/lab_kit.php';

// 1. static prose per level: model_title, model, why, fix_bad, fix_good,
//    fix_note, param, probes[]
function xx_teach_content(int $level): array { ... }

// 2. the learner's REAL input through the level's REAL filter code
function xx_teach_pipeline(int $level, array $ctx): array { ... }
function xx_teach_sink(int $level, array $ctx): string { ... }

// 3. assembler - model, pipeline, sink, why (only when solved), probes, fix
function xx_teach(int $level, array $ctx): string { ... }
```

Wire each level page with two lines:

```php
require_once __DIR__ . '/teaching.php';        // next to the helpers require
...
<?= xx_teach($levelId, ['input' => $var, 'solved' => $flag !== '']) ?>
<?= render_hint_section($hints) ?>
```

Levels that `exit` early on a blocked payload need the block wired into that
branch too, otherwise the learner never sees the stage that stopped them —
which is the most useful trace in the lab.

Rules for a retrofit:

- Recompute the filter in `teaching.php` using the **same expressions** the
  level runs. If they drift apart the trace becomes a lie.
- Do not change flag values, verification logic, or the hand-written
  syntax-highlighted source panels.
- Do check that each level is still genuinely exploitable. Language defaults
  change: PHP 8.1 changed `htmlspecialchars()` to default to
  `ENT_QUOTES|ENT_SUBSTITUTE`, which silently fixed XSS Lab level 5 until the
  flag was pinned explicitly. When you find one of these, fix the running code
  so the lesson is real, and sync the displayed source to match.
- Verify: `php -l` on everything, HTTP 200 on every page, no
  `Warning:`/`Notice:`/`Fatal error:` in the rendered HTML, known-good payloads
  still award their flags, and a blocked payload produces a trace naming the
  stage that blocked it.
