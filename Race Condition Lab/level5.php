<?php
require_once __DIR__ . '/helpers.php';
require_once __DIR__ . '/level_defs.php';
require_once __DIR__ . '/secrets.php';

$L = 5;
race_handle_reset($L);

$s      = race_read($L, ['file' => 'notes.txt', 'leaked' => false]);
$answer = trim((string)($_POST['answer'] ?? ''));
$flag   = '';
$note   = '';

// Once solved, keep the flag visible on later page loads.
if (!empty($s['solved'])) {
    $flag = race_flag($L);
}

if ($answer !== '') {
    if (!empty($s['leaked']) && hash_equals(cl_race_secret(), $answer)) {
        $flag = race_flag($L);
        $s['solved'] = true;
        race_write($L, $s);
    } else {
        $note = '<div class="message error">Not the vault contents, or the export has not leaked it yet.</div>';
    }
}

race_render($L, [
    'form' => race_launcher('api.php?level=5&op=export', ['level' => 5, 'op' => 'export'], 2, 'Step 1 — start the export')
        . race_launcher('api.php?level=5&op=select', ['level' => 5, 'op' => 'select', 'to' => 'vault.key'], 2, 'Step 2 — switch the selection to vault.key')
        . '<form method="post" style="margin-top:0.75rem">
             <div class="form-group">
                 <label class="form-label">Exported vault contents</label>
                 <input type="text" name="answer" class="form-control" spellcheck="false" autocomplete="off"
                        value="' . lk_esc($answer) . '">
             </div>
             <button class="btn btn-primary" type="submit">Submit</button>
           </form>',
    'result' => $note . race_state_block($L, [
            'selected file' => $s['file'],
            'vault exported' => !empty($s['leaked']) ? 'yes' : 'no',
        ], 'Reset restores the selection to notes.txt. The export response appears in the launcher output above.')
        . race_log_block($L),
    'flag'     => $flag,
    'flag_msg' => 'The export validated one filename and read another.',
]);
