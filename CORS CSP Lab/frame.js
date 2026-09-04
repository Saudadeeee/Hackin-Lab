/**
 * CORS CSP Lab · the frame's reporting helper.
 *
 * Every CSP level gives you something to call once your payload runs:
 * hlab.win(). It writes to the frame and posts a message to the level page, so
 * the "did it execute" question is answered by your browser rather than by the
 * lab. The server-side evaluator answers the same question independently, from
 * the policy string; when the two disagree, the browser is right and the
 * evaluator has a bug worth reporting.
 */
(function (global) {
    'use strict';

    /* A payload that runs during parsing gets here before the status element
       exists, so hold the message until the document is ready. */
    function report(text, ok) {
        var doc = global.document;

        function paint() {
            var el = doc.getElementById('hlab-status');
            if (el) {
                el.textContent = text;
                el.className = 'status ' + (ok ? 'ok' : '');
            }
        }

        if (doc.getElementById('hlab-status')) {
            paint();
        } else if (doc.readyState === 'loading') {
            doc.addEventListener('DOMContentLoaded', paint);
        }
    }

    global.hlab = {
        win: function (label) {
            var who = label ? String(label) : 'an injected script';
            report('hlab.win() called by ' + who + ' - this script executed under the policy above', true);
            try {
                if (global.parent && global.parent !== global) {
                    global.parent.postMessage({ hlab: 'win', label: who }, '*');
                }
            } catch (e) {
                /* a cross-origin parent that refuses messages is not our problem */
            }
            return true;
        }
    };
})(window);
