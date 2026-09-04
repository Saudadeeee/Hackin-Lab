<?php
/** Value level 5 exports when the TOCTOU window is hit. */
function cl_race_secret(): string
{
    return 'VAULT-9931-TOCTOU-WINS';
}
