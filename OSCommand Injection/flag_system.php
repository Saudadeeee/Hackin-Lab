<?php
// Level-specific flag access control
function get_level_flag($level) {
    // Create level-specific temporary access
    $flag_content = '';
    $allowed_flag_file = '';
    
    switch($level) {
        case 1:
            $flag_content = 'FLAG{basic_injection_discovered}';
            $allowed_flag_file = '/tmp/level1_flag.txt';
            break;
        case 2:
            $flag_content = 'FLAG{semicolon_filter_bypassed}';
            $allowed_flag_file = '/tmp/level2_flag.txt';
            break;
        case 3:
            $user_id = trim(shell_exec('id -u'));
            $flag_content = "FLAG{space_filter_{$user_id}_bypassed}";
            $allowed_flag_file = '/tmp/level3_flag.txt';
            break;
        case 4:
            $os_name = trim(shell_exec('uname'));
            $flag_content = "FLAG{keyword_{$os_name}_bypass_complete}";
            $allowed_flag_file = '/tmp/level4_flag.txt';
            break;
        case 5:
            $flag_content = 'FLAG{blind_execution_confirmed}';
            $allowed_flag_file = '/tmp/level5_flag.txt';
            break;
        case 6:
            $flag_content = 'FLAG{timing_attack_successful}';
            $allowed_flag_file = '/tmp/level6_flag.txt';
            break;
        case 7:
            $flag_content = 'FLAG{advanced_encoding_bypass_successful}';
            $allowed_flag_file = '/tmp/level7_flag.txt';
            break;
        case 8:
            $flag_content = 'FLAG{waf_bypass_master_level}';
            $allowed_flag_file = '/tmp/level8_flag.txt';
            break;
        case 9:
            $flag_content = 'FLAG{out_of_band_data_exfiltration}';
            $allowed_flag_file = '/tmp/level9_flag.txt';
            break;
        case 10:
            $flag_content = 'FLAG{race_condition_automation_bypass}';
            $allowed_flag_file = '/tmp/level10_flag.txt';
            break;
        default:
            return false;
    }
    
    // Create accessible flag file for current level only
    file_put_contents($allowed_flag_file, $flag_content);
    chmod($allowed_flag_file, 0644);
    
    // Create web-accessible copy
    $web_flag_file = "/var/www/html/level{$level}_flag.txt";
    file_put_contents($web_flag_file, $flag_content);
    chmod($web_flag_file, 0644);
    
    // Create decoy files for other levels
    create_decoy_flags($level);
    
    return $flag_content;
}

function create_decoy_flags($current_level) {
    // Create decoy files in /var/flags to confuse direct access
    $decoy_content = "DECOY_FLAG{complete_level_{LEVEL}_properly_to_get_real_flag}";
    
    for($i = 1; $i <= 10; $i++) {
        if($i != $current_level) {
            $decoy_file = "/var/flags/level{$i}_decoy.txt";
            $fake_content = str_replace('{LEVEL}', $i, $decoy_content);
            @file_put_contents($decoy_file, $fake_content);
            @chmod($decoy_file, 0644);
        }
    }
    
    // Make /var/flags directory browsable but containing only decoys
    @file_put_contents('/var/flags/README.txt', 
        "These are decoy flags. Real flags are only accessible when you properly exploit each level.\n" .
        "Listing /var/flags will only show decoy files to prevent cheating.");
}
?>
