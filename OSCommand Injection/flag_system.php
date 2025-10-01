<?php
// Level-specific flag access control - simple but secure
function get_level_flag($level) {
    // Clear any existing flags from other levels first
    cleanup_other_levels($level);
    
    // Create level-specific temporary access
    $flag_content = '';
    $allowed_flag_file = '';
    
    switch($level) {
        case 1:
            // Level 1: Basic injection - Flag location: /tmp/level1_flag.txt
            $flag_content = 'FLAG{basic_injection_discovered}';
            $allowed_flag_file = '/tmp/level1_flag.txt';
            break;
        case 2:
            // Level 2: Semicolon filter bypass - Flag location: /tmp/level2_flag.txt
            $flag_content = 'FLAG{semicolon_filter_bypassed}';
            $allowed_flag_file = '/tmp/level2_flag.txt';
            break;
        case 3:
            // Level 3: Space filter bypass - Flag location: /tmp/level3_flag.txt
            $user_id = trim(shell_exec('id -u'));
            $flag_content = "FLAG{space_filter_{$user_id}_bypassed}";
            $allowed_flag_file = '/tmp/level3_flag.txt';
            break;
        case 4:
            // Level 4: Keyword filter bypass - Flag location: /tmp/level4_flag.txt
            $os_name = trim(shell_exec('uname'));
            $flag_content = "FLAG{keyword_{$os_name}_bypass_complete}";
            $allowed_flag_file = '/tmp/level4_flag.txt';
            break;
        case 5:
            // Level 5: Blind command injection - Flag location: /tmp/level5_flag.txt
            $flag_content = 'FLAG{blind_execution_confirmed}';
            $allowed_flag_file = '/tmp/level5_flag.txt';
            break;
        case 6:
            // Level 6: Time-based blind injection - Flag location: /tmp/level6_flag.txt
            $flag_content = 'FLAG{timing_attack_successful}';
            $allowed_flag_file = '/tmp/level6_flag.txt';
            break;
        case 7:
            // Level 7: Advanced encoding bypass - Flag location: /tmp/level7_flag.txt
            $flag_content = 'FLAG{advanced_encoding_bypass_successful}';
            $allowed_flag_file = '/tmp/level7_flag.txt';
            break;
        case 8:
            // Level 8: WAF bypass techniques - Flag location: /tmp/level8_flag.txt
            $flag_content = 'FLAG{waf_bypass_master_level}';
            $allowed_flag_file = '/tmp/level8_flag.txt';
            break;
        case 9:
            // Level 9: Out-of-band data exfiltration - Flag location: /tmp/level9_flag.txt
            $flag_content = 'FLAG{out_of_band_data_exfiltration}';
            $allowed_flag_file = '/tmp/level9_flag.txt';
            break;
        case 10:
            // Level 10: Race condition and automation - Flag location: /tmp/level10_flag.txt
            $flag_content = 'FLAG{race_condition_automation_bypass}';
            $allowed_flag_file = '/tmp/level10_flag.txt';
            break;
        default:
            return false;
    }
    
    // Create accessible flag file for current level only
    file_put_contents($allowed_flag_file, $flag_content);
    chmod($allowed_flag_file, 0644);
    
    // Create web-accessible copy for convenience
    $web_flag_file = "/var/www/html/level{$level}_flag.txt";
    file_put_contents($web_flag_file, $flag_content);
    chmod($web_flag_file, 0644);
    
    return $flag_content;
}

function cleanup_other_levels($current_level) {
    // Remove any real flags that might exist from other levels to prevent cross-level access
    for($i = 1; $i <= 10; $i++) {
        if($i != $current_level) {
            @unlink("/tmp/level{$i}_flag.txt");
            @unlink("/var/www/html/level{$i}_flag.txt");
        }
    }
    
    // Clean up /var/flags directory to prevent cheating
    shell_exec('rm -rf /var/flags/* 2>/dev/null');
}
?>
