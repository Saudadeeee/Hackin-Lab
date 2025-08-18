<?php
// Level-specific flag access control with enhanced security
function get_level_flag($level) {
    // Clear any existing flags from other levels first
    cleanup_other_levels($level);
    
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
    
    // Override /var/flags with strict decoys
    create_strict_decoy_flags($level);
    
    return $flag_content;
}

function cleanup_other_levels($current_level) {
    // Remove any real flags that might exist from other levels
    for($i = 1; $i <= 10; $i++) {
        if($i != $current_level) {
            @unlink("/tmp/level{$i}_flag.txt");
            @unlink("/var/www/html/level{$i}_flag.txt");
        }
    }
}

function create_strict_decoy_flags($current_level) {
    // Ensure /var/flags contains ONLY decoy content
    $decoy_message = "DECOY_FLAG{this_is_fake_you_are_cheating_complete_level_{LEVEL}_properly}";
    
    // Remove any real content that might have been placed in /var/flags
    shell_exec('rm -rf /var/flags/level* 2>/dev/null');
    
    // Recreate decoy structure
    for($i = 1; $i <= 10; $i++) {
        $level_dir = "/var/flags/level{$i}";
        @mkdir($level_dir, 0755, true);
        
        $fake_content = str_replace('{LEVEL}', $i, $decoy_message);
        
        // Create multiple decoy files with convincing names
        @file_put_contents("{$level_dir}/flag.txt", $fake_content);
        @file_put_contents("/var/flags/level{$i}_hint.txt", $fake_content);
        @file_put_contents("/var/flags/level{$i}_timing.txt", $fake_content);
        @file_put_contents("/var/flags/level{$i}_encoding.txt", $fake_content);
        @file_put_contents("/var/flags/level{$i}_waf.txt", $fake_content);
        @file_put_contents("/var/flags/level{$i}_oob.txt", $fake_content);
        @file_put_contents("/var/flags/level{$i}_race.txt", $fake_content);
        
        @chmod("{$level_dir}/flag.txt", 0644);
        @chmod("/var/flags/level{$i}_hint.txt", 0644);
        @chmod("/var/flags/level{$i}_timing.txt", 0644);
        @chmod("/var/flags/level{$i}_encoding.txt", 0644);
        @chmod("/var/flags/level{$i}_waf.txt", 0644);
        @chmod("/var/flags/level{$i}_oob.txt", 0644);
        @chmod("/var/flags/level{$i}_race.txt", 0644);
    }
    
    // Create warning file
    $warning = "⚠️  ANTI-CHEATING SYSTEM ACTIVE ⚠️\n\n";
    $warning .= "All flags in this directory are DECOY FLAGS.\n";
    $warning .= "Real flags are dynamically generated only when you properly exploit each level.\n\n";
    $warning .= "Current level generating real flag: {$current_level}\n";
    $warning .= "Real flag location: /tmp/level{$current_level}_flag.txt\n\n";
    $warning .= "To get real flags:\n";
    $warning .= "1. Visit the specific level page\n";
    $warning .= "2. Exploit the vulnerability correctly\n";
    $warning .= "3. Access the dynamically created flag file\n\n";
    $warning .= "Accessing flags from /var/flags is considered cheating!\n";
    
    @file_put_contents("/var/flags/ANTI_CHEAT_WARNING.txt", $warning);
    @chmod("/var/flags/ANTI_CHEAT_WARNING.txt", 0644);
}
?>
?>
