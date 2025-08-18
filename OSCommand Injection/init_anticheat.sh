#!/bin/bash

# Anti-cheat initialization script
# This script runs on container startup to ensure security

echo "🔒 Initializing anti-cheat system..."

# Remove any potential real flags that might exist
rm -rf /var/flags/level*/flag.txt 2>/dev/null
rm -rf /var/flags/level*_*.txt 2>/dev/null

# Create comprehensive decoy structure
mkdir -p /var/flags

# Create warning file
cat > /var/flags/ANTI_CHEAT_WARNING.txt << 'EOF'
⚠️  ANTI-CHEATING SYSTEM ACTIVE ⚠️

All flags in this directory are DECOY FLAGS designed to prevent cheating.

Real flags are dynamically generated ONLY when you:
1. Load the specific level page in your browser
2. Properly exploit the vulnerability using command injection
3. Access the dynamically created flag file in /tmp/

IMPORTANT LOCATIONS:
- /var/flags/       = DECOY FLAGS ONLY (fake)
- /tmp/levelX_flag.txt = REAL FLAGS (generated per level)
- /var/www/html/levelX_flag.txt = REAL FLAGS (web accessible)

If you see flags in /var/flags/, they are ALL FAKE!
The system detects if you're trying to cheat by accessing other level flags.

Complete each level properly to earn your flags legitimately.
EOF

# Create convincing decoy files for all levels
for i in {1..10}; do
    mkdir -p /var/flags/level$i
    
    # Create multiple decoy files with realistic names
    echo "DECOY_FLAG{fake_level_${i}_flag_complete_properly}" > /var/flags/level$i/flag.txt
    echo "DECOY_FLAG{decoy_level_${i}_hint}" > /var/flags/level${i}_hint.txt
    echo "DECOY_FLAG{fake_level_${i}_timing}" > /var/flags/level${i}_timing.txt
    echo "DECOY_FLAG{decoy_level_${i}_encoding}" > /var/flags/level${i}_encoding.txt
    echo "DECOY_FLAG{fake_level_${i}_waf}" > /var/flags/level${i}_waf.txt
    echo "DECOY_FLAG{decoy_level_${i}_oob}" > /var/flags/level${i}_oob.txt
    echo "DECOY_FLAG{fake_level_${i}_race}" > /var/flags/level${i}_race.txt
    echo "DECOY_FLAG{decoy_level_${i}_proof}" > /var/flags/level${i}_proof.txt
    
    # Set permissions
    chmod 644 /var/flags/level$i/flag.txt
    chmod 644 /var/flags/level${i}_*.txt
done

# Create additional convincing decoy files that match old references
echo "DECOY_FLAG{fake_basic_injection}" > /var/flags/level1_hint.txt
echo "DECOY_FLAG{fake_semicolon_filter}" > /var/flags/level2_hint.txt
echo "DECOY_FLAG{fake_space_filter}" > /var/flags/level3_cmd.txt
echo "DECOY_FLAG{fake_keyword_filter}" > /var/flags/level4_cmd.txt
echo "DECOY_FLAG{fake_blind_execution}" > /var/flags/level5_proof.txt
echo "DECOY_FLAG{fake_timing_attack}" > /var/flags/level6_timing.txt
echo "DECOY_FLAG{fake_encoding_bypass}" > /var/flags/level7_encoding.txt
echo "DECOY_FLAG{fake_waf_bypass}" > /var/flags/level8_waf.txt
echo "DECOY_FLAG{fake_oob_exfiltration}" > /var/flags/level9_oob.txt
echo "DECOY_FLAG{fake_race_condition}" > /var/flags/level10_race.txt

chmod 644 /var/flags/level*_*.txt

# Ensure no real flags exist at startup
rm -f /tmp/level*_flag.txt 2>/dev/null
rm -f /var/www/html/level*_flag.txt 2>/dev/null

echo "✅ Anti-cheat system initialized. All flags in /var/flags are decoys."
echo "📍 Real flags will only be generated when levels are properly exploited."
