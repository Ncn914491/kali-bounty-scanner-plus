#!/bin/bash
# Notification script for blocked actions

TARGET=$1
ACTION=$2
REASON=$3

echo "========================================="
echo "⚠️  ACTION BLOCKED BY POLICY"
echo "========================================="
echo "Target: $TARGET"
echo "Action: $ACTION"
echo "Reason: $REASON"
echo "========================================="
echo ""
echo "This action was blocked by the policy engine."
echo "Review policy/blocked_manifest.json for details."
echo ""
echo "To request manual override:"
echo "  1. Ensure you have explicit permission"
echo "  2. Run with --allow-unblock flag"
echo "  3. Provide written justification"
echo ""

# Log to file
LOG_FILE="logs/blocked_actions.log"
mkdir -p logs
echo "$(date -Iseconds) | $TARGET | $ACTION | $REASON" >> "$LOG_FILE"
