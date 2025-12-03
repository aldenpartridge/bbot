#\!/bin/bash
# Test BBOT Telegram with a real vulnerability
echo '🧪 Testing BBOT Telegram integration...'
echo ''

# Replace with your real credentials
BOT_TOKEN='YOUR_REAL_BOT_TOKEN'
CHAT_ID='YOUR_REAL_CHAT_ID'

if [ "$BOT_TOKEN" = "YOUR_REAL_BOT_TOKEN" ] || [ "$CHAT_ID" = "YOUR_REAL_CHAT_ID" ]; then
    echo "❌ Please update BOT_TOKEN and CHAT_ID in this script"
    echo "\nGet your bot token from @BotFather on Telegram"
    echo "Get your chat ID by sending a message to your bot and visiting:"
    echo "https://api.telegram.org/bot<YOUR_BOT_TOKEN>/getUpdates"
    exit 1
fi

echo "🔍 Running BBOT scan with Telegram output..."

# Run BBOT with nuclei (produces vulnerabilities) and telegram output
poetry run bbot -t http://testphp.vulnweb.com/hv/ \
    -m nuclei \
    -o telegram \
    -c modules.telegram.bot_token="$BOT_TOKEN" \
    -c modules.telegram.chat_id="$CHAT_ID" \
    -c modules.telegram.min_severity=LOW \
    --force

echo ''
echo "✅ BBOT scan completed\!"
echo "Check your Telegram for vulnerability notifications."

