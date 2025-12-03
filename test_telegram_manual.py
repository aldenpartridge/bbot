#!/usr/bin/env python3

"""
Manual test to send a test vulnerability to Telegram via BBOT
"""

import sys
import os
sys.path.insert(0, '/home/wired/Development/bbot')

from bbot.modules.output.telegram import telegram
from bbot.scanner.preset.preset import Preset
from bbot.scanner.scanner import Scanner
from bbot.core.event import make_event
from bbot.errors import ScanError

# Your credentials
BOT_TOKEN = "8419771137:AAF3f41MwsICgh7wyb-3nfH9Apu6GakKi1Q"
CHAT_ID = "620058498"

async def send_test_vulnerability():
    """Send a test vulnerability event to Telegram"""

    try:
        # Create config with your credentials
        config = {
            "modules": {
                "telegram": {
                    "bot_token": BOT_TOKEN,
                    "chat_id": CHAT_ID,
                    "min_severity": "LOW",
                    "parse_mode": "MarkdownV2"
                }
            }
        }

        # Create a scan with just the Telegram output module
        preset = Preset('telegram_test', config=config, output_modules=['telegram'])
        scan = Scanner('example.com', preset=preset)

        # Create a test vulnerability event
        test_vuln = make_event(
            data={
                "description": "Test SQL Injection vulnerability",
                "severity": "HIGH",
                "confidence": "High",
                "url": "https://example.com/login",
                "evidence": "Parameter 'username' is vulnerable to time-based SQL injection",
                "remediation": "Use parameterized queries and input validation"
            },
            event_type="VULNERABILITY",
            module="test_module",
            scan=scan,
            tags=["test", "sql-injection", "manual", "high-severity"]
        )

        # Get the telegram module
        telegram_module = scan.modules.get('telegram')
        if not telegram_module:
            print("❌ Telegram module not loaded!")
            return False

        print(f"✅ Telegram module loaded successfully")
        print(f"   Module name: {telegram_module.name}")
        print(f"   Watched events: {telegram_module.watched_events}")
        print(f"   Bot token: {BOT_TOKEN[:20]}...")
        print(f"   Chat ID: {CHAT_ID}")
        print()

        # Test message formatting first
        print("📝 Testing message formatting...")
        formatted_message = telegram_module.format_message(test_vuln)
        print("Formatted message preview:")
        print("-" * 60)
        print(formatted_message)
        print("-" * 60)
        print()

        # Send the test event
        print("📡 Sending test vulnerability to Telegram...")
        print(f"   Event type: {test_vuln.type}")
        print(f"   Severity: {test_vuln.data.get('severity')}")
        print(f"   Description: {test_vuln.data.get('description')}")
        print()

        await telegram_module.handle_event(test_vuln)
        print("✅ Test vulnerability sent to Telegram successfully!")
        print()
        print("🎉 Check your Telegram - you should see a HIGH severity vulnerability alert!")

        return True

    except ScanError as e:
        print(f"❌ BBOT scan error: {e}")
        return False
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    import asyncio

    print("🧪 BBOT Telegram Manual Test")
    print("=" * 40)
    print()

    # Check credentials
    if BOT_TOKEN == "YOUR_REAL_BOT_TOKEN_HERE" or CHAT_ID == "YOUR_REAL_CHAT_ID_HERE":
        print("❌ Please update your credentials in the script:")
        print("   BOT_TOKEN = 'your_actual_bot_token'")
        print("   CHAT_ID = 'your_actual_chat_id'")
        exit(1)

    print(f"📱 Bot Token: {BOT_TOKEN[:20]}...")
    print(f"👥 Chat ID: {CHAT_ID}")
    print()

    # Run the test
    result = asyncio.run(send_test_vulnerability())

    if result:
        print("\n🎊 SUCCESS! Your BBOT Telegram integration is working!")
        print()
        print("🚀 Now you can use BBOT with Telegram:")
        print(f'   bbot -t target.com -m nuclei -o telegram -c modules.telegram.bot_token="{BOT_TOKEN}" -c modules.telegram.chat_id="{CHAT_ID}"')
    else:
        print("\n💥 FAILED! Check the error messages above and try again.")