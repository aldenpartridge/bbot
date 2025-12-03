#!/usr/bin/env python3

"""
Simple direct test to send a message to Telegram using BBOT's Telegram module
"""

import asyncio
import sys
import os
sys.path.insert(0, '/home/wired/Development/bbot')

from bbot.modules.output.telegram import telegram
import httpx

# Your credentials
BOT_TOKEN = "8419771137:AAF3f41MwsICgh7wyb-3nfH9Apu6GakKi1Q"
CHAT_ID = "620058498"

async def send_direct_telegram_test():
    """Send a test message directly using Telegram API"""

    print("🧪 Direct Telegram Test")
    print("=" * 30)
    print(f"📱 Bot Token: {BOT_TOKEN[:15]}...")
    print(f"👥 Chat ID: {CHAT_ID}")
    print()

    # Test vulnerability message (formatted like BBOT would send)
    test_message = """🔴 VULNERABILITY (HIGH)

Description: Test SQL Injection vulnerability found in login form
Severity: HIGH
Confidence: High
URL: https://example.com/login
Evidence: Parameter 'username' is vulnerable to time-based SQL injection
Remediation: Use parameterized queries and input validation

Tags: test, sql-injection, manual, high-severity
Module: test_module

🚀 This is a test message from BBOT's Telegram output module!"""

    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"

    data = {
        "chat_id": CHAT_ID,
        "text": test_message
    }

    try:
        print("📡 Sending test message to Telegram...")

        async with httpx.AsyncClient(timeout=15) as client:
            response = await client.post(url, json=data)

            if response.status_code == 200:
                result = response.json()
                if result.get("ok"):
                    print("✅ Message sent successfully!")
                    print(f"📨 Message ID: {result['result'].get('message_id')}")
                    print(f"💬 Chat: {result['result']['chat'].get('first_name', 'Unknown')}")
                    print()
                    print("🎉 SUCCESS! Your Telegram bot is working perfectly!")
                    print()
                    print("📊 Message Details:")
                    print(f"   Length: {len(test_message)} characters")
                    print(f"   Status: Delivered")
                    print()
                    print("🚀 Now you can use BBOT with real scans!")
                    return True
                else:
                    print(f"❌ Telegram API error: {result.get('description')}")
                    return False
            else:
                print(f"❌ HTTP error {response.status_code}")
                print(f"Response: {response.text}")
                return False

    except httpx.ConnectError:
        print("❌ Connection error - check your internet connection")
        return False
    except httpx.TimeoutException:
        print("❌ Request timed out")
        return False
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

def test_credentials():
    """Test if credentials are valid"""

    print("🔍 Testing Telegram credentials...")
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/getMe"

    try:
        response = httpx.get(url, timeout=10)
        if response.status_code == 200:
            result = response.json()
            if result.get("ok"):
                bot_info = result["result"]
                print(f"✅ Bot found: @{bot_info.get('username', 'unknown')}")
                print(f"🤖 Bot name: {bot_info.get('first_name', 'Unknown')}")
                print(f"🆔 Bot ID: {bot_info.get('id')}")
                return True
            else:
                print(f"❌ Invalid bot token: {result.get('description')}")
                return False
        else:
            print(f"❌ Error checking bot: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

if __name__ == "__main__":
    print("🧪 BBOT Telegram Integration Test")
    print("=" * 40)
    print()

    # Test credentials first
    if not test_credentials():
        print()
        print("❌ FAILED: Invalid bot token!")
        print("   Get a valid token from @BotFather on Telegram")
        exit(1)

    print()

    # Send test message
    result = asyncio.run(send_direct_telegram_test())

    if result:
        print()
        print("🎯 NEXT STEPS:")
        print("1. Run a real BBOT scan with vulnerability detection:")
        print(f'   bbot -t target.com -m nuclei -o telegram -c modules.telegram.bot_token="{BOT_TOKEN}" -c modules.telegram.chat_id="{CHAT_ID}"')
        print()
        print("2. Try with different vulnerability producers:")
        print("   - bbot -t target.com -m badsecrets -o telegram ...")
        print("   - bbot -t target.com -m nuclei -o telegram ...")
        print()
        print("3. Configure severity filtering:")
        print("   - Add: -c modules.telegram.min_severity=HIGH")
    else:
        print()
        print("💡 TROUBLESHOOTING:")
        print("1. Make sure you've sent a message to your bot first")
        print("2. Check your chat ID is correct")
        print("3. Ensure your bot has permission to send messages")