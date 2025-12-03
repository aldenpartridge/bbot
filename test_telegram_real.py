#!/usr/bin/env python3

import asyncio
import httpx

# Replace these with your real credentials
BOT_TOKEN = "YOUR_REAL_BOT_TOKEN_HERE"
CHAT_ID = "YOUR_REAL_CHAT_ID_HERE"

async def test_telegram():
    if BOT_TOKEN == "YOUR_REAL_BOT_TOKEN_HERE" or CHAT_ID == "YOUR_REAL_CHAT_ID_HERE":
        print("❌ Please update BOT_TOKEN and CHAT_ID with real values")
        return False

    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"

    test_message = """🔴 BBOT Test - VULNERABILITY ALERT

This is a test message from BBOT's Telegram output module.

Test Details:
• Severity: HIGH
• Target: example.com
• Module: telegram_test
• Status: ✅ Working

If you see this message, your Telegram bot is ready for BBOT! 🎉"""

    data = {
        "chat_id": CHAT_ID,
        "text": test_message
    }

    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(url, json=data, timeout=10)
            if response.status_code == 200:
                result = response.json()
                if result.get("ok"):
                    print("✅ Test message sent successfully!")
                    print(f"Message ID: {result['result'].get('message_id')}")
                    print(f"Chat: {result['result']['chat'].get('first_name', 'Unknown')}")
                    return True
                else:
                    print(f"❌ Telegram API error: {result.get('description')}")
                    return False
            else:
                print(f"❌ HTTP error {response.status_code}: {response.text}")
                return False
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

if __name__ == "__main__":
    print("🧪 Testing Telegram bot connection...")
    result = asyncio.run(test_telegram())

    if result:
        print("\n🎉 SUCCESS! Your Telegram bot is working!")
        print("\nYou can now use BBOT with these commands:")
        print(f'bbot -t target.com -m nuclei -o telegram -c modules.telegram.bot_token="{BOT_TOKEN}" -c modules.telegram.chat_id="{CHAT_ID}"')
    else:
        print("\n❌ FAILED! Check your:")
        print("1. Bot token (get from @BotFather)")
        print("2. Chat ID (send message to bot, then check getUpdates)")
        print("3. Bot has permission to send messages")