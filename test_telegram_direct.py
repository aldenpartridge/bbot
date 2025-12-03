#!/usr/bin/env python3

import asyncio
import httpx

bot_token = "123456789:ABCdefGHIjklMNOpqrsTUVwxyz-123456789"
chat_id = "123456789"

async def test_telegram():
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"

    test_message = """🔴 VULNERABILITY (HIGH)

Description: Test vulnerability message from BBOT
Severity: HIGH
Module: telegram_test

This is a test message to verify your Telegram bot is working correctly."""

    data = {
        "chat_id": chat_id,
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
    result = asyncio.run(test_telegram())
    if result:
        print("\n🎉 Telegram bot is working! You can now use it with BBOT.")
    else:
        print("\n⚠️  Check your bot token and chat ID.")