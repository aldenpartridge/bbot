#!/usr/bin/env python3

"""
Test the Telegram message formatting with sample vulnerability data
"""

import sys
import os
sys.path.insert(0, '/home/wired/Development/bbot')

from bbot.modules.output.telegram import telegram
from bbot.core.event.base import BaseEvent

class MockScanner:
    class MockConfig:
        def get(self, key, default=None):
            return {
                'bot_token': '123456789:ABCdefGHIjklMNOpqrsTUVwxyz-123456789',
                'chat_id': '123456789',
                'min_severity': 'LOW',
                'parse_mode': 'MarkdownV2'
            }.get(key, default)

    def __init__(self):
        self.config = self.MockConfig()

class MockEvent:
    def __init__(self):
        self.type = "VULNERABILITY"
        self.data = {
            "description": "SQL Injection vulnerability found in login form",
            "severity": "HIGH",
            "confidence": "High",
            "url": "https://example.com/login",
            "module": "nuclei"
        }
        self.tags = ["in-scope", "sql-injection", "web", "high-severity"]
        self.module = "nuclei"

def test_telegram_formatting():
    print("🧪 Testing Telegram message formatting...")
    print()

    # Create mock objects
    mock_scanner = MockScanner()
    mock_event = MockEvent()

    # Create telegram module instance
    telegram_module = telegram(mock_scanner)
    telegram_module.config = mock_scanner.config

    # Test different formatting methods
    print("📝 Raw event data:")
    print(f"   Type: {mock_event.type}")
    print(f"   Severity: {mock_event.data.get('severity')}")
    print(f"   Description: {mock_event.data.get('description')}")
    print(f"   Tags: {', '.join(mock_event.tags)}")
    print()

    # Test message formatting
    try:
        message = telegram_module.format_message(mock_event)
        print("✅ Formatted Telegram message:")
        print("-" * 50)
        print(message)
        print("-" * 50)
        print(f"📊 Message length: {len(message)} characters")
        print(f"📏 Telegram limit: 4096 characters")

        if len(message) <= 4096:
            print("✅ Message fits within Telegram limits")
        else:
            print("⚠️  Message exceeds Telegram limits (will be truncated)")

    except Exception as e:
        print(f"❌ Error formatting message: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_telegram_formatting()