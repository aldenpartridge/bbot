import httpx
import json

from .base import ModuleTestBase


class TestTelegram(ModuleTestBase):
    targets = ["http://127.0.0.1:8888/test_vuln.html", "http://127.0.0.1:8888/another_vuln.html"]
    modules_overrides = ["telegram", "nuclei", "httpx"]

    bot_token = "1234567890:ABCdefGHIjklMNOpqrsTUVwxyz-123456789"
    chat_id = "123456789"
    webhook_url = f"https://api.telegram.org/bot{bot_token}/sendMessage"

    config_overrides = {
        "modules": {
            "telegram": {
                "bot_token": bot_token,
                "chat_id": chat_id,
                "min_severity": "MEDIUM",
                "parse_mode": "MarkdownV2"
            }
        }
    }

    async def setup_after_prep(self, module_test):
        # Mock HTTP server for the target websites
        respond_args = {
            "response_data": """
            <html>
                <body>
                    <h1>Test Page</h1>
                    <form action="/login" method="POST">
                        <input type="text" name="username" />
                        <input type="password" name="password" />
                        <input type="submit" value="Login" />
                    </form>
                    <div id="admin-panel">Admin Access Required</div>
                </body>
            </html>
            """,
            "headers": {"Content-Type": "text/html"},
        }
        module_test.set_expect_requests(expect_args={"uri": "/test_vuln.html"}, respond_args=respond_args)
        module_test.set_expect_requests(expect_args={"uri": "/another_vuln.html"}, respond_args=respond_args)

        # Track Telegram API requests
        module_test.telegram_requests = []

        def telegram_response(request: httpx.Request):
            # Track the request for validation
            module_test.telegram_requests.append(request)

            # Validate request format
            if request.url != self.webhook_url:
                return httpx.Response(status_code=404, json={"ok": False, "description": "Not Found"})

            try:
                request_data = request.json()
            except Exception:
                return httpx.Response(status_code=400, json={"ok": False, "description": "Bad Request"})

            # Validate required fields
            if "chat_id" not in request_data or "text" not in request_data:
                return httpx.Response(status_code=400, json={"ok": False, "description": "Bad Request"})

            if request_data["chat_id"] != self.chat_id:
                return httpx.Response(status_code=403, json={"ok": False, "description": "Forbidden"})

            # Validate message format
            text = request_data["text"]
            if not text or len(text) > 4096:
                return httpx.Response(status_code=400, json={"ok": False, "description": "Bad Request"})

            # Simulate successful response
            return httpx.Response(
                status_code=200,
                json={
                    "ok": True,
                    "result": {
                        "message_id": 12345,
                        "from": {"id": int(self.bot_token.split(":")[0]), "is_bot": True, "first_name": "Test Bot"},
                        "chat": {"id": int(self.chat_id), "first_name": "Test User"},
                        "date": 1640995200,
                        "text": text
                    }
                }
            )

        module_test.httpx_mock.add_callback(telegram_response, url=self.webhook_url)

    def check(self, module_test, events):
        # Check that we received vulnerability events
        vulns = [e for e in events if e.type == "VULNERABILITY"]

        # Should have at least some vulnerabilities from nuclei scanning
        assert len(vulns) > 0, "Expected at least one vulnerability event"

        # Check that Telegram was called
        assert len(module_test.telegram_requests) > 0, "Expected Telegram API to be called"

        # Validate Telegram requests
        for request in module_test.telegram_requests:
            try:
                request_data = request.json()
            except Exception:
                assert False, f"Failed to parse Telegram request JSON: {request.content}"

            # Check required fields
            assert "chat_id" in request_data, "Missing chat_id in Telegram request"
            assert "text" in request_data, "Missing text in Telegram request"
            assert request_data["chat_id"] == self.chat_id, f"Incorrect chat_id: {request_data['chat_id']}"

            # Check message content contains vulnerability information
            text = request_data["text"]
            assert "VULNERABILITY" in text, f"Expected 'VULNERABILITY' in message: {text}"
            assert len(text) <= 4096, f"Message too long: {len(text)} characters"

            # Check severity filtering - should only include MEDIUM and above
            vuln_data = None
            for event in vulns:
                if str(event.data) in text or event.data.get("description", "") in text:
                    vuln_data = event.data
                    break

            if vuln_data:
                severity = vuln_data.get("severity", "UNKNOWN")
                allowed_severities = ["MEDIUM", "HIGH", "CRITICAL"]
                assert severity in allowed_severities, f"Severity {severity} should not be included (min_severity=MEDIUM)"


class TestTelegramFailure(ModuleTestBase):
    """Test Telegram module failure scenarios"""

    targets = ["http://127.0.0.1:8888/test.html"]
    modules_overrides = ["telegram"]

    def test_invalid_bot_token(self):
        """Test module failure with invalid bot token"""
        config_overrides = {
            "modules": {
                "telegram": {
                    "bot_token": "",  # Empty token
                    "chat_id": "123456789"
                }
            }
        }

        scan = self._scan(
            *self.targets,
            modules=self.modules_overrides,
            config=config_overrides
        )

        # Should fail during setup
        events = list(scan.start())
        telegram_module = scan.modules.get("telegram")
        assert telegram_module is None or telegram_module.errored, "Expected telegram module to fail or be disabled"


class TestTelegramConfigValidation(ModuleTestBase):
    """Test Telegram module configuration validation"""

    targets = []
    modules_overrides = ["telegram"]

    def test_invalid_parse_mode(self):
        """Test invalid parse_mode"""
        config_overrides = {
            "modules": {
                "telegram": {
                    "bot_token": "123456789:ABCdefGHIjklMNOpqrsTUVwxyz-123456789",
                    "chat_id": "123456789",
                    "parse_mode": "INVALID_FORMAT"  # Invalid parse mode
                }
            }
        }

        scan = self._scan(
            *self.targets,
            modules=self.modules_overrides,
            config=config_overrides
        )

        # Should fail during setup
        events = list(scan.start())
        telegram_module = scan.modules.get("telegram")
        assert telegram_module is None or telegram_module.errored, "Expected telegram module to fail with invalid parse_mode"