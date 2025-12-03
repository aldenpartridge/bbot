import yaml

from bbot.modules.templates.webhook import WebhookOutputModule


class telegram(WebhookOutputModule):
    watched_events = ["VULNERABILITY"]
    meta = {
        "description": "Send vulnerability events to a Telegram bot via Bot API",
        "created_date": "2025-01-03",
        "author": "AI Assistant",
        "auth_required": True,
    }
    options = {
        "bot_token": "",
        "chat_id": "",
        "min_severity": "LOW",
        "retries": 10,
        "parse_mode": "MarkdownV2",
        "disable_web_page_preview": False,
        "disable_notification": False,
    }
    options_desc = {
        "bot_token": "Telegram bot token (get from @BotFather)",
        "chat_id": "Chat ID to send messages to (can be user ID or channel ID)",
        "min_severity": "Only allow VULNERABILITY events of this severity or higher",
        "retries": "Number of times to retry sending the message before skipping the event",
        "parse_mode": "Message parsing format (Markdown, MarkdownV2, or HTML)",
        "disable_web_page_preview": "Disable web page preview for links",
        "disable_notification": "Send message silently (users will receive no notification)",
    }

    # Telegram-specific settings
    _default_api_retries = 10
    _api_failure_abort_threshold = 10
    message_size_limit = 4096  # Telegram message size limit

    async def setup(self):
        self.bot_token = self.config.get("bot_token", "").strip()
        self.chat_id = self.config.get("chat_id", "").strip()

        if not self.bot_token:
            self.error("bot_token is required")
            return False, "bot_token is required"

        if not self.chat_id:
            self.error("chat_id is required")
            return False, "chat_id is required"

        # Validate parse_mode
        parse_mode = self.config.get("parse_mode", "MarkdownV2")
        valid_parse_modes = ["Markdown", "MarkdownV2", "HTML", None]
        if parse_mode not in valid_parse_modes:
            self.error(f"parse_mode must be one of: {', '.join(str(m) for m in valid_parse_modes)}")
            return False, f"Invalid parse_mode: {parse_mode}"

        # Build webhook URL
        self.webhook_url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"

        return await super().setup()

    @property
    def api_retries(self):
        return self.config.get("retries", self._default_api_retries)

    async def handle_event(self, event):
        message = self.format_message(event)

        # Prepare request data for Telegram Bot API
        data = {
            "chat_id": self.chat_id,
            "text": message,
        }

        # Add optional parameters
        parse_mode = self.config.get("parse_mode", "MarkdownV2")
        if parse_mode:
            data["parse_mode"] = parse_mode

        if self.config.get("disable_web_page_preview", False):
            data["disable_web_page_preview"] = True

        if self.config.get("disable_notification", False):
            data["disable_notification"] = True

        await self.api_request(
            url=self.webhook_url,
            method="POST",
            json=data,
        )

    def format_message_str(self, event):
        # Escape special characters for Telegram MarkdownV2
        def escape_markdownv2(text):
            special_chars = '_*[]()~`>#+-=|{}.!'
            return ''.join(f'\\{char}' if char in special_chars else char for char in str(text))

        event_type = escape_markdownv2(f"[{event.type}]")
        event_data = escape_markdownv2(str(event.data))
        event_tags = escape_markdownv2(",".join(sorted(event.tags)))

        return (
            f"*{event_type}*\n"
            f"`{event_data}`\n"
            f"Tags: `{event_tags}`\n"
            f"Module: `{event.module}`"
        )

    def format_message_other(self, event):
        # Format complex event data as YAML
        try:
            event_yaml = yaml.dump(event.data, default_flow_style=False, sort_keys=False)
        except Exception:
            event_yaml = str(event.data)

        # Get severity with appropriate emoji
        if event.type == "VULNERABILITY":
            severity = event.data.get("severity", "UNKNOWN")
            severity_emoji = {
                "CRITICAL": "🔴",
                "HIGH": "🟠",
                "MEDIUM": "🟡",
                "LOW": "🟢",
                "UNKNOWN": "⚪"
            }.get(severity, "⚪")

            event_type = f"{severity_emoji} *VULNERABILITY \\({severity}\\)*"
        else:
            event_type = f"*{escape_markdownv2(event.type)}*"

        # Truncate YAML if too long
        if len(event_yaml) > 3000:  # Leave room for other content
            event_yaml = event_yaml[:3000] + "\n... (truncated)"

        return (
            f"{event_type}\n"
            f"```\n{event_yaml}\n```\n"
            f"Tags: `{','.join(sorted(event.tags))}`\n"
            f"Module: `{event.module}`"
        )

    def escape_markdownv2(self, text):
        """Helper function to escape special characters for Telegram MarkdownV2"""
        if not isinstance(text, str):
            text = str(text)
        special_chars = '_*[]()~`>#+-=|{}.!'
        return ''.join(f'\\{char}' if char in special_chars else char for char in text)

    def format_message(self, event):
        parse_mode = self.config.get("parse_mode", "MarkdownV2")

        if isinstance(event.data, str) and len(str(event.data)) < 200:
            if parse_mode == "MarkdownV2":
                return self.format_message_str(event)
            else:
                # For other parse modes, use simpler formatting
                return f"[{event.type}] {event.data}\nTags: {','.join(sorted(event.tags))}\nModule: {event.module}"
        else:
            if parse_mode == "MarkdownV2":
                return self.format_message_other(event)
            else:
                # For other parse modes, use simpler formatting
                try:
                    event_yaml = yaml.dump(event.data, default_flow_style=False, sort_keys=False)
                except Exception:
                    event_yaml = str(event.data)

                if len(event_yaml) > 3000:
                    event_yaml = event_yaml[:3000] + "\n... (truncated)"

                severity = ""
                if event.type == "VULNERABILITY":
                    severity = event.data.get("severity", "UNKNOWN")
                    severity = f" ({severity})"

                return f"[{event.type}{severity}]\n```\n{event_yaml}\n```\nTags: {','.join(sorted(event.tags))}\nModule: {event.module}"

    def evaluate_response(self, response):
        # Telegram Bot API returns {"ok": true, "result": {...}} on success
        if hasattr(response, 'json') and callable(response.json):
            try:
                response_json = response.json()
                return response_json.get("ok", False)
            except Exception:
                pass

        # Fallback to default behavior
        return getattr(response, "is_success", False)

    async def api_request_error(self, error, url="", method="", **kwargs):
        """Handle API request errors with Telegram-specific error messages"""
        await super().api_request_error(error, url, method, **kwargs)

        # Provide helpful error messages for common Telegram issues
        error_str = str(error).lower()
        if "404" in error_str and "bot" in error_str:
            self.error("Invalid bot token. Please check your bot token from @BotFather")
        elif "404" in error_str and "chat" in error_str:
            self.error("Invalid chat ID. Make sure the bot has been added to the chat/channel")
        elif "403" in error_str:
            self.error("Bot was kicked from chat or doesn't have permission to send messages")
        elif "429" in error_str:
            self.warning("Rate limited by Telegram. The request will be retried.")