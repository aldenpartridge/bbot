from bbot.modules.templates.webhook import WebhookOutputModule


class Discord(WebhookOutputModule):
    watched_events = ["*"]
    meta = {
        "description": "Message a Discord channel when certain events are encountered",
        "created_date": "2023-08-14",
        "author": "@TheTechromancer",
    }

    # Update options to include separate webhooks for each severity level
    options = {
        "webhook_urls": {
            "critical": "",  # Webhook for critical findings
            "high": "",      # Webhook for high findings
            "medium": "",    # Webhook for medium findings
            "low": "",       # Webhook for low findings
            "cloud": "",     # Webhook for cloud-specific findings
            "cryptographic": ""  # Webhook for cryptographic findings
        },
        "event_types": ["VULNERABILITY", "FINDING"],
        "min_severity": "LOW",
    }

    options_desc = {
        "webhook_urls": "Dictionary of webhook URLs for different severity levels and categories",
        "event_types": "Types of events to send",
        "min_severity": "Only allow VULNERABILITY events of this severity or higher",
    }

    def process(self, event):
        # Determine the severity of the finding
        severity = event.get('severity')
        category = event.get('category')
        
        # Get the appropriate webhook URL based on severity or category
        webhook_url = None
        if severity:
            webhook_url = self.options["webhook_urls"].get(severity.lower())
        elif category:
            webhook_url = self.options["webhook_urls"].get(category.lower())

        # If a webhook URL exists, send the event to the respective channel
        if webhook_url:
            # Assuming `send_to_webhook` is a function to send the message to the Discord webhook
            self.send_to_webhook(webhook_url, event)

    def send_to_webhook(self, webhook_url, event):
        # Use a request library (like requests or aiohttp) to send the payload to the webhook URL
        payload = {
            "content": f"New vulnerability detected: {event.get('title')}",
            "embeds": [{
                "title": event.get('title'),
                "description": event.get('description'),
                "color": self.get_color_for_severity(event.get('severity'))
            }]
        }

        response = requests.post(webhook_url, json=payload)
        if response.status_code != 200:
            print(f"Failed to send to webhook: {response.status_code}")
        else:
            print(f"Successfully sent to {webhook_url}")

    def get_color_for_severity(self, severity):
        # Assign colors based on severity for visual clarity in Discord
        colors = {
            "critical": 0xFF0000,  # Red
            "high": 0xFFA500,      # Orange
            "medium": 0xFFFF00,    # Yellow
            "low": 0x00FF00        # Green
        }
        return colors.get(severity, 0xFFFFFF)  # Default to white if severity is unknown
