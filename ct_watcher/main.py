"""Main entry point for CT Watcher."""

import asyncio
from .config import DISCORD_WEBHOOK
from .state import state
from .loaders import (
    load_known_attacker_domains,
    load_known_attacker_ips,
    load_target_mapping,
    load_email_template,
    load_attacker_ips,
    load_watched_org_ids,
)
from .websocket_client import run_websocket_client


def main() -> None:
    """Main entry point."""
    if not DISCORD_WEBHOOK:
        raise RuntimeError("DISCORD_WEBHOOK is not set in the environment or .env file")
    
    # Load all configuration files
    state.known_attacker_domains = load_known_attacker_domains()
    state.known_attacker_ips = load_known_attacker_ips()
    state.target_mapping = load_target_mapping()
    state.email_template = load_email_template()
    state.attacker_ips_data = load_attacker_ips()
    state.watched_org_ids = load_watched_org_ids()
    
    # Start the WebSocket client
    asyncio.run(run_websocket_client())


if __name__ == "__main__":
    main()
