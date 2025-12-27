# CLAUDE.md

Always reply in Chinese.

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

AnyRouter 多账号自动签到 - A Python-based automated check-in script for NewAPI/OneAPI platforms (primarily AnyRouter and AgentRouter). Runs via GitHub Actions every 6 hours or manually.

## Commands

```bash
# Install dependencies
uv sync --dev

# Install Playwright browser (required for WAF bypass)
uv run playwright install chromium

# Run the check-in script
uv run checkin.py

# Run tests
uv run pytest tests/

# Lint code (auto-fix enabled)
uv run ruff check .
uv run ruff format .
```

## Architecture

### Core Components

- **checkin.py** - Main entry point. Orchestrates account processing, WAF cookie retrieval via Playwright, and check-in execution via httpx HTTP/2 client.

- **utils/config.py** - Configuration dataclasses:
  - `ProviderConfig` - Service provider settings (domain, API paths, WAF bypass method)
  - `AppConfig` - Loads providers from env, includes built-in anyrouter/agentrouter configs
  - `AccountConfig` - Per-account settings (cookies, api_user, provider name)

- **utils/notify.py** - `NotificationKit` class supporting 6 notification channels (Email, DingTalk, Feishu, WeCom, PushPlus, Server酱). All channels attempt delivery on `push_message()`.

### Key Flows

1. **WAF Bypass** (anyrouter only): Uses Playwright headless browser to visit login page and capture `acw_tc`, `cdn_sec_tc`, `acw_sc__v2` cookies before API requests.

2. **Check-in Logic**: For providers with `bypass_method='waf_cookies'`, explicitly calls sign-in API. For others (like agentrouter), check-in happens automatically when fetching user info.

3. **Smart Notifications**: Only sends notifications on failure, first run, or balance changes (controlled by `ALWAYS_NOTIFY` env var and balance hash comparison).

### Environment Variables

Required:
- `ANYROUTER_ACCOUNTS` - JSON array of account configs

Optional:
- `PROVIDERS` - Custom provider configurations (JSON object)
- `ALWAYS_NOTIFY` - Force notifications on every run
- Notification channels: `EMAIL_USER/PASS/TO`, `DINGDING_WEBHOOK`, `FEISHU_WEBHOOK`, `WEIXIN_WEBHOOK`, `PUSHPLUS_TOKEN`, `SERVERPUSHKEY`

## Code Style

- Uses `ruff` for linting with tabs and single quotes
- Line length: 120 characters
- Python 3.11+ required
