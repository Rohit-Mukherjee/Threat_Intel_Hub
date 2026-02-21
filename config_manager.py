"""Configuration manager for Threat Intel Hub."""
import json
import os
from pathlib import Path
from typing import Optional, Dict, Any
import logging

logger = logging.getLogger('ConfigManager')


class ConfigManager:
    """Manage configuration settings including API keys."""

    DEFAULT_CONFIG = {
        "api_keys": {
            "virustotal": "",
            "abusech": "",
            "shodan": "",
            "censys": ""
        },
        "notifications": {
            "email": {
                "enabled": False,
                "smtp_server": "",
                "smtp_port": 587,
                "username": "",
                "password": "",
                "from_address": "",
                "to_addresses": []
            },
            "slack": {
                "enabled": False,
                "webhook_url": ""
            }
        },
        "collection": {
            "days_back": 7,
            "auto_refresh_hours": 6,
            "min_confidence": "Low"
        },
        "dashboard": {
            "theme": "dark",
            "items_per_page": 50,
            "enable_auto_refresh": False
        }
    }

    def __init__(self, config_path: str = "data/config.json"):
        self.config_path = Path(config_path)
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        self.config = self.load_config()

    def load_config(self) -> Dict[str, Any]:
        """Load configuration from file or create default."""
        if self.config_path.exists():
            try:
                with open(self.config_path, 'r') as f:
                    config = json.load(f)
                    # Merge with defaults to ensure all keys exist
                    return self._merge_configs(self.DEFAULT_CONFIG, config)
            except (json.JSONDecodeError, IOError) as e:
                logger.warning(f"Error loading config, using defaults: {e}")
                return self.DEFAULT_CONFIG.copy()
        else:
            self.save_config(self.DEFAULT_CONFIG)
            return self.DEFAULT_CONFIG.copy()

    def _merge_configs(self, default: Dict, custom: Dict) -> Dict:
        """Recursively merge custom config with defaults."""
        result = default.copy()
        for key, value in custom.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._merge_configs(result[key], value)
            else:
                result[key] = value
        return result

    def save_config(self, config: Dict[str, Any] = None):
        """Save configuration to file."""
        if config is None:
            config = self.config

        try:
            with open(self.config_path, 'w') as f:
                json.dump(config, f, indent=2)
            logger.info(f"Configuration saved to {self.config_path}")
        except IOError as e:
            logger.error(f"Error saving config: {e}")

    def get(self, key_path: str, default: Any = None) -> Any:
        """
        Get a configuration value using dot notation.
        Example: get('api_keys.virustotal')
        """
        keys = key_path.split('.')
        value = self.config

        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return default

        return value

    def set(self, key_path: str, value: Any):
        """
        Set a configuration value using dot notation.
        Example: set('api_keys.virustotal', 'your-api-key')
        """
        keys = key_path.split('.')
        config = self.config

        for key in keys[:-1]:
            if key not in config:
                config[key] = {}
            config = config[key]

        config[keys[-1]] = value
        self.save_config()

    def get_api_key(self, service: str) -> Optional[str]:
        """Get API key for a service."""
        key = self.get(f'api_keys.{service}')
        return key if key else None

    def set_api_key(self, service: str, key: str):
        """Set API key for a service."""
        self.set(f'api_keys.{service}', key)
        logger.info(f"API key set for {service}")

    def is_api_key_set(self, service: str) -> bool:
        """Check if API key is configured for a service."""
        return bool(self.get_api_key(service))

    def get_all_api_keys(self) -> Dict[str, bool]:
        """Get status of all API keys."""
        api_keys = self.get('api_keys', {})
        return {service: bool(key) for service, key in api_keys.items()}

    def get_notification_config(self, channel: str) -> Dict[str, Any]:
        """Get notification configuration for a channel."""
        return self.get(f'notifications.{channel}', {})

    def is_notification_enabled(self, channel: str) -> bool:
        """Check if notifications are enabled for a channel."""
        return self.get(f'notifications.{channel}.enabled', False)

    def get_collection_config(self) -> Dict[str, Any]:
        """Get collection configuration."""
        return self.get('collection', self.DEFAULT_CONFIG['collection'])

    def get_dashboard_config(self) -> Dict[str, Any]:
        """Get dashboard configuration."""
        return self.get('dashboard', self.DEFAULT_CONFIG['dashboard'])

    def reset_to_defaults(self):
        """Reset configuration to defaults."""
        self.config = self.DEFAULT_CONFIG.copy()
        self.save_config()
        logger.info("Configuration reset to defaults")


# Global config instance
_config: Optional[ConfigManager] = None


def get_config() -> ConfigManager:
    """Get global config instance."""
    global _config
    if _config is None:
        _config = ConfigManager()
    return _config


def init_config(config_path: str = "data/config.json") -> ConfigManager:
    """Initialize global config instance."""
    global _config
    _config = ConfigManager(config_path)
    return _config
