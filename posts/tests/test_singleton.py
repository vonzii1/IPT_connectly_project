from django.test import TestCase
from posts.config_manager import ConfigManager

class ConfigManagerTest(TestCase):
    def test_singleton_behavior(self):
        config1 = ConfigManager()
        config2 = ConfigManager()

        # Both instances should be the same
        self.assertIs(config1, config2)

        # Test setting and getting a configuration value
        config1.set_setting("DEFAULT_PAGE_SIZE", 50)
        self.assertEqual(config2.get_setting("DEFAULT_PAGE_SIZE"), 50)