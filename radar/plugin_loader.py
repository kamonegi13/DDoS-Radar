"""radar.plugin_loader -- Dynamic sensor plugin loading.

Scans a plugins/ directory for Python files containing BaseSensor subclasses
and dynamically loads and registers them.

Plugin structure:
  plugins/
    my_sensor.py      -- must contain a class inheriting BaseSensor
    another_sensor.py

Each plugin file should define exactly one BaseSensor subclass.
If multiple are defined, all are registered.

Configuration:
  PLUGIN_DIR       — Directory to scan (default: plugins/ in project root)
  PLUGIN_ENABLED   — Comma-separated list of plugin filenames to enable,
                     or "*" for all (default: "*")
  PLUGIN_DISABLED  — Comma-separated list to explicitly disable
"""
from __future__ import annotations
import importlib.util
import inspect
import logging
import os
import sys

log = logging.getLogger("radar")


def discover_plugins(plugin_dir: str, enabled: str = "*",
                     disabled: str = "") -> list:
    """Discover and import sensor plugins from the given directory.

    Returns a list of BaseSensor subclass instances ready for registration.
    """
    from radar.sensors.base import BaseSensor

    if not os.path.isdir(plugin_dir):
        log.info(f"[Plugins] Directory not found: {plugin_dir} — skipping.")
        return []

    enabled_set = None
    if enabled != "*":
        enabled_set = {s.strip() for s in enabled.split(",") if s.strip()}

    disabled_set = {s.strip() for s in disabled.split(",") if s.strip()}

    sensors = []
    plugin_files = sorted(f for f in os.listdir(plugin_dir)
                          if f.endswith(".py") and not f.startswith("_"))

    for filename in plugin_files:
        name = filename[:-3]  # strip .py

        # Check enabled/disabled
        if enabled_set is not None and name not in enabled_set:
            log.debug(f"[Plugins] Skipping {filename} (not in PLUGIN_ENABLED)")
            continue
        if name in disabled_set:
            log.debug(f"[Plugins] Skipping {filename} (in PLUGIN_DISABLED)")
            continue

        filepath = os.path.join(plugin_dir, filename)
        log.warning("[Plugins] Loading plugin %s — ensure this file is from a trusted source", filepath)
        try:
            # Load module dynamically
            spec = importlib.util.spec_from_file_location(f"radar_plugin_{name}", filepath)
            if spec is None or spec.loader is None:
                log.warning(f"[Plugins] Could not load spec for {filename}")
                continue

            module = importlib.util.module_from_spec(spec)
            sys.modules[f"radar_plugin_{name}"] = module
            spec.loader.exec_module(module)

            # Find all BaseSensor subclasses defined in this module
            found = 0
            for attr_name, obj in inspect.getmembers(module, inspect.isclass):
                if (issubclass(obj, BaseSensor)
                        and obj is not BaseSensor
                        and obj.__module__ == module.__name__):
                    try:
                        instance = obj()
                        sensors.append(instance)
                        found += 1
                        log.info(f"[Plugins] Loaded sensor '{instance.name}' "
                                 f"from {filename}")
                    except Exception as e:
                        log.error(f"[Plugins] Failed to instantiate "
                                  f"{attr_name} from {filename}: {e}")

            if found == 0:
                log.warning(f"[Plugins] No BaseSensor subclass found in {filename}")

        except Exception as e:
            log.error(f"[Plugins] Error loading {filename}: {e}")

    return sensors


def load_and_register_plugins(registry, plugin_dir: str = None):
    """Load plugins and register them with the SensorRegistry.

    Args:
        registry: SensorRegistry instance
        plugin_dir: Directory to scan. If None, uses PLUGIN_DIR env var
                    or defaults to plugins/ in project root.
    """
    if plugin_dir is None:
        _project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        plugin_dir = os.getenv("PLUGIN_DIR",
                               os.path.join(_project_root, "plugins"))

    # Default to empty (opt-in): set PLUGIN_ENABLED="*" to load all plugins
    enabled = os.getenv("PLUGIN_ENABLED", "")
    disabled = os.getenv("PLUGIN_DISABLED", "")

    sensors = discover_plugins(plugin_dir, enabled, disabled)
    registered = 0
    for sensor in sensors:
        if registry.get(sensor.name):
            log.warning(f"[Plugins] Sensor '{sensor.name}' already registered — "
                        f"skipping plugin duplicate.")
            continue
        registry.register(sensor)
        registered += 1

    if registered > 0:
        log.info(f"[Plugins] Registered {registered} plugin sensor(s)")
    return registered
