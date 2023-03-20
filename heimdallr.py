import heimdallr_utils.plugin
import platform, os, sys, json

from pathlib import Path
import ida_idaapi


default_config = """
{
  "ida_location": "",
  "idb_path": [
    ""
  ],
"heimdallr_client" : "heimdallr_client"
}
"""

def PLUGIN_ENTRY():
    """Entry point searched for by IDA"""
    ida_idaapi.require("heimdallr_utils.plugin")
    current_heimdallr_instance = heimdallr_utils.plugin.heimdallrRPC()
    return current_heimdallr_instance

def reload():
    """Reloads plugin logic - for testing.
    Doesn't appear to reload any part of the state maintained in the plugin, but can reload helper functions.
    """
    ida_idaapi.require("heimdallr_utils.plugin")


def macos_get_app_path(executable_path : Path):
    """Recursively looks for the root application folder for IDA under MacOS
    """
    for parent in executable_path.parents:
        if ".app" in parent.name:
            return parent
    raise RuntimeError("Could not resolve MacOS Application Path")

def install():
    """Carries out initial installation of the IDA plugin. Creates a symlink to the user specific plugin directory
    and creates the Heimdallr configuration directory.
    """
    completed = False
    if platform.system() == "Windows":
        idauser_path = Path(os.path.expandvars("%APPDATA%/Hex-Rays/IDA Pro/"))
        heimdallr_path = Path(os.path.expandvars("%APPDATA%/heimdallr/"))
    else:
        idauser_path = Path(os.path.expandvars("$HOME/.idapro/"))
        heimdallr_path = Path(os.path.expandvars("$HOME/.config/heimdallr/"))
    
    plugin_path = idauser_path / "plugins"
    plugin_path.mkdir(parents=True, exist_ok=True)
    installee = Path(__file__)
    install_path = plugin_path / installee.name
    if not install_path.exists() and not installee.is_relative_to(plugin_path):
        os.symlink(installee, install_path)
        print(f"Symlinked plugin to {install_path}")
        completed = True
    elif installee.is_relative_to(plugin_path):
        completed = True
    else:
        print(f"Error: Existing plugin exists at {install_path}")
    
    config_path = heimdallr_path / "settings.json"
    if not config_path.exists():
        config = json.loads(default_config)
        ida_path = Path(sys.executable)
        if platform.system() == "Darwin":
            ida_path = macos_get_app_path(ida_path)

        config['ida_location'] = str(ida_path)
        with open(config_path, "w") as fd:
            json.dump(config, fd)
        print(f"Wrote settings file to {config_path}")
    else:
        print(f"Skipped settings file genereation - already exists @ {config_path}")
    if completed:
        print("Installation completed! Restart IDA to activate plugin.")

def uninstall():
    """Uninstalls the IDA Plugin by removing the symlink in the IDA Plugin directory. Maintains configuration file but
    gives instructions to uninstall manually
    """
    completed = True
    if platform.system() == "Windows":
        idauser_path = Path(os.path.expandvars("%APPDATA%/Hex-Rays/IDA Pro/"))
        heimdallr_path = Path(os.path.expandvars("%APPDATA%/heimdallr/"))
    else:
        idauser_path = Path(os.path.expandvars("$HOME/.idapro/"))
        heimdallr_path = Path(os.path.expandvars("$HOME/.config/heimdallr/"))
    
    plugin_path = idauser_path / "plugins"
    installee = Path(__file__)
    install_path = plugin_path / installee.name
    if install_path.exists() and not installee.is_relative_to(plugin_path):
        os.remove(install_path)
        print(f"Removed symlink at {install_path}")
        completed = True
    elif installee.is_relative_to(plugin_path):
        print(f"Did not remove plugin files as they are directly installed at {install_path}")
    
    if completed:
        print(f"""Uninstall can be completed by:
        - Removing the configuration directory at {heimdallr_path}
        - Removing the package with pip `pip3 remove heimdallr-ida`
        """)
