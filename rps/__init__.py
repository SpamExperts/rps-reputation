"""An implementation of the Roaring Penguin IP reputation reporting system."""
import yaml

with open('manifest.yml', 'r') as f:
    __version__ = yaml.safe_load(f).get('version')
