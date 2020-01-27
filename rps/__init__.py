"""An implementation of the Roaring Penguin IP reputation reporting system."""
import re
with open('manifest.yml', 'r') as f:
    __version__ = re.search('version: (.+?)$', f.read()).group(1).strip()
