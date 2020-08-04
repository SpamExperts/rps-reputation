"""An implementation of the Roaring Penguin IP reputation reporting system."""
import re
import os
import inspect

path = os.path.dirname(os.path.abspath(
    inspect.getfile(inspect.currentframe())))
with open(path + '/manifest.yml', 'r') as f:
    __version__ = re.search('version: (.+?)$', f.read()).group(1).strip()
