import os
import shutil

import pytest

from otsec import segmentation

ROOT_OK = os.geteuid() == 0 or segmentation.available()
needs_root = pytest.mark.skipif(not ROOT_OK, reason="needs root or passwordless sudo (iptables, loopback sniffing)")
needs_mosquitto = pytest.mark.skipif(shutil.which("mosquitto") is None, reason="mosquitto not installed")
