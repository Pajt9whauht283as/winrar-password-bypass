#!/usr/bin/env python3
"""WinRaR Password Bypass - entry point.

    python main.py info   secret.rar
    python main.py hash   secret.rar -o rar5.hash
    python main.py crack  secret.rar --auto --gpu --extract
    python main.py crack  photos.zip --mask "?l?l?l?l?l?l"
    python main.py forensics D:\\Downloads
    python main.py scan   D:\\Downloads
"""

import sys

from winrar.cli import main

if __name__ == "__main__":
    sys.exit(main())
