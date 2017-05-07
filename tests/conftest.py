#!/bin/python3
# -*- coding: UTF-8 -*-

# This is like __init__ but without the side effects

import os
import sys

# Allow running ``>$ pytest`` from project root
if not os.path.basename(sys.argv[0]) == "setup.py":
    sys.path.insert(0, os.path.dirname(
        os.path.dirname(os.path.abspath(__file__))))
