#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""AEGIS-VORTEX Modül 1 JSON CLI Köprüsü (Node.js & Harici Çağrılar İçin)"""

import json
import os
import sys

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

from core.event_bus import EventBus
from modules.m1_static_pe_analyzer import StaticPEAnalyzer

if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    target = sys.argv[1] if len(sys.argv) > 1 else ""
    if not target or not os.path.isfile(target):
        print(json.dumps({"error": "File not found"}))
        sys.exit(0)

    analyzer = StaticPEAnalyzer(EventBus())
    rep = analyzer.analyze_file(target)
    print(json.dumps(rep.to_dict(), ensure_ascii=False))
