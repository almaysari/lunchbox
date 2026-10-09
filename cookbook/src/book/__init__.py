# HOME COOKBOOK data package
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from breakfast import BREAKFAST
from salads import SALADS
from mains1 import MAINS1
from mains2 import MAINS2
from mains3 import MAINS3

MAINS = MAINS1 + MAINS2 + MAINS3
ALL = BREAKFAST + SALADS + MAINS
for i, r in enumerate(ALL, 1):
    r["num"] = i
