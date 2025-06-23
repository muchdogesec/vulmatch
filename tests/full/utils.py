from itertools import tee
from operator import lt
import os
import random
import time
from types import SimpleNamespace
import unittest, pytest
from urllib.parse import urljoin

def is_sorted(iterable, key=None, reverse=False):
    it = iterable if (key is None) else map(key, iterable)
    a, b = tee(it)
    next(b, None)
    if reverse:
        b, a = a, b
    return not any(map(lt, b, a))