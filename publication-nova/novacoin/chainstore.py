"""The chain as a list-like object backed by SQLite: only a small window of recent blocks stays in memory."""
from __future__ import annotations

import copy
import json
import sqlite3
import threading
from collections import OrderedDict

from .core import block_work


class ChainStore:
    CHUNK = 250

    def __init__(self, path, window=128):
        # A second, read-only connection: the node writes through its own connection and commits before
        # it appends here, so readers always see committed blocks (WAL mode allows concurrent readers).
        self.conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True, check_same_thread=False)
        self.lock, self.window, self.cache = threading.RLock(), window, OrderedDict()
        self._len = self._count()

    # ---- size and bookkeeping
    def _count(self):
        with self.lock:
            return self.conn.execute("SELECT COUNT(*) FROM blocks").fetchone()[0]

    def __len__(self):
        return self._len

    def reload(self):
        """The blocks table was rewritten: forget everything cached."""
        with self.lock:
            self.cache.clear()
            self._len = self._count()

    def append(self, block):
        with self.lock:
            self.cache[self._len] = block
            self._len += 1
            self._trim()

    def extend(self, blocks):
        for block in blocks:
            self.append(block)

    def truncate(self, length):
        with self.lock:
            self._len = length
            for height in [h for h in self.cache if h >= length]:
                del self.cache[height]

    def _trim(self):
        while len(self.cache) > self.window:
            self.cache.popitem(last=False)

    # ---- reading
    def _get(self, height):
        with self.lock:
            block = self.cache.get(height)
            if block is not None:
                self.cache.move_to_end(height)
                return block
            row = self.conn.execute("SELECT payload FROM blocks WHERE height=?", (height,)).fetchone()
            if row is None:
                raise IndexError(f"Bloc {height} absent de la base")
            block = json.loads(row[0])
            self.cache[height] = block
            self._trim()
            return block

    def __getitem__(self, index):
        if isinstance(index, slice):
            return [self._get(h) for h in range(*index.indices(self._len))]
        if index < 0:
            index += self._len
        if not 0 <= index < self._len:
            raise IndexError("Hauteur hors de la chaîne")
        return self._get(index)

    def _range(self, start, stop):
        """Blocks in [start, stop), read in chunks without disturbing the recent-block cache."""
        for first in range(start, stop, self.CHUNK):
            last = min(stop, first + self.CHUNK)
            with self.lock:
                rows = self.conn.execute("SELECT height, payload FROM blocks WHERE height>=? AND height<? ORDER BY height",
                                         (first, last)).fetchall()
            if len(rows) != last - first:
                raise IndexError("La base ne contient pas toute la chaîne attendue")
            for _, payload in rows:
                yield json.loads(payload)

    def __iter__(self):
        return self._range(0, self._len)

    def iter_from(self, start):
        return self._range(start, self._len)

    def work_between(self, start, stop):
        """Sum of block work for heights in [start, stop)."""
        return sum(block_work(b["target"]) for b in self._range(start, stop))

    # ---- list-like conveniences used by tests and tools
    def __deepcopy__(self, memo):
        return [copy.deepcopy(block) for block in self]

    def __eq__(self, other):
        try:
            return len(self) == len(other) and all(a == b for a, b in zip(self, other))
        except TypeError:
            return NotImplemented

    __hash__ = None

    def close(self):
        with self.lock:
            self.conn.close()
