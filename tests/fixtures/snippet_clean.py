"""
tests/fixtures/snippet_clean.py
A Python source file with NO cryptographic API usage.
Used as a true-negative (non-match) fixture for PS-P2 scanner tests.
"""


def compute_fibonacci(n: int) -> list[int]:
    """Return the first n Fibonacci numbers."""
    if n <= 0:
        return []
    seq = [0, 1]
    while len(seq) < n:
        seq.append(seq[-1] + seq[-2])
    return seq[:n]


class DataTransformer:
    """Simple data transformation – no cryptography involved."""

    def __init__(self, data: list) -> None:
        self._data = data

    def normalise(self) -> list[float]:
        max_val = max(self._data) if self._data else 1
        return [x / max_val for x in self._data]

    def reverse(self) -> list:
        return list(reversed(self._data))
