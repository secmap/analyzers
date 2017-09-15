import numpy as np
from collections import Counter
import re
import sys


def build_ngrams(opcodes, n):
    counter = Counter()
    for group in opcodes:
        group = [g for g in group if g is not None]
        ngrams = make_ngrams(group, n)

        for ngram in ngrams:
            if ngram:
                counter[ngram] = counter[ngram] + 1

    return np.array(counter.items())


def make_ngrams(lst, n):
    ngrams = zip(*[lst[i:] for i in range(n)])
    if n == 1:
        ngrams = [n[0] for n in ngrams]

    return ngrams
