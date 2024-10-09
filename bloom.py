"""
This starter code is written by Alex Tsun and modified by Pemi Nguyen.
Permission is hereby granted to students registered for the  University
of Washington CSE 312 for use solely during Winter Quarter 2024 for purposes
of the course.  No other use, copying, distribution, or modification is
permitted without prior written consent.
"""

# =============================================================
# You may define helper functions, but DO NOT MODIFY
# the parameters or names of the provided functions.
# The autograder will expect that these functions exist
# and attempt to call them to grade you.

# Do NOT add any import statements.
# =============================================================

import numpy as np
import mmh3
import sys

class BloomFilter:
    def __init__(self, k:int = 10, m:int=8000):
        """
        :param k: The number of hash functions (rows).
        :param m: The number of buckets (cols).

        Initializes the Bloom filter consisting of k boolean arrays, each with size m.
        All values in the arrays are initialized to False
        """
        self.k = k
        self.m = m
        self.t = np.zeros((k, m), dtype=bool)

    def hash(self, x, i: int) -> int:
        """
        :param x: The element x to be hashed.
        :param i: A seed parameter for Murmurhash. Roughly speaking, each seed will generate a
        a different hash function.
        :return: h_i(x) the ith hash function applied to x. We use Murmurhash,
        a good consistent hash function that can distribute elements quite uniformly. We take
        the hash value and mod it by our the array size.

        Note: This consistent hash function doesn't rely on randomness.
        """
        return mmh3.hash(str(x), i) % self.m

    def add(self, x):
        """
        Adds an element to our Bloom filter.

        :param x: The element to add to the Bloom filter.

        Hint(s):
        1. Read the pseudocode provided!
        2. You will want to use self.hash(...).
        3. In our arrays, 1 is represented as True, and 0 as False.
        Thus, you want to set some suitable indices to True.
        """
        pass # TODO: Your code here (2 lines)
        for i in range (self.k):
            self.t[i, self.hash(x,i)] = 1;

    def contains(self, x) -> bool:
        """
        Check whether an element belongs to the Bloom filter.

        :param x: The element to check whether or not it belongs
        to the Bloom filter.

        :return: True or False; whether or not it is in the Bloom filter.
        As described in lecture, this is not always accurate and may give
        false positives sometimes. That is, if this function returns False,
        the element is definitely not in our structure, but if this function
        returns True, the element may or may not be in our structure.

        Hint(s):
        1. Read the pseudocode provided!
        2. You will want to use self.hash(...).
        3. Remember our arrays are of type boolean, so 1 should be
        represented as True, and 0 as False.
        """
        pass  # TODO: Your code here (<= 5 lines)
        for i in range(self.k):
            if not self.t[i, self.hash(x,i)]:
                return False
        return True

def get_size(obj, seen=None):
    """
    Returns the size of an object in bytes
    :param obj: the object that we want to check its size
    """
    size = sys.getsizeof(obj)
    if seen is None:
        seen = set()
    obj_id = id(obj)
    if obj_id in seen:
        return 0
    seen.add(obj_id)
    if isinstance(obj, dict):
        size += sum([get_size(v, seen) for v in obj.values()])
        size += sum([get_size(k, seen) for k in obj.keys()])
    elif hasattr(obj, '__dict__'):
        size += get_size(obj.__dict__, seen)
    elif hasattr(obj, '__iter__') and not isinstance(obj, (str, bytes, bytearray)):
        size += sum([get_size(i, seen) for i in obj])
    return size


if __name__ == '__main__':
    # Create a list of 10000 malicious websites to be stored in our Bloom filter
    mal_urls = np.genfromtxt('data/mal_urls.txt', dtype='str')

    # Create a list of test queries containing 8000 non-malicious websites and 2000 malicious ones
    # All the 2000 malicious websites are present in the Bloom filter
    test_urls = np.genfromtxt('data/test_urls.txt', dtype='str')

    # Create a new Bloom filter with 10 bit arrays, each with size 8000 bits
    bf = BloomFilter(k=10, m=8000)

    # Add malicious URLs to the Bloom filter
    for mal_url in mal_urls:
        bf.add(mal_url)

    # Create a set of malicious URLS to verify the query results from the Bloom filter
    s = set(mal_urls)

    # Check the size of a Bloom filter vs a Set.
    # Notice how much less space a Bloom filter occupies.
    print("The size of the Bloom Filter is: {} bytes ".format(get_size(bf)))
    print("The size of the Set is: {} bytes ".format(get_size(s)))

    # Calculate the False Positive Rate (FPR), which is the proportion of websites
    # that are non-malicious but incorrectly classified as malicious by the Bloom filter
    print("Computing False Positive Rate (FPR) on 10000 website queries")
    fpr = 0
    for test_url in test_urls:
        if bf.contains(test_url) and test_url not in s:
            fpr += 1
    fpr /= len(test_urls)
    print("FPR: {}".format(fpr))

    # Calculate the False Negative Rate (FPR), which is the proportion of websites
    # that are malicious but incorrectly classified as non-malicious by the Bloom filter
    print("Computing False Negative Rate (FNR) on 10000 website queries")
    fnr = 0
    for test_url in test_urls:
        if not bf.contains(test_url) and test_url in s:
            fnr += 1
    fnr /= len(test_urls)
    print("FNR: {}".format(fnr))
