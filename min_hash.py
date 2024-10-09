# UW CSE 312, PSet #8 Winter 2024
# Student Name: ____
# Email    : ____@uw.edu

# =============================================================
# You may define helper functions, but DO NOT MODIFY
# the parameters or names of the provided functions.
# The autograder will expect that these functions exist
# and attempt to call them to grade you.

# Do NOT add any import statements.
# =============================================================

import numpy as np
import mmh3

class MinHash:
    def __init__(self, seed_offset:int=0):
        """
        :param seed_offset: Allows for multiple instances of this
        class to provide different results.
        
        We only use one variable, self.val, in our entire
        implementation.
        """
        self.seed_offset = seed_offset
        self.val = float("inf")

    def hash(self, x:int) -> float:
        """
        :param x: The element x to be hashed.
        :return: A Unif(0,1) continuous random variable. However,
        if the same x is passed in, we will return the same exact
        Unif(0,1) rv. We do this by taking the modulus by a large
        number, and dividing by it so that we get "approximately" a
        random float between 0 and 1.
        """
        large_num = 2 ** 31
        h = mmh3.hash(x, self.seed_offset) % large_num + 1
        return h / large_num

    def update(self, x:int):
        """
        :param x: The new stream element x.
        
        In this function, you'll update self.val as you described
        in the previous part.

        Hint(s):
        1. You will want to use self.hash(...).
        """
        pass # TODO: Your code here (1 line)
        self.val = min(self.val, self.hash(x))

    def estimate(self) -> int:
        """        
        :return: Your estimate so far for the number of distinct
        elements you've seen. Make sure you round to the nearest
        integer!

        Hint(s):
        1. You will want to use self.val here.
        """
        pass # TODO: Your code here (1 line)
        if self.val == float('inf'):
            return 0
        return round(1 / self.val) - 1;

class MultMinHash:
    def __init__(self, num_reps:int=1):
        """
        :param num_reps: How many copies of MinHash we have.

        Creates num_reps different MinHash objects, by passing in
        different seed_offsets.
        """
        self.num_reps = num_reps
        self.des = [MinHash(seed_offset=i) for i in range(num_reps)]

    def update(self, x:int):
        """
        :param x: The new stream element x.
        
        In this function, you'll call `update` for all the 
        MinHash objects in self.des.
        """
        pass # TODO: Your code here (2 lines)
        for de in self.des:
            de.update(x)

    def estimate(self) -> int:
        """        
        :return: Your estimate so far for the number of distinct
        elements you've seen. You will take the AVERAGE of the mins
        from your MinHash objects in self.des to get a better estimate
        for the min, and THEN use the same approach as earlier to 
        make an estimate for the number of distinct elements. 

        Hint(s):
        1. Numpy is imported :).
        2. You can access fields of objects in Python 
           (similar to public fields in Java)
           Example:
           de = MinHash(seed_offset=0) # a MinHash Object
           val = de.val                 # the val field of de
        """
        pass # TODO: Your code here (1-5 lines)
        min_values = np.array([de.val for de in self.des])
        avg = np.mean(min_values)
        if avg == 0:
            return 0
        return round(1 / avg) - 1

if __name__ == '__main__':
    # You can test out things here. Feel free to write anything below.
    stream = np.genfromtxt('data/stream_small.txt', dtype='int')

    # 312 actual distinct Elements in the stream
    print("True Dist Elts: {}".format(312))

    # Create a MinHash object, and update for each element in the stream.
    # Finally, print out the estimate.
    de = MinHash()
    for x in stream:
        de.update(x)
    print("Min Hash Estimate: {}".format(de.estimate()))

    # Create a MultMinHash object, and update for each element in the 
    # stream. Finally, print out the estimate.
    num_reps = 50
    mde = MultMinHash(num_reps=num_reps)
    for x in stream:
        mde.update(x)
    print("Mult Min Hash Estimate with {} copies: {}".format(num_reps, mde.estimate()))

