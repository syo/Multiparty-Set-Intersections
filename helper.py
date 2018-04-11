import itertools
from functools import reduce
import operator 
import numpy as np 
import paillier.paillier.paillier as p

def gaussian(offset, deviation):
    #cut so it isnt negative
    noise = np.random.normal(0, deviation, 1) + offset
    if noise < 0:
        noise = 0
    return noise

def prod(iterable):
    return reduce(operator.mul, iterable, 1)

def combinations(iterable, r):
    # combinations('ABCD', 2) --> AB AC AD BC BD CD
    # combinations(range(4), 3) --> 012 013 023 123
    pool = tuple(iterable)
    n = len(pool)
    if r > n:
        return
    indices = range(r)
    yield tuple(pool[i] for i in indices)
    while True:
        for i in reversed(range(r)):
            if indices[i] != i + n - r:
                break
        else:
            return
        indices[i] += 1
        for j in range(i+1, r):
            indices[j] = indices[j-1] + 1
        yield tuple(pool[i] for i in indices)

def polyCoefficients(data):
    coefficients = []
    combinationSize = len(data)
    for i in range(len(data)):
        #print str(i) + "of " + str(len(data))
        combos = combinations(data, combinationSize)
        total = 0
        for cset in combos:
            #print "sum of set " + str(cset) + " = " + str(prod(cset))
            total += prod(cset)
        
        coefficients.append(total)
        combinationSize -= 1
        #if (i % 2 == 1):
        #    coefficients[i] *= -1

    coefficients.append(1)
    #if (len(data) % 2 == 1):
    #    coefficients[len(data)] *= -1
    return coefficients

def polyEvaluate(pubkey, poly, data):
    values = []
    for d in data:
        total = 0
        for i in range(len(poly)):
            x = p.e_mul_const(pubkey, poly[i], (d ** i))
            if (i % 2 == 1):
                x = p.e_mul_const(pubkey, x, -1)
            total = p.e_add(pubkey, total,x)
        values.append(total)
    return values

def encPolySum(pubkey, P, Q, R):
    result = []
    ongoing = True
    index = 0
    while ongoing:
        ongoing = False
        cursum = p.encrypt(pubkey, 0)
        if (index < len(P)):
            cursum = p.e_add(pubkey, cursum, P[index])
            ongoing = True
        if (index < len(Q)):
            cursum = p.e_add(pubkey, cursum, Q[index])
            ongoing = True
        if (index < len(R)):
            cursum = p.e_add(pubkey, cursum, R[index])
            ongoing = True
        if ongoing:
            result.append(cursum)
        index += 1
    return result

def betterPolySum(pubkey, P, Q):
    result = []
    ongoing = True
    index = 0
    while ongoing:
        ongoing = False
        cursum = p.encrypt(pubkey, 0)
        if (index < len(P)):
            cursum = p.e_add(pubkey, cursum, P[index])
            ongoing = True
        if (index < len(Q)):
            cursum = p.e_add(pubkey, cursum, Q[index])
            ongoing = True
        if ongoing:
            result.append(cursum)
        index += 1
    return result
#for testing
'''
def main():
    data = [3,5,7]
    x = polyCoefficients(data)
    y = polyEvaluate(x, data)
    print y

if __name__ == "__main__":
    main()
'''