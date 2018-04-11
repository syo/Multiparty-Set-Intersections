import socket, pickle
import helper
import operator
import numpy as np
import random
import paillier.paillier.paillier as p
import time
import sys
import subprocess

def main():
    start_time = time.time()
    tcp_ip = '127.0.0.1'
    tcp_port = 5013
    tcp_port2 = 5005
    tcp_port3 = 5006
    buffer_size = 65536
    num_parties = int(sys.argv[1])
    add_to_set = int(sys.argv[2])
    xi = 4
    data = [2,4,6,8,10]

    for i in range(add_to_set):
        data.append(100 + i)

    s = []
    for i in range(num_parties):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind((tcp_ip, tcp_port))
        sock.listen(1)
        s.append(sock)
        tcp_port += 1

    print "launching parties"
    cur_port = 5013
    offset = 200
    while (cur_port <= tcp_port):
        subprocess.Popen(["python", "party.py", str(cur_port), str(add_to_set), str(offset)])
        cur_port += 1
        offset += 100 
    print "launched"
    #generate keys
    privkey, pubkey = p.generate_keypair(128)
    #print "pub " + str(pub)

    #share keys
    print "sharing keys"
    conn = [None] * len(s)
    addr = [None] * len(s)
    pubdump = pickle.dumps(pubkey)
    for i in range(num_parties):
        conn[i], addr[i] = s[i].accept()
        conn[i].send(pubdump)

    #generate polynomial for center
    print "generating center polynomial"
    POne = helper.polyCoefficients(data)
    encP = []
    print "encrypting center polynomial"
    for coeff in POne:
        encP.append(p.encrypt(pubkey, coeff))
    POne = encP

    #get P2 and P3
    print "receiving other polynomials"
    #conn2, addr2 = s2.accept()
    poly_arr = []
    for i in range(num_parties):
        recvd = conn[i].recv(buffer_size)
        poly_arr.append(pickle.loads(recvd))

    #create P by summing polynomials
    print "summing polynomials"
    #print "POne: " + str(POne) 
    #print "PTwo: " + str(PTwo) 
    #print "PThree: " + str(PThree) 
    P = encP
    for i in range(len(poly_arr)):
        P = helper.betterPolySum(pubkey, P, poly_arr[i])

    #print "poly is " + str(P) 
    #send P to C2 and C3
    print "distributing P"
    polydata = pickle.dumps(P)

    for i in range(num_parties):
        conn[i].send(polydata)
    
    #evaluate P
    print "evaluating P"
    evaluated = helper.polyEvaluate(pubkey, P, data)

    #draw noise 
    n = helper.gaussian(xi, 3)
    #print "noise: " + str(n)
    #ensure it is not negative
    if (n < 0):
        n = 0
    #add noise to encrypted values
    for i in range(n):
        evaluated.append(p.encrypt(pubkey,0))
    
    #print "encrypted 0 " + str(p.encrypt(pubkey,0))
    #get values from C2 and C3
    print "receiving other evaluations"
    for i in range(num_parties):
        recvd = conn[i].recv(buffer_size)
        evaluated.extend(pickle.loads(recvd))
        conn[i].close()

    #add them to current values
    print "combining evaluations"

    #shuffle values for blinding
    random.shuffle(evaluated)

    #decrypt
    print "decrypting"
    #print "decrypting " + str(evaluated)
    decrypted = []
    for item in evaluated:
        #"decrypting " + str(item)
        decrypted.append(p.decrypt(privkey, pubkey, item))

    #print "decrypted " + str(decrypted)
    #tally results
    print "tallying results"
    intersection = 0
    for item in decrypted:
        if item == 0:
            intersection += 1
    
    intersection = intersection / num_parties

    print "intersection cardinality: " + str(intersection)
    print("--- %s seconds ---" % (time.time() - start_time))
if __name__ == "__main__":
    main()