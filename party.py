import socket, pickle
import helper
import random
import paillier.paillier.paillier as p
import sys

def main():
    tcp_ip = '127.0.0.1'
    tcp_port = int(sys.argv[1])
    buffer_size = 65536
    data = [3,6,9,10,15]
    xi = 4
    add_to_set = int(sys.argv[2])
    starting_at = int(sys.argv[3])

    #print "Arg "+ str(sys.argv[1])
    for i in range(add_to_set):
        data.append(3000 + i)
    #generate keys
    #priv, pub = p.generate_keypair(128)
    #print "pub " + str(pub)
    #shuffle data for blinding
    random.shuffle(data)

    #get keys
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((tcp_ip, tcp_port))
    recvk = s.recv(buffer_size)
    pubkey = pickle.loads(recvk)
    #privkey = s.recv(buffer_size)
    #generate and encrypt polynomial
    localP = helper.polyCoefficients(data)
    encP = []
    for coeff in localP:
        encP.append(p.encrypt(pubkey, coeff))
    #send polynomial to center
    data_string = pickle.dumps(encP)
    s.send(data_string)
    #s.close()

    #receive P from center
    #s.connect((tcp_ip, tcp_port))
    recvd = s.recv(buffer_size)
    
    #s.close()
    P = pickle.loads(recvd)
    #print "pubkey " + str(pubkey)
    #print "poly " + str(P)
    #evaluate P
    evaluated = helper.polyEvaluate(pubkey, P, data)

    #draw noise 
    n = helper.gaussian(xi, 3) #not working yet
    #print "noise: " + str(n)
    #ensure it is not negative
    if (n < 0):
        n = 0
    #add noise to encrypted values
    for i in range(n):
        evaluated.append(p.encrypt(pubkey, 0))
    
    #shuffle evaluated values

    #send evaluated values to center 
    #s.connect((tcp_ip, tcp_port))
    data_string = pickle.dumps(evaluated)
    s.send(data_string)
    s.close()
    #threshold decrypt


if __name__ == "__main__":
    main()