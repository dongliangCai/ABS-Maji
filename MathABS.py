from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from charm.toolbox.secretutil import SecretUtil
from charm.toolbox.policytree import PolicyParser
from charm.toolbox.node import *
import json
import random
import fire
import os
import numpy as np 


def dict_to_strval(input_d):
    output_d = {}

    for key,value in input_d.items():
        output_d[key] = str(value)
    
    return output_d


class ABS:
    '''
    2B done
    '''

    def __init__(self,group):
        self.group = group


    def generate_binary_arrays(self,length):
        arrays = []
        for i in range(2**length):
            binary_array = []
            for j in range(length):
                binary_array.append((i >> j) & 1)
            arrays.append(binary_array)
        return arrays

    # return satisfiable SKa or empty
    def spantotarget(self, tpk, matrix, ska, u):
        sk_num = []
        for i in range(1,len(matrix)+1):
            if 'K{}'.format(tpk['atr'][u[i-1]]) in ska:
                sk_num.append(tpk['atr'][u[i-1]])
        new_M = []
        for i in sk_num:
            new_M.append(matrix[i-2])

        x = self.generate_binary_arrays(len(new_M))

        result = []
        for i in range(2**len(new_M)):
            m = np.array(np.dot(x[i], new_M))
            if m[0] == 1 and sum(m) == 1:
                result = x[i]
                break 
    
        for i in range(0, len(result)):
            if result[i] == 1:
                result[i] = sk_num[i]
            else:
                result[i] = -1
        return result;  


    def trusteesetup(self):
        '''
        Run by signature trustees
        returns the trustee public key

        Notice: Certain variables have been removed completely.
        G and H are handled by G1 and G2 type generators respectively,
        and the hash function is a generic one for the curve and can
        be derived from the group attribute.

        Attributes have to be appended to the end for global-ness
        '''
        attributes = ['AGE<18','ECCENTRIC','LAZY','VIOLENT','ATTR2','test','test1','SKILLFUL']
        tpk = {}
        #tmax = 2*len(attributes)
        tmax = 50
        tpk['g'] = self.group.random(G1)
        for i in range(tmax+1): #provide the rest of the generators
            tpk['h{}'.format(i)] = self.group.random(G2)

        attriblist = {}
        counter = 2
        for i in attributes:
            attriblist[i] = counter
            counter += 1

        tpk['atr'] = attriblist
        #print(attriblist)
        #print(tpk)
        # store tpk
        self.storekey("tpk.txt",tpk)
        #print(self.getkey("tpk.txt"))
        #return tpk


    def authoritysetup(self):
        '''
        Run by attribute-giving authority, takes tpk as parametre
        returns attribute master key and public key
        '''
        ask = {}
        apk = {}
        tpk = self.getkey("tpk.txt")
        #tmax = 2 * len(tpk['atr'])
        tmax = 50
        group = self.group
        a0,a,b = group.random(ZR), group.random(ZR), group.random(ZR)
        ask['a0'] = a0
        ask['a'] = a
        ask['b'] = b
        ask['atr'] = tpk['atr'] #this is for ease of usage

        apk['A0'] = tpk['h0'] ** a0
        for i in range(1,tmax+1): #rest of the whateverifys
            apk['A{}'.format(i)] = tpk['h{}'.format(i)] ** a

        for i in range(1,tmax+1):
            apk['B{}'.format(i)] = tpk['h{}'.format(i)] ** b

        apk['C'] = tpk['g'] ** group.random(ZR) #C = g^c at the end

        self.storekey("ask.txt",ask)
        self.storekey("apk.txt",apk)

        #return ask,apk


    def generateattributes(self, id, attriblist):
        '''
        returns signing key SKa
        '''
        #print(attriblist)
        ska = {}
        ask = self.getkey("ask.txt")
        Kbase = self.group.random(G1) #"random generator" within G
        ska['Kbase'] = Kbase

        ska['K0'] = Kbase ** (1/ask['a0'])

        attriblist = attriblist.split()
        print(attriblist)

        attrstr = ''
        for i in attriblist:
            attrstr += (str(i)+'_')
            number = ask['atr'][i]
            ska['K{}'.format(number)] = Kbase ** (1 / (ask['a'] + number * ask['b']))
        
        attrstr = attrstr[:-1]
        path = os.path.join(id,"SK")
        if not os.path.exists(path):
            os.makedirs(path)
        filename = path + "/" + attrstr + ".txt"
        print(filename)
        self.storekey(filename,ska)
        return dict_to_strval(ska)


    def sign(self, id, attriblist, message, policy): #pk = (tpk,apk)
        '''
        return signature
        '''

        #tpk,apk = pk
        tpk = self.getkey("tpk.txt")
        apk = self.getkey("apk.txt")
        lambd = {}

        attriblist = attriblist.split()
        print(attriblist)
        attrstr = ''
        for i in attriblist:
            attrstr += (str(i)+'_')
        attrstr = attrstr[:-1]
        filename = id + "/SK/" + attrstr + ".txt"
        ska = self.getkey(filename)


        M,u = self.getMSP(policy, tpk['atr'])
        mu = self.group.hash(message+policy)


        #if satisfy policy return corresponding key else empty
        result = self.spantotarget(tpk, M, ska, u)
        if result == []:
            print("not satisfy sign policy.")
            return result

        r = []
        for i in range(len(M)+1):
            r.append(self.group.random(ZR))

        lambd['Y'] = ska['Kbase'] ** r[0]
        lambd['W'] = ska['K0'] ** r[0]

        for i in range(1,len(M)+1):
            end = 0
            multi = ((apk['C'] * (tpk['g'] ** mu)) ** r[i])
            #this fills in for the v vector     todo: choose satisfiable vi for signing
            if (tpk['atr'][u[i-1]]) in result:            
                end = multi * (ska['K{}'.format(tpk['atr'][u[i-1]])] ** r[0])
            else:
                end = multi
            lambd['S{}'.format(i)] = end

        for j in range(1,len(M[0])+1):
            end = 0
            for i in range(1,len(M)+1):
                base = apk['A{}'.format(j)] * (apk['B{}'.format(j)] ** tpk['atr'][u[i-1]])
                exp = M[i-1][j-1] * r[i]
                end = end * (base ** exp)
            lambd['P{}'.format(j)] = end

        path = os.path.join(id,"Sign")
        if not os.path.exists(path):
            os.makedirs(path)        
        filename = path + "/" + policy + ".txt"
        self.storekey(filename, lambd)
        return dict_to_strval(lambd)


    def verify(self, id, signpolicy, message, policy):
        '''
        return bool
        '''
        #tpk,apk = pk
        tpk = self.getkey("tpk.txt")
        apk = self.getkey("apk.txt")

        filename = id + "/Sign/" + signpolicy + ".txt"
        sign = self.getkey(filename)

        M,u = self.getMSP(policy,tpk['atr'])

        mu = self.group.hash(message+policy)

        
        if sign['Y']==0 or pair(sign['Y'],tpk['h0']) != pair(sign['W'],apk['A0']):
            return False
        else:
            sentence = True
            for j in range(1,len(M[0])+1):
                multi = 0
                for i in range(1,len(M)+1):
                    a = sign['S{}'.format(i)]
                    b = (apk['A{}'.format(j)] * (apk['B{}'.format(j)] ** tpk['atr'][u[i-1]])) ** M[i-1][j-1]
                    multi = multi * pair(a,b)
                try:
                    after = pair(apk['C'] * tpk['g'] ** mu, sign['P{}'.format(j)])
                    pre = pair(sign['Y'],tpk['h{}'.format(j)])
                    if j == 1:
                        if multi != (pre * after):#after:
                            sentence = False
                    else:
                        if multi != (after):
                            sentence = False
                except Exception as err:
                    print(err)
            return sentence


    def getMSP(self,policy,attributes):
        '''
        returns the MSP that fits given policy

        utilizes the charm-crypto "policy -> binary tree" structure which has to be
        gone through only once

        target vector (1,0,....,0)
        '''
        u = {}
        counter = 0
        for i in attributes:
            u[counter] = i
            u[i] = counter
            counter += 1
        # print("debug: begin parse policy")
        parser = PolicyParser()
        tree = parser.parse(policy)
        # print("debug: end parse policy")
        matrix = [] #create matrix as a dummy first (easy indexing)
        for i in range(len(attributes)):
            matrix.append([])

        counter = [1]
        def recursivefill(node,vector): #create MSP compatible rows
            if node.getNodeType() == OpType.ATTR:
                text = node.getAttribute()
                temp = list(vector)
                matrix[u[text]] = temp
            elif node.getNodeType() == OpType.OR:
                recursivefill(node.getLeft(),vector)
                recursivefill(node.getRight(),vector)
            else: #AND here, right?
                temp = list(vector)
                while(len(temp)<counter[0]):
                    temp.append(0)
                emptemp = []
                while(len(emptemp)<counter[0]):
                    emptemp.append(0)
                temp.append(1)
                emptemp.append(-1)
                counter[0] += 1
                recursivefill(node.getLeft(),temp)
                recursivefill(node.getRight(),emptemp)
        recursivefill(tree,[1])

        for i in matrix:
            while(len(i)<counter[0]):
                i.append(0)

        print(matrix)
        return matrix,u

    def encodestr(self, dicti):
        '''
        pairing group dict -> string
        for sending
        '''
        returnage = {}
        for i in dicti:
            returnage[i] = dicti[i]
            try:
                returnage[i] = self.group.serialize(returnage[i]).decode()
            except Exception:
                continue
        return json.dumps(returnage)

    def decodestr(self, stri):
        '''
        string -> pairing group dict
        for receiving
        '''
        dicti = json.loads(stri)
        for i in dicti:
            try:
                dicti[i] = self.group.deserialize(str.encode(dicti[i]))
            except Exception:
                continue
        return dicti

    def storekey(self, filename, key):
        file = open(filename, "w")
        file.write(self.encodestr(key))
        print("write succ:", filename) 
        file.close()

    def getkey(self, filename):
        file = open(filename, "r")
        return self.decodestr(file.read())

if __name__ == "__main__":
    group = PairingGroup('MNT159')
    fire.Fire(ABS(group))
    # print(os.system("python3 MathABS.py trusteesetup" + attributes))

    # attributes = ['AGE<18','ECCENTRIC','LAZY','VIOLENT','ATTR2','test','test1','SKILLFUL']
#     print('ATTRIBUTE TABLE: ',attributes)

    # absinst = ABS(group)
    # tpk = absinst.trusteesetup(attributes)
#     ask,apk = absinst.authoritysetup(tpk)

#     #Add new attribute
#     #tpk['atr']['AATR1'] = 7
#     #ask['atr']['AATR1'] = 7
#     print(ask['atr'])
    
#     #test OR with AND
#     ska = absinst.generateattributes(ask,['SKILLFUL','test1'])
#     lam = absinst.sign((tpk,apk), ska, 'rar', '(SKILLFUL OR ECCENTRIC) AND test1')
#     print(absinst.verify((tpk,apk),lam,'rar','(SKILLFUL OR ECCENTRIC) AND test1'))

#     #test two attributes with OR policy
#     ska2 = absinst.generateattributes(ask,['AGE<18','test'])
#     print("generate attribute key succ")

#     lam2 = absinst.sign((tpk,apk), ska2, 'rar', 'AGE<18 OR test')
#     print("sign succ")

#     print(absinst.verify((tpk,apk),lam2,'rar','AGE<18 OR test'))
    


#     #test attribute doesn't satisfy
#     ska3 = absinst.generateattributes(ask,['SKILLFUL'])
#     lam3 = absinst.sign((tpk,apk), ska3, 'rar', 'SKILLFUL AND ECCENTRIC')
#     print(absinst.verify((tpk,apk),lam3,'rar','SKILLFUL AND ECCENTRIC'))
