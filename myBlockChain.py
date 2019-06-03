import hashlib
import time
import csv
import random
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
import json
import re
from urllib.parse import parse_qs
from urllib.parse import urlparse
import threading
import cgi
import uuid
from tempfile import NamedTemporaryFile
import shutil
import requests
import pymysql
from sqlalchemy import create_engine
import pandas as pd

PORT_NUMBER = 8099
MAX_GET_DATA_LISTS = 10
MAX_NUMBER_OF_TX = 50
DATABASE_SVR_NAME = "bcSvr1" ####################
DATABASE_SVR_IP = "localhost"
DATABASE_SVR_PORT = 3300
DATABASE_SVR_USER = "root"
DATABASE_SVR_PW = "root"
DATABASE_BC_TABLE = "blockchain" ########################
DATABASE_ND_TABLE = "node"   ########################
DATABASE_TPSVR_IP = "http://localhost:8089"
DATABASE_SVR_LIST = {'192.168.110.16': 3300}
DATABASE_NODE_LIST = {'192.168.110.16': 8099}
MASTER = True
SERVE = False

g_difficulty = 2
g_receiveNewBlock = "/node/receiveNewBlock"
g_maximumTry = 100
g_maximumGetTx = 50

class Block:

    def __init__(self, index, previousHash, timestamp, data, currentHash, proof, merkleHash):
        self.index = index
        self.previousHash = previousHash
        self.timestamp = timestamp
        self.data = data
        self.currentHash = currentHash
        self.proof = proof
        self.merkleHash = merkleHash

    def toJSON(self):
        return json.dumps(self, default=lambda o: o.__dict__, sort_keys=True, indent=4)


class txData:

    def __init__(self, commitYN, sender, amount, receiver, fee, uuid, transactionTime):
        self.commitYN = commitYN
        self.sender = sender
        self.amount = amount
        self.receiver = receiver
        self.fee = fee
        self.uuid = uuid
        self.transactionTime = transactionTime

class Node:

    def __init__(self, ip, port, tryConnect):
        self.ip = ip
        self.port = port
        self.tryConnect = tryConnect

def generateGenesisBlock(timestamp, proof):
    isSuccess = True
    newBlock = None
    GenesisTxData = [{"commitYN" : "0", "sender": "Genesis Block", "amount": "0", \
              "receiver": "kim", "fee": "0"}]

    reqHeader = {'Content-Type': 'application/json; charset=utf-8'}
    try:
        URL = DATABASE_TPSVR_IP + "/txData/new"
        res = requests.post(URL, headers=reqHeader, data=json.dumps(GenesisTxData))
        if res.status_code == 200:
            print("Genesis txData sent ok.")

            txData, txTF = getTxData(0)

            merkleHash = calculateMerkleHash(txData)
            tempHash = calculateHash(0, '0', timestamp, proof, merkleHash)
            genesisBlockData = getStrTxData(txData)

            newBlock = Block(0, '0', timestamp, genesisBlockData, tempHash, proof, merkleHash)
        else:
            print(URL + " responding error " + 404)
            isSuccess = False
    except:
        print("transaction_pool server :  " + DATABASE_TPSVR_IP + " is not responding.")
        isSuccess = False
    finally:
        if isSuccess:
            print("Success to generate genesis block : \n" + str(newBlock.__dict__))

    return newBlock, isSuccess

def calculateHash(index, previousHash, timestamp, proof, merkleHash):
    value = str(index) + str(previousHash) + str(timestamp) + str(proof) + merkleHash
    sha = hashlib.sha256(value.encode('utf-8'))
    return str(sha.hexdigest())

def getStrTxData(txData) :
    strTxData = ''
    if len(txData) > 0:
        for i in txData:
            transaction = "[" + i['uuid'] + "]" "UserID " + i['sender'] + " sent " + i['amount'] + " bitTokens to UserID " + \
i['receiver'] + " fee "+ i['fee'] + " transaction time " + str(i['transactionTime']) + ". "
            print(transaction)
            strTxData += transaction
    return strTxData

def calculateMerkleHash(txData) :
    txDataList = []
    print("hash merkling..................")
    if len(txData) > 0:
        for i in txData:
            transaction = "[" + i['uuid'] + "]" "UserID " + i['sender'] + " sent " + i['amount'] + " bitTokens to UserID " + \
                            i['receiver'] + " fee "+ i['fee'] + " transaction time " + str(i['transactionTime']) + ". "
            print(transaction)
            txDataList.append(transaction)
    return rcGetMerkleHash(txDataList)


def rcGetMerkleHash(target) :
    strBinaryTxData = ""
    #check
    print("current len of Target =  " + str(len(target)))
    endIndexOfTarget = len(target) - 1
    if len(target) <= 1 :
        sha = hashlib.sha256(target[0].encode('utf-8'))
        return str(sha.hexdigest())
    #1개 이상이라면 1개가 될때까지 계속 해쉬화
    else :
        newTarget = []
        for i in range(endIndexOfTarget - 1):
            if i % 2 == 0 :
                strBinaryTxData = strBinaryTxData + target[i] + target[i+1]
                sha = hashlib.sha256(target[i].encode('utf-8'))
                newTarget.append(str(sha.hexdigest()))

        #target리스트의 길이가 홀수라면
        if (len(target) % 2) != 0:
            sha = hashlib.sha256(target[endIndexOfTarget].encode('utf-8'))
            newTarget.append(str(sha.hexdigest()))
        #짝수라면
        else :
            strBinaryTxData = strBinaryTxData + target[endIndexOfTarget-1] + target[endIndexOfTarget]
            sha = hashlib.sha256(strBinaryTxData.encode('utf-8'))
            newTarget.append(str(sha.hexdigest()))
        #재귀   
        return rcGetMerkleHash(newTarget)

def calculateHashForBlock(block):
    return calculateHash(block.index, block.previousHash, block.timestamp, block.proof, block.merkleHash)


def getLatestBlock(blockchain):
    lengthOfBlockChain = len(blockchain) - 1
    if len(blockchain) == 0 :
        lengthOfBlockChain = 0;
    return blockchain[lengthOfBlockChain]

def generateNextBlock(blockList, txData, timestamp, proof):
    print("Trying to generate next block...........")
    isSuccess = True
    newBlock = None

    try:
        previousBlock = getLatestBlock(blockList)
        nextIndex = int(previousBlock.index) + 1
        nextTimestamp = timestamp
        strTxData = getStrTxData(txData)
        merkleHash = calculateMerkleHash(txData)

        newBlockFound = False
        while not newBlockFound :
            nextHash = calculateHash(nextIndex, previousBlock.currentHash, nextTimestamp, proof, merkleHash)
            if nextHash[0:g_difficulty] == '0' * g_difficulty:
                newBlockFound = True
            else:
                proof += 1
        newBlock = Block(nextIndex, previousBlock.currentHash, nextTimestamp, strTxData, nextHash, proof, merkleHash)

    except :
        print("Fail to mine next block")
        isSuccess = False

    if isSuccess :
        print("Success to generate next block : \n" + str(newBlock.__dict__))
    return newBlock, isSuccess


def writeBlockchain(blockchain):
    print("Trying write block to blockchain table..........")
    tableBlockList, isSuccess = readBlockchain()

    result = 1

    if isSuccess :
        if len(tableBlockList) != 0 :
            lastBlock = getLatestBlock(tableBlockList)

            if lastBlock.index + 1 != blockchain.index :
                print("Failed to write new block to database. new block is invalid.")
                result = -1

        if result == 1 :
            conn = pymysql.connect(host=DATABASE_SVR_IP, port=DATABASE_SVR_PORT, user=DATABASE_SVR_USER, passwd=DATABASE_SVR_PW, \
                                   database=DATABASE_SVR_NAME)

            try:
                with conn.cursor() as curs:
                    print(blockchain.index, blockchain.previousHash, str(blockchain.timestamp), \
                                        blockchain.data, blockchain.currentHash, blockchain.proof, blockchain.merkleHash)
                    sql = "INSERT INTO " + DATABASE_BC_TABLE + " VALUES (%s,%s,%s,%s,%s,%s,%s)"
                    curs.execute(sql,(blockchain.index, blockchain.previousHash, str(blockchain.timestamp), \
                                        blockchain.data, blockchain.currentHash, blockchain.proof, blockchain.merkleHash))
                    conn.commit()
            except :
                print("Failed to insert new block on database.")
            finally:
                conn.close()

    else :
        print("Failed to read blockchain data from database")
        result = -1

    if result == 1 :
        print("Succeed to write new block on database.")
    return result

def writeAllBlockchain(blockchainList):

    result = 1
    conn = pymysql.connect(host=DATABASE_SVR_IP, port=DATABASE_SVR_PORT, user=DATABASE_SVR_USER, passwd=DATABASE_SVR_PW, \
                           database=DATABASE_SVR_NAME)
    try:
        print("Trying delete all data on table " + DATABASE_BC_TABLE + " for renewal...........")
        with conn.cursor() as curs:
            sql = "DELETE FROM " + DATABASE_BC_TABLE
            curs.execute(sql)
            conn.commit()
    except:
        print("Failed to delete all data.")
        result = -1
    finally:
        conn.close()

    print("Trying write block to blockchain table..........")
    conn = pymysql.connect(host=DATABASE_SVR_IP, port=DATABASE_SVR_PORT, user=DATABASE_SVR_USER, passwd=DATABASE_SVR_PW, \
                               database=DATABASE_SVR_NAME, charset = 'utf-8')

    try:
        for blockchain in blockchainList:
            with conn.cursor() as curs:
                print(blockchain.index, blockchain.previousHash, str(blockchain.timestamp), \
                                    blockchain.data, blockchain.currentHash, blockchain.proof, blockchain.merkleHash)
                sql = "INSERT INTO " + DATABASE_BC_TABLE + " VALUES (%s,%s,%s,%s,%s,%s,%s)"
                curs.execute(sql,(blockchain.index, blockchain.previousHash, str(blockchain.timestamp), \
                                        blockchain.data, blockchain.currentHash, blockchain.proof, blockchain.merkleHash))
            conn.commit()
    except :
        print("Failed to insert new block on database.")
        result = -1
    finally:
        conn.close()

    if result == 1 :
        print("Succeed to write new block on database.")
    return result

def readBlockchain():
    print("readBlockchain")
    isSuccess = False
    blockDataList = []
    conn = pymysql.connect(host=DATABASE_SVR_IP, port=DATABASE_SVR_PORT, user=DATABASE_SVR_USER, password=DATABASE_SVR_PW, \
                           db=DATABASE_SVR_NAME, charset='utf8')

    try:
        print("Trying to read blockchain data from " + DATABASE_BC_TABLE + " on " + DATABASE_SVR_NAME + "...........")
        with conn.cursor() as cursor :
            sql = "select * from " + DATABASE_BC_TABLE
            cursor.execute(sql)
            rows = cursor.fetchall()

            for data in rows:
                block = Block(data[0], data[1], data[2], data[3], data[4], data[5], data[6])
                blockDataList.append(block)
            isSuccess = True
    except:
        print("Failed to read blockchain data from " + DATABASE_BC_TABLE + " on " + DATABASE_SVR_NAME)
    finally:
        conn.close()

    if isSuccess :
        print("Success to read blockchain data from " + DATABASE_BC_TABLE + " on " + DATABASE_SVR_NAME)
    return blockDataList, isSuccess


def updateTx(blockData, mode = 'update'):

    if mode == 'update' :
        query = '/txData/update'
    else :
        query = '/txData/rollback'

    result = 1

    phrase = re.compile(
        r"\w+[-]\w+[-]\w+[-]\w+[-]\w+")

    print(blockData.data)
    matchList = phrase.findall(blockData.data)
    print(matchList)
    if len(matchList) == 0:
        print("No Match Found! " + str(blockData.data) + "block idx: " + str(blockData.index))
        result = -1
    else :
        reqHeader = {'Content-Type': 'application/json; charset=utf-8'}

        blockDict = []
        blockDict.append(blockData.__dict__)
        print(blockDict)
        try:
            URL = DATABASE_TPSVR_IP + query
            print(URL)
            res = requests.post(URL, headers=reqHeader, data=json.dumps(blockDict))
            if res.status_code == 200:
                print("sent ok.")
            else:
                print(URL + " responding error " + 404)
                result = -1
        except:
            print("Trusted Server " + URL + " is not responding.")
            result = -1

    if result == 1 :
        if mode == 'update' :
            print('Succeed to update')
        else :
            print('Succeed to rollback')
    return result

def getTxData(chooseData):

    url = DATABASE_TPSVR_IP + "/getTxData/zero"
    if (chooseData == 1) :
        url = DATABASE_TPSVR_IP + "/getTxData/all"
    txData = []
    isSuccess = True
    try :
        print("Trying to get txData from " + DATABASE_TPSVR_IP + "...........")
        res = requests.get(url=url)
        if res.status_code == 200 :
            txData = json.loads(res.text)

            res.close()
        else :
            isSuccess = False
    except:
        isSuccess = False

    return txData, isSuccess
def mineNewBlock():
    blockList, blockTF = readBlockchain()
    urlData, txTF = getTxData(0)
    timestamp = time.time()
    proof = 0

    if blockTF and txTF :
        if len(blockList) == 0 :
            newBlock, isSuccessBc = generateGenesisBlock(timestamp, proof)
        else:
            newBlock, isSuccessBc = generateNextBlock(blockList, urlData, timestamp, proof)
            print(newBlock, isSuccessBc)

        if isSuccessBc :
            upResult = updateTx(newBlock, mode = 'update')
        else :
            print("mineNewBlock : Failed to generate NewBlock")
            return

        if upResult == 1 :
            wrResult = writeBlockchain(newBlock)
        else :
            print("mineNewBlock : Failed to update txdata on transaction pool table used create block")
            rollBackSuccess = updateTx(newBlock, mode = 'rollback')
            if rollBackSuccess == 1 :
                print("mineNewBlock : Succeed to rollback txData")
            return

        if wrResult == 1 :
            print("mineNewBlock : Succeed to write new block on table ")
            broadResult = broadcastNewBlock(newBlock)
        else :
            print("mineNewBlock : Fail to write new block on table ")
            rollBackSuccess = updateTx(newBlock, mode='rollback')
            if rollBackSuccess == 1 :
                print("mineNewBlock : Succeed to rollback txData")
            return

        if broadResult :
            print("mineNewBlock : Succeed broadcasting new block")
            return
        else :
            print("mineNewBlock : Failed to broadcasting new block")
            syncSuccess = syncBlockChain()

        if syncSuccess :
            print("mineNewBlock : Succeed to rollback txData")
        else :
            print("mineNewBlock : Failed to sync all block data")
            rollBackSuccess = updateTx(newBlock, mode='rollback')
            if rollBackSuccess == 1:
                print("mineNewBlock : Succeed to rollback txData")
            return
    else :
        print("mineNewBlock : There's no Transaction pool data in Url.")
        return

def mine():
    mineNewBlock()

def isSameBlock(block1, block2):
    if str(block1.index) != str(block2.index):
        return False
    elif str(block1.previousHash) != str(block2.previousHash):
        return False
    elif str(block1.timestamp) != str(block2.timestamp):
        return False
    elif str(block1.data) != str(block2.data):
        return False
    elif str(block1.currentHash) != str(block2.currentHash):
        return False
    elif str(block1.proof) != str(block2.proof):
        return False
    elif str(block1.merkleHash) != str(block2.merkleHash):
        return False
    return True

# 외부에서 받은 블록들을 비교한다(순서 6개의 경우: [1,2], [2,3] ... [5,6]
def isValidNewBlock(newBlock, previousBlock):
    if int(previousBlock.index) + 1 != int(newBlock.index):
        print('Indices Do Not Match Up')
        return False
    # 체이닝이 맞는지
    elif previousBlock.currentHash != newBlock.previousHash:
        print("Previous hash does not match")
        return False
    # 해쉬검증
    elif calculateHashForBlock(newBlock) != newBlock.currentHash:
        print("Hash is invalid")
        return False
    elif newBlock.currentHash[0:g_difficulty] != '0' * g_difficulty:
        print("Hash difficulty is invalid")
        return False
    return True

def isValidChain(bcToValidate):
    genesisBlock = []
    bcToValidateForBlock = []

    # Read GenesisBlock
    try:
        blockReader = readBlockchain()
        for line in blockReader:
            block = Block(line[0], line[1], line[2], line[3], line[4], line[5], line[6])
            genesisBlock.append(block)
    except:
        print("file open error in isValidChain")
        return False

    # transform given data to Block object
    for line in bcToValidate:
        # print(type(line))
        # index, previousHash, timestamp, data, currentHash, proof
        block = Block(line['index'], line['previousHash'], line['timestamp'], line['data'], line['currentHash'],
                      line['proof'], line['merkleHash'])
        bcToValidateForBlock.append(block)

    # if it fails to read block data  from db(csv)
    if not genesisBlock:
        print("fail to read genesisBlock")
        return False

    # compare the given data with genesisBlock
    if not isSameBlock(bcToValidateForBlock[0], genesisBlock[0]):
        print('Genesis Block Incorrect')
        return False

    # tempBlocks = [bcToValidateForBlock[0]]
    # for i in range(1, len(bcToValidateForBlock)):
    #    if isValidNewBlock(bcToValidateForBlock[i], tempBlocks[i - 1]):
    #        tempBlocks.append(bcToValidateForBlock[i])
    #    else:
    #        return False

    for i in range(0, len(bcToValidateForBlock)):
        if isSameBlock(genesisBlock[i], bcToValidateForBlock[i]) == False:
            return False

    return True


def addNode(recievedNode, mode='new'):
    for getNode in recievedNode :
        if mode == 'new':
            newNode = Node(getNode['ip'], str(getNode['port']), "0")
        else:
            newNode = Node(getNode['ip'], str(getNode['port']), str((getNode['tryConnect'])))

    result = 1
    sameNodeFound = False
    conn = pymysql.connect(host=DATABASE_SVR_IP, port=DATABASE_SVR_PORT, user=DATABASE_SVR_USER, passwd=DATABASE_SVR_PW, \
                           database=DATABASE_SVR_NAME, charset='utf8')
    try:
        print("Trying to find new node on database...........")
        with conn.cursor() as cursor:
            sql = "Select ip, port FROM " + DATABASE_ND_TABLE + " WHERE ip = %s AND port = %s"
            cursor.execute(sql, (newNode.ip, newNode.port))
            rows = cursor.fetchall()
            conn.commit()
        if len(rows) != 0:
            print("new node is already existed.")
            sameNodeFound = True
    except:
        print("Failed to access nodelist database.")
        result = -1
    finally:
        conn.close()

    if not sameNodeFound :
        conn = pymysql.connect(host=DATABASE_SVR_IP, port=DATABASE_SVR_PORT, user=DATABASE_SVR_USER,
                               passwd=DATABASE_SVR_PW, \
                               database=DATABASE_SVR_NAME, charset='utf8')
        try:
            print("Trying to add new node on database...........")
            with conn.cursor() as curs:
                sql = "INSERT INTO " + DATABASE_ND_TABLE + " VALUES (%s,%s,%s)"
                curs.execute(sql, (newNode.ip, newNode.port, newNode.tryConnect))
                conn.commit()
            print('Success to write new node on' + DATABASE_ND_TABLE + ".")
        except:
            print("Failed to access nodelist database.")
            result = -1
        finally:
            conn.close()
    else:
        result = -1

    if mode == 'new' :
        reqHeader = {'Content-Type': 'application/json; charset=utf-8'}
        newNodeList = []
        newNodeList.append(newNode.__dict__)
        for key, value in DATABASE_NODE_LIST.items():
            URL = "http://" + key + ":" + str(value) + "/postNode/newSvr"
            print(URL)
            try:
                print("trying send added node to " + key + ":" + str(value) + " in SVR_LIST...........")
                res = requests.post(URL, headers=reqHeader, data=json.dumps(newNodeList))
                if res.status_code == 200:
                    print("sent ok.")
                else:
                    print("Failed to send new node to " + key + ":" + str(value) + " in SVR_LIST >> 404")
            except:
                print("Failed to send new node to " + key + ":" + str(value) + " in SVR_LIST >> not responding")


    return result

def readNodes() :
    nodeDictList = []
    conn = pymysql.connect(host=DATABASE_SVR_IP, port=DATABASE_SVR_PORT, user=DATABASE_SVR_USER,
                           passwd=DATABASE_SVR_PW, \
                           database=DATABASE_SVR_NAME)

    sql = "SELECT * FROM " + DATABASE_ND_TABLE
    try :
        with conn.cursor() as curs :
            curs.execute(sql)
            nodeList = curs.fetchall()

            for line in nodeList :
                node = Node(line[0], line[1], line[2])
                nodeDictList.append(node.__dict__)
    except:
        print("Failed to get node data from database.")
    finally:
        conn.close()

    return nodeDictList

def row_count():
    try:
        list = readBlockchain()
        return len(list)
    except:
        return 0

def compareMerge(bcDict):

    bcToValidateForBlock = []
    heldBlock = []

    try:
        blockchainList = readBlockchain()
        heldBlock = blockchainList
    except:
        print("file open error in compareMerge or No database exists")
        print("call initSvr if this server has just installed")
        return -1

    # if it fails to read block data  from db(csv)
    if len(heldBlock) == 0:
        print("fail to read")
        return -2

    # transform given data to Block object
    for line in bcDict:

        block = Block(line['index'], line['previousHash'], line['timestamp'], line['data'], line['currentHash'],
                      line['proof'], line['merkleHash'])

        bcToValidateForBlock.append(block)

    # compare the given data with genesisBlock
    if not isSameBlock(bcToValidateForBlock[0], heldBlock[0]):
        print('Genesis Block Incorrect')
        return -1

    if isValidNewBlock(bcToValidateForBlock[-1], heldBlock[-1]) == False:

        # latest block == broadcasted last block
        if isSameBlock(heldBlock[-1], bcToValidateForBlock[-1]) == True:
            print('latest block == broadcasted last block, already updated')
            return 2
        # select longest chain
        elif len(bcToValidateForBlock) > len(heldBlock):
            # validation
            if isSameBlock(heldBlock[0], bcToValidateForBlock[0]) == False:
                print("Block Information Incorrect #1")
                return -1
            tempBlocks = [bcToValidateForBlock[0]]
            for i in range(1, len(bcToValidateForBlock)):
                if isValidNewBlock(bcToValidateForBlock[i], tempBlocks[i - 1]):
                    tempBlocks.append(bcToValidateForBlock[i])
                else:
                    return -1
            # [START] save it to database
            writeAllBlockchain(bcToValidateForBlock)
            # [END] save it to database
            return 1
        elif len(bcToValidateForBlock) < len(heldBlock):
            # validation
            # for i in range(0,len(bcToValidateForBlock)):
            #    if isSameBlock(heldBlock[i], bcToValidateForBlock[i]) == False:
            #        print("Block Information Incorrect #1")
            #        return -1
            tempBlocks = [bcToValidateForBlock[0]]
            for i in range(1, len(bcToValidateForBlock)):
                if isValidNewBlock(bcToValidateForBlock[i], tempBlocks[i - 1]):
                    tempBlocks.append(bcToValidateForBlock[i])
                else:
                    return -1
            print("We have a longer chain")
            return 3
        else:
            print("Block Information Incorrect #2")
            return -1
    else:  # very normal case (ex> we have index 100 and receive index 101 ...)
        tempBlocks = [bcToValidateForBlock[0]]
        for i in range(1, len(bcToValidateForBlock)):
            if isValidNewBlock(bcToValidateForBlock[i], tempBlocks[i - 1]):
                tempBlocks.append(bcToValidateForBlock[i])
            else:
                print("Block Information Incorrect #2 \n" + tempBlocks.__dict__)
                return -1

        print("new block good")

        # validation
        for i in range(0, len(heldBlock)):
            if isSameBlock(heldBlock[i], bcToValidateForBlock[i]) == False:
                print("Block Information Incorrect #1")
                return -1
        # [START] save it to csv
        writeAllBlockchain(bcToValidateForBlock)
        return 1

def broadcastNewBlock(block):

    isSuccees = True

    blockDictList = []
    blockDictList.append(block.__dict__)

    reqHeader = {'Content-Type': 'application/json; charset=utf-8'}

    # request.post로 SVR_LIST의 모든 ip에 /validatedBock으로 보낸다.

    resDictData = {'validationResult' : 'abnormal'}

    for key, value in DATABASE_NODE_LIST.items() :
        try:
            print("Trying to send blockchain data to " + key + " : " + str(value) + " in SVR_LIST...........")
            URL = "http://" + key + ":" + str(value) + "/postBlock/validateBlock"
            res = requests.post(URL, headers=reqHeader, data=json.dumps(blockDictList))
            if res.status_code == 200:
                print("sent ok.")
                resDictData = json.loads(res.text)
                print(resDictData)
            else:
                print("Failed to send blockchain data to " + key + " : " + str(value) + " in SVR_LIST >> not responding : 404")
                isSuccees = False
        except:
            print("Failed to send blockchain data to " + key + " : " + str(value) + " in SVR_LIST >> not responding")
            isSuccees = False

        #응답이 abnormal 이라면 블록체인의 채굴에 실패로 간주 한다.

        resultDict = resDictData.get('validationResult','abnormal')
        print(resultDict)
        if resultDict == 'abnormal' :
            print("Failed to broadcast new block")
            isSuccees = False
        # 응답에 리스트가 []이거나 nomal 이라면  브로드캐스팅에 성공, 채굴을 완료한다.
        else :
            print("Succeed to broadcast new block")

    return isSuccees

def syncBlockChain() :
    print("Trying to sync blockchain data with SVR_LIST...........")
    blockList, readSuccess = readBlockchain()
    isSuccess = True

    blockDictList = []
    for block in blockList :
        blockDictList.append(block.__dict__)

    reqHeader = {'Content-Type': 'application/json; charset=utf-8'}

    # request.post로 SVR_LIST의 모든 ip에 /sync으로 보낸다.

    for key, value in DATABASE_NODE_LIST.items():
        try:
            print("Trying to send blockchain data to " + key + " : " + str(value) + " in SVR_LIST...........")
            URL = "http://" + key + ":" + str(value) + "/postBlock/sync"
            res = requests.post(URL, headers=reqHeader, data=json.dumps(blockDictList))
            if res.status_code == 200:
                print("sent ok.")

                ####응답의 상태에 따라 나의 블록체인 테이블을 업데이트 할것인지 결정해야 한다.
                #tempDict.append("we have a longer chain")
                ## 실패
                responsedMsg = json.loads(res.text)
                print("responsedMsg : " + str(responsedMsg))
                print(responsedMsg[-1])

            else:
                print("Failed to send blockchain data to " + key + " : " + str(value) + " in SVR_LIST >> not responding : 404")
                isSuccess = False
        except:
            print("Failed to send blockchain data to " + key + " : " + str(value) + " in SVR_LIST >> not responding")
            isSuccess = False

    if isSuccess :
        print("Succeed to sync blockchain")
    return isSuccess

def initSvr():
    isMasterSvr = MASTER
    if isMasterSvr :
        print("server : MASTER mode")
    else :
        print("server : SERVE mode")

    conn = pymysql.connect(host=DATABASE_SVR_IP, port=DATABASE_SVR_PORT, user=DATABASE_SVR_USER,
                           password=DATABASE_SVR_PW, db=DATABASE_SVR_NAME, charset='utf8')

    try:
        sql = "CREATE TABLE " + DATABASE_BC_TABLE + "(" \
                                                    "idx int," \
                                                    "Hash varchar(255)," \
                                                    "timeStamp varchar(255)," \
                                                    "data longtext," \
                                                    "currentHash varchar(255)," \
                                                    "proof varchar(255)," \
                                                    "merkleHash varchar(255)" \
                                                    ")"

        with conn.cursor() as curs:
            curs.execute(sql)

        print("Success to create blockchain table " + DATABASE_BC_TABLE + " on " + DATABASE_SVR_NAME)
    except:
        print("Failed to create blockchain table " + DATABASE_BC_TABLE + " on " + DATABASE_SVR_NAME)
    finally:
        conn.close()

    conn = pymysql.connect(host=DATABASE_SVR_IP, port=DATABASE_SVR_PORT, user=DATABASE_SVR_USER,
                           password=DATABASE_SVR_PW, \
                           db=DATABASE_SVR_NAME, charset='utf8')

    try:
        sql = "CREATE TABLE " + DATABASE_ND_TABLE + "(" \
                                                    "ip varchar(255)," \
                                                    "port varchar(255)," \
                                                    "tryConnect int" \
                                                    ")"

        with conn.cursor() as curs:
            curs.execute(sql)

        print("Success to create nodelist table " + DATABASE_ND_TABLE + " on " + DATABASE_SVR_NAME)
    except:
        print("Failed to create nodelist table " + DATABASE_ND_TABLE + " on " + DATABASE_SVR_NAME)
    finally:
        conn.close()
    ############################################################################################################## blockchain
    #내 서버의 mydb카운트를 가져온다
    myBlockCount = 0

    conn = pymysql.connect(host=DATABASE_SVR_IP, port=DATABASE_SVR_PORT, user=DATABASE_SVR_USER,
                           password=DATABASE_SVR_PW, \
                           db=DATABASE_SVR_NAME, charset='utf8')

    sql = "SELECT COUNT(*) FROM " + DATABASE_BC_TABLE
    try:
        with conn.cursor() as curs:
            curs.execute(sql)
            myBlockCount = curs.fetchone()

        print("Success to get blockchain rowCount from my database, count >> " + str(myBlockCount[0]))
    except:
        print("Failed to get blockchain rowCount from my database >>" + DATABASE_SVR_IP + " : " + str(DATABASE_SVR_PORT) + " : " + DATABASE_SVR_NAME)
    finally:
        conn.close()

    #master server가 아니고 myDbCount 가 0이라면 쭉 실행
    if myBlockCount[0] == 0 and not isMasterSvr:
        print("server : SERVE mode")

        #svr리스트의 db에 접속
        maxDbCount = 0
        maxCountIp = ""
        maxCountPort = 0

        for key, value in DATABASE_SVR_LIST.items() :
            conn = pymysql.connect(host= key, port= value, user=DATABASE_SVR_USER,
                                   password=DATABASE_SVR_PW, \
                                   db="bcSvr6", charset='utf8')
        #순차적으로 count 쿼리 날림

            sql = "SELECT COUNT(*) FROM " + DATABASE_BC_TABLE
            try :
                print("Trying to get number of blockchain data from table on" + key + " : " + str(value) + "...........")
                with conn.cursor() as curs:
                    curs.execute(sql)
                    currentCount = curs.fetchone()
                    print("Success to get number of blockchain data from table on" + key + " : " + str(value) + ", count >> " + str(currentCount[0]))

                    # 초기 count =0, 현재 count가 이전 count보다 높을 경우, maxCountIp와 포트번호를 교체
                    if currentCount[0] >= maxDbCount :
                        maxDbCount = currentCount
                        maxCountIp = key
                        maxCountPort = value
            except:
                print("Failed to get number of blockchain data from " + key + ":" + str(value))
            finally:
                conn.close()
        #maxCountIp와 port로 접속
            conn = pymysql.connect(host=maxCountIp, port=maxCountPort, user=DATABASE_SVR_USER,
                                   password=DATABASE_SVR_PW, \
                                   db="bcSvr1", charset='utf8')
            # selcet * 날리고 fetchall
            sql = "SELECT * FROM " + DATABASE_BC_TABLE
            try:
                print("Trying to get blockchain data from table on" + key + ":" + str(value) + "...........")
                with conn.cursor() as curs:
                    curs.execute(sql)
                    dbData = curs.fetchall()
                    print("Success to get blockchain data")
            except:
                print("Failed to get blockchain data from " + key + ":" + str(value))
            finally:
                conn.close()
        #가져온 dbData의 내용을 한행씩 해체하여 블록객체를 생성한 후 , 블록객체리스트에 담는다.
        getBlockList = []
        for line in dbData :
            row = Block(line[0],line[1],line[2],line[3],line[4],line[5],line[6])
            getBlockList.append(row)
        #나의 데이터베이스에 저장
        conn = pymysql.connect(host=DATABASE_SVR_IP, port=DATABASE_SVR_PORT, user=DATABASE_SVR_USER, passwd=DATABASE_SVR_PW, \
                               database=DATABASE_SVR_NAME, charset='utf8')

        try:
            print("Trying to write blockchain data on my database...........")
            for blockchain in getBlockList :
               with conn.cursor() as curs:
                   print(blockchain.index, blockchain.previousHash, str(blockchain.timestamp), \
                         blockchain.data, blockchain.currentHash, blockchain.proof, blockchain.merkleHash)
                   sql = "INSERT INTO " + DATABASE_BC_TABLE + " VALUES (%s,%s,%s,%s,%s,%s,%s)"
                   curs.execute(sql, (blockchain.index, blockchain.previousHash, str(blockchain.timestamp), \
                                      blockchain.data, blockchain.currentHash, blockchain.proof, blockchain.merkleHash))
                   conn.commit()
            print("Success to write blockchain data on my database")
        except:
            print("Failed to write blockchain data on my database")
        finally:
            conn.close()
    else :
        pass
    ################################################################################################################ node
    #DATABASE_BC_TABLE 를 DATABASE_ND_TABLE 로 교체
    myNnodeCount = 0

    conn = pymysql.connect(host=DATABASE_SVR_IP, port=DATABASE_SVR_PORT, user=DATABASE_SVR_USER,
                           password=DATABASE_SVR_PW, \
                           db=DATABASE_SVR_NAME, charset='utf8')

    sql = "SELECT COUNT(*) FROM " + DATABASE_ND_TABLE
    try:

        with conn.cursor() as curs:
            curs.execute(sql)
            myNnodeCount = curs.fetchone()

        print("Success to get node rowCount from my database, count >> " + str(myNnodeCount[0]))
    except:
        print("Failed to get nodelist from my database >> " + DATABASE_SVR_IP + " : " + str(DATABASE_SVR_PORT) + " : " + DATABASE_SVR_NAME)
    finally:
        conn.close()

    # myDbCount 가 0이라면 쭉 실행
    if myNnodeCount[0] == 0 and not isMasterSvr:
        # svr리스트의 db에 접속
        dbCount = 0
        maxCountIp = ""
        maxCountPort = 0

        for key, value in DATABASE_SVR_LIST.items():
            conn = pymysql.connect(host=key, port=value, user=DATABASE_SVR_USER,
                                   password=DATABASE_SVR_PW, db="bcSvr6", charset='utf8')
            # 순차적으로 count 쿼리 날림

            sql = "SELECT COUNT(*) FROM " + DATABASE_ND_TABLE
            try:
                print("Trying to get number of node data from table on" + key + ":" + str(value) + "...........")
                with conn.cursor() as curs:
                    curs.execute(sql)
                    currentCount = curs.fetchone()

                    print("Success to get nodelist rowCount from my database, count : " + str(currentCount[0]))
                    # 초기 count =0, 현재 count가 이전 count보다 높을 경우, maxCountIp와 포트번호를 교체
                    if currentCount[0] >= dbCount:
                        dbCount = currentCount[0]
                        maxCountIp = key
                        maxCountPort = value

            except:
                print("Failed to get nodelist data from svr_list")
            finally:
                conn.close()
            # maxCountIp와 port로 접속
            conn = pymysql.connect(host=maxCountIp, port=maxCountPort, user=DATABASE_SVR_USER,
                                   password=DATABASE_SVR_PW, \
                                   db="bcSvr6", charset='utf8')
            # selcet * 날리고 fetchall
            sql = "SELECT * FROM " + DATABASE_ND_TABLE
            try:
                print("Trying to get node data from table on" + key + ":" + str(value) + "...........")
                with conn.cursor() as curs:
                    curs.execute(sql)
                    dbData = curs.fetchall()
                print("Success to get node data")
            except:
                print("Failed to get node data from " + key + ":" + str(value))
            finally:
                conn.close()
        # 가져온 dbData의 내용을 한행씩 해체하여 블록객체를 생성한 후 , 블록객체리스트에 담는다.
        getNodeList = []
        for line in dbData:
            row = Node(line[0],line[1],line[2])
            getNodeList.append(row)
        # 나의 데이터베이스에 저장
        conn = pymysql.connect(host=DATABASE_SVR_IP, port=DATABASE_SVR_PORT, user=DATABASE_SVR_USER,
                               passwd=DATABASE_SVR_PW, \
                               database=DATABASE_SVR_NAME, charset='utf8')


        try:
            for node in getNodeList:
                print("Trying to write node data on my database...........")
                with conn.cursor() as curs:
                    sql = "INSERT INTO " + DATABASE_ND_TABLE + " VALUES (%s,%s,%s)"
                    curs.execute(sql, (node.ip, node.port, node.tryConnect))
                    conn.commit()
            print("Success to write node data on my database")
        except:
            print("Failed to write node data on my database")
        finally:
            conn.close()
    else:
        pass

    print("initSvr setting Done.........")
    return 1

# This class will handle any incoming request from
# a browser
class myHandler(BaseHTTPRequestHandler):

    # def __init__(self, request, client_address, server):
    #    BaseHTTPRequestHandler.__init__(self, request, client_address, server)

    # Handler for the GET requests
    # get방식으로 보내는 요청의 종류로는 블록체인의 데이터 요청, 블록 생성, 노드데이터 요청, 노드생성이 존재한다.
    def do_GET(self):
        data = []  # response json data
        if None != re.search('/block/*', self.path):
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()

            if None != re.search('/block/getBlockData', self.path):

                blockList, isSuccess = readBlockchain()

                # block의 값이 None인 경우
                if blockList == [] and isSuccess:

                    print("No Block Exists")

                    data.append("no data exists")
                else:
                    for i in blockList:
                        print(i.__dict__)
                        data.append(i.__dict__)

                self.wfile.write(bytes(json.dumps(data, sort_keys=True, indent=4), "utf-8"))

            # 블럭을 생성하는 경우 (최초, 그 이후 전부)
            elif None != re.search('/block/generateBlock', self.path):
                t = threading.Thread(target=mine)
                t.start()
                data.append("{mining is underway:check later by calling /block/getBlockData}")
                self.wfile.write(bytes(json.dumps(data, sort_keys=True, indent=4), "utf-8"))
            else:
                data.append("{info:no such api}")
                self.wfile.write(bytes(json.dumps(data, sort_keys=True, indent=4), "utf-8"))

        elif None != re.search('/node/*', self.path):
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()

            if None != re.search('/node/addNode', self.path):
                queryDict =[{'ip' : self.client_address[0],'port':self.client_address[1]}]

                res = addNode(queryDict, mode = 'new')

                if res == 1:
                    importedNodes = readNodes()
                    data = importedNodes
                    print("node added okay")

                elif res == 0:
                    data.append("caught exception while saving")

                elif res == -1:
                    importedNodes = readNodes()
                    data = importedNodes
                    data.append("requested node is already exists")

                self.wfile.write(bytes(json.dumps(data, sort_keys=True, indent=4), "utf-8"))

            elif None != re.search('/node/getNode', self.path):
                importedNodes = readNodes()
                data = importedNodes
                self.wfile.write(bytes(json.dumps(data, sort_keys=True, indent=4), "utf-8"))

        else:
            self.send_response(403)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
        # ref : https://mafayyaz.wordpress.com/2013/02/08/writing-simple-http-server-in-python-with-rest-and-json/

    def do_POST(self):

        if None != re.search('/postBlock/*', self.path):
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()

            if None != re.search('/postBlock/validateBlock', self.path):
                ctype, pdict = cgi.parse_header(self.headers['content-type'])
                # print(ctype) #print(pdict)

                if ctype == 'application/json':
                    content_length = int(self.headers['Content-Length'])
                    post_data = self.rfile.read(content_length)
                    receivedData = post_data.decode('utf-8')
                    print(type(receivedData))
                    tempDictList = json.loads(receivedData)  # load your str into a list #print(type(tempDict))

                    for tempDict in tempDictList :
                        newBlock = Block(tempDict['index'], tempDict['previousHash'], tempDict['timestamp'], tempDict['data'], tempDict['currentHash'], \
                                         tempDict['proof'], tempDict['merkleHash'])


                    blockList, readSuccess = readBlockchain()

                    if len(blockList) > 0:
                        previousBlock = getLatestBlock(blockList)

                        if isValidNewBlock(newBlock, previousBlock) == True:
                            tempDict['validationResult'] = 'normal'
                            result = writeBlockchain(newBlock)

                            if result == 1 :
                                print("Succeed to insert new block on database.")
                            else :
                                print("Failed to insert new block on database.")
                        else:
                            tempDict['validationResult'] = 'abnormal'
                    else :
                        result = writeBlockchain(newBlock)

                        if result == 1:
                            print("Succeed to insert new block on database.")
                        else:
                            print("Failed to insert new block on database.")

                    self.wfile.write(bytes(json.dumps(tempDict), "utf-8"))

            if None != re.search('/postBlock/sync', self.path):
                ctype, pdict = cgi.parse_header(self.headers['content-type'])

                if ctype == 'application/json':
                    content_length = int(self.headers['Content-Length'])
                    post_data = self.rfile.read(content_length)
                    receivedData = post_data.decode('utf-8')
                    tempDict = json.loads(receivedData)  # load your str into a list
                    print(tempDict)
                    res = compareMerge(tempDict)
                    if res == -1:  # internal error
                        tempDict.append("internal server error")
                    elif res == -2:  # block chain info incorrect
                        tempDict.append("block chain info incorrect")
                    elif res == 1:  # normal
                        tempDict.append("accepted")
                    elif res == 2:  # identical
                        tempDict.append("already updated")
                    elif res == 3:  # we have a longer chain
                        tempDict.append("we have a longer chain")
                    self.wfile.write(bytes(json.dumps(tempDict), "utf-8"))

        elif None != re.search('/postNode/*', self.path):
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()

            if None != re.search('/postNode/newSvr', self.path):
                ctype, pdict = cgi.parse_header(self.headers['content-type'])
                print("get response")
                if ctype == 'application/json':
                    content_length = int(self.headers['Content-Length'])
                    post_data = self.rfile.read(content_length)
                    receivedData = post_data.decode('utf-8')
                    tempDict = json.loads(receivedData)  # load your str into a list
                    if addNode(tempDict, mode='sync') == 1:
                        self.wfile.write(bytes(json.dumps(tempDict), "utf-8"))
                    else:
                        tempDict.append("error : cannot add node to sync")
                        self.wfile.write(bytes(json.dumps(tempDict), "utf-8"))
        else:
            self.send_response(404)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()

        return


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread."""

try:

    # Create a web server and define the handler to manage the
    # incoming request
    # server = HTTPServer(('', PORT_NUMBER), myHandler)
    server = ThreadedHTTPServer(('', PORT_NUMBER), myHandler)
    print('Started httpserver on port ', PORT_NUMBER)

    initSvr()
    # Wait forever for incoming http requests
    server.serve_forever()

except (KeyboardInterrupt, Exception) as e:
    print('^C received, shutting down the web server')
    print(e)
    server.socket.close()