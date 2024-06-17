from flask import Flask, session, abort, request, jsonify, render_template, redirect, url_for, flash, redirect
import os
import datetime
import hashlib
import json
from urllib.parse import urlparse
from flask_cors import CORS
import requests
import asyncio
from flask_bootstrap import Bootstrap
from flask_sslify import SSLify
import os
import pandas as pd
import numpy as np
import datetime as dt
import time
import json
import pandas as pd 
from uuid import *

from werkzeug.security import generate_password_hash, check_password_hash
from faunadb import query as q
from faunadb.client import FaunaClient
from faunadb.objects import Ref
from faunadb.errors import BadRequest, NotFound

client = FaunaClient(secret=os.getenv("API_KEY"),domain="db.us.fauna.com")

class CIA_NETn:

    def __init__(self):
        self.chain = []
        self.transactions = []
        self.create_block(proof=1, previous_hash='0000',name=str('Mine The First Block'),description=str("Block Has Not Been Mined"))
        self.nodes = set()

    def create_block(self, proof, previous_hash,name,description):
  
        block = {'index': len(self.chain) + 1,
                 'timestamp': str(datetime.datetime.now()),
                 'proof': proof,
                 'previous_hash': previous_hash,
                 'name': name,
                 'description': description,
                 'transactions': self.transactions
                 }
        self.transactions = []
        self.chain.append(block)
        return block

    def get_previous_block(self):
        return self.chain[-1]

    def proof_of_work(self, previous_proof):
        new_proof = 1
        check_proof = False
        while check_proof is False:
            hash_operation = hashlib.sha256(
                str(new_proof**2 - previous_proof**2).encode()).hexdigest()
            if hash_operation[:4] == '0000':
                check_proof = True
            else:
                new_proof += 1
        return new_proof

    def hash(self, block):
        encoded_block = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(encoded_block).hexdigest()

    def is_chain_valid(self, chain):
        previous_block = chain[0]
        block_index = 1
        while block_index < len(chain):
            block = chain[block_index]
            if block['previous_hash'] != self.hash(previous_block):
                return False
            previous_proof = previous_block['proof']
            proof = block['proof']
            hash_operation = hashlib.sha256(
                str(proof**2 - previous_proof**2).encode()).hexdigest()
            if hash_operation[:4] != '0000':
                return False
            previous_block = block
            block_index += 1
        return True

    # sender,receiver,amount # sender = sender receiver = receiver amount = amount
    def add_transaction(self,sender,receiver,amount):
        previous_block = blockchain.get_previous_block()
        previous_proof = previous_block['proof']
        proof = blockchain.proof_of_work(previous_proof)
        previous_hash = blockchain.hash(previous_block)
        self.transactions.append({
            'sender': sender,
            'receiver':receiver,
            'amount':amount,
        })
        previous_block = self.get_previous_block()
        return previous_block['index'] + 1

    def add_node(self, address):
        # address = 'http:127.0.0.1:8677/'
        parsed_url = urlparse(address)
        self.nodes.add(parsed_url.netloc)
        # node = parsed_url.
# Give the Chain a Reason to exist

    def replace_chain(self):
        network = self.nodes
        longest_chain = None
        max_length = len(self.chain)
        for node in network:
            response = requests.get(f'http://{node}/get_chain')
            if response.status_code == 200:
                length = response.json()['length']
                chain = response.json()['chain']
                if length > max_length and self.is_chain_valid(chain):
                    max_length = length
                    longest_chain = chain
        if longest_chain:
            self.chain = longest_chain
            return True
        return False



    # json = request.get_json() 
    # nodes = json.get('nodes')
    # for node in nodes:
    #     blockchain.add_node(node)
    # # response = {'message':'THE FOLLOWING NODES ARE CONNECTED',
    # # 'total_nodes': list(blockchain.nodes)} 
    # total_nodes = list(blockchain.nodes)
    # connected = 'THE FOLLOWING NODES ARE CONNECTED {}'.format(total_nodes)




app = Flask(__name__)
sslify = SSLify(app)
bootstrap = Bootstrap(app)

# cors = CORS(app, resources={r"/*": {"origins": ["https://www..com","https://.herokuapp.com"]}})
# cors = CORS(infura_url, resources={r"/*": {"origins": "https://ropsten.infura.io/v3/89f69d97c5c44c35959cc4d15c0f0531"}})

app.config['BOOTSTRAP_BTN_STYLE'] = 'primary'  # default to 'secondary'
# app.config['BOOTSTRAP_BOOTSWATCH_THEME'] = 'lumen'
app.secret_key = 'regurgitationA maximation'

# engine = pyttsx3.init('sapi5')
# voices = engine.getProperty('voices')
# engine.setProperty('voice', voices[1].id)

# def speak(audio):
#     engine.say(audio)
#     engine.runAndWait()

TIMEOUT_SECONDS = 2


def worker(ws, loop):
    asyncio.set_event_loop(loop)
    loop.run_until_complete(ws.start())




@app.route('/chain')
def chain():
    message = 'Welcome To The Network !'
    
    fullChain = 'full blockchain {}, {}'.format(len(blockchain.chain),blockchain.chain)


    is_chain_replaced = blockchain.replace_chain()

    if is_chain_replaced:
        # response = {'message': 'NODES HAD DIFFERENT CHAINS , REPLACED BY LONGEST CHAIN',
        # 'new_chain': blockchain.chain }
        chain_replaced = 'NODES HAD DIFFERENT CHAINS , REPLACED BY LONGEST CHAIN'
        # data['status'] = 200 
        # data['data'] = message
    else:
        # response = {'message': 'NODE IS CONNECT TO LARGEST CHAIN',
        # 'actual_chain':blockchain.chain}
        chain_replaced = 'NODE IS CONNECT TO LARGEST CHAIN'
        # data['status'] = 200 
        # data['data'] = message 

    is_valid = blockchain.is_chain_valid(blockchain.chain)
    # message = {} 
    # data = {}
    if is_valid:
        # response = {'message': 'All good. The Blockchain is valid.'}
        valid = 'All good,Blockchain Is Valid' 
        # data['status'] = 200 
        # data['data'] = message
        # json = request.get_json() 
        # nodes = json.post('nodes')
        # for node in nodes:
        #     blockchain.add_node(node)
        # # response = {'message':'THE FOLLOWING NODES ARE CONNECTED',
        # # 'total_nodes': list(blockchain.nodes)} 
        # total_nodes = list(blockchain.nodes)
        # connected = 'THE FOLLOWING NODES ARE CONNECTED {}'.format(total_nodes)

    else:
        # response = {'message': 'Houston, we have a problemo. The Blockchain is not valid.'}
        valid = 'Houston, we have a problemo. The Blockchain is not valid' 
        # data['status'] = 200 
        # data['data'] = message

    # json = request.get_json() 
    # nodes = json.get('nodes')
    # for node in nodes:
    #     blockchain.add_node(node)
    # # response = {'message':'THE FOLLOWING NODES ARE CONNECTED',
    # # 'total_nodes': list(blockchain.nodes)} 
    # total_nodes = list(blockchain.nodes)
    # connected = 'THE FOLLOWING NODES ARE CONNECTED {}'.format(total_nodes)


    return render_template('chain.html', message=message,fullChain=fullChain, valid = valid, chain_replaced=chain_replaced)



@app.route('/complete',methods=['POST'])
def complete():
    import re

    enter = 'ACCESSGRANTED'
    key = request.form.get('Enter Access Key')
    if key == enter:
        return render_template('files.html')
    else:
        return redirect('/')

@app.route('/files',methods=['GET'])
def files():

    return render_template('files.html')



@app.route('/')
def home():


    if session.get('user_id'):
        flash('You are logged in!', 'warning')
        return redirect(url_for('files'))


    message = 'Welcome To The  Network !'
    
    fullChain = 'full blockchain {}, {}'.format(len(blockchain.chain),blockchain.chain)


    is_chain_replaced = blockchain.replace_chain()

    if is_chain_replaced:
        # response = {'message': 'NODES HAD DIFFERENT CHAINS , REPLACED BY LONGEST CHAIN',
        # 'new_chain': blockchain.chain }
        chain_replaced = 'NODES HAD DIFFERENT CHAINS , REPLACED BY LONGEST CHAIN'
        # data['status'] = 200 
        # data['data'] = message
    else:
        # response = {'message': 'NODE IS CONNECT TO LARGEST CHAIN',
        # 'actual_chain':blockchain.chain}
        chain_replaced = 'NODE IS CONNECT TO LARGEST CHAIN'
        # data['status'] = 200 
        # data['data'] = message 

    is_valid = blockchain.is_chain_valid(blockchain.chain)
    # message = {} 
    # data = {}
    if is_valid:
        # response = {'message': 'All good. The Blockchain is valid.'}
        valid = 'All good,Blockchain Is Valid' 
        # data['status'] = 200 
        # data['data'] = message
        # json = request.get_json() 
        # nodes = json.post('nodes')
        # for node in nodes:
        #     blockchain.add_node(node)
        # # response = {'message':'THE FOLLOWING NODES ARE CONNECTED',
        # # 'total_nodes': list(blockchain.nodes)} 
        # total_nodes = list(blockchain.nodes)
        # connected = 'THE FOLLOWING NODES ARE CONNECTED {}'.format(total_nodes)

    else:
        # response = {'message': 'Houston, we have a problemo. The Blockchain is not valid.'}
        valid = 'Houston, we have a problemo. The Blockchain is not valid' 
        # data['status'] = 200 
        # data['data'] = message

    # json = request.get_json() 
    # nodes = json.get('nodes')
    # for node in nodes:
    #     blockchain.add_node(node)
    # # response = {'message':'THE FOLLOWING NODES ARE CONNECTED',
    # # 'total_nodes': list(blockchain.nodes)} 
    # total_nodes = list(blockchain.nodes)
    # connected = 'THE FOLLOWING NODES ARE CONNECTED {}'.format(total_nodes)


    return render_template('index.html', message=message,fullChain=fullChain, valid = valid, chain_replaced=chain_replaced)


@app.route('/connected')
def connected():
    return render_template('connected.html')





blockchain = CIA_NETn()

node_address = str(uuid4()).replace('-', '') #New
root_node = 'e36f0158f0aed45b3bc755dc52ed4560d' #New






def save_data_to_json(data, filename='local_data.json'):
    with open(filename, 'w') as json_file:
        json.dump(data, json_file)

@app.route("/create_document", methods=["POST"])
def create_document():
    import time

    
    name = request.form.get("Enter Name of the file")
    description = request.form.get("Enter Description")

    data = {"Name":name,'Description':description,'Entry_Node':node_address}
    print(data)
    execute = {
        "name":name,
        "description":description,
        "node_address":node_address
    }

                            # Save the data
    save_data_to_json(execute)

    data = client.query(q.create(
                    q.collection('files'),
                    {'data': data}
                ))
    print(data)

    previous_block = blockchain.get_previous_block()
    previous_proof = previous_block['proof']
    proof = blockchain.proof_of_work(previous_proof)
    previous_hash = blockchain.hash(previous_block)
 
    trans = blockchain.add_transaction(sender = root_node, receiver = node_address, amount = 1.15)
    
    block = blockchain.create_block(proof, previous_hash,name,description) 
    
    message= 'Congratulations, you just mined GPT Block {} at {} !, Proof of work {}, previous hash {}\n, block {}, transactions: {}'.format(block['index'],block['timestamp'],block['proof'],block['previous_hash'],block,block['transactions']) #\n transactions{}, \n LaFranc-TRX HASH {}, ,RECEIVING MINTER {},tx_hash,block['transactions'],receiver


    is_chain_replaced = blockchain.replace_chain()

    if is_chain_replaced:
        # response = {'message': 'NODES HAD DIFFERENT CHAINS , REPLACED BY LONGEST CHAIN',
        # 'new_chain': blockchain.chain }
        chain_replaced = 'NODES HAD DIFFERENT CHAINS , REPLACED BY LONGEST CHAIN'
        # data['status'] = 200 
        # data['data'] = message
    else:
        # response = {'message': 'NODE IS CONNECT TO LARGEST CHAIN',
        # 'actual_chain':blockchain.chain}
        chain_replaced = 'NODE IS CONNECT TO LARGEST CHAIN'
        # data['status'] = 200 
        # data['data'] = message 
    # command = context 
    is_valid = blockchain.is_chain_valid(blockchain.chain)
    # message = {} 
    # data = {}
    if is_valid:
        # response = {'message': 'All good. The Blockchain is valid.'}
        valid = 'All good,Blockchain Is Valid' 
        # data['status'] = 200 
        # data['data'] = message
    else:
        # response = {'message': 'Houston, we have a problemo. The Blockchain is not valid.'}
        valid = 'Houston, we have a problemo. The Blockchain is not valid' 
        # data['status'] = 200 
        # data['data'] = message
    print(session)

    return render_template("files.html", result=name ,description=description,message=message,valid=valid,chain_replaced=chain_replaced,trans=trans) #answers=answers

        




# Checking if the Blockchain is valid
@app.route('/is_valid', methods = ['GET'])
def is_valid():
    is_valid = blockchain.is_chain_valid(blockchain.chain)
    message = {} 
    data = {}
    if is_valid:
        # response = {'message': 'All good. The Blockchain is valid.'}
        message = 'All good,Blockchain Is Valid' 
        # data['status'] = 200 
        # data['data'] = message
    else:
        response = {'message': 'Houston, we have a problemo. The Blockchain is not valid.'}
        message['message'] = 'Houston, we have a problemo. The Blockchain is not valid' 
        data['status'] = 200 
        data['data'] = message   
    return jsonify(data)

### Adding Chain Transactions
@app.route('/add_transaction', methods = ['POST'])
def add_transaction():
    message = {} 
    data = {}
    json = request.get_json()
    transactions_keys= ['sender','receiver','amount']
    if not all (key in json for key in transactions_keys):
        message['message'] = 'HOME ELMENTS OF THE TRASACTION ARE MISSING' 
        data['status'] =  400
        data['data'] = message   
        return jsonify(data) #'HOME ELMENTS OF THE TRASACTION ARE MISSING' 
    index = blockchain.add_transaction(json['sender'],json['receiver'],json['amount']) 
    response = {'message': f'This Transaction IS NOW ON BLOCK {index}'}
    message['message'] = 'This Transaction IS NOW ON BLOCK {}'.format(index)
    data['status'] = 201 
    data['data'] = message   
    return jsonify(response),201

### Decentralizing the Network 

###Connecting Nodes 
@app.route('/connect_node',methods=["POST"]) 
def connect_node():
    received_json = request.get_json() 
    nodes = received_json.get('nodes')
    if nodes is None:
        message = ' No Node Found'
        return render_template('connected.html',nodes=nodes,message = message)
    for node in nodes:
        blockchain.add_node(node)
        message = 'All the nodes are now connected. The Blockchain now contains the following nodes:'
        total_nodes= list(blockchain.nodes)

    # data['status'] = 201 
    # data['data'] = message   
    return render_template('connected.html',nodes=nodes,connected = message,total_nodes=total_nodes)


### Connect longest chain if necessary
@app.route('/replace_chain', methods = ['GET'])
def replace_chain():
    is_chain_replaced = blockchain.replace_chain()
    message = {} 
    data = {}
    if is_chain_replaced:
        response = {'message': 'NODES HAD DIFFERENT CHAINS , REPLACED BY LONGEST CHAIN',
        'new_chain': blockchain.chain }
        message['message'] = 'NODES HAD DIFFERENT CHAINS , REPLACED BY LONGEST CHAIN {}'.format(blockchain.chain)
        data['status'] = 200 
        data['data'] = message
    else:
        response = {'message': 'NODE IS CONNECT TO LARGEST CHAIN',
        'actual_chain':blockchain.chain}
        message['message'] = 'NODE IS CONNECT TO LARGEST CHAIN {}'.format(blockchain.chain)
        data['status'] = 200 
        data['data'] = message   
    return jsonify(data)







usr_agent = {
    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.11 (KHTML, like Gecko) Chrome/23.0.1271.64 Safari/537.11',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Charset': 'ISO-8859-1,utf-8;q=0.7,*;q=0.3',
    'Accept-Encoding': 'none',
    'Accept-Language': 'en-US,en;q=0.8',
    'Connection': 'keep-alive',
}

if __name__ == "__main__":
    # debug=True,host="0.0.0.0",port=50000
    app.run(debug=True, host="0.0.0.0", port=5000)
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
  


