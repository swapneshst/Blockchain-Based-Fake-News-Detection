# --------------------------------- Initial Imports -----------------------------
from config import Config
from datetime import datetime
import hashlib
from flask import jsonify, Flask, request, render_template, redirect, flash, url_for
import json
from uuid import uuid4
import requests
from urllib.parse import urlparse
from forms import BasicForm
import argparse
# -------------------------------------------------------------------------------

# ---------------------------------- Blockchain Class ---------------------------
class Blockchain:

	def __init__(self, title, info):
		self.chain = []
		self.nodes = set()
		self.create_genesis_block(title, info)
		self.flagged_blocks = []
		self.published_blocks = []
		self.edited_blocks = []

	def create_genesis_block(self, title, info):
		block = {
			'title' : title,
			'info'	: info
		}
		self.chain.append(block)

	def create_block(self, news_data, previous_hash):
		block = {
			'index'			: len(self.chain) + 1,
			'timestamp'		: str(datetime.utcnow()),
			'previous_hash' : previous_hash,
			'data'			: news_data,
		}
		self.chain.append(block)
		return block

	def hash(self, block):
		encoded_block = json.dumps(block, sort_keys=True).encode()
		return hashlib.sha256(encoded_block).hexdigest()

	def get_previous_block(self):
		return self.chain[-1]

	def is_chain_valid(self, chain):
		previous_block = chain[0]
		block_index = 1
		while block_index < len(chain):
			new_block = chain[block_index]
			if new_block['previous_hash'] != self.hash(previous_block):
				return False
			previous_block = new_block
			block_index += 1
		return True

	def add_node(self, address):
		parsed_url = urlparse(address)
		self.nodes.add(parsed_url.netloc)

	def replace_chain(self):
		network = self.nodes
		longest_chain = None	
		max_length = len(self.chain)
		for node in network:
			try:
				response = requests.get(f'http://{node}/get_chain')
				if response.status_code == 200:
					length_of_chain = response.json()['Length']
					chain = response.json()['Chain']
					flagged_blocks = response.json()['Flagged']
					if length_of_chain > max_length and self.is_chain_valid(chain):
						longest_chain = chain
						max_length = length_of_chain
			except:
				pass

		if longest_chain:
			self.chain = longest_chain
			self.flagged_blocks = flagged_blocks
			return True	
		return False
	
	def is_chain_synched(self):
		network = self.nodes
		longest_chain = None
		max_length = len(self.chain)
		for node in network:
			try:
				response = requests.get(f'http://{node}/get_chain')
				if response.status_code == 200:
					length_of_chain = response.json()['Length']
					chain = response.json()['Chain']
					if length_of_chain > max_length and self.is_chain_valid(chain):
						return False
			except:
				pass
		
		return True


class WIPBlockchain(Blockchain):

	def replace_chain(self):
		network = self.nodes
		longest_chain = None	
		max_length = len(self.chain)
		for node in network:
			try:
				response = requests.get(f'http://{node}/get_wip_chain')
				if response.status_code == 200:
					length_of_chain = response.json()['Length']
					chain = response.json()['Chain']
					if length_of_chain > max_length and self.is_chain_valid(chain):
						longest_chain = chain
						max_length = length_of_chain
			except:
				pass

		if longest_chain:
			self.chain = longest_chain
			return True	
		return False

	def is_chain_synched(self):
		network = self.nodes
		longest_chain = None
		max_length = len(self.chain)
		for node in network:
			try:
				response = requests.get(f'http://{node}/get_wip_chain')
				if response.status_code == 200:
					length_of_chain = response.json()['Length']
					chain = response.json()['Chain']
					if length_of_chain > max_length and self.is_chain_valid(chain):
						return False
			except:
				pass
		
		return True

# -------------------------------------------------------------------------------------


# -------------------------------- app section ----------------------------------------
title = 'News Blockchain'
info = 'Main News Blockchain'
blockchain = Blockchain(title, info)
title = 'News Work-in-Progress'
info = 'Blockchain for work in progress news'
wip_blockchain = WIPBlockchain(title, info)
node_address = str(uuid4()).replace('-', '')

app = Flask(__name__)
app.config.from_object(Config)
# -------------------------------------------------------------------------------------


# -------------------------------- get arguments --------------------------------------



@app.route('/')
def index():
	return render_template('home.html', title='Welcome')

@app.route('/register', methods=['GET' ,'POST'])
def register():
	form = BasicForm()
	if form.validate_on_submit():
		student_data_record = {
			'f_name'	: form.f_name.data,
			'l_name' 	: form.l_name.data,
			'email'		: form.email.data,
			'address'	: form.address.data,
			'batch'		: form.batch.data,
			'roll_no'	: form.roll_no.data,
			'enrollment_no'	: form.enrollment_no.data
		}
		previous_block = blockchain.get_previous_block() 
		previous_block_hash = blockchain.hash(previous_block)
		new_block = blockchain.create_block(student_data_record, previous_block_hash)

		response = {
			'message'	: 'New block has been added successfully',
			'block'		: new_block
		}

		return render_template('block.html', block=new_block)

	return render_template('register.html', title='Register', form=form)


@app.route('/get_chain')
def get_chain():
	response = {
		'message'	: 'Here is yout blockchain',
		'chain'		: blockchain.chain,
		'length'	: len(blockchain.chain)
	}

	return jsonify(response)

@app.route('/validity')
def validity():
	validity = blockchain.is_chain_valid(blockchain.chain)
	if validity:
		response = {
			'message' : 'Chain is valid',
			'chain'	: blockchain.chain 
		}
	else:
		response = {
			'message' : 'Chain is invalid',
			'chain'	: blockchain.chain
		}
	
	return jsonify(response)

@app.route('/show_chain')
def show_chain():
	hash = blockchain.hash
	return render_template('chain.html', chain=blockchain.chain, title='show_chain', hash=hash)

@app.route('/is_chain_valid')
def check_chain_validity():
	validity = blockchain.is_chain_valid(blockchain.chain)

	if validity:
		flash('Blockchain is well and fine. Go ahead with your work.', 'success')
	else:
		flash('Well something seems wrong with the chain. Do take a look', 'danger')

	return redirect(url_for('show_chain'))

@app.route('/connect_node', methods=['POST'])
def connect_node():
	json_file = request.get_json()
	nodes = json_file.get('node_address')
	if nodes is None:
		return 'No Nodes', 400
	for node in nodes:
		blockchain.add_node(node)
	response = {
		'message'	: 'All nodes are now connected',
		'nodes'		: list(nodes)
	}

	return jsonify(response)

@app.route('/replace_chain')
def replace_chain():
	is_chain_replaced = blockchain.replace_chain()
	if is_chain_replaced:
		response = {
			'message' : 'The chain was replaced successfully',
			'chain'	: blockchain.chain
		}
	else:
		response = {
			'message' : 'The chain is up to date. No need to change',
			'chain'	: blockchain.chain
		}
	return jsonify(response)

