from flask import Flask, render_template, redirect, flash, request, jsonify, url_for, session
from config import Config
import hashlib
import json
from blockchain import blockchain, node_address, wip_blockchain
from forms import BasicForm, SearchForm, LoginForm
import argparse
import subprocess
#-------------------------------------------------------------------------------------------------

app = Flask(__name__)
app.config.from_object(Config)
password_hash = '8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918'
agencies = ['news_agency_1', 'news_agency_2', 'news_agency_3']
user = ''

#-------------------------------------------------------------------------------------------------



def get_arguments():
	parser = argparse.ArgumentParser(description='Arguments for Blockchain app')
	parser.add_argument('-ah', '--host', dest='app_host', help="Host to run application on")
	parser.add_argument('-p', '--port', dest='app_port', type=int, help="Port to run application on")

	return parser.parse_args()

args = get_arguments()
host = args.app_host
port = args.app_port
server_number = str(port)[-1]
is_logged_in=False
edited_blocks = []
published_blocks = []
flagged_blocks = []

def ping_servers(nodes_list):
    response = []
    if nodes_list is None:
        return False
    for node in nodes_list:
        url = f'http://{node}'
        print(f'Pinging url {url}')
        try:
            output = str(subprocess.check_output(['curl', '-Is', url]).decode('utf-8')).split('\n')[0]
            print(f'Output: {output}')
            if output[9:12] == '200':
                server_response = {
                    'address'   : node,
                    'output'    : 'Up'
                }
                response.append(server_response)
            else:
                server_response = {
                    'address'   : node,
                    'output'    : 'Down'
                }
                response.append(server_response)
        except:
            server_response = {
                'address'   : node,
                'output'    : 'Down'
            }
            response.append(server_response)
    return response

#-------------------------------------------------------------------------------------------------




@app.route('/', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        form_username = form.username.data
        form_password = form.password.data
        print(form_username, form_password)
        form_password_hash = hashlib.sha256(str(form_password).encode()).hexdigest()

        if form_username == 'admin' and form_password_hash == password_hash:
            session['user'] = 'admin'
            session['is_logged_in'] = True
            flash('Login Successfull', 'success')
            return redirect(url_for('index'))
        else:
            flash('Sorry Invalid Credentials', 'danger')
            return redirect(url_for('login')) 
    return render_template('login.html', title='Login', form=form)

#-------------------------------------------------------------------------------------------------

@app.route('/home')
def index():
    if session.get('is_logged_in'):
        print(is_logged_in)
        print(user)
        print(session['user'])
        print(wip_blockchain.nodes)
        return render_template('home.html', title='HomePage', blockchain_nodes=blockchain.nodes, address=node_address, server_number=server_number, host=host, port=port)
    else:
        flash('Sorry. You need to login to access this page', 'danger')
        return redirect(url_for('login'))
	
#-------------------------------------------------------------------------------------------------


@app.route('/create_news', methods=['GET' ,'POST'])
def create_news():
	form = BasicForm()
	if form.validate_on_submit():
		news_data = {
			'title'	: form.title.data,
			'author' 	: form.author.data,
			'agency'		: form.agency.data,
			'date'	: form.date.data,
			'content'		: form.content.data,
		}
		previous_block = wip_blockchain.get_previous_block() 
		previous_block_hash = wip_blockchain.hash(previous_block)
		new_block = wip_blockchain.create_block(news_data, previous_block_hash)
		response = {
			'Message'	: 'New block has been added successfully',
			'Block'		: new_block
		}
		return render_template('block.html', block=new_block, server_number=server_number)
	return render_template('create_news.html', title='Create News', form=form, server_number=server_number)

#-------------------------------------------------------------------------------------------------

@app.route('/show_chain', methods=['GET'])
def show_chain():
    print(blockchain.chain)
    hash = blockchain.hash
    synched = blockchain.is_chain_synched()
    show_sync_button = False
    if not synched:
        flash(f'Chain is not up to date. Please synchronize', 'danger')
        show_sync_button = True
    return render_template('chain.html', chain_type="mainchain", chain=blockchain.chain, title='MainChain', hash=hash,show_sync_button=show_sync_button, server_number=server_number)

#-------------------------------------------------------------------------------------------------

@app.route('/show_wip_chain', methods=['GET'])
def show_wip_chain():
    if session.get('is_logged_in'):
        hash = wip_blockchain.hash
        # synched = wip_blockchain.is_chain_synched()
        show_sync_button = False
        # if not synched:
        #     flash(f'Chain is not up to date. Please synchronize', 'danger')
        #     show_sync_button = True
        chain = []
        if len(edited_blocks) > 0:
            for block in wip_blockchain.chain[::-1]:
                if (block.get('index') not in edited_blocks) and (block.get('index') not in published_blocks):
                    chain.append(block)
        else:
            chain = wip_blockchain.chain
                    

        return render_template('wip_chain.html',chain_type="wipchain", chain=chain, title='WIP Chain', hash=hash,show_sync_button=show_sync_button, server_number=server_number)
    else:
        flash('Sorry. You need to login to access this page', 'danger')
        return redirect(url_for('login'))

#-------------------------------------------------------------------------------------------------

@app.route('/get_chain', methods=['GET'])
def get_chain():
    response = {
        'Message'   : 'Here is your Chain',
        'Chain'     : blockchain.chain,
        'Host'      : host,
        'Port'      : port,
        'Length'    : len(blockchain.chain),
        'Flagged'   : blockchain.flagged_blocks,
     }    
    return jsonify(response)


@app.route('/get_wip_chain', methods=['GET'])
def get_wip_chain():
    response = {
        'Message'   : 'Here is your Chain',
        'Chain'     : wip_blockchain.chain,
        'Host'      : host,
        'Port'      : port,
        'Length'    : len(wip_blockchain.chain),
    }    
    return jsonify(response)

#-------------------------------------------------------------------------------------------------

@app.route('/validity')
def validity():
	validity = blockchain.is_chain_valid(blockchain.chain)
	if validity:
		response = {
			'Message' : 'Chain is valid',
			'Chain'	: blockchain.chain 
		}
	else:
		response = {
			'Message' : 'Chain is invalid',
			'Chain'	: blockchain.chain
		}
	return jsonify(response)

#-------------------------------------------------------------------------------------------------

@app.route('/is_chain_valid')
def check_chain_validity():
    if session.get('is_logged_in'):
        validity = blockchain.is_chain_valid(blockchain.chain)
        if validity:
            flash('Blockchain is well and fine. Go ahead with your work.', 'success')
        else:
            flash('Well something seems wrong with the chain. Do take a look', 'danger')
        return redirect(url_for('show_chain'))
    else:
        flash('Sorry. You need to login to access this page', 'danger')
        return redirect(url_for('login'))

#-------------------------------------------------------------------------------------------------

@app.route('/is_wip_chain_valid')
def check_wip_chain_validity():
    if session.get('is_logged_in'):
        validity = wip_blockchain.is_chain_valid(wip_blockchain.chain)
        if validity:
            flash('Blockchain is well and fine. Go ahead with your work.', 'success')
        else:
            flash('Well something seems wrong with the chain. Do take a look', 'danger')
        return redirect(url_for('show_chain'))
    else:
        flash('Sorry. You need to login to access this page', 'danger')
        return redirect(url_for('login'))

#-------------------------------------------------------------------------------------------------

@app.route('/connect_node', methods=['POST'])
def connect_node():
    json_file = request.get_json()
    nodes = json_file.get('nodes')
    if nodes is None:
        return 'Sorry no Nodes Found', 400
    for node in nodes:
        blockchain.add_node(node)
        wip_blockchain.add_node(node)
    response ={
        'Message'   : 'All the nodes have been added Successfully.',
        'Nodes'     : list(blockchain.nodes)
    }
    return jsonify(response)

#-------------------------------------------------------------------------------------------------

@app.route('/replace_chain')
def replace_chain():
    if session.get('is_logged_in'):
        is_chain_replaced = blockchain.replace_chain()
        if is_chain_replaced:
            flash(f'Chain was replaced successfully. Continue with your work', 'success')
        else:
            flash(f'Chain is up to date. No need to change.', 'info')
        return redirect(url_for('show_chain'))
    else:
        flash('Sorry. You need to login to access this page', 'danger')
        return redirect(url_for('login'))

#-------------------------------------------------------------------------------------------------

@app.route('/replace_wip_chain')
def replace_wip_chain():
    if session.get('is_logged_in'):
        is_chain_replaced = wip_blockchain.replace_chain()
        if is_chain_replaced:
            flash(f'Chain was replaced successfully. Continue with your work', 'success')
        else:
            flash(f'Chain is up to date. No need to change.', 'info')
        return redirect(url_for('show_wip_chain'))
    else:
        flash('Sorry. You need to login to access this page', 'danger')
        return redirect(url_for('login'))

#-------------------------------------------------------------------------------------------------

@app.route('/servers')
def servers():
    if session.get('is_logged_in'):
        nodes = list(blockchain.nodes)
        #nodes.append('127.0.0.1:5004')
        response = ping_servers(nodes)
        if not response:
            flash('Looks like the network is not connected', 'danger')
            return redirect(url_for('index'))
        print(response)
        return render_template('servers.html', title='Servers', response=response, server_number=server_number)
    else:
        flash('Sorry. You need to login to access this page', 'danger')
        return redirect(url_for('login'))

#-------------------------------------------------------------------------------------------------

@app.route('/search', methods=['GET', 'POST'])
def search():
    if session.get('is_logged_in'):
        form = SearchForm()
        if form.validate_on_submit():
            answer_block = None
            enroll = str(form.enrollment.data).lower()
            print(enroll)
            if enroll[:4] == 'mitu':
                for block in blockchain.chain[::-1]:
                    if str(block.get('enrollment_no')).lower() == enroll:
                        answer_block = block
                        break
                if answer_block:
                    return render_template('block.html', title='Block', block=answer_block)
            flash('Sorry. Invalid enrollment No', 'danger')
            return redirect('search')
        return render_template('search.html', title='Search', form=form, server_number=server_number)
    else:
        flash('Sorry. You need to login to access this page', 'danger')
        return redirect(url_for('login'))

#-------------------------------------------------------------------------------------------------

@app.route('/logout')
def logout():
    if session.get('is_logged_in'):
        session.clear()
        flash('Logged out Successfully', 'info')
        return redirect(url_for('login'))
    else:
        flash('Sorry. You need to login to access this page', 'danger')
        return redirect(url_for('login'))

#-------------------------------------------------------------------------------------------------

@app.route('/login/news_agency', methods=['GET', 'POST'])
def news_agency_login():
    form = LoginForm()
    if form.validate_on_submit():
        form_username = form.username.data
        form_password = form.password.data

        if form_username in agencies and form_password == 'password':
            session['user'] = 'news_agency'
            session['is_logged_in'] = True
            flash('Login Successfull', 'success')
            return redirect(url_for('index'))
        else:
            flash('Sorry Invalid Credentials', 'danger')
            return redirect(url_for('news_agency_login'))
    return render_template('news_agency_login.html', title='Login', form=form, server_number=server_number)
        
#-------------------------------------------------------------------------------------------------

@app.route('/wip_block/<int:index>/')
def wip_block_profile(index):
    result_block = None
    for block in wip_blockchain.chain[::-1]:
        if block['index'] == index:
            result_block = block
            hash = wip_blockchain.hash(result_block)
            break
    
    if result_block:
        return render_template('wip_block_profile.html', block=result_block, title=result_block['data']['title'], hash=hash)
    else:
        flash('Sorry no block found with current index')
        return redirect('show_wip_chain')
#-------------------------------------------------------------------------------------------------

@app.route('/login/editor', methods=['GET', 'POST'])
def editor_login():
    form = LoginForm()
    if form.validate_on_submit():
        form_username = form.username.data
        form_password = form.password.data

        if form_username == 'editor1' and form_password == 'password':
            session['user'] = 'editor'
            session['is_logged_in'] = True
            flash('Login Successfull', 'success')
            return redirect(url_for('index'))
        else:
            flash('Sorry Invalid Credentials', 'danger')
            return redirect(url_for('editor_login'))
    return render_template('editor_login.html', title='Login', form=form, server_number=server_number)
#-------------------------------------------------------------------------------------------------

@app.route('/publish/<int:index>')
def publish(index):
    news_data = {}
    result_block = None
    for block in wip_blockchain.chain[::-1]:
        if block['index'] == index:
            result_block = block
            break
    
    if result_block:
        published_blocks.append(result_block.get('index'))
        for key, value in result_block['data'].items():
            news_data[key] = value
        
        previous_block = blockchain.get_previous_block() 
        previous_block_hash = blockchain.hash(previous_block)
        new_block = blockchain.create_block(news_data, previous_block_hash)
        
        return redirect(url_for('show_chain'))
    else:
        flash('sorry block not found', 'danger')
        return redirect(url_for('show_chain'))

#-------------------------------------------------------------------------------------------------

@app.route('/block/<int:index>/')
def block_profile(index):
    result_block = None
    for block in blockchain.chain[::-1]:
        if block['index'] == index:
            result_block = block
            hash = blockchain.hash(result_block)
            break
    
    if result_block:
        return render_template('block_profile.html', flagged_blocks=blockchain.flagged_blocks, block=result_block, title=result_block['data']['title'], hash=hash)
    else:
        flash('Sorry no block found with current index')
        return redirect('show_wip_chain')

#-------------------------------------------------------------------------------------------------

@app.route('/block/<int:index>/edit', methods=['GET', 'POST'])
def edit_block(index):
    result_block = None
    for block in wip_blockchain.chain[::-1]:
        if block['index'] == index:
            result_block = block
            hash = wip_blockchain.hash(result_block)
            break
    
    if result_block:
        form = BasicForm()
        if form.validate_on_submit():
            index = result_block['index']
            edited_blocks.append(index)
            news_data = {
                'title'	: form.title.data,
                'author' 	: form.author.data,
                'agency'		: form.agency.data,
                'date'	: form.date.data,
                'content'		: form.content.data,
		    }
            previous_block = wip_blockchain.get_previous_block() 
            previous_block_hash = wip_blockchain.hash(previous_block)
            new_block = wip_blockchain.create_block(news_data, previous_block_hash)
            return redirect(url_for('show_wip_chain'))
        elif request.method == 'GET':
            form.title.data = block['data']['title']
            form.author.data = block['data']['author']
            form.date.data = block['data']['date']
            form.agency.data = block['data']['agency']
            form.content.data = block['data']['content']
        return render_template('edit_block.html', block=result_block,form=form, title=result_block['data']['title'], hash=hash)
    else:
        flash('Sorry no block found with current index')
        return redirect('show_wip_chain')

#-------------------------------------------------------------------------------------------------

@app.route('/login/crowd_auditor', methods=['GET', 'POST'])
def crowd_auditor_login():
    form = LoginForm()
    if form.validate_on_submit():
        form_username = form.username.data
        form_password = form.password.data

        if form_username == 'crowd_auditor1' and form_password == 'password':
            session['user'] = 'crowd_auditor'
            session['is_logged_in'] = True
            flash('Login Successfull', 'success')
            return redirect(url_for('index'))
        else:
            flash('Sorry Invalid Credentials', 'danger')
            return redirect(url_for('crowd_auditor_login'))
    return render_template('crowd_auditor_login.html', title='Login', form=form, server_number=server_number)

#-------------------------------------------------------------------------------------------------

@app.route('/block/<int:index>/flag_misinformation')
def flag_misinformation(index):
    result_block = None
    for block in blockchain.chain[::-1]:
        if block['index'] == index:
            result_block = block
            break
    
    if result_block:
        blockchain.flagged_blocks.append(result_block.get('index'))
        flash('Post has been flagged as Misinformation', 'info')
        return redirect(url_for('block_profile', index=result_block['index']))
    else:
        flash('Sorry. Block not found', 'danger')
        return redirect('show_chain')




#-------------------------------------------------------------------------------------------------

app.run(host=host, port=port)
