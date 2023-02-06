import os
from flask import Flask, render_template, redirect, request, session
import pymongo
import datetime
import time
import random
import asyncio

app = Flask(__name__)

app.secret_key = os.environ['secret_key']

cluster = pymongo.MongoClient(os.environ['MONGO_URI'])
from cryptography.fernet import Fernet
global load_key
global generate_key

global encrypt_message


def encrypt_message(message):
	key = load_key()
	encoded_message = message.encode()
	f = Fernet(key)
	return f.encrypt(encoded_message)


global decrypt_message


def decrypt_message(encrypted_message):
	key = load_key()
	f = Fernet(key)
	decrypted_message = f.decrypt(encrypted_message)

	return decrypted_message.decode()


def load_key():
	return os.environ['fernet_key']


@app.route('/')
def home():
	try:
		cluster = pymongo.MongoClient(os.environ['MONGO_URI'])
		flow_db = cluster['FlowMaster']['flows']
		userFlowData = flow_db.find_one({"username": session['username']})
		flowCount = userFlowData['count']
		flowList = []
		for flow in userFlowData:
			if flow not in ['count', 'username', 'lower_username', '_id']:
				flowList.append(flow)
		flows = {}
		for flow in flowList:
			flows[flow] = userFlowData[flow]
		return render_template('loggedin.html',
							   username=session['username'],
							   logged_in=session['logged_in'], flows=flows)
	except KeyError:
		session['logged_in'] = 'false'
		return render_template("index.html", logged_in=session['logged_in'])


@app.route('/signup', methods=['POST', 'GET'])
def signup():
	if request.method == 'POST':
		username = request.form['username']
		password = encrypt_message(request.form['password'])
		cluster = pymongo.MongoClient(os.environ['MONGO_URI'])
		user_db = cluster['FlowMaster']['users']
		if user_db.find_one({"lower_username": username.lower()}):
			return render_template('signup.html', error='Username is Already in Use')
		elif ' ' in username:
			return render_template('signup.html',
								   error='Usernames cannot have spaces or be blank!')
		elif len(request.form['password']) < 5:
			return render_template('signup.html',
								   error='Passwords must be at least 5 characters long')
		user_db.insert_one({
		 "username": username,
		 "lower_username": username.lower(),
		 "password": password,
		})
		flow_db = cluster['FlowMaster']['flows']
		flow_db.insert_one({
		 "username": username,
		 "lower_username": username.lower(),
		 'count': 0
		})
		session['logged_in'] = 'true'
		session['username'] = username
		return redirect('https://flowmaster.mythify.repl.co')

	return render_template("signup.html")


#login
@app.route('/login', methods=['POST', 'GET'])
def login():
	if request.method == 'POST':
		try:
			if session['logged_in'] == 'true':
				return redirect('https://flowmaster.mythify.repl.co/')
		except KeyError:
			pass
		username = request.form['username']
		cluster = pymongo.MongoClient(os.environ['MONGO_URI'])
		user_db = cluster['FlowMaster']['users']
		userData = user_db.find_one({"username": username})
		if not userData:
			return render_template('login.html', error='Invalid Username or Password')

		if request.form['password'] == decrypt_message(userData['password']):
			session['logged_in'] = 'true'
			session['username'] = username
			return redirect('https://flowmaster.mythify.repl.co')
		else:
			return render_template('login.html', error='Invalid Username or Password')
	else:
		return render_template('login.html')


@app.route('/logout')
def logout():
	try:
		session.pop('username')
		session.pop('logged_in')
	except:
		return redirect('https://flowmaster.mythify.repl.co/')
	return redirect('/login')


@app.route('/delacc')
def delaccount():
	# try:
	cluster = pymongo.MongoClient(os.environ['MONGO_URI'])
	user_db = cluster['FlowMaster']['users']
	user_db.delete_one({"username": session['username']})
	flow_db = cluster['FlowMaster']['flows']
	flow_db.delete_one({"username": session['username']})
	session.pop('username')
	session.pop('logged_in')

	# except:
	# 	return redirect('https://flowmaster.mythify.repl.co/')
	return redirect('https://flowmaster.mythify.repl.co/')


# @app.route("/flows", methods = ["POST", "GET"])
# def flows():
# 	try:
# 		session['count']
# 	except KeyError:
# 		session['count'] = 1
# 	global count
# 	if request.method == 'POST':
# 		if 'add' in request.form:
# 			val = session['count'] + 1
# 			session['count']=val
# 		if 'remove' in request.form:
# 			session['count']-=1
# 	return render_template("flows.html", e=session['count'], logged_in=session['logged_in'])

@app.route("/flows", methods=["POST", "GET"])
def flows():

	
	cluster = pymongo.MongoClient(os.environ['MONGO_URI'])
	flow_db = cluster['FlowMaster']['flows']
	userFlowData = flow_db.find_one({"username": session['username']})
	flowCount = userFlowData['count']
	flowList = []
	for flow in userFlowData:
		if flow not in ['count', 'username', 'lower_username', '_id']:
			flowList.append(flow)
	flows = {}
	for flow in flowList:
		flows[flow] = userFlowData[flow]


		
	if request.method == 'POST':
		cluster = pymongo.MongoClient(os.environ['MONGO_URI'])

		if 'flowadd' in list(request.form):
			flow_db = cluster['FlowMaster']['flows']
			flow_db.update_one({"username": session['username']},
							   {"$set": {
								"count": flowCount + 1
							   }})
			# flowsDict = {f"Flow{flowCount+1}": []}
			# flow_db.insert_one(flowsDict)
			flow_db.update_one({"username": session['username']},
							   {"$set": {
								f"Flow{flowCount+1}": []
							   }})
			cluster = pymongo.MongoClient(os.environ['MONGO_URI'])
			flow_db = cluster['FlowMaster']['flows']
			userFlowData = flow_db.find_one({"username": session['username']})
		if 'url' in list(request.form):
			data = list(request.form)
			cutData = data[1][0:len(data[1]) - 7]
			print(cutData)
			flow_db = cluster['FlowMaster']['flows']
			flowData = flow_db.find_one({"username": session['username']})
			print(flowData)
			print("\n\n\n\n\n\n")
			flowList = flowData[cutData]
			flowList.append(request.form['url'])
			print(flowData)
			print("\n\n\n\n\n\n")
			flow_db.update_one({"username": session['username']},
							   {"$set": {
								f"{cutData}": flowList
							   }})

			
	cluster = pymongo.MongoClient(os.environ['MONGO_URI'])
	flow_db = cluster['FlowMaster']['flows']
	userFlowData = flow_db.find_one({"username": session['username']})
	flowCount = userFlowData['count']
	flowList = []
	for flow in userFlowData:
		if flow not in ['count', 'username', 'lower_username', '_id']:
			flowList.append(flow)
	flows = {}
	for flow in flowList:
		flows[flow] = userFlowData[flow]

	
	return render_template("flows.html",
						   logged_in=session['logged_in'],
						   flows=flows)


if __name__ == "__main__":
	app.run(host='0.0.0.0', port=8080, debug=True)
