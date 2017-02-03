from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session as login_session, make_response, g
from functools import wraps
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Base, User, Category, NGO
import random, string
from oauth2client.client import flow_from_clientsecrets, FlowExchangeError
import httplib2
import json
import requests
from flask.ext.seasurf import SeaSurf

app = Flask(__name__)
csrf = SeaSurf(app) # Protects CRUD operations against CSRF attacks

engine = create_engine('sqlite:///ngosandusers.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()

CLIENT_ID = json.loads(
	open('g_client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "NGO Emporium"


@app.route('/')
@app.route('/categories/')
def categories():
	"""
	Displays a page listing all categories
	"""
	try:
		user_id = login_session['user_id']
	except:
		user_id = None
	categories = session.query(Category).all()
	return render_template('categories.html', categories=categories,
						   user_id=user_id)


def login_required(f):
    @wraps(f)
    def protected_function(*args, **kwargs):
        if 'user_id' in login_session:
        	return f(*args, **kwargs)
        flash("You must be logged in to access that page!")
        return redirect('/login')
    return protected_function


@app.route('/login')
def login():
	"""
	Displays log-in page, and generates a random 32 character string for
	authentication purposes
	"""
	state = ''.join(random.choice(string.ascii_uppercase + string.digits)
		for x in xrange(32))
	login_session['state'] = state
	return render_template('login.html', STATE=state)


@app.route('/logout')
def logout():
	"""
	Logs the current user out and wipes the login_session dictionary
	"""
	if 'provider' in login_session:
		if login_session['provider'] == 'google':
			gdisconnect()
			del login_session['gplus_id']
			del login_session['access_token']
		if login_session['provider'] == 'facebook':
			fbdisconnect()
			del login_session['facebook_id']
		del login_session['username']
		del login_session['email']
		del login_session['picture']
		del login_session['user_id']
		del login_session['provider']
		del login_session['_csrf_token']
		flash("You have logged out successfully")
		return redirect('/categories')
	else:
		flash("You were not logged in")
		return redirect('/categories')


@csrf.exempt
@app.route('/fbconnect', methods=['POST'])
def fbconnect():
	if request.args.get('state') != login_session['state']:
		response = make_response(json.dumps('Invalid state parameter.'), 401)
		response.headers['Content-Type'] = 'application/json'
		return response
	access_token = request.data
	print "access token received %s " % access_token

	app_id = json.loads(open('fb_client_secrets.json', 'r').read())[
		'web']['app_id']
	app_secret = json.loads(
		open('fb_client_secrets.json', 'r').read())['web']['app_secret']
	url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s' % (
		app_id, app_secret, access_token)
	h = httplib2.Http()
	result = h.request(url, 'GET')[1]

	# Use token to get user info from API
	userinfo_url = "https://graph.facebook.com/v2.4/me"
	# strip expire tag from access token
	token = result.split("&")[0]

	url = 'https://graph.facebook.com/v2.4/me?%s&fields=name,id,email' % token
	h = httplib2.Http()
	result = h.request(url, 'GET')[1]
	# print "url sent for API access:%s"% url
	# print "API JSON result: %s" % result
	data = json.loads(result)
	login_session['provider'] = 'facebook'
	login_session['username'] = data["name"]
	login_session['email'] = data["email"]
	login_session['facebook_id'] = data["id"]

	# The token must be stored in the login_session in order to properly logout, let's strip out the information before the equals sign in our token
	stored_token = token.split("=")[1]
	login_session['access_token'] = stored_token

	# Get user picture
	url = 'https://graph.facebook.com/v2.4/me/picture?%s&redirect=0&height=200&width=200' % token
	h = httplib2.Http()
	result = h.request(url, 'GET')[1]
	data = json.loads(result)

	login_session['picture'] = data["data"]["url"]

	# see if user exists
	user_id = get_user_id(login_session['email'])
	if not user_id:
		user_id = create_user(login_session)
	login_session['user_id'] = user_id

	output = ''
	output += '<h1>Welcome, '
	output += login_session['username']
	output += '!</h1>'
	output += '<img src="'
	output += login_session['picture']
	output += '" style="display: block; margin: 0 auto; width: 300px; height: 300px; border-radius: 150px; -webkit-border-radius: 150px; -moz-border-radius: 150px;">'
	flash("Now logged in as %s" % login_session['username'])
	return output


@app.route('/fbdisconnect')
def fbdisconnect():
	facebook_id = login_session['facebook_id']
	# The access token must be included to successfully logout
	access_token = login_session['access_token']
	url = 'https://graph.facebook.com/%s/permissions?access_token=%s' % (facebook_id,access_token)
	h = httplib2.Http()
	result = h.request(url, 'DELETE')[1]
	return "You have been logged out"


@csrf.exempt
@app.route('/gconnect', methods=['POST'])
def gconnect():
	# Validate state token
	if request.args.get('state') != login_session['state']:
		response = make_response(json.dumps('Invalid state parameter.'), 401)
		response.headers['Content-Type'] = 'application/json'
		return response
	# Obtain authorization code
	code = request.data

	try:
		# Upgrade the authorization code into a credentials object
		oauth_flow = flow_from_clientsecrets('g_client_secrets.json', scope='')
		oauth_flow.redirect_uri = 'postmessage'
		credentials = oauth_flow.step2_exchange(code)
	except FlowExchangeError:
		response = make_response(
			json.dumps('Failed to upgrade the authorization code.'), 401)
		response.headers['Content-Type'] = 'application/json'
		return response

	# Check that the access token is valid.
	access_token = credentials.access_token
	url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
		   % access_token)
	h = httplib2.Http()
	result = json.loads(h.request(url, 'GET')[1])
	# If there was an error in the access token info, abort.
	if result.get('error') is not None:
		response = make_response(json.dumps(result.get('error')), 500)
		response.headers['Content-Type'] = 'application/json'
		return response

	# Verify that the access token is used for the intended user.
	gplus_id = credentials.id_token['sub']
	if result['user_id'] != gplus_id:
		response = make_response(
			json.dumps("Token's user ID doesn't match given user ID."), 401)
		response.headers['Content-Type'] = 'application/json'
		return response

	# Verify that the access token is valid for this app.
	if result['issued_to'] != CLIENT_ID:
		response = make_response(
			json.dumps("Token's client ID does not match app's."), 401)
		print "Token's client ID does not match app's."
		response.headers['Content-Type'] = 'application/json'
		return response

	stored_access_token = login_session.get('access_token')
	stored_gplus_id = login_session.get('gplus_id')
	if stored_access_token is not None and gplus_id == stored_gplus_id:
		response = make_response(json.dumps('Current user is already connected.'),
								 200)
		response.headers['Content-Type'] = 'application/json'
		return response

	# Store the access token in the session for later use.
	login_session['access_token'] = credentials.access_token
	login_session['gplus_id'] = gplus_id

	# Get user info
	userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
	params = {'access_token': credentials.access_token, 'alt': 'json'}
	answer = requests.get(userinfo_url, params=params)

	data = answer.json()

	login_session['username'] = data['name']
	login_session['picture'] = data['picture']
	login_session['email'] = data['email']
	# ADD PROVIDER TO LOGIN SESSION
	login_session['provider'] = 'google'

	user_id = get_user_id(login_session['email'])
	if not user_id:
		user_id = create_user(login_session)
	login_session['user_id'] = user_id

	output = ''
	output += '<h1>Welcome, '
	output += login_session['username']
	output += '!</h1>'
	output += '<img src="'
	output += login_session['picture']
	output += '" style="display: block; margin: 0 auto; width: 300px; height: 300px; border-radius: 150px; -webkit-border-radius: 150px; -moz-border-radius: 150px;">'
	flash("You are now logged in as %s" % login_session['username'])
	print "Done!"
	return output


@app.route('/gdisconnect')
def gdisconnect():
	"""
	Revokes a current user's token
	"""
	credentials = login_session.get('credentials')
	if credentials is None:
		response = make_response(
			json.dumps('Current user not connected.'), 401)
		response.headers['Content-Type'] = 'application/json'
		return response
	access_token = credentials.access_token
	url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
	h = httplib2.Http()
	result = h.request(url, 'GET')[0]
	if result['status'] != '200':
		# For whatever reason, the given token was invalid.
		response = make_response(
			json.dumps('Failed to revoke token for given user.'), 400)
		response.headers['Content-Type'] = 'application/json'
		return response


@app.route('/<category_name>/<int:category_id>/')
@app.route('/<category_name>/<int:category_id>/ngos/')
def show_ngos(category_name, category_id):
	"""
	Displays a page listing all NGOs in a given category. Groups the NGOs by
	continent so that NGOs from the same continent can be displayed together.
	"""
	category = session.query(Category).filter_by(id=category_id).one()
	admin = get_user_info(category.user_id)
	try:
		if admin.id == login_session['user_id']:
			show_restricted = True
		else:
			show_restricted = False
	except:
		show_restricted = False
	ngos = session.query(NGO).filter_by(category_id=category.id).all()
	africa = [n for n in ngos if n.continent == 'Africa']
	antarctica = [n for n in ngos if n.continent == 'Antarctica']
	asia = [n for n in ngos if n.continent == 'Asia']
	australia = [n for n in ngos if n.continent == 'Australia']
	europe = [n for n in ngos if n.continent == 'Europe']
	north_america = [n for n in ngos if n.continent == 'North America']
	south_america = [n for n in ngos if n.continent == 'South America']
	worldwide = [n for n in ngos if n.continent == 'Worldwide']
	return render_template('ngos.html', category_name=category_name,
						   category_id=category_id, admin=admin, ngos=ngos,
						   africa=africa, antarctica=antarctica, asia=asia,
						   australia=australia, europe=europe,
						   north_america=north_america,
						   south_america=south_america, worldwide=worldwide,
						   show_restricted=show_restricted)


@app.route('/ngos/')
@app.route('/ngos/all/')
def show_all_ngos():
	"""
	Displays a page listing all NGOs
	"""
	try:
		user_id = login_session['user_id']
	except:
		user_id = None
	ngos = session.query(NGO).all()
	return render_template('allngos.html', ngos=ngos,
						   user_id=user_id)


@app.route('/<category_name>/<int:category_id>/ngo/new/',
		   methods=['GET', 'POST'])
@login_required
def new_ngo(category_name, category_id):
	"""
	Displays page for creating a new NGO
	"""
	category = session.query(Category).filter_by(id=category_id).one()
	if category.user_id != login_session['user_id']:
		flash("Only the admin of this category can add NGOs to it!")
		return redirect('/categories')
	if request.method == 'POST':
		new_item = NGO(name=request.form['name'],
					   focus=request.form['focus'],
					   founded=request.form['founded'],
					   website=request.form['website'],
					   logo=request.form['logo'],
					   continent=request.form['continent'],
					   category_id=category.id,
					   user_id=category.user_id)
		session.add(new_item)
		flash("New NGO successfully created!")
		session.commit()
		return redirect(url_for('show_ngos', category_name=category_name,
								category_id=category_id))
	else:
		return render_template('newngo.html', category_name=category_name,
								category_id=category_id)


@app.route('/<category_name>/<int:category_id>/ngo/<int:ngo_id>/edit/',
		   methods=['GET', 'POST'])
@login_required
def edit_ngo(category_name, category_id, ngo_id):
	"""
	Displays page for editing an NGO
	"""
	category = session.query(Category).filter_by(id=category_id).one()
	if category.user_id != login_session['user_id']:
		flash("Only the admin of this category can edit its NGOs!")
		return redirect('/categories')
	ngo_to_edit = session.query(NGO).filter_by(id=ngo_id).one()
	if request.method == 'POST':
		if request.form['name'] != ngo_to_edit.name:
			ngo_to_edit.name = request.form['name']
		if request.form['focus'] != ngo_to_edit.focus:
			ngo_to_edit.focus = request.form['focus']
		if request.form['founded'] != ngo_to_edit.founded:
			ngo_to_edit.founded = request.form['founded']
		if request.form['website'] != ngo_to_edit.website:
			ngo_to_edit.website = request.form['website']
		if request.form['logo'] != ngo_to_edit.logo:
			ngo_to_edit.logo = request.form['logo']
		if request.form['continent'] != ngo_to_edit.continent:
			ngo_to_edit.continent = request.form['continent']
		session.add(ngo_to_edit)
		session.commit()
		flash("NGO successfully edited!")
		return redirect(url_for('show_ngos', category_name=category_name,
								category_id=category_id))
	else:
		return render_template('editngo.html', category_name=category_name,
							   ngo=ngo_to_edit, category_id=category_id,
							   ngo_id=ngo_id)


@app.route('/<category_name>/<int:category_id>/ngo/<int:ngo_id>/delete/',
		   methods=['GET', 'POST'])
@login_required
def delete_ngo(category_name, category_id, ngo_id):
	"""
	Displays page for deleting an NGO
	"""
	category = session.query(Category).filter_by(id=category_id).one()
	if category.user_id != login_session['user_id']:
		flash("Only the admin of this category can delete its NGOs!")
		return redirect('/categories')
	ngo_to_delete = session.query(NGO).filter_by(id=ngo_id).one()
	if request.method == 'POST':
		session.delete(ngo_to_delete)
		session.commit()		
		flash("NGO successfully deleted!")
		return redirect(url_for('show_ngos', category_name=category_name,
								category_id=category_id))
	else:
		return render_template('deletengo.html', category_name=category_name,
							   ngo=ngo_to_delete, category_id=category_id,
							   ngo_id=ngo_id)


@app.route('/categories/new/', methods=['GET', 'POST'])
@login_required
def new_category():
	"""
	Displays page for creating an new category
	"""
	if request.method == 'POST':
		new_category = Category(name=request.form['name'],
							   user_id=login_session['user_id'])
		session.add(new_category)
		flash("New category successfully created!")
		session.commit()
		return redirect('/categories')
	else:
		return render_template('newcategory.html')


@app.route('/<category_name>/<int:category_id>/edit/',
		   methods=['GET', 'POST'])
@login_required
def edit_category(category_name, category_id):
	"""
	Displays page for editing a category
	"""
	ctgry_to_edit = session.query(Category).filter_by(id=category_id).one()
	if ctgry_to_edit.user_id != login_session['user_id']:
		flash("Only the admin of this category can add edit it!")
		return redirect('/categories')
	if request.method == 'POST':
		if request.form['name']:
			ctgry_to_edit.name = request.form['name']
		session.add(ctgry_to_edit)
		session.commit()		
		flash("Category successfully edited!")
		return redirect('/categories')
	else:
		return render_template('editcategory.html',
							   category_name=category_name,
							   c=ctgry_to_edit, category_id=category_id)


@app.route('/<category_name>/<int:category_id>/delete/',
		   methods=['GET', 'POST'])
@login_required
def delete_category(category_name, category_id):
	"""
	Displays page for deleting a category
	"""
	ctgry_to_delete = session.query(Category).filter_by(id=category_id).one()
	if ctgry_to_delete.user_id != login_session['user_id']:
		flash("Only the admin of this category can delete it!")
		return redirect('/categories')
	if request.method == 'POST':
		session.delete(ctgry_to_delete)
		session.commit()		
		flash("Category successfully deleted!")
		return redirect('/categories')
	else:
		return render_template('deletecategory.html',
							   category_name=category_name,
							   category_id=category_id, c=ctgry_to_delete)


@app.route('/categories/JSON')
def categories_JSON():
	"""
	JSON endpoint for all categories
	"""
	categories = session.query(Category).all()
	return jsonify(Categories=[c.serialise for c in categories])


@app.route('/categories/ngos/JSON')
def ngos_JSON():
	"""
	JSON endpoint for all ngos
	"""
	ngos = session.query(NGO).all()
	return jsonify(NGOs=[n.serialise for n in ngos])


@app.route('/<category_name>/<int:category_id>/ngos/JSON')
def ngos_by_category_JSON(category_name, category_id):
	"""
	JSON endpoint for all ngos in a given category
	"""
	category = session.query(Category).filter_by(id=category_id).one()
	ngos = session.query(NGO).filter_by(category_id=category.id).all()
	return jsonify(NGOs=[n.serialise for n in ngos])


@app.route('/<category_name>/<int:category_id>/<ngo_name>/<int:ngo_id>/JSON')
def ngo_JSON(category_name, category_id, ngo_name, ngo_id):
	"""
	JSON endpoint for an individual NGO
	"""
	ngo = session.query(NGO).filter_by(id=ngo_id).one()
	return jsonify(NGO=ngo.serialise)


def create_user(login_session):
	"""
	Creates new user in database if a user is logging in for the first time.
	Returns id of the new user entry.
	"""
	new_user = User(name=login_session['username'],
					email=login_session['email'],
					picture=login_session['picture'])
	session.add(new_user)
	session.commit()
	user = session.query(User).filter_by(email=login_session['email']).one()
	return user.id


def get_user_info(user_id):
	"""
	Takes a user id as arg and returns complete user object.
	"""
	user = session.query(User).filter_by(id=user_id).one()
	return user


def get_user_id(email):
	"""
	Takes email address as arg and returns id of corresponding user if they
	exist; otherwise returns None
	"""
	try:
		user = session.query(User).filter_by(email=email).one()
		return user.id
	except:
		return None


if __name__ == '__main__':
	app.secret_key = 'super_secret_key'
	app.debug = True
	app.run(host='0.0.0.0', port=5000)
