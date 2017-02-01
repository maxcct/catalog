from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session as login_session, make_response
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Base, User, Restaurant, MenuItem
import random, string
from oauth2client.client import flow_from_clientsecrets, FlowExchangeError
import httplib2
import json
import requests
# from gconnect import gconnect, gdisconnect

app = Flask(__name__)

engine = create_engine('sqlite:///restaurantmenuwithusers.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()

# Client ID: 361791903681-kdk05q35lqdrsq996clbi1g4lhl8v6pn.apps.googleusercontent.com
# Client secret: eya2Op5nmrHq59cGtnzxMTLM
CLIENT_ID = json.loads(
	open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Restaurant Menu App"


@app.route('/')
@app.route('/restaurants/')
def restaurants():
	try:
		user_id = login_session['user_id']
	except:
		user_id = None
	restaurants = session.query(Restaurant).all()
	return render_template('restaurants.html', restaurants=restaurants,
						   user_id=user_id)


@app.route('/login')
def login():
	state = ''.join(random.choice(string.ascii_uppercase + string.digits)
		for x in xrange(32))
	login_session['state'] = state
	return render_template('login.html', STATE=state)


@app.route('/logout')
def logout():
	if 'provider' in login_session:
		if login_session['provider'] == 'google':
			gdisconnect()
			del login_session['gplus_id']
			del login_session['credentials']
		if login_session['provider'] == 'facebook':
			fbdisconnect()
			del login_session['facebook_id']
		del login_session['username']
		del login_session['email']
		del login_session['picture']
		del login_session['user_id']
		del login_session['provider']
		flash("You have logged out successfully")
		return redirect('/restaurants')
	else:
		flash("You were not logged in")
		return redirect('/restaurants')


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
		oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
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

	
# DISCONNECT - Revoke a current user's token and reset their login_session
@app.route('/gdisconnect')
def gdisconnect():
	# Only disconnect a connected user.
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


@app.route('/restaurant/<int:restaurant_id>/')
@app.route('/restaurant/<int:restaurant_id>/menu/')
def restaurant_menu(restaurant_id):
	restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
	owner = get_user_info(restaurant.user_id)
	try:
		if owner.id == login_session['user_id']:
			show_restricted = True
		else:
			show_restricted = False
	except:
		show_restricted = False
	items = session.query(MenuItem).filter_by(restaurant_id=restaurant.id).all()
	starters = [i for i in items if i.course == 'Starter' or
				i.course == 'Appetizer']
	mains = [i for i in items if i.course == 'Main' or
			 i.course == 'Main Course' or i.course == 'Entree']
	desserts = [i for i in items if i.course == 'Dessert']
	drinks = [i for i in items if i.course == 'Drink' or i.course == 'Beverage']
	return render_template('menu.html', restaurant=restaurant, items=items,
						   starters=starters, mains=mains, desserts=desserts,
						   drinks=drinks, owner=owner,
						   show_restricted=show_restricted)


@app.route('/restaurant/<int:restaurant_id>/menu/new/', methods=['GET', 'POST'])
def new_menu_item(restaurant_id):
	restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
	if login_session['user_id']:
		if restaurant.user_id != login_session['user_id']:
			flash("Only the owner of this restaurant can add menu items!")
			return redirect('/restaurants')
	else:
		flash("You must be logged in to add menu items!")
		return redirect('/login')
	if request.method == 'POST':
		new_item = MenuItem(name=request.form['name'],
							description=request.form['description'],
							price=request.form['price'],
							course=request.form['course'],
							restaurant_id=restaurant_id,
							user_id=restaurant.user_id)
		session.add(new_item)
		flash("New menu item successfully created!")
		session.commit()
		return redirect(url_for('restaurant_menu',
								restaurant_id=restaurant_id))
	else:
		return render_template('newmenuitem.html', restaurant_id=restaurant_id)


@app.route('/restaurant/<int:restaurant_id>/menu/<int:menu_id>/edit/',
		   methods=['GET', 'POST'])
def edit_menu_item(restaurant_id, menu_id):
	restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
	if login_session['user_id']:
		if restaurant.user_id != login_session['user_id']:
			flash("Only the owner of this restaurant can edit menu items!")
			return redirect('/restaurants')
	else:
		flash("You must be logged in to edit menu items!")
		return redirect('/login')
	item_to_edit = session.query(MenuItem).filter_by(id=menu_id).one()
	if request.method == 'POST':
		if request.form['name'] != item_to_edit.name:
			item_to_edit.name = request.form['name']
		if request.form['description'] != item_to_edit.description:
			item_to_edit.description = request.form['description']
		if request.form['price'] != item_to_edit.price:
			item_to_edit.price = request.form['price']
		if request.form['course'] != item_to_edit.course:
			item_to_edit.course = request.form['course']
		session.add(item_to_edit)
		session.commit()		
		flash("Menu item successfully edited!")
		return redirect(url_for('restaurant_menu',
								restaurant_id=restaurant_id))
	else:
		return render_template('editmenuitem.html', item=item_to_edit,
							   restaurant_id=restaurant_id, menu_id=menu_id)


@app.route('/restaurant/<int:restaurant_id>/menu/<int:menu_id>/delete/',
		   methods=['GET', 'POST'])
def delete_menu_item(restaurant_id, menu_id):
	restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
	if login_session['user_id']:
		if restaurant.user_id != login_session['user_id']:
			flash("Only the owner of this restaurant can delete menu items!")
			return redirect('/restaurants')
	else:
		flash("You must be logged in to delete menu items!")
		return redirect('/login')
	item_to_delete = session.query(MenuItem).filter_by(id=menu_id).one()
	if request.method == 'POST':
		session.delete(item_to_delete)
		session.commit()		
		flash("Menu item successfully deleted!")
		return redirect(url_for('restaurant_menu',
								restaurant_id=restaurant_id))
	else:
		return render_template('deletemenuitem.html', item=item_to_delete,
							   restaurant_id=restaurant_id, menu_id=menu_id)


@app.route('/restaurant/new/', methods=['GET', 'POST'])
def new_restaurant():
	if 'username' not in login_session:
		flash("You must be logged in to create new restaurants!")
		return redirect('/login')
	if request.method == 'POST':
		new_rstrt = Restaurant(name=request.form['name'],
							   user_id=login_session['user_id'])
		session.add(new_rstrt)
		flash("New restaurant successfully created!")
		session.commit()
		return redirect('/restaurants')
	else:
		return render_template('newrestaurant.html')


@app.route('/restaurant/<int:restaurant_id>/edit/',
		   methods=['GET', 'POST'])
def edit_restaurant(restaurant_id):
	rstrt_to_edit = session.query(Restaurant).filter_by(id=restaurant_id).one()
	if login_session['user_id']:
		if rstrt_to_edit.user_id != login_session['user_id']:
			flash("Only the owner of this restaurant can add edit it!")
			return redirect('/restaurants')
	else:
		flash("You must be logged in to edit restaurants!")
		return redirect('/login')
	if request.method == 'POST':
		if request.form['name']:
			rstrt.name = request.form['name']
		session.add(rstrt_to_edit)
		session.commit()		
		flash("Restaurant successfully edited!")
		return redirect('/restaurants')
	else:
		return render_template('editrestaurant.html', r=rstrt_to_edit,
							   restaurant_id=restaurant_id)


@app.route('/restaurant/<int:restaurant_id>/delete/',
		   methods=['GET', 'POST'])
def delete_restaurant(restaurant_id):
	rstrt_to_delete = session.query(Restaurant).filter_by(id=restaurant_id).one()
	if login_session['user_id']:
		if rstrt_to_delete.user_id != login_session['user_id']:
			flash("Only the owner of this restaurant can delete it!")
			return redirect('/restaurants')
	else:
		flash("You must be logged in to delete restaurants!")
		return redirect('/login')
	if request.method == 'POST':
		session.delete(rstrt_to_delete)
		session.commit()		
		flash("Restaurant successfully deleted!")
		return redirect('/restaurants')
	else:
		return render_template('deleterestaurant.html', r=rstrt_to_delete,
							   restaurant_id=restaurant_id)


@app.route('/restaurants/JSON')
def restaurants_JSON():
	restaurants = session.query(Restaurant).all()
	return jsonify(Restaurants=[r.serialise for r in restaurants])


@app.route('/restaurant/<int:restaurant_id>/menu/JSON')
def restaurant_menu_JSON(restaurant_id):
	restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
	items = session.query(MenuItem).filter_by(restaurant_id=restaurant.id).all()
	return jsonify(MenuItems=[i.serialise for i in items])


@app.route('/restaurant/<int:restaurant_id>/menu/<int:menu_id>/JSON')
def menu_item_JSON(restaurant_id, menu_id):
	item = session.query(MenuItem).filter_by(id=menu_id).one()
	return jsonify(MenuItem=item.serialise)


def create_user(login_session):
	new_user = User(name=login_session['username'],
					email=login_session['email'],
					picture=login_session['picture'])
	session.add(new_user)
	session.commit()
	user = session.query(User).filter_by(email=login_session['email']).one()
	return user.id


def get_user_info(user_id):
	user = session.query(User).filter_by(id=user_id).one()
	return user


def get_user_id(email):
	try:
		user = session.query(User).filter_by(email=email).one()
		return user.id
	except:
		return None


if __name__ == '__main__':
	app.secret_key = 'super_secret_key'
	app.debug = True
	app.run(host='0.0.0.0', port=5000)
