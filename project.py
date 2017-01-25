from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session as login_session, make_response
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Restaurant, MenuItem
import random, string
from oauth2client.client import flow_from_clientsecrets, FlowExchangeError
import httplib2
import json
import requests
# from gconnect import gconnect, gdisconnect

app = Flask(__name__)

engine = create_engine('sqlite:///restaurantmenu.db')
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
	restaurants = session.query(Restaurant).all()
	return render_template('restaurants.html', restaurants=restaurants)


@app.route('/login')
def show_login():
	state = ''.join(random.choice(string.ascii_uppercase + string.digits)
		for x in xrange(32))
	login_session['state'] = state
	return render_template('login.html', STATE=state)


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

    stored_credentials = login_session.get('credentials')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_credentials is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['credentials'] = credentials
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    login_session['location'] = data['locale']

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    return output


@app.route('/gdisconnect')
def gdisconnect():
    access_token = login_session['access_token']
    print 'In gdisconnect access token is %s', access_token
    print 'User name is: ' 
    print login_session['username']
    if access_token is None:
        print 'Access Token is None'
        response = make_response(json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % login_session['access_token']
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    print 'result is '
    print result
    if result['status'] == '200':
        del login_session['access_token'] 
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['location']
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
    
        response = make_response(json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


@app.route('/restaurant/<int:restaurant_id>/')
@app.route('/restaurant/<int:restaurant_id>/menu/')
def restaurant_menu(restaurant_id):
	restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
	items = session.query(MenuItem).filter_by(restaurant_id=restaurant.id).all()
	starters = [i for i in items if i.course == 'Starter' or i.course == 'Appetizer']
	mains = [i for i in items if i.course == 'Main' or i.course == 'Entree']
	desserts = [i for i in items if i.course == 'Dessert']
	drinks = [i for i in items if i.course == 'Drink' or i.course == 'Beverage']
	return render_template('menu.html', restaurant=restaurant, items=items,
						   starters=starters, mains=mains, desserts=desserts,
						   drinks=drinks)


@app.route('/restaurant/<int:restaurant_id>/menu/new/', methods=['GET', 'POST'])
def new_menu_item(restaurant_id):
	if request.method == 'POST':
		new_item = MenuItem(name=request.form['name'],
							description=request.form['description'],
							price=request.form['price'],
							course=request.form['course'],
							restaurant_id=restaurant_id)
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
	if request.method == 'POST':
		new_rstrt = Restaurant(name=request.form['name'])
		session.add(new_rstrt)
		flash("New restaurant successfully created!")
		session.commit()
		return redirect(url_for('restaurants'))
	else:
		return render_template('newrestaurant.html')


@app.route('/restaurant/<int:restaurant_id>/edit/',
		   methods=['GET', 'POST'])
def edit_restaurant(restaurant_id):
	rstrt_to_edit = session.query(Restaurant).filter_by(id=restaurant_id).one()
	if request.method == 'POST':
		if request.form['name']:
			rstrt.name = request.form['name']
		session.add(rstrt_to_edit)
		session.commit()		
		flash("Restaurant successfully edited!")
		return redirect(url_for('restaurants'))
	else:
		return render_template('editrestaurant.html', r=rstrt_to_edit,
							   restaurant_id=restaurant_id)


@app.route('/restaurant/<int:restaurant_id>/delete/',
		   methods=['GET', 'POST'])
def delete_restaurant(restaurant_id):
	rstrt_to_delete = session.query(Restaurant).filter_by(id=restaurant_id).one()
	if request.method == 'POST':
		session.delete(rstrt_to_delete)
		session.commit()		
		flash("Restaurant successfully deleted!")
		return redirect(url_for('restaurants'))
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


if __name__ == '__main__':
	app.secret_key = 'super_secret_key'
	app.debug = True
	app.run(host='0.0.0.0', port=5000)
