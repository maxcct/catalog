from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Restaurant, MenuItem

app = Flask(__name__)

engine = create_engine('sqlite:///restaurantmenu.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()


@app.route('/')
@app.route('/restaurants/')
def restaurants():
	restaurants = session.query(Restaurant).all()
	return render_template('restaurants.html', restaurants=restaurants)


@app.route('/restaurants/<int:restaurant_id>/')
def restaurant_menu(restaurant_id):
	restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
	items = session.query(MenuItem).filter_by(restaurant_id=restaurant.id).all()
	return render_template('menu.html', restaurant=restaurant, items=items)


@app.route('/restaurants/<int:restaurant_id>/new/', methods=['GET', 'POST'])
def new_menu_item(restaurant_id):
	if request.method == 'POST':
		new_item = MenuItem(name=request.form['name'],
							description=request.form['description'],
							price=request.form['price'],
							restaurant_id=restaurant_id)
		session.add(new_item)
		flash("New menu item successfully created!")
		session.commit()
		return redirect(url_for('restaurant_menu',
								restaurant_id=restaurant_id))
	else:
		return render_template('newmenuitem.html', restaurant_id=restaurant_id)


@app.route('/restaurants/<int:restaurant_id>/<int:menu_id>/edit/',
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
		session.add(item_to_edit)
		session.commit()		
		flash("Menu item successfully edited!")
		return redirect(url_for('restaurant_menu',
								restaurant_id=restaurant_id))
	else:
		return render_template('editmenuitem.html', item=item_to_edit,
							   restaurant_id=restaurant_id, menu_id=menu_id)


@app.route('/restaurants/<int:restaurant_id>/<int:menu_id>/delete/',
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


@app.route('/restaurants/new/', methods=['GET', 'POST'])
def new_restaurant():
	if request.method == 'POST':
		new_rstrt = Restaurant(name=request.form['name'])
		session.add(new_rstrt)
		flash("New restaurant successfully created!")
		session.commit()
		return redirect(url_for('restaurants'))
	else:
		return render_template('newrestaurant.html')


@app.route('/restaurants/<int:restaurant_id>/edit/',
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


@app.route('/restaurants/<int:restaurant_id>/delete/',
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


@app.route('/restaurants/<int:restaurant_id>/menu/JSON')
def restaurant_menu_JSON(restaurant_id):
	restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
	items = session.query(MenuItem).filter_by(restaurant_id=restaurant.id).all()
	return jsonify(MenuItems=[i.serialise for i in items])


@app.route('/restaurants/<int:restaurant_id>/menu/<int:menu_id>/JSON')
def menu_item_JSON(restaurant_id, menu_id):
	item = session.query(MenuItem).filter_by(id=menu_id).one()
	return jsonify(MenuItem=item.serialise)


if __name__ == '__main__':
	app.secret_key = 'super_secret_key'
	app.debug = True
	app.run(host='0.0.0.0', port=5000)
