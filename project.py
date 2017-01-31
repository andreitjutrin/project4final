from flask import Flask, render_template, request, redirect, jsonify, url_for, flash
from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
import json
# import database tables
from database_setup import Base, User, Category, Topic

#
# Oauth login required imports
#
from flask import session as login_session
import random, string
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
from flask import make_response
import requests

app = Flask(__name__)

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Relationship blog"
#
# create a connection to database
#
engine = create_engine('mysql://root:admin@localhost/marriedtochinese1', echo=True)
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()
#
# Json API to view blog details
#
@app.route('/categories/all/list/JSON')
def allTopicsJSON():
    topics = session.query(Topic).order_by(Topic.created_at).all()
    for topic in topics:
    	topic.created_at = str(topic.created_at)
    return jsonify(topic=[i.serialize for i in topics])

@app.route('/categories/JSON')
def allCategoriesJSON():
    categories = session.query(Category).all()
    return jsonify(category=[i.serialize for i in categories])

@app.route('/categories/<int:category_id>/JSON')
def categoriesJSON(category_id):
    chosen_category = session.query(Category).filter_by(id=category_id).one()
    return jsonify(chosen_category=chosen_category.serialize)

@app.route('/categories/<int:category_id>/list/<int:story_id>/JSON')
def topicsJSON(category_id, story_id):
    topic = session.query(Topic).filter_by(category_id=category_id).filter_by(
    	id=story_id).one()
    topic.created_at = str(topic.created_at)
    return jsonify(topic=topic.serialize)

########################################################################

# User Functions
def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id

def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user

def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None

# Create anti-forgery state token
@app.route('/login')
def showLogin():
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

    user_id = getUserID(login_session['email'])
    if not user_id:
    	user_id = createUser(login_session)

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

    # DISCONNECT - Revoke a current user's token and reset their login_session


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
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response

@app.route('/')
@app.route('/categories/')
def showCategories():
    topics = session.query(Topic).order_by(Topic.created_at).all()
    categories = session.query(Category).all()
    user_id = "0"
    if "email" in login_session:
        user_id = getUserID(login_session['email'])
        print "user id inside IF statement ......" , user_id
    print "USER ID outside of if statement...." , user_id
    return render_template('showCategories.html', topics=topics, categories=categories, user_id=user_id)
# Category: new ##############################################
#
@app.route('/categories/new', methods=['GET','POST'])
def newShowCategories():
	if 'username' not in login_session:
		return redirect('/login')
	if request.method == 'POST':
		name = request.form['name']
		description = request.form['description']
		user_id = getUserID(login_session['email'])
		newCategory = Category(name = name, description=description, user_id=user_id)
		session.add(newCategory)
		flash('New category [ %s ] successfully created!' % newCategory.name)
		session.commit()
		return redirect(url_for('showCategories'))
	else:
		return render_template('newShowCategories.html')
#
# Category: edit ##############################################`
#
@app.route('/categories/<int:category_id>/edit', methods=['GET','POST'])
def editShowCategories(category_id):
	chosen_category = session.query(Category).filter_by(id=category_id).one()
	creater_email = session.query(Category, User).join(User).filter(Category.user_id == User.id).group_by(User.id).one()
	if 'username' not in login_session:
		return redirect('/login')
	if creater_email[1].email == login_session['email']:
		if request.method == 'POST':
			chosen_category.name = request.form['name']
			chosen_category.description = request.form['description']
			session.add(chosen_category)
			flash('The category [ %s ] was successfully edited!' % chosen_category.name)
			session.commit()
			return redirect(url_for('showCategories'))
		else:
			return render_template('editShowCategories.html', chosen_category=chosen_category)
	else:
		return redirect('/login')


#
# Category: delete ##############################################
#
@app.route('/categories/<int:category_id>/delete', methods=['GET','POST'])
def deleteShowCategories(category_id):
	chosen_category = session.query(Category).filter_by(id=category_id).one()
	creater_email = session.query(Category, User).join(User).filter(Category.user_id == User.id).group_by(User.id).one()
	if 'username' not in login_session:
		return redirect('/login')
	if creater_email[1].email == login_session['email']:
		if request.method == 'POST':
			session.delete(chosen_category)
			flash('Chosen category was successfully deleted!')
			session.commit()
			return redirect(url_for('showCategories'))
		else:
			return render_template('deleteShowCategories.html', chosen_category=chosen_category)
	else:
		return redirect('/login')

#
# A list of articles in specific category ##############################################
#
@app.route('/categories/<int:category_id>/list/')
def Categories(category_id):
	topics = session.query(Topic).filter_by(category_id=category_id).order_by(Topic.created_at).all()
	categories = session.query(Category).filter(Category.id != category_id).all()
	chosen_category = session.query(Category).filter_by(id=category_id).one()
	user_id = ""
	if "email" in login_session:
		user_id = getUserID(login_session['email'])
	return render_template('category.html', topics=topics, categories=categories, chosen_category=chosen_category, user_id=user_id)
#
# Individual article: view ##############################################
#
@app.route('/categories/<int:category_id>/list/<int:story_id>/')
def Story(category_id, story_id):
	topic = session.query(Topic).filter_by(id=story_id).one()
	chosen_category = session.query(Category).filter_by(id=category_id).one()
	if "email" in login_session:
		user_id = getUserID(login_session['email'])
		if user_id == story_id:
			return render_template('story.html', topic=topic, chosen_category=chosen_category)
		return render_template('storyNoEdit.html', topic=topic, chosen_category=chosen_category)
	else:
		return render_template('storyNoEdit.html', topic=topic, chosen_category=chosen_category)
#
# Individual article: new ##############################################
#
@app.route('/categories/<int:category_id>/list/new', methods=['GET','POST'])
def NewStory(category_id):
	chosen_category = session.query(Category).filter_by(id=category_id).one()
	if 'username' not in login_session:
		return redirect('/login')
	if request.method == 'POST':
		user_id = getUserID(login_session['email'])
		newTopic = Topic(title=request.form['title'], summary=request.form['summary'],
		content=request.form['content'], category_id=category_id, user_id=user_id)
		session.add(newTopic)
		flash('New topic [ %s ] successfully created!' % newTopic.title)
		session.commit()
		return redirect(url_for('Categories', category_id=category_id))
	else:
		return render_template('newShowTopics.html')

#
# Individual article: edit ##############################################
#
@app.route('/categories/<int:category_id>/list/<int:story_id>/edit', methods=['GET','POST'])
def editStory(category_id, story_id):
	topic = session.query(Topic).filter_by(id=story_id).one()
	chosen_category = session.query(Category).filter_by(id=category_id).one()
	creater_email = session.query(Category, User).join(User).filter(Category.user_id == User.id).group_by(User.id).one()
	if 'username' not in login_session:
		return redirect('/login')
	if creater_email[1].email == login_session['email']:
		if request.method == 'POST':
			topic.title = request.form['title']
			topic.summary = request.form['summary']
			topic.content = request.form['content']
			session.add(topic)
			flash('The topic [ %s ] was successfully edited!' % topic.title)
			session.commit()
			return redirect(url_for('Categories', category_id=category_id))
		else:
			return render_template('editShowTopics.html', topic=topic, chosen_category=chosen_category) 
	else:
		return redirect('/login')
#
# Individual article: delete ##############################################
#
@app.route('/categories/<int:category_id>/list/<int:story_id>/delete', methods=['GET','POST'])
def deleteStory(category_id, story_id):
	topic = session.query(Topic).filter_by(id=story_id).one()
	chosen_category = session.query(Category).filter_by(id=category_id).one()
	creater_email = session.query(Category, User).join(User).filter(Category.user_id == User.id).one()
	if 'username' not in login_session:
		return redirect('/login')
	if creater_email[1].email == login_session['email']:
		if request.method == 'POST':
			session.delete(topic)
			flash('The topic was successfully deleted!')
			session.commit()
			return redirect(url_for('Categories', category_id=category_id))
		else:
			return render_template('deleteShowTopics.html', topic=topic, chosen_category=chosen_category)
	else:
		return redirect('/login')

if __name__ == '__main__':
  app.secret_key = 'some_secret'
  app.debug = True
  app.run(host = '0.0.0.0', port = 11000)
