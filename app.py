from flask import Flask, render_template, request, url_for, flash, redirect, session, g
from flask_session import Session
from tempfile import mkdtemp
import sqlite3 as sql
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
import random, string, os
from datetime import date
import pandas as pd
import datetime

app = Flask(__name__)

#use random chars to make this secure
size = 100
cookiemonster = ''.join(random.choices(string.ascii_uppercase + string.ascii_lowercase + string.punctuation + string.hexdigits + string.digits, k = size))
app.secret_key = cookiemonster

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
app.config['UPLOAD_FOLDER'] = 'static/files'
app.config['USR_FOLDER'] = 'static/users'
Session(app)

@app.before_request
def before_request():
    g.user = None
    if 'user' in session:
        g.user = session['user']

@app.route("/login", methods=["GET", "POST"])
def login():

    # connection
    con = sql.connect('bcv.db')
    con.row_factory = sql.Row  
    cur = con.cursor()

    """Log user in"""

    # Forget any user_id
    session.clear()

    if request.method == "POST":
        session.pop('user', None)
        username = request.form['username']
        password = request.form['password']

        #user validation       
        if not username:
            flash('Username is required!')
        # Ensure password was submitted
        elif not password:
            flash("Must provide password!")

        #user verification
        UIDchk = cur.execute("SELECT user FROM users WHERE user = ?", (username,))
        for row in UIDchk:
            UIDchk = row[0]
        if UIDchk != username:
            flash("Your email doesn't seem to match our records. Please try again.")
            return render_template('login.html')
        #if user checks out, verify that password matches hash
        else:
            #create boolean to check password hash
            dbpass = cur.execute("""SELECT hash FROM users WHERE user = ?""", (username,))
            for row in dbpass:
                dbpass = row[0]       
            hashver = check_password_hash(dbpass, password)
        if hashver is False:
            flash('There was a problem with your password. Please try again.')
            return render_template('login.html')
        else:
            session['user'] = username
            return redirect('/profile')

    # make sure a long-in template is generated    
    else:
        usrpic = ''
        return render_template("login.html", usrpic = usrpic)


@app.route('/adminlogin')
@app.route('/bcvadmin')
@app.route("/bcvlogin", methods=["GET", "POST"])
def bcvlogin():

    # connection
    con = sql.connect('bcv.db')
    con.row_factory = sql.Row  
    cur = con.cursor()

    """Log user in"""

    # Forget any user_id
    session.clear()

    if request.method == "POST":
        session.pop('user', None)
        username = request.form['username']
        password = request.form['password']

        #user validation       
        if not username:
            flash('Username is required!')
        # Ensure password was submitted
        elif not password:
            flash("Must provide password!")

        #user verification
        UIDchk = cur.execute("SELECT user FROM users WHERE user = ?", (username,))
        for row in UIDchk:
            UIDchk = row[0]

        if UIDchk != username:
            flash("Your email doesn't seem to match our records. Please try again.")
            return render_template('bcvlogin.html')
        #if user checks out, verify that password matches hash
        else:
            #create boolean to check password hash
            dbpass = cur.execute("""SELECT hash FROM users WHERE user = ?""", (username,))
            for row in dbpass:
                dbpass = row[0]       
            hashver = check_password_hash(dbpass, password)
        if hashver is False:
            flash('There was a problem with your password. Please try again.')
            return render_template('bcvlogin.html')
        else:
            session['user'] = username
            return redirect('/publish')

    # make sure a long-in template is generated    
    else:
        return render_template("bcvlogin.html")

@app.route("/", methods=['GET', 'POST'])
def index():
    
    # connection
    con = sql.connect('bcv.db')
    con.row_factory = sql.Row  
    cursor = con.cursor()
    cursor.execute("SELECT * FROM inventory ORDER BY RANDOM() LIMIT 5")
    rnddig = cursor.fetchall()
    # profile picture
    usrpic = '' 
    if g.user:
        cursor.execute("SELECT photo FROM users WHERE user = ?", (g.user,))
        usrpic = cursor.fetchall()

    if request.method == 'POST':
        qry = request.form['qry']
        qry = qry.replace(' ', '%')
        qry = ('%' + qry + '%')

        cursor.execute("SELECT * FROM inventory WHERE artist LIKE ? OR album LIKE ? OR description LIKE ? OR media LIKE ? OR crateid LIKE ? OR condition LIKE ?", (qry, qry, qry, qry, qry, qry,))
        qryres = cursor.fetchall()
        
        return render_template("/search.html", usrpic = usrpic, rnddig = rnddig, qryres = qryres)
            
    return render_template("/index.html", usrpic = usrpic, rnddig = rnddig)

@app.route("/adminsearch", methods=['GET', 'POST'])
def adminsearch():
    
    # connection
    con = sql.connect('bcv.db')
    con.row_factory = sql.Row  
    cursor = con.cursor()
    # profile variable
    usrpic = ''

    if g.user:
        # CHECKPOINT FOR PRIVLEGES
        cursor.execute("SELECT * FROM users WHERE priv = 1 AND user = ?", (g.user,))
        chpnt = cursor.fetchall()
        if chpnt == []:
            flash("You're not supposed to be here buddy. :)")
            flash('If you think this was a mistake, please get in touch with your administrator.')
            return render_template("index.html")

        if request.method == 'POST':
            qry = request.form['qry']
            qry = qry.replace(' ', '%')
            qry = ('%' + qry + '%')
            cursor.execute("SELECT * FROM inventory WHERE artist LIKE ? OR album LIKE ? OR description LIKE ? OR media LIKE ? OR crateid LIKE ? OR condition LIKE ?", (qry, qry, qry, qry, qry, qry,))
            qryres = cursor.fetchall()

            return render_template("/cd", qryres = qryres)
            
        #return redirect("/bcvlogin")
    else:        
        flash('login required')
        return render_template("/bcvlogin.html")

@app.route("/profile", methods=["GET", "POST"])
def profile():
    
    # connection
    con = sql.connect('bcv.db')
    con.row_factory = sql.Row  
    cursor = con.cursor()
    cursor.execute("SELECT lyric FROM lyrics ORDER BY RANDOM() LIMIT 1")
    lyrics = cursor.fetchall()
    cursor.execute("SELECT * FROM users")

    # profile picture
    path = (app.config['USR_FOLDER'])
    usrpic = ''
    if g.user:

        cursor.execute("SELECT photo FROM users WHERE user = ?", (g.user,))
        usrpic = cursor.fetchall()

        cursor.execute("SELECT * FROM users WHERE user = ?", (g.user,))
        usrdeets = cursor.fetchall()
    
        if request.method == 'POST':
            bio = request.form['bio']
            name = request.form['name']
            con.execute("UPDATE users SET bio = ? WHERE user = ?", (bio, g.user,))
            con.execute("UPDATE users SET name = ? WHERE user = ?", (name, g.user,))
            con.commit()
            cursor.execute("SELECT * FROM users WHERE user = ?", (g.user,))
            usrdeets = cursor.fetchall()

        return render_template("profile.html", usrdeets = usrdeets, usrpic = usrpic, lyrics = lyrics)

    else:
        flash('login required')
        return render_template("/login.html", usrpic = usrpic)

@app.route("/add")
@app.route("/crateadd", methods=["GET", "POST"])
def crateadd():
    # connection
    con = sql.connect('bcv.db')
    con.row_factory = sql.Row  
    cursor = con.cursor()
    # profile pic
    usrpic = ''

    #check that session is set
    if g.user:
        # connection
        con = sql.connect('bcv.db')
        con.row_factory = sql.Row  
        cursor = con.cursor()
        if g.user:
            # CHECKPOINT FOR PRIVLEGES
            cursor.execute("SELECT * FROM users WHERE priv = 1 AND user = ?", (g.user,))
            chpnt = cursor.fetchall()
            if chpnt == []:
                flash("You're not supposed to be here buddy. :)")
                flash('If you think this was a mistake, please get in touch with your administrator.')
                return render_template("index.html")

        cursor.execute("SELECT * FROM inventory ORDER BY item DESC")
        rows = cursor.fetchall()
        # profile picture
        cursor.execute("SELECT photo FROM users WHERE user = ?", (g.user,))
        usrpic = cursor.fetchall()

        if request.method == "POST":
            #text entries
            artist = request.form['artist']
            album = request.form['album']
            price = request.form['price']
            condition = request.form['condition']
            medium = request.form['medium']
            description = request.form['description']

            #makeUID to associate image filename with db entry
            crateid = ''.join(random.choices(string.ascii_lowercase + string.digits, k = 10))
            #print('CRATE ID NUMBER:::::::::::::', crateid)
            #file handling
            coverimg = request.files['cover']
            #saving to UPLOAD_FOLDER as defined at the top of app 
            coverimg.save(os.path.join(os.path.abspath(os.path.dirname(__file__)),app.config['UPLOAD_FOLDER'],secure_filename(crateid + '.jpg')))

            con.execute('INSERT INTO inventory (artist, album, description, price, condition, media, crateid) VALUES (?, ?, ?, ?, ?, ?, ?)', (artist, album, description, price, condition, medium, crateid))
            con.commit()

            deetlist = cursor.execute("SELECT crateid FROM inventory WHERE crateid = ?", (crateid,))
            #con.close()
            #flash(session['user'])
            flash('item has been added. please note the serial number below...')

            return render_template("crateadd.html", deetlist = deetlist)
        
        
        return render_template("crateadd.html")
    else:
        flash('login required')
        return render_template("/bcvlogin.html")
   
@app.route("/cd")
@app.route("/cdig")
@app.route("/cratedigger", methods=["GET", "POST"])
def cratedigger():
    # connection
    con = sql.connect('bcv.db')
    con.row_factory = sql.Row  
    cursor = con.cursor()

    # profile pic attributes
    usrpic = ''

    #check that session is set
    if g.user:
        # connection
        con = sql.connect('bcv.db')
        con.row_factory = sql.Row  
        cursor = con.cursor()
        if g.user:
            # CHECKPOINT FOR PRIVLEGES
            cursor.execute("SELECT * FROM users WHERE priv = 1 AND user = ?", (g.user,))
            chpnt = cursor.fetchall()
            if chpnt == []:
                flash("You're not supposed to be here buddy. :)")
                flash('If you think this was a mistake, please get in touch with your administrator.')
                return render_template("index.html")

        cursor.execute("SELECT * FROM inventory ORDER BY item DESC")
        rows = cursor.fetchall()
        # profile picture
        cursor.execute("SELECT photo FROM users WHERE user = ?", (g.user,))
        usrpic = cursor.fetchall()

        if request.method == "POST":
            #text entries
            deleteid = request.form['deleteid']
            #remove image file
            os.remove('static/files/' + str(deleteid) + '.jpg')
            # delete record
            con.execute('DELETE FROM inventory WHERE crateid = ?', (deleteid,))
            # refresh query before rendering template
            cursor.execute("SELECT * FROM inventory ORDER BY item DESC")
            rows = cursor.fetchall()
            con.commit()
            con.close()

            flash('item has been removed...')
            return render_template("cratedigger.html", rows = rows)
     
        #return redirect(url_for('cratedigger'))
        return render_template("cratedigger.html", rows = rows)
    else:
        flash('login required')
        return render_template("/bcvlogin.html", usrpic = usrpic)

@app.route("/register", methods=("GET", "POST"))
def register():
    # connection
    con = sql.connect('bcv.db')
    con.row_factory = sql.Row  
    cur = con.cursor()
    usrpic = ''
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conf = request.form['conf']
        name = request.form['name']

        UIDchk = cur.execute("SELECT user FROM users WHERE user = ?", (username,))
        #check for dupe IDs
        for row in UIDchk:
            UIDchk = row[0]

        #handle profile pic
        #get photo from form
        photo = request.files['photo']
        #generate unique name
        photoname = ((name) + ''.join(random.choices(string.ascii_lowercase + string.digits, k = 10)) + '.jpg')
        print(photoname)

        photo.save(os.path.join(os.path.abspath(os.path.dirname(__file__)),app.config['USR_FOLDER'],secure_filename(photoname)))

        #user validation       
        if not username:
            flash('Username is required!')
        elif not '@' in username:
            flash('Something is wrong with the email address. Please check for typos.')
        elif not '.' in username:
            flash('Something is wrong with the email address. Please check for typos.')
        elif UIDchk == username:
            flash("Username already taken")
            return render_template('register.html')
        #password validation
        elif not password:
            flash('Password is required!')
        elif not conf:
            flash('Password confirmation is required!')
        elif conf != password:
            flash('Passwords do not match!')
            return render_template('register.html')
        #password complexity check
        chars = ['$', '#', '@', '!', '*', '.']
        if len(password) < 7:
            flash('The password must be 7 characters or longer.')
        elif not any (c in chars for c in password):
            flash("Password must contain one of the following... " + str(chars))

        else:
            phash = generate_password_hash(password) 
            con.execute('INSERT INTO users (user, hash, name, photo) VALUES (?, ?, ?, ?)', (username, phash, name, photoname))
            con.commit()
            con.close()
            return redirect(url_for('login'))
        
    return render_template('register.html', usrpic = usrpic)

@app.route("/lyrics", methods=["GET", "POST"])
def lyrics():
    
    # connection
    con = sql.connect('bcv.db')
    con.row_factory = sql.Row  
    cursor = con.cursor()

    cursor.execute("SELECT * FROM lyrics ORDER BY RANDOM() LIMIT 1")
    rndlyr = cursor.fetchall()

    cursor.execute("SELECT * FROM users")

    # profile picture
    path = (app.config['USR_FOLDER'])
    usrpic = ''
    if g.user:

        cursor.execute("SELECT photo FROM users WHERE user = ?", (g.user,))
        usrpic = cursor.fetchall()
        cursor.execute("SELECT * FROM users WHERE user = ?", (g.user,))
        usrdeets = cursor.fetchall()
    
        if request.method == 'POST':
            lyrics = request.form['lyrics']
            con.execute('INSERT INTO lyrics (lyric, user) VALUES (?, ?)', (lyrics, g.user))
            con.commit() 

        return render_template("lyrics.html", usrdeets = usrdeets, usrpic = usrpic, user = g.user, rndlyr = rndlyr)
    else:
        flash('login required')
        return render_template("/login.html", usrpic = usrpic)

@app.route("/msg")
@app.route("/contact")
@app.route("/sendmessage")
@app.route("/message", methods=["GET", "POST"])
def message():

    # connection
    con = sql.connect('bcv.db')
    con.row_factory = sql.Row  
    cursor = con.cursor()

    # profile picture
    path = (app.config['USR_FOLDER'])
    usrpic = ''
    if g.user:

        cursor.execute("SELECT photo FROM users WHERE user = ?", (g.user,))
        usrpic = cursor.fetchall()

        cursor.execute("SELECT * FROM users WHERE user = ?", (g.user,))
        usrdeets = cursor.fetchall()
    
    if request.method == 'POST':
        # change to match message inputs
        email = request.form['email']
        name = request.form['name']
        message = request.form['message']
        registration = g.user

        #timestamp for message tracking.
        time = datetime.datetime.now()

        con.execute('INSERT INTO messages (email, name, message, registration, time) VALUES (?, ?, ?, ?, ?)', (email, name, message, registration, time,))
        con.commit()
        con.close()
        flash('Thanks for dropping us a note!')
        return render_template("index.html", usrpic = usrpic)

    else:
        return render_template("msg.html", usrpic = usrpic)

@app.route('/inbox')
@app.route("/bcvinbox", methods=["GET", "POST"])
def bcvinbox():
    
    # connection
    con = sql.connect('bcv.db')
    con.row_factory = sql.Row  
    cursor = con.cursor()

    # profile picture
    path = (app.config['USR_FOLDER'])
    usrpic = ''
    if g.user:
        # CHECKPOINT FOR PRIVLEGES
        cursor.execute("SELECT * FROM users WHERE priv = 1 AND user = ?", (g.user,))
        chpnt = cursor.fetchall()
        if chpnt == []:
            flash("You're not supposed to be here buddy. :)")
            flash('If you think this was a mistake, please get in touch with your administrator.')
            return render_template("index.html")
        else:

            #if auth != 3:
            #    print('not authorized')
            #else:
            #    print('user checks out!')
            cursor.execute("SELECT photo FROM users WHERE user = ?", (g.user,))
            usrpic = cursor.fetchall()

            inbox = cursor.execute('SELECT * FROM messages ORDER BY time DESC')
            return render_template("bcvinbox.html", usrpic = usrpic, inbox = inbox)

    else:
        flash('login required')
        return render_template("/bcvlogin.html")

@app.route("/nfo")
@app.route("/news")
@app.route("/updates") 
@app.route("/information")
@app.route("/info", methods=["GET", "POST"])
def info():
    
    # connection
    con = sql.connect('bcv.db')
    con.row_factory = sql.Row  
    cursor = con.cursor()
    #cursor.execute("SELECT * FROM info ORDER BY date ASC LIMIT 5")

    # profile picture
    usrpic = '' 
    if g.user:
        cursor.execute("SELECT photo FROM users WHERE user = ?", (g.user,))
        usrpic = cursor.fetchall()

    cursor.execute("SELECT * FROM info")
    news = cursor.fetchall()    

    return render_template("/info.html", news = news)

@app.route("/post")
@app.route("/blog")
@app.route("/publish")
@app.route("/postinfo", methods=["GET", "POST"])
def postinfo():
    
    # connection
    con = sql.connect('bcv.db')
    con.row_factory = sql.Row  
    cursor = con.cursor()

    # profile pic attributes
    usrpic = ''

    #check that session is set
    if g.user:
        # connection
        con = sql.connect('bcv.db')
        con.row_factory = sql.Row  
        cursor = con.cursor()
        if g.user:
            # CHECKPOINT FOR PRIVLEGES
            cursor.execute("SELECT * FROM users WHERE priv = 1 AND user = ?", (g.user,))
            chpnt = cursor.fetchall()
            if chpnt == []:
                flash("You're not supposed to be here buddy. :)")
                flash('If you think this was a mistake, please get in touch with your administrator.')
                return render_template("index.html")
            else:
                deets = cursor.execute("SELECT photo, name FROM users WHERE user = ?", (g.user,))
                for i in deets:
                    usrpic = (i["photo"])
                    name = (i["name"])

                if request.method == "POST":
                    title = request.form['title']
                    post = request.form['post']                
                    user = g.user
                    date = datetime.datetime.now()
                    date = (date.strftime('%x'))

                    con.execute('INSERT INTO info (title, post, date, user, photo, name) VALUES (?, ?, ?, ?, ?, ?)', (title, post, date, user, usrpic, name))
                    con.commit()
                    con.close()
                return render_template("post.html", usrpic = usrpic)

                
    else:
        flash('login required')
        return render_template('/bcvlogin.html')

@app.route("/signout")
@app.route("/logout")
def logout():
    """Log user out"""
    if g.user:
        # Forget any user_id
        session.clear()

        # Redirect user to login form
        flash("You have been logged out.")
        return redirect("/")
    else:
        return redirect('/login')

if __name__ == '__main__':
    app.run(debug=True)