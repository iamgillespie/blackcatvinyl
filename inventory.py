import sqlite3

###code for inputing data....
# connection
conn = sqlite3.connect(('bcv.db'))
# used to point much like the cursor of a mouse
cursor = conn.cursor()
#create the table if not created
mktable = "CREATE TABLE IF NOT EXISTS inventory(artist TEXT PRIMARY KEY, album TEXT, upc INTEGER, mediatype TEXT, condition TEXT, price INTEGER)"
cursor.execute(mktable)

#get input
artist = input('artist: ')
album = input('album: ')
upc = input("upc: ")
mediatype = input("media type (LP/45/Cassette/CD etc...): ")
condition = input("condition: ")
price = input("price: ")

# apply input
cursor.execute("INSERT INTO inventory(artist, album, upc, mediatype, condition, price) VALUES(?, ?, ?, ?, ?, ?)", (artist, album, upc, mediatype, condition, price))
conn.commit()