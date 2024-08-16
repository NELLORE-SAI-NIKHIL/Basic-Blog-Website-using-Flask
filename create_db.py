import pymysql

try:
    # Establish the database connection
    myDB = pymysql.connect(
        host="localhost",
        user="root",
        passwd="nikhil08012004"
    )

    # Create a cursor object
    my_cursor = myDB.cursor()

    # Create a new database
    my_cursor.execute("CREATE DATABASE IF NOT EXISTS our_users")

    # Show all databases
    my_cursor.execute("SHOW DATABASES")

    # Print the list of databases
    for db in my_cursor:
        print(db)

except pymysql.MySQLError as e:
    print(f"Error: {e}")
finally:
    # Close the cursor and connection
    if my_cursor:
        my_cursor.close()
    if myDB:
        myDB.close()
