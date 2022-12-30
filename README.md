# IMGCrypt
#### Video Demo: https://youtube.com/watch?v=BaCnWBYE7mw
#### Description: Web application in Python made with Flask and SQL Alchemy that allows registered users to hide encrypted data in images.

IMGCrypt is a web application that allows you to hide data in images securely. It uses Flask as the web framework and Jinja as the templating engine. User accounts and tasks are stored in a SQLite database using SQL Alchemy.

You can encrypt any text or binary files into an image with a password within seconds. You can also view how many uploads you and other users have made in total. And of course you can also decrypt your files.

At the start I decided to hide the data in multiple EXIF tags, but they didn't allow more than 32kb of data in them and wasn't very flexible. Then I tried storing them in the image comment, but that also had issues. So I switched to hiding the data in the end of the binary file, which does not have a size limit and allows for very big files, I tried up to 2 GB.

The image upload uses the [Dropzone](https://www.dropzone.dev/) library which provides easy drag and drop for files, the encryption is done with Fernet and PBKDF2HMAC with SHA256, and the frontend with Bootstrap.

Making Dropzone work with the project was a bit hard, but it provided access to the XHR request before and after sending, so I managed to make it work. Also, Dropzone didn't handle the error messages when the response was an array buffer, so I had to fix that.

# How it works

It works by appending the data you uploaded to the image. It uses a header to let the program know when the encrypted data starts. First header along with the filename, then the header again, the salt and finally the encrypted data.

# Files

### app.py

Contains flask endpoints and SQLAlchemy models.

### encrypt.py

Manages encrypting and decrypting bytes with Fernet.

### helpers.py

Contains functions that are used on app.py for endpoints.

### templates/layout.j2

Layout for all the templates

### templates/changepwd.j2

Page for changing user password.

### templates/decrypt.j2

Page for decrypting images that have hidden encrypted data with a password.

### templates/encrypt.j2

Page for encrypting and hiding data in a image.

### templates/home.j2

Page that displays user and global stats.

### templates/login.j2

Login page for users to login after registering

### templates/register.j2

Page for users to register and begin encrypting images.

### templates/tasks.j2

Page that shows history of encrypted images and their date.

### static/decrypt.js

JavaScript code for decrypt page managing the user file uploads.

### static/encrypt.js

JavaScript code for decrypt page managing the user file uploads.

### static/script.js

Contains javascript functions used by other pages.
