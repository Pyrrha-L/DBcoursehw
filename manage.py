from flask_script import Manager

from utils.functions import create_app

app = create_app()
app.debug = True
app.threaded = True
manage = Manager(app=app)

if __name__ == '__main__':
    manage.run()
