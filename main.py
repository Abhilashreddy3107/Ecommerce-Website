from app import application
from app.apis import *

# db.init_app(application)
# api.init_app(application)
# docs.init_app(application)

# with application.app_context():
#     db.create_all()
#     db.session.commit()


if __name__ == "__main__":
    application.run(debug=True,port=8000)

