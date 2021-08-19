import os
from website import app, setup
from website.settings import FLASK_DEBUG, FLASK_THREADED


def main():
#   website.setup()
    app.run(host="0.0.0.0", threaded=FLASK_THREADED, debug=FLASK_DEBUG, port=80)

if __name__ == "__main__":
    main()

