import os
import sys
from website import app, setup
from website.settings import FLASK_DEBUG, FLASK_THREADED, ROLE


def main():
    if ROLE == "MASTER":
        app.run(host="0.0.0.0", threaded=FLASK_THREADED, debug=FLASK_DEBUG, port=80)
    elif ROLE == "SLAVE":
        app.run(host="0.0.0.0", threaded=FLASK_THREADED, debug=FLASK_DEBUG, port=4242)
    else:
        print("[-] ROLE in settings should be set to 'MASTER' or 'SLAVE'")
        sys.exit(1)

if __name__ == "__main__":
    main()

