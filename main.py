import os
from website import app, setup


def main():
    website.setup()
    app.run(host="0.0.0.0", threaded=True, debug=True, port=80)

if __name__ == "__main__":
    main()
    
