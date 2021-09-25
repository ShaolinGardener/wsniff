import requests
from requests.exceptions import Timeout, ConnectionError
from requests.models import HTTPBasicAuth

#a wsniff-server typically runs on port 4242
SERVER_PORT = 4242
SERVER_URL = "http://localhost"
SERVER = f"{SERVER_URL}:{SERVER_PORT}"

#use this for request calls (e.g. instead of requests.get() use session.get())
#since you can set headers that will be valid for all subsequent requests instead of
#having to send them again every time
session = requests.Session()

#just as a quick help: response object 
#attributes: status_code (int); headers (dict)
#methods: content() -> raw bytes of resp payload; text() -> string repr of payload; 
#         json() -> if the response payload is a JSON string, this returns a dict

def get(endpoint: str, params:dict=None, headers:dict=None):
    """
    Executes a GET request to the API and returns the JSON response. 
    
    endpoint: should start with a '/' 
    params: a dict of query parameters
    headers: e.g. {'user-agent': 'my-app/0.0.1'}

    returns: (JSON response as dict, response object so you can get all its other attributes)
    """
    resp = session.get(f"{SERVER}{endpoint}", params=params)
    return resp.json(), resp 

def post(endpoint: str, data:dict=None, timeout=0, headers:dict=None):
    """
    Executes a POST to the API and returns the JSON response. 
    
    endpoint: should start with a '/' 
    data: a dict with the data that should be posted as JSON 
    timeout: if the server does start a response within this time (in s), 
            this will cause a Timeout exception
            Otherwise, the request will never time out
    headers: e.g. {'user-agent': 'my-app/0.0.1'}

    returns: (JSON response as dict, response object so you can get all its other attributes)
    """
    if not timeout:
        #such a request will never time out
        #it is important to use the json and not the data parameter of requests.post since
        #only then requests will convert the dict to a JSON string and set the correct
        #Content-Type of the request
        resp = session.post(f"{SERVER}{endpoint}", json=data)
    else:
        resp = session.post(f"{SERVER}{endpoint}", json=data, timeout=timeout)
    
    return resp.json(), resp 

def server_is_available(timeout: float = 10.0) -> bool:
    """
    Returns whether the server with the URL specified by the user is currently available
    and is functioning correctly.

    timeout: the server has to start the reply within <timeout> seconds in order to count as available 
             (prevents blocking). Should be set to a rather high value since it is only supposed to 
             cover errors when the server can be reached but does not reply for some internal reasons 
             The default case (sniffer has no internet connection) will simply throw a ConnectionError
             since the server cannot be reached at all
    """
    try:
        data, resp = post('/availability', data={'message': 'ping'}, timeout=timeout)
        if data.get('message') == 'pong':
            return True
    except (ConnectionError, Timeout) as e:
        return False



def set_auth_token(token: str):
    session.headers.update({'x-access-token': token})

def autheticate(username: str, password: str):
    """
    Try to autheticate with username and password.
    If these login credentials are wrong, this returns False
    Otherwise, this returns True and you can now request protected resources on the server.
    """

    #note: this is not our custom get() function but the one of the request library since we
    #need to pass an auth-object here
    resp= session.get(f'{SERVER}/login', auth=HTTPBasicAuth(username, password))
    if resp.status_code != 200:
        return False
    
    #username+password were correct -> now store access token in header for future requests
    token = resp.json().get('token')
    set_auth_token(token)
    return True

if __name__ == '__main__':
    data, resp = get('/users')
    print(data)

    autheticate('admin', '1234')

    data, resp = get('/users')
    print(data)    