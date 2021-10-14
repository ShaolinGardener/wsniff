from website import db
from website.server import post, get
from website.models import Discovery


class ApiException(Exception):
    pass

def create_map(title, description=None):
    """
    Create a map entry on the server.

    Returns: the ID of the map on the server
    """
    data = {
        "title": title,
        "desc": description
    }
    data, resp = post('/maps', data=data)
    if not resp.status_code == 200:
        raise ApiException(data.get('message'))

    #else: everything is fine
    return data.get("map_id")

def upload_discovery(d: Discovery):
    """
    d: a local Discovery object
    Upload the given local Discovery object to the server via the API
    """
    server_map_id = d.map.server_map_id
    data = {
        "access_point_mac": d.mac,
        "ssid":  d.ssid,
        "channel": d.channel,
        "encryption": d.encryption,
        "gps_lon": d.gps_lon,
        "gps_lat": d.gps_lat,
        "timestamp": d.timestamp,
        "signal_strength": d.signal_strength
    }

    data, resp = post(f'/maps/{server_map_id}', data=data)
    if not resp.status_code == 200:
        raise ApiException(data.get('message'))
    
    #else: successful upload
    d.is_uploaded = True
    db.session.commit()

    return True