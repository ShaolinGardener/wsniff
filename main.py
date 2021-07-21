from website import app
from website.oui import load_local_oui
from website.gps import start_gps_tracking
from website.interfaces import monitor_iface

def setup():
    load_local_oui(directory_path="./website/static/res")
    start_gps_tracking()
    try:
        monitor_iface.enable_monitor_mode()
    except Exception as e:
        print(f"[-] Failed to activate monitor mode for {monitor_iface}")


def main():
    setup()
    app.run(host="0.0.0.0", threaded=True, debug=True)

if __name__ == "__main__":
    main()
    