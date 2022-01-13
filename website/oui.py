import os.path
import logging
import urllib.request as request

#init logger
_logger = logging.getLogger("website.oui")

#used in own oui.txt file to separate identifying part of the mac address and the organization
SEPARATOR = "\t"
OUI_FILENAME = "oui.txt"

#lookup table
_table = dict()

def download(to_directory: str):
    """
    get the newest version of oui.txt 
    to_path: parsed oui.txt will be stored there
    """
    URL = "http://standards-oui.ieee.org/oui.txt"
    req = request.Request(URL)
    
    _logger.info("[+] Starting to download and parse oui.txt")
    out = None
    count = 0
    try:
        res = request.urlopen(req)
        
        fname = os.path.join(to_directory, OUI_FILENAME)
        out = open(fname, "w")
        
        c = 0
        for line in res:
            line = line.decode("utf-8").strip() #bytes object to string
            #the relevant lines which map the part of a mac address to a organization contain this substring, so skip all other lines
            if "(hex)" not in line: 
                continue

            mac, organization = line.split("(hex)")
            mac, organization = mac.strip(), organization.strip() #remove whitespace like tabs
            
            out.write(f"{mac}{SEPARATOR}{organization}\n") #e.g. one line could be:40-55-82    Nokia
            count += 1
    except Exception as e:
        print(f"[-] Error occurred when updating 'oui.txt': {e}")
        raise Exception()
    finally:
        if out: out.close()
    
    if count != 0:
        _logger.info("[+] Update successfull")
        _logger.info("Got %d mappings.", count)

def load_local_oui(directory_path: str):
    _logger.info("[*] Trying to load local oui")
    fname = os.path.join(directory_path, OUI_FILENAME)
    file = None
    try:
        file = open(fname, "r")

        line = file.readline()
        while line:
            mac, organization = line.strip().split(SEPARATOR)
            _table[mac] = organization
            line = file.readline()
    except Exception as e:
        _logger.exception("[-] Exception when loading local oui:")
    finally:
        if file: file.close()

def lookup(mac: str):
    """
    Takes an entire MAC-address and returns an organization
    """

    oui_part = mac[:8] 

    #convert address to a uniform format 
    if ":" in oui_part: #in order to change addresses with the :-Syntax 
        oui_part = oui_part.replace(":", "-")
    oui_part = oui_part.upper()

    organization = _table.get(oui_part)
    if organization:
        return organization
    else:
        return "not known"

def test_lookup():
    load_local_oui("./static/res/")
    print(lookup("A0:64:8F:EF:4C:E2"))

def main():
    download("./static/res/")

if __name__ == "__main__":
    main()