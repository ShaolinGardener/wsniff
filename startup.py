import subprocess

def main():
    """
    You might wonder why the user should not start wsniff himself by simply
    calling 'python main.py' after 'source venv/bin/source' ?!

    Well, because in order to sniff packets via scapy, you need root privileges - 
    but when you try to execute main.py with sudo the libraries in the virtial environment
    are not available. That is why the correct command is 'sudo ./venv/bin/python main.py'

    To simplify the execution of wsniff for the user, this file is provided which  
    encapsulated the necessary command and behaves just like the normal program would do.
    """
    str_start = "sudo ./venv/bin/python main.py"
    try:
        #also output all debug messages
        subprocess.run(str_start, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        print("Exit due to error ...")

if __name__ == "__main__":
    main()
