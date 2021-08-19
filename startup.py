import subprocess

def main():
    str_start = "sudo ./venv/bin/python main.py"
    subprocess.run(str_start, shell=True, check=True)

if __name__ == "__main__":
    main()
