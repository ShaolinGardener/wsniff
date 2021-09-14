import subprocess

def main():
    str_start = "sudo ./venv/bin/python main.py"
    try:
        subprocess.run(str_start, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        print("Exit due to error ...")

if __name__ == "__main__":
    main()
