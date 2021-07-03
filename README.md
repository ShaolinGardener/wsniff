# wsniff
A WiFi sniffer 🌱


## Setup
- Von Github klonen
```
cd <path>
git clone https://github.com/JulianWindeck/wsniff wsniff
```
- Virtual environment für Python einrichten
```
cd wsniff
python3 -m venv venv //kann auch python sein, haengt vom alias ab
source ./venv/bin/activate

pip install -r ./res/requirements.txt

#...

deactivate
```

- Für Designarbeiten automatisches Transpilieren von Sass aktivieren
```
sass --watch ./sass:./css //zum Abbrechen im Terminal Ctrl-C
```

## Start Server
Per `python main.py` kann der Server gestartet werden.
Achte darauf, ob die Aktivierung des Debug-Modus erwünscht ist!


## Other
- Nach Installation neuer Packages requirements.txt updaten
```
pip freeze > ./res/requirements.txt
```

