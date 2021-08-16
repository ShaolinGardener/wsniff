from website import db
import os

os.system('rm -r ./website/static/captures/*')
print("[+] Deleting all captures")

db.drop_all()
db.create_all()
print("[+] Created new database")
