PATH_TO_CHECK = 'checkme'
PATCH_TO_MOVE_MISSING_FILES_TO = 'transferme'

import sqlite3, hashlib, os

def hash_file(path):
  sha1 = hashlib.sha1()
  with open(path, 'rb') as f:
    while True:
      data = f.read(64*1024)
      if not data:
        break
      sha1.update(data)
  return sha1.digest()


db = sqlite3.connect('data.db')
cur = db
missing_count = 0
checked_count = 0

for file in os.listdir(PATH_TO_CHECK):
  fpath = os.path.join(PATH_TO_CHECK, file)
  hash = hash_file(fpath)
  cur = cur.execute('SELECT path FROM changes WHERE hash = (?)', (hash,))
  res = cur.fetchall()
  checked_count += 1
  if not res:
    missing_count += 1
    print('NOTFOUND', file)
    os.rename(fpath, os.path.join(PATCH_TO_MOVE_MISSING_FILES_TO, file))
  elif not res[0][0].endswith(file):
    missing_count += 1
    print('BADNAME', file)

print('\n\nMissing:', missing_count)
print('Checked:', checked_count)
print('Looked in:', PATH_TO_CHECK)
