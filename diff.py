import sqlite3

def get_changes(db_path):
  with sqlite3.connect(db_path) as con:
    cur = con.execute('SELECT * FROM Changes')
    return set(cur.fetchall())

changes_a = get_changes('data.db')
changes_b = get_changes('data-r2.db')

print('changes_a - changes_b\n', changes_a - changes_b)
print('changes_b - changes_a\n', changes_b - changes_a)
