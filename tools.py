import ReflectiveNAS, os, time, hashlib, logging, shutil, posixpath, code, functools
from datetime import datetime as dt

try:
  import readline
except ModuleNotFoundError:
  pass

TICK = 0.00002

def fmt_time(t):
  return dt.utcfromtimestamp(t).strftime('%Y-%m-%d %H:%M:%S')

def fmt_size(num, suffix='B'):
  for unit in ['','K','M','G','T','P','E','Z']:
    if abs(num) < 1024.0:
      return ('%3.2f %s%s' if unit else '%d %s%s') % (num, unit, suffix)
    num /= 1024.0
  return '%.2f %s%s' % (num, 'Y', suffix)

@functools.lru_cache(maxsize=1000000)
def hash_file_cached(path):
  return ReflectiveNAS.hash_file(path)

class Tools(object):
  def __init__(self, core):
    self.core = core
    self.synchronizer = ReflectiveNAS.Synchronizer(self.core,
                                                   start_worker=False,
                                                   use_memfs=False)

  def main_menu(self):
    while True:
      print(' - ReflectiveNAS Tools -')
      print(' 1) View Status')
      print(' 2) Search for Files')
      print(' 3) Get File from Remote Servers')
      print(' 4) Resolve Conflicts')
      print(' 5) Pull Changes from Remote Servers')
      print(' 6) Reset Last Remote Timestamp')
      print(' 7) Ensure a local directory matches the database')
      print(' 8) Use InteractiveConsole')
      print(' Q) Quit')
      print('')
      inp = input('> ').lower()
      print('')
      if   inp == '1': self.view_status()
      elif inp == '2': self.search_for_files()
      elif inp == '3': self.get_file_from_remote_servers()
      elif inp == '4': self.resolve_conflicts()
      elif inp == '5': self.pull_changes_from_remote_servers()
      elif inp == '6': self.reset_last_remote_timestamp()
      elif inp == '7': self.ensure_local_directory_matches_database()
      elif inp == '8': self.use_InteractiveConsole()
      elif inp == 'q': return

  def view_status(self):
    last_local_timestamp = self.core.db.get_var('last_local_timestamp') or 0
    last_remote_timestamp = self.core.db.get_var('last_remote_timestamp') or 0
    db_hash = ReflectiveNAS.bhex(self.core.db.get_var('db_hash') or '')
    print('-= This Server =-')
    print('Last Local Change:', fmt_time(last_local_timestamp))
    print('Last Remote Change:', fmt_time(last_remote_timestamp))
    print('Database Hash:', db_hash)
    print('Code Hash:', ReflectiveNAS.bhex(self.core.code_hash))
    print('')

    for server in self.synchronizer.remote_servers:
      print('-= '+server.url+' =-')
      try:
        s = server.status()
        print('Last Change:', fmt_time(s['last_timestamp']))
        print('Database Hash:', s['db_hash'])
        print('Code Hash:', s['code_hash'])
      except ReflectiveNAS.SynchronizationServerUnavailableException:
        print('  Server Unavailable')
      print('')

  def search_for_files(self):
    limit = 3
    max_page = float('inf')
    page = 0
    while True:
      print('Enter a query or leave blank to quit:')
      q = input('> ')
      if not q:
        return
      try:
        results = self.core.db.search(q, limit, 0)
        break
      except Exception as ex:
        print('Error running query:', repr(ex))

    while True:
      if len(results) < limit:
        max_page = min(max_page, page)
      print('-'*80)
      print('')
      for idx, result in enumerate(results):
        print('Index:', idx)
        print('Path:', result[2])
        print('Hash:', ReflectiveNAS.bhex(result[3]))
        print('Size:', fmt_size(result[4]))
        print('Modified:', fmt_time(result[5]))
        print('Action:', ReflectiveNAS.Action(result[1]).name)
        print('Timestamp:', fmt_time(result[0]))
        print('')
      print('')
      print('Enter an index to restore a file or pick an option below.')
      print('Page', page+1, 'of', '?' if max_page == float('inf') else max_page+1)
      print('(p) previous page   (n) next page   (q) main menu')
      inp = input('> ').lower()
      if inp == 'q':
        print('\n\n')
        return
      elif inp == 'n':
        page += 1
        if page > max_page:
          page = 0
      elif inp == 'p':
        page -= 1
        if page < 0 and max_page != float('inf'):
          page = max_page
        elif page < 0:
          page = 0
      else:
        try:
          file = results[int(inp)]
          if file[3] == b'':
            print("\nError: Can't download a folder!")
          else:
            dest = input('Enter destination: ')
            local_copy = self.core.get_real_path_by_hash_and_size(file[3], file[4])
            if local_copy:
              print('Copying...')
              shutil.copyfile(local_copy, dest)
            else:
              print('Error: No local copies exist')
              y = (inp('Try remote server? ').lower()+' ')[0]=='y'
              if y:
                self._get_file_from_remote_servers_by_hash_and_size(hash, size, dest)
        except (ValueError, IndexError):
          print('\nInvalid Selection!\n')
      offset = limit*page
      results = self.core.db.search(q, limit, offset)

  def _get_file_from_remote_servers_by_hash_and_size(self, hash, size, dest):
    print('Looking for file...')
    for server in self.synchronizer.remote_servers:
      try:
        server.get_file(hash, size, dest)
        print('File downloaded!\n')
        return
      except FileNotFoundError:
        pass
      except ReflectiveNAS.SynchronizationServerUnavailableException:
        pass
    print('Couldn\'t find file!\n')
    
  def get_file_from_remote_servers(self):
    try:
      hash = bytes.fromhex(input('Enter file hash: '))
      size = int(input('Enter file size: '))
      dest = input('Enter file destination: ')
    except ValueError:
      print('Invalid input!\n')
      return
    self._get_file_from_remote_servers_by_hash_and_size(hash, size, dest)

  def find_a_conflict(self):
    _, _, conflict = self.core.db.verify_database(fail_safe_on_conflict=False)
    return conflict

  def resolve_a_conflict(self, conflict):
    if conflict['type'] == 'created_exists':
      ts, _, path, hash, size, mtime = conflict['last']
      ts += TICK
      self.core.db.record_change(ReflectiveNAS.Action.DELETE, path,
                                 hash=hash, size=size, mtime=mtime, timestamp=ts)
    elif conflict['type'] == 'modified_missing':
      ts, _, path, hash, size, mtime = conflict['new']
      ts -= TICK
      self.core.db.record_change(ReflectiveNAS.Action.CREATE, path,
                                 hash=hash, size=size, mtime=mtime, timestamp=ts)
    elif conflict['type'] == 'move_no_destination':
      ts, _, path, hash, size, mtime = conflict['new']
      self.core.db.record_change(ReflectiveNAS.Action.MOVE_DESTINATION, path,
                                 hash=hash, size=size, mtime=mtime, timestamp=ts)

  def resolve_conflicts(self):
    print('This tool will attempt to fix conflicting changes by guessing which change')
    print('to use. It will add changes to the database but will not change any files.')
    print('After it runs, you will need to manually verify that all of the paths with')
    print('conflicts have been fixed. You may need to run this tool multiple times. A')
    print('copy of what\'s been changed will also be recorded to the log. You can use')
    print('the other tools to restore files from history if nessicary.')
    print('')
    print('Enter 1 to start or anything else to abort:')
    inp = input('> ')
    if inp != '1':
      return
    print('')
    conflicts_found = False
    type2change = {'created_exists':'deleting', 'modified_missing': 'creating', 'move_no_destination': 'moving'}
    while True:
      conflict = self.find_a_conflict()
      if conflict is None:
        break
      conflicts_found = True
      self.resolve_a_conflict(conflict)
      c = type2change[conflict['type']]
      desc  = 'Auto-resolved a conflict by ' + c + ' a path!\n'
      desc += 'Path: ' + conflict['new'][2] + '\n\n'
      print(desc)
      logging.critical(desc)
    if conflicts_found:
      print('All conflicts resolved.')
    else:
      print('No conflicts found')
    print('')
    
  def pull_changes_from_remote_servers(self):
    print('Pulling changes, this may take a long time...')
    self.synchronizer.pull_changes_from_remote_servers()
    print('Done!\n')

  def reset_last_remote_timestamp(self):
    while True:
      print('Enter a date (e.g. 2019-1-20) or leave blank to reset to the earliest date')
      d = input('> ')
      if d == '':
        d = 0
      else:
        try:
          d = time.mktime(dt.strptime(d, '%Y-%m-%d').timetuple())
        except ValueError:
          print('Invalid date!\n')
          continue
      self.core.db.set_var('last_remote_timestamp', d)
      print('Timestamp reset!\n')
      return

  # XXX This assumes the directory depth will never get so large it causes call stack size issues
  def walk_local_directory_and_ensure_it_matches_database(self, root, fix_discrepancies = False):
    if self.core.is_excluded(root):
      return
    
    try:
      local_files = set(os.listdir(self.core.full_path(root)))
    except FileNotFoundError:
      local_files = set()
    for name in self.core.db.listdir(root) | local_files:
      path = posixpath.join(root, name)
      self.ensure_local_item_matches_database(path, fix_discrepancies = fix_discrepancies)

  def ensure_local_item_matches_database(self, path, fix_discrepancies = False):
    if self.core.is_excluded(path):
      return

    st = self.core.db.stat(path)
    full_path = self.core.full_path(path)
    if st is not None: # Should exist
      if st['hash'] == b'':
        # Directory
        try:
          if os.path.getmtime(full_path) != st['mtime']:
            print('Wrong timestamp for directory:', path)
            if fix_discrepancies:
              os.utime(full_path, (st['mtime'], st['mtime']))
        except FileNotFoundError:
          print('Missing directory:', path)
          if fix_discrepancies:
            os.mkdir(full_path)
            os.utime(full_path, (st['mtime'], st['mtime']))

        self.walk_local_directory_and_ensure_it_matches_database(path, fix_discrepancies = fix_discrepancies)
      else:
        # File
        try:
          local_st = os.stat(full_path)
          if local_st.st_size != st['size']:
            print('Wrong size for file:', path)
            if fix_discrepancies:
              self.core.move_to_history(path)
              self._get_file_from_remote_servers_by_hash_and_size(st['hash'], st['size'], full_path)
          if hash_file_cached(full_path) != st['hash']:
            print('Wrong hash for file:', path)
            if fix_discrepancies:
              self.core.move_to_history(path)
              self._get_file_from_remote_servers_by_hash_and_size(st['hash'], st['size'], full_path)
          if local_st.st_mtime != st['mtime']:
            print('Wrong timestamp for file:', path)
            if fix_discrepancies:
              os.utime(full_path, (st['mtime'], st['mtime']))
        except FileNotFoundError:
          print('Missing file:', path)
          if fix_discrepancies:
            self._get_file_from_remote_servers_by_hash_and_size(st['hash'], st['size'], full_path)
    else: # Shouldn't exist
      if os.path.isdir(full_path):
        self.walk_local_directory_and_ensure_it_matches_database(path, fix_discrepancies = fix_discrepancies)
        if not os.listdir(full_path):
          print('Directory not in database:', path)
          if fix_discrepancies:
            os.rmdir(full_path)
      elif os.path.isfile(full_path):
        print('File not in database:', path)
        if fix_discrepancies:
          self.core.move_to_history(path)

  def ensure_local_directory_matches_database(self):
    print('Enter a directory to check:')
    root = input('> ')
    print('Fix discrepancies? [y]es / [n]o')
    fix_discrepancies = (input('> ').lower()[:1] == 'y')
    self.ensure_local_item_matches_database(root, fix_discrepancies = fix_discrepancies)
    print('Done!\n')

  def use_InteractiveConsole(self):
    variables = globals().copy()
    variables.update(locals())
    shell = code.InteractiveConsole(variables)
    shell.interact()

def main():
  import argparse
  parser = argparse.ArgumentParser(description='ReflectiveNAS Tools\nSee readme.md for help.')
  parser.add_argument('-c', '--config', help='config file path', default='config.json')
  args = parser.parse_args()
  
  core = ReflectiveNAS.Core(config_path=args.config)
  tools = Tools(core)
  try:
    tools.main_menu()
  except KeyboardInterrupt:
    pass
  core.exit(0)

if __name__ == '__main__':
  main()
