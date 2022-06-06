import sys, os, platform, errno, threading, time, json, sqlite3, requests, logging, enum, pickle, hashlib, queue, shutil, http.server, socketserver, ssl, email.message, smtplib, stat, posixpath, datetime, binascii
sys.path.append('FUSE')
import fuse

# Each change uses 158 B to 32188 B depending on path length, size, etc.
CHANGE_PAGE_SIZE = 1000

class AsyncTask(object):
  def __init__(self, func, args=(), kwargs={}):
    self.completed = threading.Event()
    def _(self, func, args, kwargs):
      self.result = None
      self.exception = None
      try:
        self.result = func(*args, **kwargs)
      except Exception as e:
        self.exception = e
      self.completed.set()
    self.thread = threading.Thread(target=_,args=(self,func,args,kwargs))
    self.thread.start()

  def get(self):
    self.completed.wait()
    if self.exception:
      raise self.exception
    return self.result

def hash_file_async(path):
  f = open(path, 'rb')
  def _(f):
    with f:
      sha1 = hashlib.sha1()
      while True:
        data = f.read(64*1024)
        if not data:
          break
        sha1.update(data)
    return sha1.digest()
  return AsyncTask(_,(f,))

def hash_file(path):
  return hash_file_async(path).get()

def bhex(b):
  try:
    return binascii.hexlify(b).decode()
  except TypeError:
    return binascii.hexlify(b.encode('utf-8')).decode()

def copyfile_exclusive(src, dst, core=None):
  try:
    with open(src, 'rb') as fsrc:
      with open(dst, 'xb') as fdst:
        return shutil.copyfileobj(fsrc, fdst)
  except FileExistsError:
    if core:
      core.fail_safe(src+' -> '+dst+' - copyfile_exclusive - destination already exists')
    else:
      raise

class Action(enum.IntEnum):
  CREATE = 1
  UPDATE = 2
  MOVE_SOURCE = 3
  MOVE_DESTINATION = 4
  DELETE = 5

CREATE_ACTIONS = [Action.CREATE, Action.MOVE_DESTINATION]
DESTROY_ACTIONS = [Action.DELETE, Action.MOVE_SOURCE]

class DatabaseConnection(object):
  def __init__(self, core):
    self.core = core
    self.config = core.config
    self.con = sqlite3.connect(self.config['Database']['Path'])
    cur = self.con.execute('PRAGMA CACHE_SIZE = ' + str(round(-1024*self.config['Database']['Cache_Size'])) + ';')
    cur.execute('create table if not exists changes (timestamp REAL, action INTEGER, path BLOB, hash BLOB, size INTEGER, mtime INTEGER, UNIQUE (timestamp, action, path, hash, size, mtime))')
    cur.execute('create table if not exists vars (key BLOB PRIMARY KEY, value BLOB)')
    self.cache_stale = True

  def close(self):
    self.con.close()

  def record_change(self, action, path, timestamp=None, hash=None, size=None, mtime=None):
    if None in (hash, size, mtime): full_path = self.core.full_path(path)
    if None in (size, mtime): st = os.stat(full_path)

    if timestamp is None: timestamp = time.time()
    if hash is None: hash = hash_file(full_path)
    if type(hash) is AsyncTask: hash = hash.get()

    self.core.unlock_path(path)

    if size is None: size = st.st_size
    if mtime is None: mtime = st.st_mtime

    self.cache_stale = True
    with self.con:
      self.con.execute('INSERT INTO changes VALUES (?,?,?,?,?,?)', (timestamp, action, path, hash, size, mtime))

  def get_changes_since(self, timestamp, page=0):
    limit = CHANGE_PAGE_SIZE
    offset = page*limit
    cur = self.con.execute('SELECT * FROM changes WHERE timestamp>=(?) LIMIT (?), (?)', (timestamp, offset, limit))
    return cur.fetchall()

  def filter_existing_changes(self, changes, timestamp=0):
    result = set(changes)
    cur = self.con.execute('SELECT * FROM changes WHERE timestamp>=(?)', (timestamp,))
    for c in cur:
      try: result.remove(c)
      except KeyError: pass
      if len(result) < 1:
        break
    return result

  def stat(self, path):
    cur = self.con.execute('SELECT * FROM changes WHERE path=(?) ORDER BY timestamp DESC LIMIT 1', (path,))
    r = cur.fetchone()
    if r is None:
      return None
    if Action(r[1]) in DESTROY_ACTIONS:
      return None
    return {'timestamp':r[0], 'hash': r[3], 'size': r[4], 'mtime': r[5]}

  def listdir(self, path):
    contents = set()
    if not path.endswith('%'):
      path += '%'
    cur = self.con.execute('SELECT DISTINCT path FROM changes WHERE path like (?)', (path,))
    path = path[:-1]
    for i in cur:
      base, name = posixpath.split(i[0])
      if base == path:
        contents.add(name)
    return contents

  def get_real_path_by_hash_and_size(self, hash, size):
    cur = self.con.execute('SELECT DISTINCT path FROM changes WHERE hash=(?) and size=(?) ORDER BY timestamp DESC', (hash,size))
    for r in cur:
      stat = self.stat(r[0])
      if stat and stat['size'] == size and stat['hash'] == hash:
        fpath = self.core.full_path(r[0])
        try:
          if os.path.getsize(fpath) == size:
            return fpath
        except FileNotFoundError:
          pass
    return None

  def get_n_random_paths(self, n):
    cur = self.con.execute('SELECT DISTINCT path FROM changes ORDER BY RANDOM() LIMIT (?)', (n,))
    return [i[0] for i in cur.fetchall()]

  def _keyword_split(self, str):
    buf = ''
    in_string_quote = None
    escaped = False
    for idx, c in enumerate(str):
      if not in_string_quote and c in ['"', "'"]:
        in_string_quote = c
        buf += c
        start = idx
      elif c == in_string_quote and not escaped:
        return self._keyword_split(str[:start])+[buf+c]+self._keyword_split(str[idx+1:])
      elif in_string_quote and c == '\\':
        escaped = True
      elif in_string_quote:
        buf += c
        escaped = False
    if in_string_quote:
      raise ValueError('Unterminated string', buf)

    result = []
    special = '=<>!()'
    for part in str.split(' '):
      for c in part:
        if ((buf and buf[0] not in special and c in special) or
            (buf and buf[0] in special and c not in special)):
          result.append(buf)
          buf = c
        else:
          buf += c
      if buf:
        result.append(buf)
        buf = ''
    return result

  def search(self, query, limit, offset):
    keywords = ['=', '<', '>', '>=', '<=', '!=', 'like', 'not', 'or', 'and', 'order', 'by', 'asc', 'desc', '(', ')']
    collumns = ['timestamp', 'action', 'path', 'hash', 'size', 'mtime']
    keywords.extend(collumns)
    sql = 'SELECT * FROM changes WHERE'.split()
    args = []
    for k in self._keyword_split(query):
      if k in collumns:
        collumn = k
      if k.lower() in keywords:
        sql.append(k)
      else:
        sql.append('?')
        try: args.append([collumn, k])
        except NameError: raise ValueError('Argument without collumn', k)

    size_dict = {'K':1024, 'M':1024**2, 'G':1024**3, 'T':1024**4}
    for arg in args:
      collumn, value = arg
      if collumn == 'action':
        try:
          value = int(value)
        except ValueError:
          try:
            value = Action[value.upper()]
          except KeyError:
            raise ValueError('Invalid value for action', value)
      elif collumn == 'timestamp' or collumn == 'mtime':
        try:
          value = float(value)
        except ValueError:
          try:
            value = time.mktime(datetime.datetime.strptime(value, '%Y-%m-%d').timetuple())
          except ValueError:
            raise ValueError('Invalid value for ' + collumn, value)
      elif collumn == 'size':
        try:
          value = int(value)
        except ValueError:
          try:
            value = int(value[:-1])*size_dict[value.upper()[-1]]
          except KeyError:
            raise ValueError('Invalid value for size', value)
      elif collumn == 'hash':
        try: value = bytes.fromhex(value)
        except ValueError: raise ValueError('Invalid value for hash', value)
      elif collumn == 'path':
        if value[0] == value[-1] and value[0] in ['"',"'"]:
          value = value[1:-1]
      arg[1] = value

    query = ' '.join(sql) + ' LIMIT ' + str(int(limit)) + ' OFFSET ' + str(int(offset))
    cur = self.con.execute(query, tuple(a[1] for a in args))
    return cur.fetchall()

  def _find_move_pair(self, change):
    action = Action.MOVE_SOURCE if Action(change[1])==Action.MOVE_DESTINATION else Action.MOVE_DESTINATION
    args = action, change[0], change[3], change[4], change[5]
    cur = self.con.execute('SELECT path FROM changes WHERE action=(?) and timestamp=(?) and hash=(?) and size=(?) and mtime=(?)', args)
    r = cur.fetchone()
    if r is None:
      return None
    return r[0]

  def verify_database(self, fail_safe_on_conflict=True):
    if not self.cache_stale:
      return self.cached_db_hash, self.cached_last_local_timestamp, None
    db_hash = hashlib.sha1(b'925dba3c-f894-41cf-9fa3-78ebff3ac71d')
    last_local_timestamp = 0
    cur = self.con.execute('SELECT * FROM changes ORDER BY path, timestamp ASC')
    cpath = None
    for change in cur:
      if change[2] != cpath:
        if cpath is not None and path_exists:
          chunk = map(str,[cpath, bhex(hash), size, mtime])
          chunk = ('>'+('|'.join(chunk))).encode()
          db_hash.update(chunk)
        path_exists = False
        hash = '?'
        size = 0
        mtime = 0
        cpath = change[2]
      action = Action(change[1])
      if path_exists and action in CREATE_ACTIONS:
        if fail_safe_on_conflict:
          self.core.fail_safe(cpath + ' - CONFLICT: created but already exists')
        conflict = {'type':'created_exists', 'new': change, 'last': last_change}
        return db_hash.digest(), last_local_timestamp, conflict
      if not path_exists and action not in CREATE_ACTIONS:
        if fail_safe_on_conflict:
          self.core.fail_safe(cpath + " - CONFLICT: modified but doesn't exist")
        conflict = {'type':'modified_missing', 'new': change}
        return db_hash.digest(), last_local_timestamp, conflict
      if len(change[3]) != 20 and len(change[3]) != 0:
        self.core.fail_safe(cpath + ' - invalid hash length')
      if hash != '?' and path_exists and len(change[3]) != len(hash):
        if fail_safe_on_conflict:
          self.core.fail_safe(cpath + ' - CONFLICT: hash changed length')
        conflict = {'type':'created_exists', 'new': change, 'last': last_change}
        return db_hash.digest(), last_local_timestamp, conflict
      if (action == Action.MOVE_SOURCE or action == Action.MOVE_DESTINATION) and not self._find_move_pair(change):
        if fail_safe_on_conflict:
          self.core.fail_safe(cpath + ' - missing move pair')
        if action == Action.MOVE_SOURCE:
          conflict = {'type':'move_no_destination', 'new': change, 'last': last_change}
          return db_hash.digest(), last_local_timestamp, conflict
        self.core.fail_safe(cpath + ' - missing move source')
      if action in CREATE_ACTIONS:
        path_exists = True
      elif action in DESTROY_ACTIONS:
        path_exists = False
      hash = change[3]
      size = change[4]
      mtime = change[5]
      last_local_timestamp = max(last_local_timestamp, change[0])
      last_change = change
    self.cached_db_hash = db_hash.digest()
    self.cached_last_local_timestamp = last_local_timestamp
    self.cache_stale = False
    return db_hash.digest(), last_local_timestamp, None

  def set_var(self, key, value):
    with self.con:
      cur = self.con.execute('INSERT OR REPLACE INTO vars VALUES (?,?)', (key, pickle.dumps(value)))

  def get_var(self, key):
    cur = self.con.execute('SELECT value FROM vars WHERE key=(?)', (key,))
    r = cur.fetchone()
    if r is None:
      return None
    return pickle.loads(r[0])

class MultithreadedDatabaseConnection(object):
  def __init__(self, core):
    self.q = queue.Queue()
    self.core = core
    self.keep_running = True
    self.worker_thread = threading.Thread(target=self._worker, daemon=False)
    self.worker_thread.start()

  def _worker(self):
    db = DatabaseConnection(self.core)
    while True:
      try:
        fname, args, kwargs, result = self.q.get(timeout=1)
        r, ex = None, None
        try: r = getattr(db, fname)(*args, **kwargs)
        except Exception as e: ex = e
        result.put((r, ex))
      except queue.Empty:
        if not self.keep_running:
          break      
    db.close()

  def __getattr__(self, name):
    return lambda *a, **k: self._invoke(name, a, k)

  def _invoke_async(self, fname, args, kwargs):
    result = queue.Queue()
    self.q.put((fname, args, kwargs, result))
    return result

  def _invoke(self, fname, args, kwargs):
    result = self._invoke_async(fname, args, kwargs)
    r, ex = result.get()
    if ex:
      raise ex
    return r

  def close(self):
    self.keep_running = False
    self.worker_thread.join()

  def record_change_async(self, *args, **kwargs):
    if 'timestamp' not in kwargs:
      kwargs['timestamp'] = time.time()
    full_path = self.core.full_path(args[1])
    if 'hash' not in kwargs:
      kwargs['hash'] = hash_file_async(full_path)
    if 'size' not in kwargs or 'mtime' not in kwargs:
      st = os.stat(full_path)
      if 'size' not in kwargs:
        kwargs['size'] = st.st_size
      if 'mtime' not in kwargs:
        kwargs['mtime'] = st.st_mtime
    return self._invoke_async('record_change', args, kwargs)

class Core(object):
  def __init__(self, config_path = 'config.json', fail_locally=False):
    with open(config_path,'r') as f:
      self.config = json.loads(f.read())
    self.fail_locally = fail_locally
    self.fail_safe_callbacks = []
    self.exit_callbacks = []
    self.exit_in_progress_lock = threading.Lock()
    self.exit_in_progress = False
    self._fix_config_paths()
    self._setup_logging()
    self.real_directory = self.config['Passthrough']['Real_Directory']
    self.memfs = {}
    self.db = MultithreadedDatabaseConnection(self)
    self.exit_event = threading.Event()
    self.return_code = 0
    self.code_hash = hash_file(__file__)
    self._cache_certs()
    self.fds = {}
    self.fds_lock = threading.Lock()
    self.paths = {}
    self.paths_lock = threading.Lock()

  def _make_abs(self, path):
    if 'cygwin' in sys.platform.lower():
      import ntpath
      isabs = ntpath.isabs(path) or os.path.isabs(path)
    else:
      isabs = os.path.isabs(path)
    if not isabs:
      path = os.path.join(os.getcwd(), path)
    return path
  
  def _setup_logging(self):
    logging.basicConfig(filename=self.config['Logging']['Path'],
                        format='%(asctime)s %(name)-12s %(levelname)-8s %(message)s',
                        datefmt='%Y-%m-%d %H:%M',
                        level=self.config['Logging']['Level'])
    def log_exception_handler(type, value, tb):
      logging.error('Uncaught exception', exc_info=(type, value, tb))
      self.fail_safe('Uncaught exception')
    sys.excepthook = log_exception_handler

  # workaroung since WinFSP can change the working directory
  def _fix_config_paths(self):
    c = self.config
    c['Passthrough']['Real_Directory'] = self._make_abs(c['Passthrough']['Real_Directory'])
    c['Passthrough']['Proxy_Directory'] = self._make_abs(c['Passthrough']['Proxy_Directory'])
    c['Passthrough']['History'] = self._make_abs(c['Passthrough']['History'])
    c['Database']['Path'] = self._make_abs(c['Database']['Path'])
    c['Logging']['Path'] = self._make_abs(c['Logging']['Path'])
    c['Local_Server']['Cert_Path'] = self._make_abs(c['Local_Server']['Cert_Path'])
    c['Local_Server']['Key_Path'] = self._make_abs(c['Local_Server']['Key_Path'])
    for i in range(len(c['Passthrough']['Excluded_Paths'])):
      if c['Passthrough']['Excluded_Paths'][i][-1] != posixpath.sep:
        c['Passthrough']['Excluded_Paths'][i] += posixpath.sep

  # setup cache for loading SSL certs without having to spinup the disc
  def _cache_certs(self):
    with open(self.config['Local_Server']['Cert_Path'], 'rb') as f:
      self.cached_cert = f.read()
    with open(self.config['Local_Server']['Key_Path'], 'rb') as f:
      self.cached_key = f.read()

  def full_path(self, partial):
      if partial.startswith(posixpath.sep):
        partial = partial[1:]
      path = os.path.join(self.real_directory, partial)
      return path

  def is_excluded(self, path):
    if path[-1] != posixpath.sep:
        path += posixpath.sep
    for ep in self.config['Passthrough']['Excluded_Paths']:
      if path.startswith(ep):
        return True
    return False

  def get_tmp_history_path(self):
    id = bhex(os.urandom(20))
    return os.path.join(self.config['Passthrough']['History'], id)

  def get_history_path(self, hash, size):
    hname = bhex(hash)+'-'+str(size)
    return os.path.join(self.config['Passthrough']['History'], hname)

  def _set_final_history_path(self, path):
    st = os.stat(path)
    hash = hash_file_async(path)
    def _(self, path, hash, st):
      hash = hash.get()
      hpath = self.get_history_path(hash, st.st_size)
      try:
        os.rename(path, hpath)
      except FileExistsError:
        os.unlink(path)
      return hash
    return AsyncTask(_,(self,path,hash,st)), st

  def move_to_history(self, path):
    tmp_path = self.get_tmp_history_path()
    os.rename(self.full_path(path), tmp_path)
    return self._set_final_history_path(tmp_path)

  def copy_to_history(self, path):
    tmp_path = self.get_tmp_history_path()
    copyfile_exclusive(self.full_path(path), tmp_path, self)
    return self._set_final_history_path(tmp_path)

  def get_real_path_by_hash_and_size(self, hash, size):
    path = self.get_history_path(hash, size)
    try:
      if os.path.getsize(path) == size and hash_file(path) == hash:
        return path
      else:
        self.fail_safe(path + ' - history file has wrong size or hash')
    except FileNotFoundError:
      pass
    return self.db.get_real_path_by_hash_and_size(hash, size)

  def get_open_fds_by_path(self, path):
    with self.fds_lock:
      return list(filter(lambda i: i == path, self.fds.values()))

  def lock_path(self, path, reentrant=True):
    while True:
      with self.paths_lock:
        try:
          l = self.paths[path]
          if reentrant and l['reentrant']:
            l['count'] += 1
            return
        except KeyError:
          self.paths[path] = {'reentrant': reentrant, 'count': 1}
          return
      time.sleep(0.1)

  def unlock_path(self, path):
    with self.paths_lock:
      try:
        l = self.paths[path]
        l['count'] -= 1
        if l['count'] < 1:
          del self.paths[path]
      except KeyError:
        pass

  def send_email(self, subject, msg):
    subject = '[ReflectiveNAS] ' + subject
    msg = 'Source: ' + self.config['Friendly_Name'] + '\n\n' + msg
    logging.critical('Sending email...\nSubject: ' + subject + '\n' + msg)
    try:
      m = email.message.EmailMessage()
      m['Subject'] = subject
      m['From'] = self.config['Email']['User']
      recipient = ', '.join(self.config['Email']['Recipients'])
      m['to'] = recipient
      m.set_content(msg)
      if self.config['Email']['SSL']:
        s = smtplib.SMTP_SSL(self.config['Email']['Host']+':'+str(self.config['Email']['Port']))
      else:
        s = smtplib.SMTP(self.config['Email']['Host']+':'+str(self.config['Email']['Port']))
      if self.config['Email']['TLS']:
        s.starttls()
      s.login(self.config['Email']['User'], self.config['Email']['Password'])
      s.send_message(m)
      s.quit()
      logging.info('Message sent!')
    except Exception as ex:
      logging.exception('Error sending email')

  def wait_for_exit(self):
    try:
      self.exit_event.wait()
    except KeyboardInterrupt:
      pass
    sys.exit(self.return_code)

  def exit(self, return_code = 0):
    first_exit = False
    with self.exit_in_progress_lock:
      if not self.exit_in_progress:
        self.exit_in_progress = True
        first_exit = True
    if first_exit:
      for callback in self.exit_callbacks:
        callback(return_code)
      self.db.close()
      self.return_code = return_code
      self.exit_event.set()
      os._exit(return_code)

  def fail_safe(self, reason, propagate=True):
    print('FAIL_SAFE', reason)
    logging.critical('FAIL_SAFE ' + reason)
    if not self.fail_locally:
      self.send_email('A Fail Safe Error has Occurred', 'Reason: ' + reason)
    for callback in self.fail_safe_callbacks:
      callback(reason, propagate=propagate)
    self.exit(1)

  def verbose_print(self, msg):
    if self.config['Verbose']:
      yr, mon, day, hr, min, sec, _, _, _ = time.localtime()
      t = '[%d-%02d-%02d %02d:%02d:%02d]' % (yr, mon, day, hr, min, sec)
      print(t, msg)

class PathLock(object):
  def __init__(self, core, path, reentrant=True, only_unlock_on_exception=False):
    self.core = core
    self.path = path
    self.only_unlock_on_exception = only_unlock_on_exception
    core.lock_path(path, reentrant=reentrant)

  def __enter__(self):
    return self

  def __exit__(self, et, exception, tb):
    if not self.only_unlock_on_exception or exception is not None:
      self.core.unlock_path(self.path)

class MemFSFile(object):
  def __init__(self, name, data, core, closes_remaining=-1):
    self.memfs_path = '/'+name+'_'+bhex(os.urandom(20))
    self.memfs = core.memfs
    self.memfs[self.memfs_path] = {'data': data, 'closes_remaining': closes_remaining}
    pd = self._remove_trailing_path_sep(core.config['Passthrough']['Proxy_Directory'])
    self.file_path = pd + self.memfs_path

  def _remove_trailing_path_sep(self, path):
    seps = {os.path.sep}
    if 'cygwin' in sys.platform.lower():
      seps.add('\\')
    if path[-1] in seps:
      return path[:-1]
    return path
  
  def __enter__(self):
    return self

  def __exit__(self, type, value, traceback):
    try: self.memfs.pop(self.memfs_path)
    except KeyError: pass

class FusePassthrough(fuse.Operations):
  def __init__(self, core):
    self.core = core
    self.system = platform.system()
    self.rwlock = threading.Lock()

    # Setup statvfs shim and ids if we're on Windows
    if self.system == 'Windows':
      self.uid, self.gid = self._get_uid_gid()
      from ctypes import WINFUNCTYPE, windll, POINTER, byref, c_ulonglong
      from ctypes.wintypes import BOOL, DWORD, LPCWSTR
      PULARGE_INTEGER = POINTER(c_ulonglong)
      GetDiskFreeSpaceExW = WINFUNCTYPE(BOOL, LPCWSTR, PULARGE_INTEGER, PULARGE_INTEGER, PULARGE_INTEGER)(("GetDiskFreeSpaceExW", windll.kernel32))
      GetLastError = WINFUNCTYPE(DWORD)(("GetLastError", windll.kernel32))
      def statvfs(path):
        n_free_for_user = c_ulonglong(0)
        n_total         = c_ulonglong(0)
        n_free          = c_ulonglong(0)
        r = GetDiskFreeSpaceExW(path, byref(n_free_for_user), byref(n_total), byref(n_free))
        if r == 0:
          raise OSError('[WinError %d] GetDiskFreeSpaceExW for %r' % (GetLastError(), path))
        return os.statvfs_result([
          4096,                        # f_bsize
          4096,                        # f_frsize
          n_total.value//4096,         # f_blocks
          n_free.value//4096,          # f_bfree
          n_free_for_user.value//4096, # f_bavail
          0,                           # f_files
          1,                           # f_ffree
          1,                           # f_favail
          0,                           # f_flag
          255])                        # f_namemax
      self._statvfs = statvfs
    else:
      self._statvfs = os.statvfs

  def _get_uid_gid(self):
    import subprocess
    d, f = os.path.split(fuse._libfuse_path)
    cmd = os.path.join(d, 'fsptool-x86.exe' if 'x86' in f else 'fsptool-x64.exe') + ' id'
    ids = {}
    for line in subprocess.check_output(cmd).splitlines():
      sp = line.split(b'=')
      ids[sp[-2].split(b'(')[-1]] = int(sp[-1][:-1])
    return ids[b'uid'], ids[b'gid']

  def start_async(self):
    def _(self):
      fuse.FUSE(self, self.core.config['Passthrough']['Proxy_Directory'],
                allow_other=self.core.config['Passthrough']['Allow_Other'],
                foreground=True)
      self.core.exit()
    return AsyncTask(_, (self,))

  def _copy_on_write(self, path, fd):
    modified = False
    with self.core.fds_lock:
      try:
        if not self.core.fds[fd]['created'] and not self.core.fds[fd]['modified']:
          self.core.fds[fd]['modified'] = True
          modified = True
      except KeyError:
        pass
    if modified:
      self.core.copy_to_history(path)

  def _ignore_excluded_paths(func):
    def wrapper(self, path, *args, **kwargs):
      if self.core.is_excluded(path):
        raise fuse.FuseOSError(errno.ENOENT)
      return func(self, path, *args, **kwargs)
    return wrapper

  def _handle_errors(func):
    def wrapper(*args, **kwargs):
      try:
        return func(*args, **kwargs)
      except OSError as err:
        raise fuse.FuseOSError(err.errno)
    return wrapper
    
  def _block_if_exit_in_progress(func):
    def wrapper(self, *args, **kwargs):
      if self.core.exit_in_progress:
        raise fuse.FuseOSError(errno.EACCES)
      return func(self, *args, **kwargs)
    return wrapper

  @_block_if_exit_in_progress
  @_ignore_excluded_paths
  @_handle_errors
  def chmod(self, path, mode):
    return os.chmod(self.core.full_path(path), mode)

  def chown(self, path, uid, gid):
    raise fuse.FuseOSError(errno.ENOTSUP)

  @_block_if_exit_in_progress
  @_ignore_excluded_paths
  @_handle_errors
  def create(self, path, mode):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(self.core.full_path(path), flags, mode)
    with self.core.fds_lock:
      if fd in self.core.fds:
        self.core.fail_safe('create used already existing fd')
      self.core.fds[fd] = {'path': path, 'flags': flags, 'mode': mode, 'modified': False, 'created': True}
    return fd

  @_ignore_excluded_paths
  @_handle_errors
  def flush(self, path, fh):
    if path in self.core.memfs:
      return None
    return os.fsync(fh)

  @_ignore_excluded_paths
  @_handle_errors
  def fsync(self, path, fdatasync, fh):
    return self.flush(path, fh)

  @_ignore_excluded_paths
  @_handle_errors
  def getattr(self, path, fh=None):
    if path in self.core.memfs:
      d = {'st_atime': 0, 'st_ctime': 0, 'st_mtime': 0, 'st_mode': stat.S_IFREG, 'st_nlink': 1,
           'st_size': len(self.core.memfs[path]['data']), 'st_uid': 0, 'st_gid': 0}
      try:
        d['st_gid'] = os.getgid()
        d['st_uid'] = os.getuid()
      except AttributeError:
        pass
    else:
      st = os.lstat(self.core.full_path(path))
      d = dict((k, getattr(st, k)) for k in ('st_atime', 'st_ctime', 'st_gid', 'st_mode',
                                             'st_mtime', 'st_nlink', 'st_size', 'st_uid'))
    if self.system == 'Windows':
      d['st_uid'] = self.uid
      d['st_gid'] = self.gid
    d['st_mode'] |= 0o777
    return d

  @_block_if_exit_in_progress
  @_ignore_excluded_paths
  @_handle_errors
  def mkdir(self, path, mode):
    with PathLock(self.core, path, only_unlock_on_exception=True):
      r = os.mkdir(self.core.full_path(path), mode)
    self.core.db.record_change_async(Action.CREATE, path, hash=b'', size=0)
    return r

  @_block_if_exit_in_progress
  @_ignore_excluded_paths
  @_handle_errors
  def open(self, path, flags):
    if path in self.core.memfs:
      return int.from_bytes(os.urandom(2), byteorder='big')

    fd = os.open(self.core.full_path(path), flags)
    with self.core.fds_lock:
      if fd in self.core.fds:
        self.core.fail_safe('open used already existing fd')
      self.core.fds[fd] = {'path': path, 'flags': flags, 'modified': False, 'created': False}
    return fd

  @_ignore_excluded_paths
  @_handle_errors
  def read(self, path, length, offset, fh):
    with self.rwlock:
      if path in self.core.memfs:
        return self.core.memfs[path]['data'][offset:length]

      new_offset = os.lseek(fh, offset, os.SEEK_SET)
      assert(new_offset == offset)
      return os.read(fh, length)

  @_ignore_excluded_paths
  @_handle_errors
  def readdir(self, path, fh):
    memfs = [i[1:] for i in self.core.memfs] if path == '/' else []
    ls = os.listdir(self.core.full_path(path))
    ls = filter(lambda i: not self.core.is_excluded(posixpath.join(path, i)), ls)
    return ['.', '..'] + list(ls) + memfs

  def readlink(self, path):
    raise fuse.FuseOSError(errno.ENOTSUP)

  @_ignore_excluded_paths
  @_handle_errors
  def release(self, path, fd):
    try:
      if self.core.memfs[path]['closes_remaining'] > 0:
        self.core.memfs[path]['closes_remaining'] -= 1
      if self.core.memfs[path]['closes_remaining'] == 0:
        try: self.core.memfs.pop(path)
        except: pass
      return
    except KeyError:
      pass

    with self.core.fds_lock:
      try:
        f = self.core.fds[fd]
      except KeyError:
        return None
      del self.core.fds[fd]
      if f['created'] or f['modified']:
        with PathLock(self.core, path, only_unlock_on_exception=True):
          r = os.close(fd)
      else:
        r = os.close(fd)
    if f['created']:
      self.core.db.record_change_async(Action.CREATE, path)
    elif f['modified']:
      self.core.db.record_change_async(Action.UPDATE, path)
    return r

  def _recursive_move(self, old, new):
    new_path = self.core.full_path(new)
    try:
      with PathLock(self.core, new, only_unlock_on_exception=True):
        r = os.mkdir(new_path)
      self.core.db.record_change_async(Action.CREATE, new, hash=b'', size=0)
    except FileExistsError:
      pass

    old_path = self.core.full_path(old)
    for file in os.listdir(old_path):
      self.rename(os.path.join(old, file), os.path.join(new, file))

    with PathLock(self.core, old, only_unlock_on_exception=True):
      mt = os.path.getmtime(old_path)
      os.rmdir(old_path)
    self.core.db.record_change_async(Action.DELETE, old, hash=b'', size=0, mtime=mt)

  @_block_if_exit_in_progress
  @_ignore_excluded_paths
  @_handle_errors
  def rename(self, old, new):
    old_path = self.core.full_path(old)
    if os.path.isdir(old_path):
      self._recursive_move(old, new)
    else:
      new_path = self.core.full_path(new)
      with PathLock(self.core, old, only_unlock_on_exception=True):
        with PathLock(self.core, new, reentrant=False, only_unlock_on_exception=True):
          if os.path.exists(new_path):
            raise FileExistsError()
          r = os.rename(old_path, new_path)
          st = os.stat(new_path)
          mt = st.st_mtime
          ts = time.time()
          if stat.S_ISDIR(st.st_mode):
            h = b''
            sz = 0
          else:
            h = hash_file_async(new_path)
            sz = st.st_size
      self.core.db.record_change_async(Action.MOVE_SOURCE, old, timestamp=ts, hash=h, size=sz, mtime=mt)
      self.core.db.record_change_async(Action.MOVE_DESTINATION, new, timestamp=ts, hash=h, size=sz, mtime=mt)

  @_block_if_exit_in_progress
  @_ignore_excluded_paths
  @_handle_errors
  def rmdir(self, path):
    full_path = self.core.full_path(path)
    with PathLock(self.core, path, only_unlock_on_exception=True):
      mt = os.path.getmtime(full_path)
      r = os.rmdir(full_path)
    self.core.db.record_change_async(Action.DELETE, path, hash=b'', size=0, mtime=mt)
    return r

  @_ignore_excluded_paths
  @_handle_errors
  def statfs(self, path):
    sfs = self._statvfs(self.core.full_path(path))
    return dict((k, getattr(sfs, k)) for k in ('f_bavail', 'f_bfree', 'f_blocks', 'f_bsize', 'f_favail',
                                                 'f_ffree', 'f_files', 'f_flag', 'f_frsize', 'f_namemax'))

  def symlink(self, target, source):
    raise fuse.FuseOSError(errno.ENOTSUP)

  @_block_if_exit_in_progress
  @_ignore_excluded_paths
  @_handle_errors
  def truncate(self, path, length, fd=None):
    if fd is None:
      with PathLock(self.core, path, only_unlock_on_exception=True):
        self.core.copy_to_history(path)
        with open(self.core.full_path(path), 'r+') as f:
          f.truncate(length)
      self.core.db.record_change_async(Action.UPDATE, path)
    elif fd not in self.core.fds:
      self.core.fail_safe(path + ' - ' + str(fd) + ' - truncate called on untracked fd')
    else:
      with PathLock(self.core, path):
        self._copy_on_write(path, fd)
        os.truncate(fd, length)
      # create or open was already called for this file so wait for release to be called before recording changes

  @_block_if_exit_in_progress
  @_ignore_excluded_paths
  @_handle_errors
  def unlink(self, path):
    hash, st = self.core.move_to_history(path)
    self.core.db.record_change_async(Action.DELETE, path, hash=hash, size=st.st_size, mtime=st.st_mtime)

  @_block_if_exit_in_progress
  @_ignore_excluded_paths
  @_handle_errors
  def utimens(self, path, times=None):
    r = os.utime(self.core.full_path(path), times)
    open_fds = self.core.get_open_fds_by_path(path)
    if len(open_fds) > 0:
      for fd in open_fds:
        if not fd['created']:
          fd['modified'] = True
    else:
      _, mtime = times
      self.core.db.record_change_async(Action.UPDATE, path, mtime=mtime)
    return r

  @_ignore_excluded_paths
  @_handle_errors
  def write(self, path, data, offset, fd):
    with self.rwlock:
      with PathLock(self.core, path):
        self._copy_on_write(path, fd)
        os.lseek(fd, offset, os.SEEK_SET)
        return os.write(fd, data)

class SynchronizationRequestHandler(http.server.BaseHTTPRequestHandler):
  def log_message(self, format, *args):
    core = self.server.synchronizer.core
    core.verbose_print(self.address_string() + ' - ' + format%args)

  def _authenticate(func):
    def wrapper(self, *args, **kwargs):
      core = self.server.synchronizer.core
      secret = core.config['Local_Server']['Secret']
      xsecret = self.headers.get('X-Secret')
      if xsecret != secret:
        request_info = repr(self.__dict__)+'\n-=Headers=-\n'+str(self.headers)
        logging.error('unauthenticated request\n'+request_info)
        core.verbose_print('Blocked unauthenticated request from ' + self.address_string())
        return
      return func(self, *args, **kwargs)
    return wrapper

  def _send_response_and_headers(self, content_type, code=200, content_length=None):
    self.send_response(code)
    self.send_header('Content-Type', content_type)
    if content_length is not None:
      self.send_header('Content-Length', content_length)
    self.end_headers()

  def _send_json(self, payload):
    j = json.dumps(payload)
    self._send_response_and_headers('text/json')
    self.wfile.write(j.encode())

  def _get_ranges(self):
    h = self.headers.get('Range')
    if h is None:
      return []
    h = h.split('=')[1]
    ranges = []
    for r in h.split(', '):
      range = tuple(map(int, r.split('-')))
      if range[1] < range[0] or range[0] < 0:
        self.send_error(400)
        raise Exception('invalid range')
      ranges.append(range)
    return ranges

  @_authenticate
  def do_GET(self):
    s = self.server.synchronizer
    if self.path == '/status':                   # GET /status
      core = self.server.synchronizer.core
      self._send_json({
        'code_hash': bhex(s.core.code_hash),
        'db_hash': bhex(s.db_hash),
        'last_timestamp': s.last_local_timestamp,
        'delay_between_syncs': core.config['Synchronization']['Delay_Between_Syncs'],
      })
    elif self.path.startswith('/changes/'):      # GET /changes/{timestamp}/{page}
      sp = self.path.split('/')
      timestamp = float(sp[2])
      page = int(sp[3])
      changes = list(map(list, s.core.db.get_changes_since(timestamp, page)))
      for change in changes:
        change[3] = bhex(change[3])
      self._send_json(changes)
    elif self.path.startswith('/file/'):         # GET /file/{hash}-{size}
      id = self.path.split('/')[2].split('-')
      hash = bytes.fromhex(id[0])
      size = int(id[1])
      ranges = self._get_ranges()
      if ranges == []:
        ranges = [(0,size)]
      path = s.core.get_real_path_by_hash_and_size(hash, size)
      if path is None:
        self.send_error(404)
      else:
        self.log_message('Beginning to send ' + path)
        with open(path, 'rb') as f:
          content_length = sum([(i[1]-i[0]) for i in ranges])
          self._send_response_and_headers('application/octet-stream', code=206, content_length=content_length)
          for range in ranges:
            remaining = range[1] - range[0]
            f.seek(range[0])
            while remaining > 0:
              buf = f.read(min(4096, remaining))
              remaining -= len(buf)
              self.wfile.write(buf)
        self.log_message('Finished sending ' + path)

  @_authenticate
  def do_POST(self):
    if self.path == '/fail_safe':                # POST /fail_safe
      l = int(self.headers.get('content-length'))
      reason = json.loads(self.rfile.read(l).decode())
      self._send_json("OK")
      self.server.synchronizer.core.fail_safe(reason, propagate=False)

class SynchronizationServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
  synchronizer = None

class SynchronizationServerUnavailableException(Exception):
  pass

class IgnoreHostNameAdapter(requests.adapters.HTTPAdapter):
  def init_poolmanager(self, connections=3, maxsize=3, block=False):
    PoolManager = requests.packages.urllib3.poolmanager.PoolManager
    self.poolmanager = PoolManager(num_pools=connections,
                                   maxsize=maxsize,
                                   block=block,
                                   assert_hostname=False)

class SynchronizationClient(object):
  def __init__(self, url, secret, core, use_memfs=True):
    self.url = url
    if self.url.endswith('/'):
      self.url = self.url[:-1]
    self.secret = secret
    self.core = core
    self.use_memfs = use_memfs
    self.retry_count = self.core.config['Synchronization']['Retry_Count']
    self.retry_delay = self.core.config['Synchronization']['Retry_Delay']

  def _do_request(self, verb, args, kwargs):
    if 'timeout' not in kwargs:
      kwargs['timeout'] = self.core.config['Synchronization']['Timeout']
    for _ in range(self.retry_count):
      try:
        session = requests.Session()
        session.headers['X-Secret'] = self.secret
        session.mount('https://', IgnoreHostNameAdapter())
        if self.use_memfs:
          with MemFSFile('.cert', self.core.cached_cert, self.core) as cert:
            return getattr(session, verb)(*args, verify = cert.file_path, **kwargs)
        else:
          cert_path = self.core.config['Local_Server']['Cert_Path']
          return getattr(session, verb)(*args, verify = cert_path, **kwargs)
      except requests.exceptions.RequestException:
        time.sleep(self.retry_delay)
    raise SynchronizationServerUnavailableException()

  def _get(self, *args, **kwargs):
    return self._do_request('get', args, kwargs)

  def _post(self, *args, **kwargs):
    return self._do_request('post', args, kwargs)
  
  def status(self):
    return self._get(self.url+'/status').json()

  def get_changes_since(self, timestamp, page=0):
    changes = self._get(self.url+'/changes/'+str(timestamp)+'/'+str(page)).json()
    for change in changes:
      change[3] = bytes.fromhex(change[3])
    return list(map(tuple, changes))

  def get_file(self, hash, size, local_path, offset=0):
    local_copy = self.core.get_real_path_by_hash_and_size(hash, size)
    if local_copy:
      copyfile_exclusive(local_copy, local_path)
    else:
      url = self.url+'/file/'+bhex(hash)+'-'+str(size)
      chunk_size = 4096
      retry_count = (round(size/chunk_size)+1)*self.retry_count
      with open(local_path, 'xb') as f:
        for itr in range(retry_count):
          try:
            rng = 'bytes='+str(offset)+'-'+str(size)
            r = self._get(url, stream=True, headers={'Range': rng})
            if r.status_code == 404:
              f.close()
              os.remove(local_path)
              raise FileNotFoundError(url)
            for chunk in r.iter_content(chunk_size=chunk_size):
              if chunk:
                f.write(chunk)
                offset += len(chunk)
            break
          except requests.exceptions.RequestException:
            if itr == retry_count-1:
              self.core.fail_safe(url + ' - failed to download file too many times')
            time.sleep(self.retry_delay)
    if os.path.getsize(local_path) != size or hash_file(local_path) != hash:
      self.core.fail_safe(local_path + ' - retrieved file has wrong size or hash')

  def fail_safe(self, reason):
    try: self._post(self.url+'/fail_safe', json=reason, timeout=1)
    except SynchronizationServerUnavailableException: pass

class Synchronizer(object):
  def __init__(self, core, start_worker=True, use_memfs=True):
    self.core = core
    self.hd_age_email_sent = False
    self.ssl_socket = None
    self.db_hash = core.db.get_var('db_hash') or b''
    self.last_local_timestamp = core.db.get_var('last_local_timestamp') or 0
    self.last_remote_timestamp = core.db.get_var('last_remote_timestamp') or 0
    self.remote_servers = []
    self.use_memfs = use_memfs
    for server in self.core.config['Remote_Servers']:
      client = SynchronizationClient(server['URL'], server['Secret'], core, use_memfs=use_memfs)
      self.remote_servers.append(client)
    if start_worker:
      self.worker_thread = threading.Thread(target=self._worker, daemon=True)
      self.worker_thread.start()
    core.fail_safe_callbacks.append(lambda *a, **k: self.fail_safe_callback(*a, **k))
    core.exit_callbacks.append(lambda *a, **k: self.exit_callback(*a, **k))
    self.finished_applying_changes_event = threading.Event()
    self.finished_applying_changes_event.set()
    self.last_hash_mismatch_times = {}

  def _worker(self):
    while True:
      self.update_DNS_records()
      if self.core.config['Local_Server']['Start_Server']:
        self.start_server()
      if self.core.config['Email']['Notify_When_HD_Should_Be_Replaced']:
        self.check_hd_age()
      self.verify_database_and_files()
      self.core.verbose_print('Waiting')
      time.sleep(self.core.config['Synchronization']['Delay_Between_Syncs'])
      self.pull_changes_from_remote_servers()
      if self.core.config['Local_Server']['Start_Server']:
        self.kill_server()

  def update_DNS_records(self):
    self.core.verbose_print('Updating DNS record')
    try:
      requests.get(self.core.config['Local_Server']['DNS_Update_URL'])
    except:
      pass

  def check_hd_age(self):
    if not self.hd_age_email_sent and time.time() > self.core.config['Email']['HD_Replace_Date']:
      self.core.send_email('Replace Hard Drive', 'This hard drive is due to be replaced.')
      self.hd_age_email_sent = True

  def verify_database_and_files(self):
    self.core.verbose_print('Verifying database')
    db_hash, last_local_timestamp, _ = self.core.db.verify_database()
    if db_hash != self.db_hash:
      self.db_hash = db_hash
      self.core.db.set_var('db_hash', db_hash)
    if last_local_timestamp != self.last_local_timestamp:
      self.last_local_timestamp = last_local_timestamp
      self.core.db.set_var('last_local_timestamp', last_local_timestamp)

    config = self.core.config['Synchronization']
    p = config['Probability_of_Checking_Files']
    should_check_files = p*(2**16)/100 > int.from_bytes(os.urandom(2),byteorder='big')
    if should_check_files:
      self.core.verbose_print('Checking local files')
      paths = self.core.db.get_n_random_paths(config['Number_of_Files_To_Check'])
      for path in paths:
        self.core.verbose_print('Checking ' + path)
        db_st = self.core.db.stat(path)
        full_path = self.core.full_path(path)
        try:
          real_st = os.stat(full_path)
          if db_st is None:
            self.core.fail_safe(path + ' - file deleted in DB but actually exists')
          db_is_dir = db_st['hash'] == b''
          real_is_dir = stat.S_ISDIR(real_st.st_mode)
          if real_is_dir != db_is_dir:
            self.core.fail_safe(path + ' - DB-real file-dir mismatch')
          if len(self.core.get_open_fds_by_path(path)) == 0:
            if real_st.st_mtime != db_st['mtime'] and not real_is_dir:
              self.core.fail_safe(path + ' - DB and real have different mtimes')
            real_size = 0 if real_is_dir else real_st.st_size
            if real_size != db_st['size']:
              self.core.fail_safe(path + ' - DB and real have different sizes')
            real_hash = b'' if real_is_dir else hash_file(full_path)
            if real_hash != db_st['hash']:
              self.core.fail_safe(path + ' - DB and real have different hashes')
        except FileNotFoundError:
          if db_st:
            self.core.fail_safe(path + ' - path exists in DB but not in real')

  def start_server(self):
    self.core.verbose_print('Starting server')
    self.server = SynchronizationServer(('', self.core.config['Local_Server']['Port']), SynchronizationRequestHandler)
    self.server.synchronizer = self
    self.server.daemon_threads = True
    if self.use_memfs:
      with MemFSFile('.cert', self.core.cached_cert, self.core) as cert:
        with MemFSFile('.key', self.core.cached_key, self.core) as key:
          self.server.socket = ssl.wrap_socket(self.server.socket,
                                               certfile=cert.file_path,
                                               keyfile=key.file_path,
                                               server_side=True)
    else:
      self.server.socket = ssl.wrap_socket(self.server.socket,
                                           certfile=self.core.config['Local_Server']['Cert_Path'],
                                           keyfile=self.core.config['Local_Server']['Key_Path'],
                                           server_side=True)
    def _(self):
      self.server.serve_forever()
      self.server.server_close()
    self.server_thread = threading.Thread(target=_, args=(self,), daemon=True)
    self.server_thread.start()

  def kill_server(self):
    self.core.verbose_print('Stopping server')
    self.server.shutdown()

  def apply_changes(self, changes, server):
    self.finished_applying_changes_event.clear()

    source_dict = {}
    final_states = {}
    for change in changes:
      timestamp, act, path, hash, size, mtime = change
      action = Action(act)
      if action == Action.MOVE_SOURCE:
        source_dict[(timestamp,hash,size,mtime)] = path
      if action in DESTROY_ACTIONS:
        try: final_states.pop(path)
        except KeyError: pass
      else:
        final_states[path] = (hash,size)
    final_states = set(final_states.values())

    skipped_paths = set()
    for change in changes:
      timestamp, act, path, hash, size, mtime = change
      action = Action(act)
      fpath = self.core.full_path(path)

      if self.core.exit_in_progress:
        return
      
      with PathLock(self.core, path, reentrant=False, only_unlock_on_exception=True):
        if action == Action.CREATE:
          self.core.verbose_print('Applying change from ' + server.url + ' - Creating ' + path)
          try:
            if len(hash):
              try:
                server.get_file(hash, size, fpath)
              except FileNotFoundError:
                if (hash,size) in final_states:
                  self.core.fail_safe(server.url + ' - ' + path + ' - missing create data')
                else:
                  skipped_paths.add(path)
            else:
              os.mkdir(fpath)
          except FileExistsError:
            self.core.fail_safe(server.url + ' - ' + path + ' - CONFLICT: create on existing path')
        elif action == Action.UPDATE:
          self.core.verbose_print('Applying change from ' + server.url + ' - Updating ' + path)
          db_st = self.core.db.stat(path)
          if not (db_st and db_st['hash'] == hash and db_st['size'] == size):
            try:
              self.core.move_to_history(path)
            except FileNotFoundError:
              if path not in skipped_paths:
                self.core.fail_safe(server.url + ' - ' + path + ' - CONFLICT: update on nonexistent path')
            try:
              server.get_file(hash, size, fpath)
            except FileNotFoundError:
              if (hash,size) in final_states:
                self.core.fail_safe(server.url + ' - ' + path + ' - missing update data')
              else:
                skipped_paths.add(path)
        elif action == Action.DELETE:
          self.core.verbose_print('Applying change from ' + server.url + ' - Deleting ' + path)
          try:
            if len(hash):
              self.core.move_to_history(path)
            else:
              os.rmdir(fpath)
          except FileNotFoundError:
            if path not in skipped_paths:
              self.core.fail_safe(server.url + ' - ' + path + ' - CONFLICT: delete on nonexistent path')
        elif action == Action.MOVE_DESTINATION:
          try:
            old = source_dict[(timestamp,hash,size,mtime)]
            self.core.verbose_print('Applying change from ' + server.url + ' - Moving ' + old + ' to ' + path)
            os.rename(self.core.full_path(old), fpath)
          except (FileNotFoundError, KeyError):
            if (hash,size) in final_states:
              self.core.fail_safe(server.url + ' - ' + path + ' - CONFLICT: MOVE_DESTINATION missing source')
        if action not in DESTROY_ACTIONS:
          try: os.utime(fpath, (mtime, mtime))
          except FileNotFoundError: pass
      self.core.db.record_change(action, path, timestamp, hash, size, mtime)

  def pull_changes_from_remote_servers(self):
    last_remote_timestamp = self.last_remote_timestamp
    skipped_a_server = False
    no_unexpected_hash_mismatch = True
    for server in self.remote_servers:
      self.core.verbose_print('Beginning to pull changes from ' + server.url)
      try:
        status = server.status()
        if status['code_hash'] != bhex(self.core.code_hash):
          self.core.fail_safe(server.url + ' - remote server is running a different version')
        if bhex(self.db_hash) != status['db_hash']:
          if status['last_timestamp'] > self.last_remote_timestamp:
            new_changes = set()
            page = 0
            while True:
              remote_changes = server.get_changes_since(self.last_remote_timestamp, page)
              if len(remote_changes) < 1:
                if new_changes:
                  for change in new_changes:
                    last_remote_timestamp = max(last_remote_timestamp, change[0])
                break
              new_changes.update(self.core.db.filter_existing_changes(remote_changes, self.last_remote_timestamp))
              if len(new_changes) >= CHANGE_PAGE_SIZE:
                break
              page += 1
            if new_changes:
              new_changes = sorted(list(new_changes), key=lambda i: i[0])
              self.apply_changes(new_changes, server)
          else:
            no_unexpected_hash_mismatch = False
            if server not in self.last_hash_mismatch_times:
              self.last_hash_mismatch_times[server] = time.time()
            max_delay_between_syncs = 2*max(status['delay_between_syncs'], self.core.config['Synchronization']['Delay_Between_Syncs'])
            if (self.last_hash_mismatch_times[server]-time.time()) > max_delay_between_syncs:
              self.core.fail_safe(server.url + ' - databases out of sync')
      except SynchronizationServerUnavailableException:
        skipped_a_server = True
        if self.core.config['Email']['Notify_When_Other_Servers_Are_Offline']:
          self.core.send_email('Warning: A server could not be reached for synchronization',
                               server.url + ' could not be reached.')
      self.core.verbose_print('Finished pulling changes from ' + server.url)
      self.finished_applying_changes_event.set()
      if no_unexpected_hash_mismatch and server in self.last_hash_mismatch_times:
        self.last_hash_mismatch_times.pop(server)
    if not skipped_a_server and last_remote_timestamp > self.last_remote_timestamp:
      self.last_remote_timestamp = last_remote_timestamp
      self.core.db.set_var('last_remote_timestamp', last_remote_timestamp)

  def fail_safe_callback(self, reason, propagate=False):
    if propagate:
      reason = self.core.config['Friendly_Name'] + ' - ' + reason
      for server in self.remote_servers:
        t = threading.Thread(target=lambda r: server.fail_safe(r), args=(reason,), daemon=True)
        t.start()
  
  def exit_callback(self, return_code):
    if not self.finished_applying_changes_event.is_set():
      self.finished_applying_changes_event.wait()

def main():
  import argparse
  parser = argparse.ArgumentParser(description='ReflectiveNAS Server\nSee readme.md for help.')
  parser.add_argument('-c', '--config', help='config file path', default='config.json')
  args = parser.parse_args()

  core = Core(config_path=args.config)
  synchronizer = Synchronizer(core)
  passthrough = FusePassthrough(core)
  passthrough.start_async()
  core.wait_for_exit()

if __name__ == '__main__':
  main()
