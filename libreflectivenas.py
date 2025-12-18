import sys, os, time

def load_config(path = None):
  config_path = path or os.environ.get('LIBREFLECTIVENAS_CONFIG')
  if not config_path:
    xdg_config_home = os.environ.get('XDG_CONFIG_HOME')
    if xdg_config_home:
      config_path = os.path.join(xdg_config_home, 'libreflectivenas.toml')
  if not config_path:
    appdata = os.environ.get('APPDATA')
    if appdata:
      config_path = os.path.join(appdata, 'libreflectivenas.toml')
  if not config_path:
    config_path = os.path.expanduser(
      os.path.join('~', '.config', 'libreflectivenas.toml'))
  with open(config_path, 'rb') as f:
    import tomllib
    return tomllib.load(f)

_parse_map = {
  'path': ('path', 'root'),
  'username': ('user', 'username'),
  'password': ('password', 'pass'),
  'port': ('port',),
  'key_filename': ('key_filename', 'key_file',
                   'identity_filename', 'identity_file'),
}

def _parse_site(site):
  s, _, path = site['address'].partition(':')
  user, _, hostname = s.rpartition('@')
  parsed = {'hostname': hostname}
  missing = object()
  if user:
    parsed['username'] = user
  if path:
    parsed['path'] = path
  for pkey, ckeys in _parse_map.items():
    for pfx in ('ssh_', ''):
      for ckey in ckeys:
        if pkey in parsed:
          continue
        value = site.get(pfx + ckey, missing)
        if value is not missing:
          parsed[pkey] = value
  key = parsed.get('key_filename', missing)
  if key is not missing:
    key = os.path.expandvars(os.path.expanduser(key))
    parsed['key_filename'] = key
  return parsed

def _parse_sites(config):
  return list(map(_parse_site, config.get('sites', [])))

def _build_address(site):
        address = site['hostname']
        user = site.get('username')
        if user:
          address = user+'@'+address
        path = site.get('path')
        if path:
          address = address+':'+path
        return address

def _make_config_key(sites):
  return '\n-\n'.join(('\n'.join(
    '{} {}'.format(repr(k), repr(site[k]))
    for k in sorted(site.keys()))
    for site in sites))

def _get_timeout(config, site, default = 15):
  timeout = site.get('connection_timeout')
  if timeout:
    return timeout
  timeout = config.get('connection_timeout')
  if timeout:
    return timeout
  return default

def _pushwd(path):
  globals().setdefault('_chdir_stack', []).append(os.getcwd())
  try:
    os.chdir(path)
  except:
    _popwd()
    raise

def _popwd():
  os.chdir(globals()['_chdir_stack'].pop())

def _validate_dev(st, dev, path = None):
    if st.st_dev != dev:
      import errno
      raise PermissionError(errno.EACCES,
                            'Symlink points to path outside of NAS',
                            path)

def _with_chdir(func, *args, **kwargs):
    wd = kwargs.pop('_dir_path_a')
    wd_pushed = False
    try:
      _pushwd(wd)
      wd_pushed = True
      _validate_dev(os.stat(os.curdir), kwargs.pop('_st_dev'), path = wd)
      return func(*args, **kwargs)
    finally:
      if wd_pushed:
        _popwd()

class ReflectiveNASAttributes(object):
  @classmethod
  def from_stat(cls, obj, filename = None):
    attr = cls()
    attr.filename = filename
    attr.attr = {}
    for i in dir(obj):
      attr.attr[i] = getattr(obj, i)
    for i in ('st_size', 'st_uid', 'st_gid', 'st_mode',
              'st_atime', 'st_mtime'):
      setattr(attr, i, attr.attr.pop(i))
    return attr

def _raise_file_not_found(name, msg = None):
  import errno
  raise FileNotFoundError(errno.ENOENT, msg or os.strerror(errno.ENOENT), name)

def _warn_get_path(other, ignore_security_warning):
  if ignore_security_warning:
    return
  import warnings
  other = 'other ' if other else ''
  msg = (
    'get_path() is less secure than the {}functions in'.format(other) +
    'ReflectiveNASConnection as it does not protect against symlinks which' +
    ' point to local files. Consider using them instead or set ' +
    'ignore_security_warning to suppress this message. Only use this ' +
    'function for operations that cannot be performed with ' +
    'ReflectiveNASConnection\'s functions.'
  )
  warnings.warn(msg, stacklevel = 2)

class ReflectiveNASConnection(dict):
  def __init__(self,
               path = None,
               client = None,
               cfg = None,
               weak = False,
               cached = False):
    if path is not None:
      self._path = path
    self._client = client
    if client:
      self['has_client'] = True
    self['cfg'] = cfg
    if weak:
      self._weak = True
    if cached:
      self['cached'] = True

  def __del__(self):
    path = getattr(self, '_path', None)
    if path and not getattr(self, '_weak', False):
      cleanup_path(path, config = self['cfg'])

  def chdir(path = None):
    if self._client:
      return self._client.chdir(path = path)
    self.cwd = path

  def getcwd(self):
    if self._client:
      return self._client.getcwd()
    return getattr(self, 'cwd', None)

  def get_path(self, ignore_security_warning = False):
    path = getattr(self, '_path', None)
    if not path:
      return path
    _warn_get_path(True, ignore_security_warning)
    return path

  def to_dict(self, weak = False):
    d = dict(self)
    if weak:
      d['path'] = getattr(self, '_path', None)
    return d

  @classmethod
  def from_dict(cls, d):
    path = d.get('path')
    config = d.get('cfg')
    site_index = d.get('site_index')
    cached = d.get('cached')
    weak = bool(path)
    if weak and os.path.ismount(path):
      connection = cls(path = path, cfg = config, weak = True, cached = cached)
      if site_index is not None:
        connection._site_index = site_index
      return connection
    kwargs = {'use_cache': cached}
    if site_index is not None:
      kwargs['starting_site_index'] = site_index
    if d.get('has_client'):
      return get_connection(config, **kwargs)
    if (connection := get_sshfs_connection(config, **kwargs)):
      return connection
    return get_sshfs_connection(config, **kwargs)

  def __reduce__(self):
    return (self.from_dict, (self.to_dict(),))

  def __repr__(self):
    r = '{} at {}'.format(self.__class__.__name__, hex(id(self)))
    try:
      site = self['cfg']['sites'][self['site_index']]
      return '<{} to {}>'.format(r, _build_address(_parse_site(site)))
    except (KeyError, IndexError):
      return '<{}>'.format(r)

  def _join(self, *parts):
    absroot = os.path.abspath('/')
    joined = os.path.abspath(os.path.join(absroot, *parts))
    joined = joined[len(absroot):]
    wd = self.getcwd()
    if wd is None:
      wd = '/'
    if self._path:
      wd = os.path.join(self._path, wd[1:]) if len(wd) > 1 else self._path
    return os.path.abspath(os.path.join(wd, joined))

  def _get_dev(self):
    dev = getattr(self, '_st_dev', None)
    if dev is not None:
      return dev
    dev = os.lstat(self._path).st_dev
    self._st_dev = dev
    return dev

  def _validate_stat_con_dev(self, st, path = None):
    _validate_dev(st, self._get_dev(), path = path)

  def _validate_path_dev(self, fd = None, path = None):
    st = os.stat(path if fd is None else path,
                 follow_symlinks = type(fd_or_path) is int)
    self._validate_stat_con_dev(st, path = path)

  def _with_dirfd(self, func, *args, **kwargs):
    path_idx_a, path_idx_b = kwargs.pop('_path_idxs', (0, None))
    dir_path_a, filename = os.path.split(self._join(args[path_idx_a]))
    args = list(args)
    args[path_idx_a] = filename
    if path_idx_b is not None:
       path_b = self._join(args[path_idx_b])
    wd_pushed = False
    try:
      if func in os.supports_dir_fd:
        if path_idx_b is None:
          dirs = ((dir_path_a, 'dir_fd'),)
        else:
          dir_path_b, filename = os.path.split(path_b)
          args[path_idx_b] = filename
          dirs = ((dir_path_a, 'src_dir_fd'), (dir_path_b, 'dst_dir_fd'))
        for dir_path, kw in dirs:
          fd = os.open(dir_path, os.O_RDONLY)
          kwargs[kw] = fd
          self._validate_path_dev(fd = fd, path = dir_path)
        return func(*args, **kwargs)
      else:
        import multiprocessing
        use_mp_pool_cache = self['cfg'].get('use_mp_pool_cache', True)
        kwargs['_dir_path_a'] = dir_path_a
        kwargs['_st_dev'] = self._get_dev()
        arg = [func] + args
        if path_idx_b is not None:
          args[path_idx_b] = path_b
          self._validate_path_dev(path = os.path.dirname(path_b))
        if use_mp_pool_cache:
          if (pool := getattr(self, '_pool', None)) is None:
            pool = multiprocessing.Pool(1)
            self._pool = pool
          return pool.apply(_with_chdir, args, kwargs)
        else:
          with (pool := multiprocessing.Pool(1)):
            return pool.apply(_with_chdir, args, kwargs)
    finally:
      for k,v in kwargs.items():
        if k.endswith('_fd'):
          os.close(v)

  def listdir_iter(self, path = '.', read_aheads = 50):
    if self._client:
      for a in self._client.listdir_iter(path = path,
                                        read_aheads = read_aheads):
        attr = ReflectiveNASAttributes()
        for k,v in a.__dict__.items():
          if not k.startswith('_'):
            setattr(attr, k, v)
        yield attr
    else:
      with os.scandir(self._join(path)) as it:
        for entry in it:
          st = entry.stat(follow_symlinks = False)
          self._validate_stat_con_dev(st, path = entry.path)
          yield ReflectiveNASAttributes.from_stat(st, filename = entry.name)

  def listdir_attr(self, path = '.'):
    return list(self.listdir_iter(path = path))

  def listdir(self, path = '.'):
    if self._client:
      return self._client.listdir(path = path)
    return [i.filename for i in self.listdir_iter(path = path)]

  def mkdir(self, path, mode = 0o777):
    if self._client:
      return self._client.mkdir(path, mode = mode)
    if os.name == 'nt' and (mode != 0o700 or self['cfg'].get('fast_mkdir')):
      os.close(self._open_nt(path, os.O_CREAT | os.O_EXCL, is_dir = True))
      return
    self._with_dirfd(os.mkdir, path, mode = mode)

  def rename(self, oldpath, newpath):
    if self._client:
      return self._client.rename(oldpath, newpath)
    self._with_dirfd(os.rename, oldpath, newpath,
                     _path_idxs = (0, 1))

  def remove(self, path):
    if self._client:
      return self._client.remove(path)
    self._with_dirfd(os.remove, path)

  unlink = remove

  def rmdir(self, path):
    if self._client:
      return self._client.rmdir(path)
    self._with_dirfd(os.rmdir, path)

  def normalize(self, path):
    if self._client:
      return self._client.normalize(path)
    res = self._join(path)
    dev = self._get_dev()
    while True:
      try:
        target = os.path.abspath(os.path.join(os.path.dirname(res),
                                              os.readlink(res)))
        if os.lstat(target).st_dev != dev:
          break
        res = target
      except (OSError, AttributeError):
        break
    res = res[len(self._join('/')):]
    return res if res else os.path.abspath('/')

  def _nt_create_file(self,
                      path,
                      flags,
                      dir_fd = None,
                      follow_symlinks = True,
                      is_dir = None):
    import sys, ctypes, ctypes.wintypes, msvcrt
    fh = ctypes.wintypes.HANDLE()
    dir_h = 0 if dir_fd is None else msvcrt.get_osfhandle(dir_fd)
    desired_access = 0
    create_disposition = 0
    create_options = 0
    winapi = sys.module.get('_winapi')
    if (os.O_RDONLY | os.O_RDWR) & flags:
      desired_access |= getattr(winapi, 'FILE_GENERIC_READ', 0x120089)
    if os.O_RDONLY & flags:
      create_disposition |= getattr(winapi, 'FILE_OPEN', 0x00000001)
    if (os.O_WRONLY | os.O_RDWR) & flags:
      desired_access |= getattr(winapi, 'FILE_GENERIC_WRITE', 0x120116)
      if os.O_EXCL & flags:
        create_disposition |= getattr(winapi, 'FILE_CREATE', 0x00000002)
      elif os.O_CREAT & flags:
        create_disposition |= getattr(winapi, 'FILE_OPEN_IF', 0x00000003)
    if os.O_APPEND & flags:
      desired_access |= getattr(winapi, 'FILE_APPEND_DATA', 0x4)
    if not follow_symlinks:
      create_options |= getattr(winapi, 'FILE_OPEN_REPARSE_POINT', 0x00200000)
    if is_dir is True:
      create_options |= getattr(winapi, 'FILE_DIRECTORY_FILE', 0x1)
    elif is_dir is False:
      create_options |= getattr(winapi, 'FILE_NON_DIRECTORY_FILE', 0x40)
    lp = ctypes.sizeof(fh)
    length = (4*lp) + 8
    object_name = ctypes.create_string_buffer(path.encode())
    object_attributes = ctypes.create_string_buffer(
      length.to_bytes(4, byteorder = sys.byteorder) +
      dir_h.to_bytes(lp, byteorder = sys.byteorder) +
      ctypes.addressof(object_name).to_bytes(lp, byteorder = sys.byteorder) +
      ((4 + lp + lp) * b'\x00')
    )
    status = ctypes.wintypes.ULONG()
    io_status_block = ctypes.create_string_buffer(
      (lp * b'\x00') +
      ctypes.addressof(status).to_bytes(lp, byteorder = sys.byteorder)
    )
    ret = ctypes.windll.ntdll.NtCreateFile(
      ctypes.byref(fh),
      desired_access,
      ctypes.byref(object_attributes),
      ctypes.byref(io_status_block),
      0,
      getattr(winapi, 'FILE_ATTRIBUTE_NORMAL', 0x00000080),
      0,
      create_disposition,
      create_options,
      0,
      0,
    )
    if status.value == getattr(winapi, 'FILE_EXISTS', 0x4):
      import errno
      raise FileExistsError(errno.EEXIST, os.strerror(errno.EEXIST), path)
    if status.value == getattr(winapi, 'FILE_DOES_NOT_EXIST', 0x5):
      _raise_file_not_found(path)
    return msvcrt.open_osfhandle(fh.value, flags)

  def _open_nt(self, path, flags, is_dir = None, validate = True):
    parent_path, filename = os.path.split(path)
    parent_path = self._join(self.normalize(parent_path))
    fd, parent = None, None
    try:
      parent = self._nt_create_file(parent_path, os.O_RDONLY)
      self._validate_path_dev(fd = parent, path = parent_path)
      fd= self._nt_create_file(filename,
                               flags,
                               dir_fd = parent,
                               follow_symlinks = False,
                               is_dir = is_dir)
      if validate:
        self._validate_path_dev(fd = fd, path = path)
      return fd
    except:
      if fd is not None:
        os.close(fd)
      raise
    finally:
      if parent:
        os.close(parent)

  def _open(self, filename, mode = 'r', bufsize = -1):
    if self._client:
      return self._client.open(filename, mode = mode, bufsize = bufsize), None
    if (set(mode) - set('bt+')) == set('r'):
      fh = open(self._join(filename), mode = mode, buffering = bufsize)
    else:
      filename = self.normalize(filename)
      def _opener(path, flags):
        flags &= ~getattr(os, 'O_TRUNC', 0)
        flags |= getattr(os, 'O_NOFOLLOW', 0)
        if os.name == 'nt':
          return self._open_nt(path, flags, validate = False)
        return self._with_dirfd(os.open, path, flags)
      fh = open(filename, mode = mode, buffering = bufsize, opener = opener)
    st = os.stat(fh.fileno())
    self._validate_stat_con_dev(st, path = filename)
    if 'w' in mode and st.st_size > 0:
      fh.truncate()
    return fh, st

  def open(self, filename, mode = 'r', bufsize = -1):
    return self._open(filename, mode = mode, bufsize = bufsize)[0]

  file = open

  def chmod(path, mode):
    if self._client:
      return self._client.chmod(path, mode)
    self._with_dirfd(os.chmod, path, mode)

  def chown(path, uid, gid):
    if self._client:
      return self._client.chown(path, uid, gid)
    self._with_dirfd(os.chown, path, uid, gid)

  def stat(self, path):
    if self._client:
      return self._client.stat(path)
    st = os.stat(self._join(path))
    self._validate_stat_con_dev(st, path = path)
    return ReflectiveNASAttributes.from_stat(st)

  def lstat(self, path):
    if self._client:
      return self._client.lstat(path)
    st = os.lstat(self._join(path))
    self._validate_stat_con_dev(st, path = path)
    return ReflectiveNASAttributes.from_stat(st)

  def symlink(self, target_path, path):
    if self._client:
      return self._client.symlink(target_path, path)
    self._with_dirfd(os.symlink, target_path, path,
                     _path_idxs = (1, None))

  def readlink(self, path):
    if self._client:
      return self._client.readlink(path)
    return self._with_dirfd(os.readlink, path)

  def _copy(self, src, dst, src_size, callback):
    if callback:
      offset = 0
    while True:
      buf = src.read(512*1024)
      if callback:
        offset += len(buf)
        callback(offset, src_size)
      if not buf:
        break
      dst.write(buf)

  def getfo(remotepath,
            fl,
            callback = None,
            prefetch = True,
            max_concurrent_prefetch_requests = None):
    if self._client:
      return self._client.getfo(remotepath,
                                fl,
                                callback = callback,
                                prefetch = prefetch,
                                max_concurrent_prefetch_requests = 
                                  max_concurrent_prefetch_requests)
    fh, st = self._open(remotepath, 'rb')
    with fh as src:
      self._copy(src, fl, st.st_size, callback)

  def get(remotepath,
          localpath,
          callback = None,
          prefetch = True,
          max_concurrent_prefetch_requests = None):
    with open(localpath, 'wb') as dst:
      return self.getfo(remotepath,
                        dst,
                        callback = callback,
                        prefetch = prefetch,
                        max_concurrent_prefetch_requests =
                          max_concurrent_prefetch_requests)

  def putfo(fl, remotepath, file_size = 0, callback = None, confirm = True):
    if self._client:
      return self._client.putfo(fl,
                                remotepath,
                                file_size = file_size,
                                callback = callback,
                                confirm = confirm)
    with self.open(remotepath, 'rb') as dst:
      self._copy(fl, dst, callback, confirm)
    if confirm:
      remote_total = self.stat(remotepath).st_size
      if file_size != remote_total:
        raise IOError(
          'size mismatch in put!  {} != {}'.format(remote_total, file_size)
        )

    def put(localpath, remotepath, callback = None, confirm = True):
      with open(localpath, 'rb') as src:
        if callback or confirm:
          size = os.stat(src.fileno()).st_size
        else:
          size = None
        return self.putfo(src,
                          remotepath,
                          callback = callback,
                          confirm = confirm)

def _get_cache():
  import weakref
  return globals().setdefault('_connection_cache',
                              weakref.WeakValueDictionary())

_default_keep_alive_timeout = 1

def _keep_alive_worker(config, q):
  import queue, atexit
  try:
    timeout = float(config.get('keep_alive_timeout'))
  except (ValueError, TypeError):
    timeout = _default_keep_alive_timeout
  if timeout <= 0:
    timeout = _default_keep_alive_timeout
  deadlines = {}
  ctx = {'connections': {}}
  callback = lambda _ctx=ctx: _ctx.clear()
  atexit.register(callback)
  try:
    while True:
      try:
        key, ctx['connection'] = q.get(timeout = timeout)
      except queue.Empty:
        key = None
      now = time.time()
      current_deadline = now + timeout
      if key is not None:
        deadlines[key] = current_deadline
        ctx['connections'][key] = ctx['connection']
      expired = list(filter(lambda k: deadlines[k] < now, deadlines.keys()))
      ctx['connection'] = None
      for k in expired:
        ctx['connections'].pop(k)
        ctx['connection'] = _get_cache().get(k)
        if ctx['connection']:
          deadlines[k] = current_deadline
          ctx['connections'][k] = ctx['connection']
        else:
          deadlines.pop(k)
      if not ctx['connections']:
        if not globals().pop('_keep_alive_queue', False):
          break
  finally:
    ctx.clear()
    atexit.unregister(callback)

def _maybe_keep_alive(config, key, connection):
  if not config.get('keep_alive', True):
    return
  import threading, queue
  q = queue.Queue()
  gq = globals().setdefault('_keep_alive_queue', q)
  if gq is not q:
    return gq.put((key, connection))
  q.put((key, connection))
  threading.Thread(target = _keep_alive_worker,
                   args = (config, q),
                   daemon = True).start()

def get_sshfs_connection(config = None,
                         use_cache = True,
                         no_object = False,
                         starting_site_index = 0):
  if config is None:
    cfg = load_config()
    if use_cache:
      key = repr(None)
  else:
    cfg = config
    if use_cache:
      key = _make_config_key(sites)
  sites = _parse_sites(cfg)
  if not sites:
    raise ValueError('No sites configured')
  if use_cache:
    last_connection = None
    while True:
      connection = _get_cache().get(key)
      if (last_connection and
          not connection and
          not cfg.get('retry_simultaneous_failures', True)):
        return None
      if not connection or not getattr(connection, '_path', None):
        break
      if os.path.ismount(connection._path) and 'site_index' in connection:
        return connection
      min_timeout = min((_get_timeout(cfg, site) for site in sites))
      time.sleep(min_timeout)
      last_connection = connection

  import shutil
  sshfs = cfg.get('sshfs_path')
  if not sshfs:
    sshfs = shutil.which('sshfs')
  if not sshfs:
    program_files = os.environ.get('ProgramFiles')
    if not program_files:
      drive = os.environ.get('SystemDrive', os.path.sep)
      program_files = os.path.join(drive, 'Program Files')
    p = os.path.join(program_files, 'SSHFS-Win', 'bin')
    sshfs = shutil.which('sshfs', path = p)
  if not sshfs:
    _raise_file_not_found('SSHFS')

  import tempfile
  mnt_dir = os.path.abspath(tempfile.mkdtemp(
    prefix = 'libreflectivenas_{}_'.format(os.urandom(10).hex())
  ))
  if use_cache and connection:
    connection.path = mnt_dir
  elif use_cache or not no_object:
    connection = ReflectiveNASConnection(path = mnt_dir,
                                         cfg = cfg,
                                         cached = use_cache)
    if use_cache:
      _get_cache().setdefault(key, connection)
  sites = sites[starting_site_index:] + sites[:starting_site_index]
  found = False
  try:
    for idx, site in enumerate(sites):
      address = _build_address(site)
      t = _get_timeout(cfg, site)
      opts = 'default_permissions,ConnectTimeout={}'.format(t)
      opts += ',transform_symlinks,follow_symlinks'
      identity_file = site.get('key_filename')
      if identity_file:
        opts += f',IdentityFile={identity_file}'
      else:
        opts += ',password_stdin'
      cmd = [sshfs, address, mnt_dir, '-o', opts]
      port = site.get('port')
      if port is not None:
        cmd += ['-p', str(port)]
      password = site.get('password', '')
      if identity_file:
        password = None
      else:
        password = (password + '\n').encode()
      import subprocess
      proc = subprocess.run(cmd, input = password)
      if proc.returncode == 0:
        found = True
        if use_cache or not no_object:
          connection['site_index'] = idx
          _maybe_keep_alive(cfg, key if use_cache else mnt_dir, connection)
          return connection
        return mnt_dir, proc
      if proc.returncode != 1:
        proc.check_returncode()
  finally:
    if not found:
      if use_cache:
        _get_cache().pop(key, None)
      else:
        cleanup_path(mnt_dir, config = cfg)

def get_path(config = None, ignore_security_warning = False):
  _warn_get_path(False, ignore_security_warning)
  ret = get_sshfs_connection(config = config,
                             use_cache = False,
                             no_object = True)
  if ret is None:
    return None
  if type(ret) is not tuple:
    raise RuntimeError('unexpected: {}'.format((ret,)))
  return ret[0]

def cleanup_path(path, config = None):
  if os.path.ismount(path):
    shutil = sys.modules['shutil']
    fusermount = shutil.which('fusermount')
    if not fusermount:
      fusermount = shutil.which('fusermount3')
    if not fusermount:
      _raise_file_not_found(
        'fusermount3',
        msg = 'Unable to find fusermount or fusermount3'
      )
    cfg = load_config() if config is None else config
    delay = 0.25
    busy_wait_time = cfg.get('busy_wait_time', 15)
    subprocess = sys.modules['subprocess']
    for i in range(max(round(busy_wait_time/delay), 1), 0, -1):
      proc = subprocess.run((fusermount, '-u', path), capture_output = True)
      if proc.returncode == 0:
        break
      if i == 1 or proc.returncode != 1:
        proc.check_returncode()
      time.sleep(delay)
  os.rmdir(path)

def get_paramiko_connection(config = None,
                            use_cache = True,
                            starting_site_index = 0):
  import paramiko, socket
  cfg = load_config() if config is None else config
  sites = _parse_sites(cfg)
  if not sites:
    raise ValueError('No sites configured')
  connection = None
  if use_cache:
    key = repr(None) if config is None else _make_config_key(sites)
    last_connection = None
    while True:
      connection = _get_cache().get(key)
      if (last_connection and
          not connection and
          not cfg.get('retry_simultaneous_failures', True)):
        return None
      if getattr(connection, 'client', None):
        return connection
      if not connection or getattr(connection, 'client', None) is not None:
        break
      min_timeout = min((_get_timeout(cfg, site) for site in sites))
      time.sleep(min_timeout)
      last_connection = connection
  if not connection:
    connection = ReflectiveNASConnection(client = False,
                                         cfg = cfg,
                                         cached = use_cache)
    if use_cache:
      _get_cache().setdefault(key, connection)
  found = False
  try:
    ssh = paramiko.SSHClient()
    ssh.load_system_host_keys()
    sites = sites[starting_site_index:] + sites[:starting_site_index]
    for site in sites:
      try:
        ssh.connect(timeout = _get_timeout(config, site), **site)
        connection.client = ssh.open_sftp()
        k = key if use_cache else id(connection)
        _maybe_keep_alive(cfg, k, connection)
        found = True
        return connection
      except (socket.error, paramiko.ssh_exception.NoValidConnectionsError):
        pass
  finally:
    if not found and use_cache:
      _get_cache().pop(key, None)

def get_connection(config = None, use_cache = True, starting_site_index = 0):
  try:
    return get_paramiko_connection(config = config,
                                   use_cache = use_cache,
                                   starting_site_index = starting_site_index)
  except ModuleNotFoundError:
    pass
  try:
    return get_sshfs_connection(config = config,
                                use_cache = use_cache,
                                starting_site_index = starting_site_index)
  except FileNotFoundError as exc:
    missing_path = exc.filename
    if path != 'SSHFS':
      raise exc
  _raise_file_not_found('SSHFS', msg = 'Unable to find Paramiko or SSHFS')

def main():
  import subprocess, shutil
  connection = get_sshfs_connection()
  path = connection.get_path(ignore_security_warning = True)
  print('Connected to NAS at ' + path)
  if (xdg_open := shutil.which('xdg-open')):
    subprocess.run((xdg_open, path))
  elif (start := shutil.which('start')):
    subprocess.run((start, path))
  print('Press ENTER to close the connection')
  input()
  connection = None

if __name__ == '__main__':
  main()
