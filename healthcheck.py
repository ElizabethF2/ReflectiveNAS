#!/usr/bin/env python3

import sys, json
sys.dont_write_bytecode = True

import ReflectiveNAS

def unbuffered_print(*args, **kwargs):
  print(*args, **kwargs)
  sys.stdout.flush()

def main():
  kw = {'fail_locally': True}
  if len(sys.argv) > 2:
    kw['config_path'] = sys.argv[1]
    own_url = sys.argv[2]
  elif len(sys.argv) > 1:
    own_url = sys.argv[1]
  else:
    own_url = None

  core = ReflectiveNAS.Core(**kw)
  try:
    if not own_url:
      own_url = core.config.get('Local_Server', {}).get('URL')
    if not own_url:
      raise ValueError('Invalid URL for self: {}'.format(repr(own_url)))
    core.fail_safe = lambda *a: unbuffered_print('FAIL_SAFE:', *a)
    synchronizer = ReflectiveNAS.Synchronizer(core,
                                              use_memfs = False)
    node = ReflectiveNAS.SynchronizationClient(own_url,
                                               core.config['Local_Server']['Secret'],
                                               core,
                                               use_memfs = False)
    nodes = [node] + list(synchronizer.remote_servers)
    if len(nodes) < 2:
      raise ValueError('No remote nodes given')
    code_hash = ReflectiveNAS.bhex(
      ReflectiveNAS.hash_file(ReflectiveNAS.__file__)
    )
    unbuffered_print('Local Code Hash: {}'.format(code_hash))
    db_hashes = set()
    final_return_code = 0
    for node in nodes:
      unbuffered_print('Querying {}...'.format(node.url))
      status = node.status()
      unbuffered_print('Got status: {}'.format(json.dumps(status, indent = 2)))
      if not status:
        final_return_code = 1
      elif status.get('code_hash') != code_hash:
        unbuffered_print('Node is running an outdated version!')
        final_return_code = 1
      if not (db_hash := (status or {}).get('db_hash')):
        unbuffered_print('Invalid db_hash: {}'.format(repr(db_hash)))
        final_return_code = 1
      else:
        db_hashes.add(db_hash)
    if len(db_hashes) != 1:
      unbuffered_print('Non-matching db_hashes!')
      final_return_code = 1
  finally:
    core.exit()
  return final_return_code

if __name__ == '__main__':
  sys.exit(main())
