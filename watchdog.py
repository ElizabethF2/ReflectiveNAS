import sys, os, subprocess, shutil, signal, time, socket, json, argparse

SUCCESS = 0
NO_MOUNT_ENTRY = 1
CREATE_NEW_PROCESS_GROUP = 512

parser = argparse.ArgumentParser(description='ReflectiveNAS Server\nSee readme.md for help.')
parser.add_argument('-c', '--config', help='config file path', default='config.json')
parser.add_argument('-s', '--script', help='main ReflectiveNAS script path', default='ReflectiveNAS.py')
args = parser.parse_args()

with open(args.config, 'r') as f:
  config = json.load(f)

while True:
  # Try to unmount the proxy directory, ignore errors if it's already unmounted
  if not (fusermount := shutil.which('fusermount')):
    fusermount = shutil.which('fusermount3')
  if fusermount:
    res = subprocess.run(['fusermount', '-u', config['Passthrough']['Proxy_Directory']])
    if res.returncode not in (SUCCESS, NO_MOUNT_ENTRY):
      print('Invalid return code on unmount:', res)
      sys.exit(-1)
  elif 'cygwin' not in sys.platform.lower():
    print('No valid unmount util for this platform. Update script or use a different OS.')
    sys.exit(-1)

  # Start ReflectiveNAS
  kwargs = {}
  if sys.platform == 'win32':
    kwargs['creationflags'] = CREATE_NEW_PROCESS_GROUP
  else:
    kwargs['start_new_session'] = True
  nas_proc = subprocess.Popen(
    [sys.executable, args.script, '-c', args.config],
    **kwargs,
  )

  # Poll ReflectiveNAS until its REST endpoint becomes unresponsive
  try:
    while True:
      time.sleep(config['Synchronization']['Delay_Between_Syncs'])

      if nas_proc.poll() is not None:
        break

      sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      try:
        sock.connect(('127.0.0.1', config['Local_Server']['Port']))
        alive = True
      except (ConnectionRefusedError, TimeoutError):
        alive = False
      sock.close()
      if not alive:
        break
  except KeyboardInterrupt:
    break
  finally:
    # Stop ReflectiveNAS
    if nas_proc.poll() is None:
      nas_proc.send_signal(getattr(signal, 'CTRL_C_EVENT', signal.SIGINT))
      while nas_proc.poll() is None:
        try:
          nas_proc.wait(timeout = config['Synchronization']['Timeout'])
        except subprocess.TimeoutExpired:
          nas_proc.terminate()
    else:
      sys.exit(nas_proc.poll())
