# ----- Settings -----

verbose = True
disks = ['sda']
timeout_secs = 3*60*60
loop_secs = 30

# --------------------

# Modified code based on http://dev.gentoo.org/~lxnay/misc/spindown.py
# Archived at https://web.archive.org/web/20161208081523/https://dev.gentoo.org/~lxnay/misc/spindown.py

import os
import time
import subprocess

disks_stats = {}
disks_ts = {}
disks_sleeping = {}

def get_cur_stats(disk):
    stats_file = "/sys/block/%s/stat" % (disk,)
    try:
        with open(stats_file, "rb") as f:
            data = f.readline().split()
            # return (reads, writes)
            return data[2], data[6]
    except (IOError, OSError):
        return None

def do_sleep_disk(disk):
    subprocess.call(("hdparm", "-y", "/dev/"+disk))

while True:
    for disk in disks:
        if verbose:
            print("/ started checking for " + disk)
        cur_stats = get_cur_stats(disk)
        stored_stats = disks_stats.get(disk, (None, None))
        if cur_stats == stored_stats:
            if disks_sleeping.get(disk):
                if verbose:
                    print("\ disk " + disk + " is already sleeping...")
                continue
            if verbose:
                print("- no changes for " + disk + ", checking ts")
            now = time.time()
            previous_now = disks_ts.get(disk, now)
            delta = abs(now - previous_now)
            if delta >= timeout_secs:
                if verbose:
                    print("! time to get some sleep, " + disk)
                # time to get some sleep
                do_sleep_disk(disk)
                disks_sleeping[disk] = True
                # save new stats, could be racey but hey, no monkeys will be harmed
                disks_stats[disk] = cur_stats
            else:
                # its not time yet
                if verbose:
                    print("-- it's not yet your time, " + disk + ", only " + \
                        str(delta) + " seconds passed")
        else:
            if verbose:
                print("-- there has been some activity on " + disk)
            # disk content changed, store new stats
            disks_stats[disk] = cur_stats
            # reset timer
            disks_ts[disk] = time.time()
            # reset sleeping status
            disks_sleeping[disk] = False
        if verbose:
            print("\ all done for " + disk)

    time.sleep(loop_secs)
    if verbose:
        print("")
