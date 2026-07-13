# Snapshot and Restore

The goal for the snapshot/restore feature is to provide the user with the
ability to take a snapshot of a previously paused virtual machine. This
snapshot can be used as the base for creating new identical virtual machines,
without the need to boot them from scratch. The restore codepath takes the
snapshot and creates the exact same virtual machine, restoring the previously
saved states. The new virtual machine is restored in a paused state, as it was
before the snapshot was performed.

## Snapshot a Cloud Hypervisor VM

First thing, we must run a Cloud Hypervisor VM:

```bash
./cloud-hypervisor \
    --api-socket /tmp/cloud-hypervisor.sock \
    --cpus boot=4 \
    --memory size=4G \
    --kernel vmlinux \
    --cmdline "root=/dev/vda1 console=hvc0 rw" \
    --disk path=focal-server-cloudimg-amd64.raw
```

At any point in time when the VM is running, one might choose to pause it:

```bash
./ch-remote --api-socket=/tmp/cloud-hypervisor.sock pause
```

Once paused, the VM can be safely snapshot into the specified directory and
using the following command:

```bash
./ch-remote --api-socket=/tmp/cloud-hypervisor.sock snapshot file:///home/foo/snapshot
```

Given the directory was present on the system, the snapshot will succeed and
it should contain the following files:

```bash
ll /home/foo/snapshot/
total 4194536
drwxrwxr-x  2 foo bar       4096 Jul 22 11:50 ./
drwxr-xr-x 47 foo bar       4096 Jul 22 11:47 ../
-rw-------  1 foo bar       1084 Jul 22 11:19 config.json
-rw-------  1 foo bar 4294967296 Jul 22 11:19 memory-ranges
-rw-------  1 foo bar     217853 Jul 22 11:19 state.json
```

`config.json` contains the virtual machine configuration. It is used to create
a similar virtual machine with the correct amount of CPUs, RAM, and other
expected devices. It is stored in a human readable format so that it could be
modified between the snapshot and restore phases to achieve some very special
use cases. But for most cases, manually modifying the configuration should not
be needed.

`memory-ranges` stores the content of the guest RAM.

`state.json` contains the virtual machine state. It is used to restore each
component in the state it was left before the snapshot occurred.

## Restore a Cloud Hypervisor VM

Given that one has access to an existing snapshot in `/home/foo/snapshot`,
it is possible to create a new VM based on this snapshot with the following
command:

```bash
./cloud-hypervisor \
    --api-socket /tmp/cloud-hypervisor.sock \
    --restore source_url=file:///home/foo/snapshot
```

Or using two different commands from two terminals:

```bash
# First terminal
./cloud-hypervisor --api-socket /tmp/cloud-hypervisor.sock

# Second terminal
./ch-remote --api-socket=/tmp/cloud-hypervisor.sock restore source_url=file:///home/foo/snapshot
```

Remember the VM is restored in a `paused` state, which was the VM's state when
it was snapshot. For this reason, one must explicitly `resume` the VM before to
start using it.

```bash
./ch-remote --api-socket=/tmp/cloud-hypervisor.sock resume
```

Alternatively, the `resume` option can be used to automatically resume the VM
after restore completes:

```bash
./cloud-hypervisor \
    --api-socket /tmp/cloud-hypervisor.sock \
    --restore source_url=file:///home/foo/snapshot,resume=true
```

At this point, the VM is fully restored and is identical to the VM which was
snapshot earlier.

Restore also supports selecting how guest memory is populated:

```bash
./cloud-hypervisor \
    --api-socket /tmp/cloud-hypervisor.sock \
    --restore source_url=file:///home/foo/snapshot,memory_restore_mode=ondemand
```

If `memory_restore_mode` is omitted, Cloud Hypervisor uses the eager-copy
restore path (`copy`).

With `memory_restore_mode=ondemand`, restore uses `userfaultfd` to fault snapshot
pages in on first access instead of copying the full `memory-ranges` file into
guest RAM before restore completes. This mode is strict: if Cloud Hypervisor
cannot enable the `userfaultfd` restore path, restore fails instead of falling
back to `copy`.

Current constraints for `memory_restore_mode=ondemand`:

- `prefault=on` is not supported
- the snapshot memory ranges must be page-aligned

### Copy-on-write restore

With `memory_restore_mode=copyonwrite`, guest RAM is created by mapping the snapshot
memory file copy-on-write before any KVM memslot or device consumes the
mapping: nothing is copied up front, pages fault in from the page cache — so
many VMs restored from the same snapshot share it — and guest writes stay
private to each VM.

Current constraints for `memory_restore_mode=copyonwrite`:

- Plain private guest RAM only. Anything else falls back to the eager copy
  (logged): `shared=on` or hugepages (global or per-zone), zones with
  `host_numa_node`, `reserve`, `mergeable` or hotplug fields (a purely static
  `id`+`size` zone is fine), resizable RAM (`hotplug_size`, virtio-mem), KSM
  (`mergeable=on`), `--pvmemcontrol`, device passthrough
  (`--device`/`--user-device`/`--vdpa`), and snapshot ranges that are not
  page-aligned single-region extents. Each region's `reserve` policy and the
  THP policy are re-applied to the mapped region.
- A snapshot memory file shorter than the saved ranges is rejected up front (it
  would otherwise fault `SIGBUS` at run time).
- `prefault` is rejected.
- The snapshot memory file must remain on disk **and unchanged** for the
  entire lifetime of the VM. This is stronger than `ondemand`: UFFD copies each
  page into the original anonymous mapping and stops needing the file once every
  page is populated, and a read error there is a controlled VM exit; the
  copy-on-write region stays file-backed forever, so truncating it delivers a
  synchronous `SIGBUS` and any in-place edit corrupts the guest. The length
  check only rejects a file that is already short at restore time.
- `virtio-balloon` operates normally. Balloon inflation uses `MADV_DONTNEED`,
  which is valid on the private file mapping: the kernel releases the private
  page copies and the host reclaims the memory. A released page reads from the
  snapshot file again on the next access. The guest must not expect specific
  content in a page that returns from the balloon, so this is correct.
  (`pvmemcontrol` differs: it issues operations that are only valid on
  anonymous memory, which is why it is on the fallback list above.)
- A device that is hot-plugged after the restore and that pins guest memory
  (VFIO, vfio-user, vDPA) write-faults every guest page when its IOMMU mapping
  is created. Every page becomes a private copy: the VM stays correct, but the
  page-cache sharing is lost for that VM and host memory use grows to the
  eager-copy level. The same applies to `ondemand` restores.

## Restore a VM with new Net FDs
For a VM created with FDs explicitly passed to NetConfig, a set of valid FDs
need to be provided along with the VM restore command in the following syntax:

```bash
# First terminal
./cloud-hypervisor --api-socket /tmp/cloud-hypervisor.sock

# Second terminal
./ch-remote --api-socket=/tmp/cloud-hypervisor.sock restore source_url=file:///home/foo/snapshot net_fds=[net1@[23,24],net2@[25,26]]
```
In the example above, the net device with id `net1` will be backed by FDs '23'
and '24', and the net device with id `net2` will be backed by FDs '25' and '26'
from the restored VM.

## Limitations

VFIO devices is out of scope.
