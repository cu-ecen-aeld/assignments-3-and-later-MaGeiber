Output of `echo “hello_world” > /dev/faulty` was the following:
```
[   54.583354] Unable to handle kernel NULL pointer dereference at virtual address 0000000000000000
[   54.585532] Mem abort info:
[   54.587453]   ESR = 0x0000000096000045
[   54.592456]   EC = 0x25: DABT (current EL), IL = 32 bits
[   54.595998]   SET = 0, FnV = 0
[   54.596375]   EA = 0, S1PTW = 0
[   54.597447]   FSC = 0x05: level 1 translation fault
[   54.600382] Data abort info:
[   54.601593]   ISV = 0, ISS = 0x00000045
[   54.605723]   CM = 0, WnR = 1
[   54.606788] user pgtable: 4k pages, 39-bit VAs, pgdp=0000000043dfc000
[   54.614628] [0000000000000000] pgd=0000000000000000, p4d=0000000000000000, pud=0000000000000000
[   54.619017] Internal error: Oops: 96000045 [#1] PREEMPT SMP
[   54.621366] Modules linked in: scull(O) hello(O) faulty(O)
[   54.623626] CPU: 3 PID: 346 Comm: sh Tainted: G           O      5.15.96-yocto-standard #1
[   54.626534] Hardware name: linux,dummy-virt (DT)
[   54.629305] pstate: 80000005 (Nzcv daif -PAN -UAO -TCO -DIT -SSBS BTYPE=--)
[   54.631385] pc : faulty_write+0x18/0x20 [faulty]
[   54.639597] lr : vfs_write+0xf8/0x29c
[   54.639942] sp : ffffffc009bfbd80
[   54.640114] x29: ffffffc009bfbd80 x28: ffffff8002019b00 x27: 0000000000000000
[   54.640546] x26: 0000000000000000 x25: 0000000000000000 x24: 0000000000000000
[   54.640826] x23: 0000000000000000 x22: ffffffc009bfbdf0 x21: 00000055757b5ba0
[   54.641556] x20: ffffff8002044400 x19: 000000000000000c x18: 0000000000000000
[   54.641860] x17: 0000000000000000 x16: 0000000000000000 x15: 0000000000000000
[   54.642144] x14: 0000000000000000 x13: 0000000000000000 x12: 0000000000000000
[   54.642497] x11: 0000000000000000 x10: 0000000000000000 x9 : ffffffc008265d4c
[   54.642845] x8 : 0000000000000000 x7 : 0000000000000000 x6 : 0000000000000000
[   54.643127] x5 : 0000000000000001 x4 : ffffffc000b60000 x3 : ffffffc009bfbdf0
[   54.643445] x2 : 000000000000000c x1 : 0000000000000000 x0 : 0000000000000000
[   54.644445] Call trace:
[   54.644679]  faulty_write+0x18/0x20 [faulty]
[   54.648329]  ksys_write+0x70/0x100
[   54.648636]  __arm64_sys_write+0x24/0x30
[   54.648812]  invoke_syscall+0x5c/0x130
[   54.649463]  el0_svc_common.constprop.0+0x4c/0x100
[   54.649672]  do_el0_svc+0x4c/0xb4
[   54.649824]  el0_svc+0x28/0x80
[   54.649956]  el0t_64_sync_handler+0xa4/0x130
[   54.650128]  el0t_64_sync+0x1a0/0x1a4
[   54.650494] Code: d2800001 d2800000 d503233f d50323bf (b900003f) 
[   54.651108] ---[ end trace ffd93956ff1bab5a ]---
Segmentation fault

Poky (Yocto Project Reference Distro) 4.0.8 qemuarm64 /dev/ttyAMA0
```

Some important takeaways from the output we get:
- `[   54.583354] Unable to handle kernel NULL pointer dereference at virtual address`
  - Tells pretty much exactly what happened. A NULL pointer was dereferenced.
- `Internal error: Oops` indicates a kernel fault.
- `Modules linked in: scull(O) hello(O) faulty(O)` tells us the modules that we had running.
- The Call trace and pc both indicate that the function where the issue occurred is `faulty_write` within the module `[faulty]`

So the result of this is, a null pointer was dereferenced within the module faulty, by a function faulty_write(). From there, the function can be analyzed to find where the NULL dereference occurs. In this case, by the line: `*(int *)0 = 0;`
