from qiling import *
from qiling.const import *
import os, random, string

packet = bytes([int(x, 16) for x in """
95 5c 15 0f 01 00 00 00 19 9c eb dd 17 ed 65 02 10 2f a8 ba c9 35 95 a7 49 f4 42 24 7d d5 00 11 ca 5b b4 62 56 92 ec f5 66 fd 10 31 ab 7b c5 31 e8 7e 26 54 d9 59 fc 42 21 4a 09 cd 41 0d bd 53 15 f9 8f 74 c5 8f eb 53 dd 96 66 10 2d 4d fa 75 b5 46 7d 91 13 b4 e5 98 84 ec 8f 01 bb 72 14 7c 10 91 25 32 77 54 f1 7e 0a c7 99 21 20 1b 5b f1 c1 c0 a4 48 bf 0e 1f 08 47 51 6b a6 6e e7 1e 89 bc f6 c6 40 37 a9 61 07 5e 0a f8 7c 43 80 ee 56 fa 60 c1 69 1e dc dd 17 f9 56 0c cf 3a cc 04 2d ca ac 57 7c b6 3c 1e dd 31 0d c0 58 3a 0b 4a aa
""".strip().split(" ")])
module = "rootfs/x86_windows/bin/init.tmp"
snapshot = os.path.basename(module) + ".snapshot"

procs = {}
modules = {}

def GetProcAddress(ql, address, params):
    global procs
    name = params["lpProcName"]
    dll_name = [key for key, value in ql.loader.dlls.items() if value == params["hModule"]][0]
    ql.loader.load_dll(dll_name.encode())
    try:
        addr = ql.loader.import_address_table[dll_name][name.encode()]
        procs[name] = addr
    except:
        pass

def LoadLibraryExA(ql, address, params):
    global modules
    name = params["lpLibFileName"]
    addr = ql.loader.load_dll(name.encode())
    modules[name] = addr

ql = Qiling([module], "rootfs/x86_windows", output="debug", libcache=True)
ql.set_api("GetProcAddress", GetProcAddress, QL_INTERCEPT.EXIT)
ql.set_api("LoadLibraryExA", LoadLibraryExA, QL_INTERCEPT.EXIT)

if not os.path.isfile(snapshot):
    ql.mem.map(0x100000, 4096*100) # enough stack for __alloca_probe
    ql.reg.write("esp", 0x132000)

    addr = ql.mem.map_anywhere(4)
    ql.mem.write(addr, ql.pack32(4096))
    ql.stack_push(addr)
    ql.stack_push(ql.mem.map_anywhere(4096))

    ql.stack_push(176)
    addr = ql.mem.map_anywhere(176)
    ql.mem.write(addr, packet)
    ql.stack_push(addr)

    ql.stack_push(4)

    ql.stack_push(0) # ret address

    ql.run(begin=0x00402B6C, end=0x00404516) # set up routines
    ql.dprint(D_INFO, "Finished setting up routines")
    ql.run(begin=0x00404516, end=0x00404522) # decrypt packet with ICE
    ql.dprint(D_INFO, "Finished decrypting packet with ICE key from module")
    ql.run(begin=0x00404522, end=0x00406416) # decrypt section with ICE
    ql.dprint(D_INFO, "Finished decryption data section with ICE key from decrypted packet")
    ql.save(reg=True, mem=True, cpu_context=True, snapshot=snapshot)
    ql.dprint(D_INFO, f"Saved snapshot to {snapshot}")
else:
    ql.restore(snapshot=snapshot)
    ql.dprint(D_INFO, f"Restored snapshot from {snapshot}")

ql.run(begin=0x00406416, end=0x00406482) # rebuild IAT
ql.dprint(D_INFO, "Finished building IAT")
ql.run(begin=0x00406482, end=0x0040648F) # check imports
ql.dprint(D_INFO, f"Verified imports. AL = {ql.reg.read('al')}")
ql.debugger = True
ql.run(begin=0x0040648F, end=0x004064B9) # idk

ql.dprint(D_INFO, f"Found {len(modules)} modules")
ql.dprint(D_INFO, f"Found {len(procs)} procs")

idb_procs = {}
for name, addr in procs.items():
    try:
        addr = ql.mem.search(ql.pack32(addr), begin=0x00407000, end=0x40E000)[0]
        idb_procs[addr] = name
    except:
        pass
idb_procs_sorted = sorted(idb_procs.items())

addr = idb_procs_sorted[0][0]
last_addr = idb_procs_sorted[-1][0]
struct = "struct import_table {\n"
ida = "import ida_name\n"
apis = open("typedefs.h").readlines()
while addr < last_addr:
    if addr in idb_procs.keys():
        name = idb_procs[addr]
        typedef = [typedef for typedef in apis if " " + name + ")" in typedef]
        if " " + name + ")" in struct: # make sure there's no duplicate fields
            new_name = name + "_" + "".join(random.choice(string.ascii_lowercase) for i in range(4))
            if len(typedef) > 0: typedef[0] = typedef[0].replace(name, new_name)
        if len(typedef) > 0:
            typedef = typedef[0].replace("typedef ", "").strip()
            struct += f"    {typedef}\n"
        else:
            struct += f"    void* {name};\n"        
        ida += f"set_name({addr}, \"{idb_procs[addr]}_0\")\n"
    else:
        struct += f"    void* unknown{hex(addr)[2:]};\n"
    addr += 4
struct += "};"

open("import_table.h", "w").write(struct)
open("ida.py", "w").write(ida)

"""
for name, addr in modules.items():
    try:
        addr = ql.mem.search(ql.pack32(addr), begin=0x00407000, end=0x40E000)[0]
        print(f"{name} -> {hex(addr)}")
    except:
        pass
"""