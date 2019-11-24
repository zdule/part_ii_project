#/usr/bin/python3

from mmap import mmap, PROT_READ, PAGESIZE

with open("/dev/kambpf_update",'r+') as f:
    mm = mmap(f.fileno(), 4*PAGESIZE)
    for i in range(4*PAGESIZE):
        mm[i] = 7
    import code
    code.interact(local=locals())
    print("done with interactive mode")

