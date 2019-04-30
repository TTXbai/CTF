### 2019.4.30 
### by TTX

### 1.Windows pwn简介

Windows pwn是对Windows平台下二进制服务利用漏洞进行get shell/提权的过程。

### 2.Windows pwn与Linux pwn区别

Windows pwn相比于Linux pwn比较罕见。经过调研，Windows平台下也有堆栈操作，但是结构不尽相同

1.堆栈地址随机化

2.Windows下有特有的SEH机制，以及对应的保护机制

3.Windows下有更多的保护机制，使得对Windows的攻击更加困难

4.Windows不同版本下机制都各不相同

### 3.Windows 保护机制与利用

- DEP(NX on linux,可写和可执行互斥)

- ALSR(虽然是随机的，但只有操作系统重启后进程的基地址才会变。且所有共享的库的地址是一样的。栈的随机化和linux一样)

    - Bypassed by

        - Info leak

        - Brute force(Win7 x64,win10 x86(随机8bits),如果是强行PIE,可爆破)

        - Attack Non-ASLR images or top down alloc(类mmap)(win 7)

- CFG(Control Flow Guard,默认关闭)

    - All indirect call are checked by predefined read-only bitmap(函数开头才能调用)

    - Attack Vtable is done now 

    - Bypassed by

        - 改CFG没有保护的值(return adress,SEG handler,etc)

        - overwrite CFG disabled module

        - COOP++
  
- LFH(堆的随机化,同样大小16次，任意大小0x50次),Windows heap还有heap canary

	- Get RWX page via virtualprotect like function

	- heap manipulation

	- stack canary leak and overwrite

	- Shellcode 

- GS
	
	- similar to stack canary

    - corrupt SEH(x86)

       - SEH:对于try ..excpect的函数，会push一个VC_EXCEPCTION_REGISTRATION struct到stack

       - SAFE SEH:产生handler的白名单，不能随便改handler

       - SEHOP：会遍历链表，检查最后是否的ntdll!FinalExpccetionHandler(修复列表即可)

- 常见攻击方法（较简单）

	- 栈攻击： 通过栈溢出覆盖SEH handler，使其指向构造好的gadget
	
	- 堆攻击： 条件比较通常苛刻，如通过leak堆地址，在堆上执行shellcode等

### 4.Windows pwn工具

#### General Tools

- Cygwin

- socket lib(pwntools的windows版本)

- Process Hacker(进程或程序的详细信息)

- Visual Studio(Developer Command Prompt)

#### Debuggers

- Windbg

- IDA pro Debugger

- Ollydbg

- X64dbg

### 5.Windows pwn 小结
Windows pwn的CTF题目看过比较经典的一项是对Safeseh机制的突破上，因为safeseh对seh handler的修改进行了限制，虽然是如此，但是仍有dll没有开启safeseh（个人感觉safeseh很safe了），通过在执行对应dll函数时的覆盖绕过的。

另外，由于Windows pwn通常比较罕见，对Windows pwn的研究都集中于其与Linux pwn中不同的保护机制或者处理上，比如SEH机制和CFG机制等。因此Windows pwn在比赛中估计都是这些不同于Linux保护机制类型的题目。

目前缺乏的是还未复现具体的实验环境，没有真正的调试过，如果能够复现环境调试一下，想必对机制的了解会更进一步。
