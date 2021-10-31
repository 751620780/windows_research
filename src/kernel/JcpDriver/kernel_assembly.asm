title  "x64 assembly code"

;++
;x64下C++不支持内联汇编，因此用到的汇编代码应当独立出来。
;注意汇编代码的编写，常量数值10进制直接写；
;16进制应当用h结束不应当加0x作为开头
;--

;++
;如何让这个asm文件能够在工程中编译：
;选择该asm文件右键属性->常规->项类型：选择自定义生成工具
;然后在自定义生成工具选项的常规里面进行如下修改：
;命令行：ml64 /Fo $(IntDir)%(Filename).obj /c %(Filename).asm
;输出：$(IntDir)%(Filename).obj
;注意：请留意该asm文件实际相对于项目的相对位置
;--

;++
;x64下汇编在定义函数时应当注意的参数传递问题：
;int foo(a,b,c,d,e,f,g)
;foo函数拥有从左到右7个参数，采用fast call调用约定
;参数从左到右分别放入(rcx,rdx,r8,r9,rsp+20h,rsp+28h,rsp+30h)
;但是放入顺序却是从右往左依次放入，可以看出已经为前四个参数放入通用寄存器，但是rsp依然为其留下了内存空间
;mov         dword ptr [rsp+30h],g
;mov         dword ptr [rsp+28h],f 
;mov         dword ptr [rsp+20h],e  
;mov         r9d,d
;mov         r8d,c  
;mov         rdx,b  
;mov         rcx,a
;call		 foo
;如果前4个参数有浮点，则用XMMO~XMM3的对应位置保存参数。
;虽然是快速调用，但是在foo函数内部依然会先将前4个参数放入栈内，由于调用call后，rsp自减8来存放返回地址，所以，第一个参数放在rsp+8内，即
;mov         dword ptr [rsp+20h],r9d  
;mov         dword ptr [rsp+18h],r8d  
;mov         dword ptr [rsp+10h],edx  
;mov         dword ptr [rsp+8],ecx
;push        rbp						;后续需要使用rbp
;push        rdi						;后续需要使用rdi
;sub         rsp,0E8h					;预留空间
;mov         rbp,rsp					;这里使用rbp充当rsp，即rbp就是rsp
;mov         rdi,rsp					;rep stos指令需要rcx参数，rdi参数，rax参数
;mov         ecx,3Ah  
;mov         eax,0CCCCCCCCh  
;rep stos    dword ptr [rdi]			;将eax中的值，拷贝到es:[rdi指向的地址中]，拷贝次数是ecx次 ，这里将之间预留的e8h个字节初始化为cch
;后续使用栈内的变量和参量原则上使用rsp直接引用，废弃rbp,当然并不是说不可以使用rbp
;--

;++
;push xxx执行过程：先将esp减少4/8，然后将xxx复制到[esp]中
;call xxx执行过程：先将call xxx后的地址push进栈，然后将eip的值修改为xxx
;ret  xxx执行过程：先将[esp]的值放入到eip中，然后esp的值减少(xxx+4/8)
;--

;++
;X64汇编介绍：
;寄存器扩展：8个通用寄存器扩展到16个用r8-r5表示。eax->rax另外8个类推。acdbsbsd8-15
;eflags寄存器扩展64位成为rflags，但高32位恒为0；eip扩展为rip
;浮点运算寄存器好像是从X87变为xmm系列寄存器（xmmX寄存器占128位）
;对32位寄存器写操作包括其他操作，都会使该寄存器的高32位清0，例如xor eax,eax?rax=0?清空rax应当用xor eax,eax因为指令短效率快
;mov等将立即数放入寄存器的指令，应当根据数据位长度选择较小的寄存器存放，因为指令短效率高。例如mov eax,1;而不用mov rax,1
;诸如mov rax,-1指令，立即数部分也占4字节，只不过指令的操作码部分已经标识了是8字节的符号扩展(为了提高效率而指令长度，在操作码部分都进行了优化)
;这种变短的指令，在hook时应当注意。
;很多操作都不支持直接8直接的立即数。例如 push 0x123456789;是错误的，正确做法是mov rax,0x123456789;push rax;
;内存访问多采用相对偏移(相对该指令结束后的下一个字节的地址)，而非绝对偏移。能绝对偏移的指令很少。
;诸如0f 1f xxx这样的指令是nop xxx;表示的意思就是快速跳过很多个字节，为了对齐
;Jmp指令：
;小跳（-128-+127内）eb fe是死循环（调到自己）
;大跳 e9 xxx(4字节)相对该指令结束地址跳的偏移，注意：这种情况跳转很难跳到其他模块，因为偏移很大。但是可以在同一个模块内任意跳
;地址偏移大跳 ff 25 xxx;读取该指令结束后下一地址+偏移xxx位置的8字节内存作为跳转目的地。即jmp qword ptr[xxx+?]; xxx是4字节。也就是6字节跳转，hook常用
;Ff 24 25 xxx指令是直接读取xxx内存里的8字节内容进行跳转。该指令不常用
;注意：立即数超过4个字节时都应当小心，小心编译器不按照代码进行编译
;Hook 跳转最好的方式时mov rax,xxxxxx;jmp rax;
;X64调用约定：
;只有一种调用约定是“类fastcall”。函数前的各种调用约定修饰符自动被编译器忽略。
;由调用者栈平衡，基本看不到ret n指令，除非你不遵循标准
;前四个参数从左到右依次使用rcx(xmm0)、rdx(xmm1)、r8(xmm2)、r9(xmm3).xmmX寄存器主要存储浮点参数，多余的依然至左向右放入栈中
;即使前四个参数用寄存器传参：依然为其保留栈空间
;对于不定长的参数的函数：调用者至少为其分配4个参数的栈空间，即使只有一个参数。因为编译器在函数开头强制使用这块栈内存
;对于易变寄存器：rax、rcx、rdx、r8-r11共7个寄存器，其他非易变寄存器带被调用的函数中使用时会用push 和pop进行保存。调用者认为被调函数不会修改非易变寄存器的值。
;以上介绍的出结论：rax，rcx，rdx，r8-r11寄存器进入函数后你可以随便使用。其他寄存器使用前必须备份，使用后需要恢复！！！
;X64的编译器不会主动使用push 立即数的指令，而是直接用mov [rsp-xxx],xxx.则可以清晰的看到栈分配，因为传参时是sub rsp,28h;mov [rsp+20h],5;call xxx;
;在一个函数开始会先提升栈，用于调用函数的参数和局部变量和rsp的16字节对齐。在函数返回前平衡栈。并非每调用一次函数就平衡一次
;每次call函数前rsp一定是10h字节对齐的，但是执行call指令进入后会压入返回地址，则rsp的值就变成8结尾的数
;栈帧分析：一个函数默认会先push 非易失寄存器，然后sub rsp,xxx;假设这两步共抬栈x字节。则进去后就是[rsp+x+8]=arg1 [rsp+x+10h]=arg2
;函数结束时会add rsp,x;直接得出x的值
;x64下内核态gs寄存器指向的是KPCR，在用户态指向的是teb64
;--

extern basic_add:proc;测试函数

extern WPOFFx64:proc;关闭内存写保护

extern WPONx64:proc;开启内存写保护

.data

num dword 1
str1 db 'hello world',0ah,00h


.code



test_add PROC
	mov		rax,rdx
	add		rax,rcx
	mov		ecx,num
	add		rax,rcx
	mov		rcx,rax
	sub		rsp,20h
	call	basic_add
	add		rsp,20h
	ret
test_add ENDP


get_int3 proc
	int 3
	ret
get_int3 endp






super_memcpy_copy proc
	;rcx 是目标地址
	;rdx 是内容
	;r8  是长度
	cmp r8,8
	jnz A
	lock xchg qword ptr [rcx],rdx
	mov rax,8
	jmp R
A:
	cmp r8,4
	jnz B
	lock xchg dword ptr [rcx],edx
	mov rax,4
	jmp R
B:
	cmp r8,2
	jnz C
	lock xchg word ptr [rcx],dx
	mov rax,2
	jmp R
C:	
	cmp r8,1
	jnz F
	lock xchg byte ptr [rcx],dl
	mov rax,1
F:
	mov rax,0
R:
	ret
super_memcpy_copy endp

end

