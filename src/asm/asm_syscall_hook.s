# Assembly file for syscall hook - fixed for cc and PIC

# Make sure the file is position-independent
.text
.section .text.asm_syscall_hook,"ax",@progbits
.p2align 4
.global asm_syscall_hook
.global restore_selector_trampoline

# Constants from gsreldata.h - define these explicitly here
.set SUD_SELECTOR_OFFSET, 0
.set SIGRETURN_STACK_SP_OFFSET, 16
.set RIP_AFTER_SYSCALL_STACK_SP_OFFSET, 4120
.set XSAVE_AREA_STACK_SP_OFFSET, 8224
.set XSAVE_SIZE, 768
.set XSAVE_EAX, 0b111

# Linux syscall numbers
.set __NR_rt_sigreturn, 15
.set __NR_clone, 56
.set __NR_fork, 57
.set __NR_vfork, 58
.set __NR_sigreturn, 119
.set __NR_clone3, 435

.set SYSCALL_DISPATCH_FILTER_ALLOW, 0
.set SYSCALL_DISPATCH_FILTER_BLOCK, 1

# Configuration
.set SAVE_VECTOR_REGS, 1

.macro xsave_vector_regs_to_gsrel
.if SAVE_VECTOR_REGS
    pushq %rdx
    pushq %rax
    pushq %rsi
    xorl %edx, %edx
    movl $XSAVE_EAX, %eax
    movq %gs:XSAVE_AREA_STACK_SP_OFFSET, %rsi
    xsave (%rsi)
    addq $XSAVE_SIZE, %rsi
    movq %rsi, %gs:XSAVE_AREA_STACK_SP_OFFSET
    popq %rsi
    popq %rax
    popq %rdx
.endif
.endm

.macro xrstor_vector_regs_from_gsrel
.if SAVE_VECTOR_REGS
    pushq %rdx
    pushq %rax
    pushq %rsi
    xorl %edx, %edx
    movl $XSAVE_EAX, %eax
    movq %gs:XSAVE_AREA_STACK_SP_OFFSET, %rsi
    subq $XSAVE_SIZE, %rsi
    xrstor (%rsi)
    movq %rsi, %gs:XSAVE_AREA_STACK_SP_OFFSET
    popq %rsi
    popq %rax
    popq %rdx
.endif
.endm

.macro setup_c_stack
    pushq %rbp
    movq %rsp, %rbp

    # 16 byte stack alignment for SSE operations
    andq $-16, %rsp

    # Push registers to preserve them
    pushq %r11
    pushq %r9
    pushq %r8
    pushq %rdi
    pushq %rsi
    pushq %rdx
    pushq %rcx
    pushq %r10
.endm

.macro teardown_c_stack
    popq %r10
    popq %rcx
    popq %rdx
    popq %rsi
    popq %rdi
    popq %r8
    popq %r9
    popq %r11

    movq %rbp, %rsp
    popq %rbp
.endm

.macro exit_interposer
    movb $SYSCALL_DISPATCH_FILTER_BLOCK, %gs:SUD_SELECTOR_OFFSET
.endm

asm_syscall_hook:
    # Pop the saved rax from when we did the trampoline jump
    popq %rax

    # Unblock SUD
    movb $SYSCALL_DISPATCH_FILTER_ALLOW, %gs:SUD_SELECTOR_OFFSET

    pushq %r12  # We use it to check whether we should emulate the syscall or not

    xsave_vector_regs_to_gsrel
    setup_c_stack

    # Arguments for zpoline_syscall_handler
    movq %r10, %rcx
    xorq %r12, %r12
    pushq %r12 # Make room for `should_emulate` (false by default)
    leaq 0x0(%rsp), %r12 # &should_emulate -> r12
    pushq %r12  # &should_emulate as last arg of zpoline_syscall_handler
    pushq 16(%rbp) # Address of instruction after rewritten syscall
    pushq %rax

    # Call the Rust zpoline_syscall_handler function
    callq zpoline_syscall_handler
    # rax now contains the syscall return value

    addq $24, %rsp # Discard the pushed rax, rip_after_syscall and &should_emulate
    popq %r12 # should_emulate -> r12
    
    teardown_c_stack
    xrstor_vector_regs_from_gsrel

    # Check whether we have to emulate some special system calls
    test %r12, %r12 # If !should_emulate: do nothing
    popq %r12 # Restore r12 (callee-saved)
    jz .do_nothing

    # SUD is still unblocked here

    # When emulating, rax will contain the syscall to emulate
    # Check whether we have to sigreturn
    cmpq $__NR_rt_sigreturn, %rax
    je .do_rt_sigreturn
    cmpq $__NR_sigreturn, %rax
    je .do_rt_sigreturn

    # Check whether we have to clone
    cmpq $__NR_clone, %rax
    je .do_clone_thread_or_clone_vfork

    # Check whether we have to clone3
    cmpq $__NR_clone3, %rax
    je .do_clone3

    # Check whether we have to vfork
    cmpq $__NR_vfork, %rax
    je .do_vfork

    # Check whether we have to fork
    cmpq $__NR_fork, %rax
    je .do_fork

    # If none of the above, something's wrong
    ud2
    int3

.do_nothing:
    exit_interposer
    ret

.do_rt_sigreturn:
    addq $8, %rsp # discard the pushed return address

    pushq %rdx
    # Retrieve selector on entry from the sigreturn stack
    movq %gs:SIGRETURN_STACK_SP_OFFSET, %rdx
    subq $8, %rdx
    movq %rdx, %gs:SIGRETURN_STACK_SP_OFFSET
    movq (%rdx), %rdx
    cmpq $0, %rdx
    popq %rdx
    je .sigreturn_syscall # Only restore SUD selector if selector at entry was BLOCK

    pushq %rdi
    movq %rsp, %rdi
    addq $8, %rdi # rdi now points to ucontext_t on the stack
    pushq %rax
    setup_c_stack
    callq setup_restore_selector_trampoline
    teardown_c_stack
    popq %rax
    popq %rdi

.sigreturn_syscall:
    syscall 
    ud2
    int3

.do_clone_thread_or_clone_vfork:
    # Check if CLONE_VFORK (0x4000) is set in clone_flags (%rdi)
    testq $0x4000, %rdi
    jnz .do_vfork

    # Check if rsi is 0 (which means it's a fork() where child inherits parent's stack)
    testq %rsi, %rsi
    jz .do_clone_syscall

    # Extract rip_after_syscall before manipulating stack
    movq (%rsp), %r10

    # Pre-adjust the child's stack pointer in %rsi without dereferencing it
    subq $8, %rsi 

    # Build a strictly defined child context on the parent's stack
    pushq %rsi  # 24(%rsp) modified_child_stack_ptr
    pushq %r10  # 16(%rsp) rip_after_syscall
    pushq %r12  # 8(%rsp)  original_r12
    pushq $1    # 0(%rsp)  spinlock (1 = locked by parent)
    movq %rsp, %r12

    # Execute clone syscall
    syscall

    testq %rax, %rax
    jz .new_thread_init
    js .Lclone_failed 

.Lwait_child:
    cmpq $0, (%r12)
    je .Lclone_done
    pause
    jmp .Lwait_child

.Lclone_failed:
.Lclone_done:
    # Cleanup child context frame
    movq %r12, %rsp
    addq $8, %rsp
    popq %r12
    addq $16, %rsp
    
    exit_interposer
    ret

.new_thread_init:
    # Child thread context
    movq 16(%r12), %r11  # rip_after_syscall
    movq 8(%r12), %rcx   # original_r12

    movq $0, (%r12)      # Unlock parent IMMEDIATELY

    # Write return address precisely where `ret` will look for it
    # Kernel already sets child %rsp to the modified %rsi
    movq %r11, (%rsp)

    movq %rcx, %r12      # Restore original r12
    jmp .new_thread


.do_clone_syscall:
    # All args are still set up as original
    syscall
    testq %rax, %rax
    jz .new_thread
    # Parent here: either done, or error
    exit_interposer
    ret

.do_fork:
    # fork() takes no arguments, child gets a COW copy of the stack.
    jmp .do_clone_syscall

.do_clone3:
    # clone3() passes a struct clone_args pointer in %rdi and size in %rsi.
    
    # Check if CLONE_VFORK (0x4000) is set in clone_args->flags (offset 0)
    movq 0(%rdi), %r11
    testq $0x4000, %r11
    jnz .do_vfork

    # Check if struct size is at least 56 (includes stack_size at offset 48)
    cmpq $56, %rsi
    jl .do_clone_syscall

    # Check if stack pointer is provided (clone_args->stack is at offset 40)
    movq 40(%rdi), %r8
    testq %r8, %r8
    jz .do_clone_syscall

    # Check if stack_size > 0 (clone_args->stack_size is at offset 48)
    movq 48(%rdi), %r9
    testq %r9, %r9
    jz .do_clone_syscall

    # Extract rip_after_syscall before manipulating stack
    movq (%rsp), %r10

    # Adjust stack size for our return address overhead
    subq $8, %r9

    # Build a strictly defined clone3 child context on the parent's stack
    pushq %r9   # 40(%rsp) modified_stack_size
    pushq %r8   # 32(%rsp) original_stack_base
    pushq %rdi  # 24(%rsp) original_clone_args_ptr
    pushq %r10  # 16(%rsp) rip_after_syscall
    pushq %r12  # 8(%rsp)  original_r12
    pushq $1    # 0(%rsp)  spinlock (1 = locked)
    movq %rsp, %r12

    # PREVENT RO MEMORY CRASH: We must copy clone_args to the parent stack 
    # before modifying stack_size to prevent crashing on const user structs.
    pushq %rbp
    movq %rsp, %rbp
    
    # Dynamically allocate space for clone_args based on %rsi length
    movq %rsp, %r11
    subq %rsi, %r11
    andq $-16, %r11
    movq %r11, %rsp

    # Copy the struct from %rdi to the allocated %rsp buffer
    pushq %rcx
    pushq %rsi
    pushq %rdi
    
    movq %rsi, %rcx
    movq %rdi, %rsi
    movq %rsp, %rdi
    addq $24, %rdi # Offset destination past our pushed registers
    rep movsb
    
    popq %rdi # original clone_args ptr
    popq %rsi # size
    popq %rcx
    
    movq %rsp, %rdi # Update %rdi to point to our stack-allocated clone_args

    # Write the modified stack_size to our copied struct safely
    movq %r9, 48(%rdi)

    # Execute clone3 with modified struct pointer
    syscall

    testq %rax, %rax
    jz .new_thread_init_clone3
    js .Lclone3_failed 

.Lwait_child_clone3:
    cmpq $0, (%r12)
    je .Lclone3_done
    pause
    jmp .Lwait_child_clone3

.Lclone3_failed:
.Lclone3_done:
    # Teardown the dynamically allocated struct buffer
    movq %rbp, %rsp
    popq %rbp

    # Teardown the child context
    movq %r12, %rsp
    addq $8, %rsp
    popq %r12
    addq $32, %rsp

    exit_interposer
    ret


.new_thread_init_clone3:
    # Child thread context for clone3
    movq 16(%r12), %r11  # rip_after_syscall
    movq 24(%r12), %rdi  # original_clone_args_ptr
    movq 32(%r12), %r8   # original_stack_base
    movq 40(%r12), %r9   # modified_stack_size
    movq 8(%r12), %rcx   # original_r12

    movq $0, (%r12)      # Unlock parent IMMEDIATELY

    # Calculate stack top safely inside child context
    addq %r8, %r9

    # Safely write the return address. Faults here will cleanly SIGSEGV the child.
    movq %r11, (%r9)

    # Restore r12
    movq %rcx, %r12

    # Extract clone_flags from user's original struct 
    # to pass it to `setup_new_thread` via %rdi
    movq 0(%rdi), %rdi
    
    jmp .new_thread

.new_thread:
    # Child running on a completely new stack
    # Save the return code
    pushq %rax
    setup_c_stack
    # clone_flags must be in %rdi
    callq setup_new_thread
    # Restore registers
    teardown_c_stack
    # Block SUD in the child
    exit_interposer
    # Cleanup and return to syscall site
    popq %rax
    ret

.do_vfork:
    # vfork is a really annoying syscall
    # Push the rip_after_syscall to a dedicated stack in the parent's gsrel region
    pushq %rsi
    movq %gs:RIP_AFTER_SYSCALL_STACK_SP_OFFSET, %rsi
    movq 8(%rsp), %rcx # rcx is clobbered by syscall anyway
    movq %rcx, (%rsi)
    addq $8, %rsi
    movq %rsi, %gs:RIP_AFTER_SYSCALL_STACK_SP_OFFSET
    popq %rsi
    
    # Do the syscall
    syscall
    testq %rax, %rax
    jz .vforked_child_enable_sud
    
    # Parent here: either done or error
    # Restore the saved rip_after_syscall to the stack & return
    pushq %rsi
    movq %gs:RIP_AFTER_SYSCALL_STACK_SP_OFFSET, %rsi
    subq $8, %rsi 
    movq (%rsi), %rcx # rcx has to hold `rip_after_syscall` anyway
    movq %rsi, %gs:RIP_AFTER_SYSCALL_STACK_SP_OFFSET
    popq %rsi
    movq %rcx, (%rsp)

    exit_interposer
    ret

.vforked_child_enable_sud:
    # We will set up a gsrel region here that shares sigdisps with the parent
    pushq %rax
    setup_c_stack
    callq setup_vforked_child
    teardown_c_stack
    popq %rax
    # Lower privileges and return
    exit_interposer
    ret

.section .text.restore_selector_trampoline,"ax",@progbits
.p2align 4
# This is the landingpad for sigreturns from user-supplied signal handlers
restore_selector_trampoline:
    # due to a potential redzone on the stack we cannot push anything on it including the rip after sigreturn
    # so we push everything 128 bytes down to avoid this potential redzone
    subq $128, %rsp
    pushq %rax

    # set SUD permissions to blocking
    movb $SYSCALL_DISPATCH_FILTER_BLOCK, %gs:SUD_SELECTOR_OFFSET

    # restore rip after sigreturn
    movq %gs:SIGRETURN_STACK_SP_OFFSET, %rax
    subq $8, %rax
    movq %rax, %gs:SIGRETURN_STACK_SP_OFFSET
    movq (%rax), %rax
    movq %rax, -0x8(%rsp) # put rip after sigreturn on the bottom of the stack this way we can jump to it without using a register later
    popq %rax
    addq $128, %rsp
    jmp *-0x90(%rsp) # old RIP sits at top of stack
