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
    movb $SYSCALL_DISPATCH_FILTER_ALLOW, %gs:SUD_SELECTOR_OFFSET
.endm

asm_syscall_hook:
    # Pop the saved rax from when we did the trampoline jump
    popq %rax

    subq $128, %rsp

    # At this point, the register & stack state is exactly as at the
    # syscall invocation site, except that the rip_after_syscall is
    # pushed to the stack at 128(%rsp)

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

    # At this point, all of our handling mingling has been undone
    # Most of the register state is the same as before (minus clobbered regs & rax & r12)
    # The stack is the same as during syscall invocation, plus the rip_after_syscall and r12

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
    addq $136, %rsp
    jmp *-8(%rsp)

.do_rt_sigreturn:
    # All the syscall arguments in rdi etc should still be in the original state
    # But they don't matter for sigreturn

    addq $136, %rsp # Discard the pushed return address and skip red zone padding
    # `wrap_signal_handler` will have set REG_RIP to `restore_selector_trampoline`
    # and the original RIP to return to is pushed to the stack of the original program
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

    # Push the right return address to the child's stack as well
    pushq %r11
    # Note: 136(%rsp) because we just pushed r11
    movq 136(%rsp), %r11 # rip_after_syscall -> clobbered reg
    subq $136, %rsi # Make space on the child stack and respect red zone
    movq %r11, 128(%rsi) # rip_after_syscall -> new top of child stack
    popq %r11

.do_clone_syscall:
    # All args are still set up as original
    syscall
    testq %rax, %rax
    jz .new_thread
    # Parent here: either done, or error
    exit_interposer
    addq $136, %rsp
    jmp *-8(%rsp)

.do_fork:
    # fork() takes no arguments, child gets a COW copy of the stack.
    # No need to push return address on a new stack pointer.
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

    pushq %r11
    movq 136(%rsp), %r11 # rip_after_syscall -> clobbered reg
    
    # Adjust stack size to make room on the child stack (128 red zone + 8 return addr)
    subq $136, %r9
    movq %r9, 48(%rdi)   # Write back new stack_size to struct clone_args
    
    # Calculate the new top of the child stack: stack (bottom) + stack_size
    addq %r8, %r9
    
    # Write the return address exactly where `jmp *-8(%rsp)` will look for it
    # after `.new_thread` adds 136 back to %rsp.
    movq %r11, 128(%r9)  
    
    popq %r11
    jmp .do_clone_syscall

.new_thread:
    # Child running on a completely new stack
    # Save the return code
    pushq %rax
    setup_c_stack
    # clone_flags should still be in %rdi: perfect
    callq setup_new_thread
    # Restore registers
    teardown_c_stack
    # Block SUD in the child
    exit_interposer
    # Cleanup and return to syscall site
    popq %rax
    addq $136, %rsp
    jmp *-8(%rsp)

.do_vfork:
    # vfork is a really annoying syscall
    # Push the rip_after_syscall to a dedicated stack in the parent's gsrel region
    pushq %rsi
    movq %gs:RIP_AFTER_SYSCALL_STACK_SP_OFFSET, %rsi
    movq 136(%rsp), %rcx # rcx is clobbered by syscall anyway
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
    movq %rcx, 128(%rsp)

    exit_interposer
    addq $136, %rsp
    jmp *-8(%rsp)

.vforked_child_enable_sud:
    # We will set up a gsrel region here that shares sigdisps with the parent
    pushq %rax
    setup_c_stack
    callq setup_vforked_child
    teardown_c_stack
    popq %rax
    # Lower privileges and return
    exit_interposer
    addq $136, %rsp
    jmp *-8(%rsp)

.section .text.restore_selector_trampoline,"ax",@progbits
.p2align 4
# This is the landingpad for sigreturns from user-supplied signal handlers
restore_selector_trampoline:
    # We've intercepted all signal-handler syscalls
    # Restore the selector to the value it had during the delivery of the signal
    pushq %rax
    pushq %rdx
    pushq %rcx

    # We always enter this trampoline with unblocked SUD

    # Pop & apply saved SUD permissions from the sigreturn stack
    movq %gs:SIGRETURN_STACK_SP_OFFSET, %rax
    decq %rax
    movb 0(%rax), %dl # Get privilege level into dl
    movq %rax, %gs:SIGRETURN_STACK_SP_OFFSET # Update sigreturn stack pointer
    movb %dl, %gs:SUD_SELECTOR_OFFSET

.return_to_app:
    popq %rcx
    popq %rdx
    popq %rax
    # Only orig_rip is on the stack here (from wrap_signal_handler), no red zone gap
    addq $8, %rsp
    jmp *-8(%rsp) # Indirect jump to the safely stored RIP
