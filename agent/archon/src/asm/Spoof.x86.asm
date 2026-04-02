[BITS 32]

DEFAULT REL

GLOBAL _Spoof
GLOBAL _SynthStackSleep86

[SECTION .text]
_Spoof:
    ret

; ---- ARC-02: Synthetic call-stack sleep (x86) ----
;
; DWORD __cdecl SynthStackSleep86(
;     PVOID                  WaitFunc,     // [ebp+0x08]
;     HANDLE                 hObject,      // [ebp+0x0C]
;     DWORD                  dwTimeout,    // [ebp+0x10]
;     BOOL                   bAlertable,   // [ebp+0x14]
;     PSYNTH_STACK_CTX_X86   Ctx           // [ebp+0x18]
; );
;
; SYNTH_STACK_CTX_X86 offsets (all 4 bytes on x86):
;   +0x00  OriginalEsp
;   +0x04  OriginalEbp
;   +0x08  ShadowBase       (unused here)
;   +0x0C  ShadowSize       (unused here)
;   +0x10  ShadowEsp
;   +0x14  ShadowEbp
;
; Pivots ESP/EBP to shadow stack, calls WaitFunc via stdcall
; (WaitForSingleObjectEx: 3 args), restores, returns DWORD.

_SynthStackSleep86:
    push   ebp
    mov    ebp, esp

    ; Save non-volatile registers
    push   ebx
    push   esi
    push   edi

    ; Load arguments into registers
    mov    edi, [ebp + 0x08]    ; WaitFunc
    mov    esi, [ebp + 0x18]    ; Ctx

    ; Save original ESP/EBP into context
    mov    [esi + 0x00], esp    ; OriginalEsp
    mov    [esi + 0x04], ebp    ; OriginalEbp

    ; Load WaitForSingleObjectEx args before pivot
    mov    eax, [ebp + 0x0C]   ; hObject
    mov    ebx, [ebp + 0x10]   ; dwTimeout
    mov    ecx, [ebp + 0x14]   ; bAlertable

    ; Pivot to shadow stack
    mov    esp, [esi + 0x10]    ; ShadowEsp
    mov    ebp, [esi + 0x14]    ; ShadowEbp

    ; Push WaitForSingleObjectEx args (stdcall, right-to-left)
    push   ecx                  ; bAlertable
    push   ebx                  ; dwTimeout
    push   eax                  ; hObject
    call   edi                  ; WaitFunc — stdcall cleans up its own args

    ; Save return value
    mov    ebx, eax

    ; Restore original ESP/EBP
    mov    esp, [esi + 0x00]    ; OriginalEsp
    mov    ebp, [esi + 0x04]    ; OriginalEbp

    ; Return value
    mov    eax, ebx

    ; Restore non-volatile registers
    pop    edi
    pop    esi
    pop    ebx

    pop    ebp
    ret
