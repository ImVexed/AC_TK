format pe gui 4.0
entry start
include 'INCLUDE/win32a.inc'
macro pushstr string
{
  local behind
  call behind
  db string,0
  behind:
}

macro loadv var1, var2
{
	mov var1, edi
	add var1, var2
	mov var1, [var1]
}
macro addv var1, var3
{
	mov var1, edi
	add var1, var3
}

macro storv var2, var3
{
	push edx
	mov edx, edi
	add edx, var2
	mov [edx], var3
	pop edx
}

macro saveax var1
{
	mov ebx, edi
	add ebx, var1
	mov dword [ebx], eax
}
macro callv var1
{
	mov eax, edi
	add eax, var1
	call dword [eax]
}

macro pushv var1
{
    mov eax, edi
	add eax, var1
	push eax
}

macro initvars
{
	mov     eax, [fs:0x30] 
    mov     eax, [eax+0xC] 
    mov     esi, [eax+0x1C] 
    lodsd 
    mov     ebx, [eax+0x8]
    mov     esi, [ebx+0x3C]  
    add     esi, ebx       
    mov     esi, [esi+0x78] 
    add     esi, ebx       
    mov     ecx, [esi+0x20] 
    add     ecx, ebx        
    xor     eax, eax 
    mov     edx, ecx 
nextproc: 
    push    eax esi ecx 
    mov     esi, [edx] 
    add     esi, ebx 
	addv   ecx, jGetProcAddress
next: 
	mov 	al, [esi] 
	mov 	ah, [ecx] 
	cmp 	al, ah 
	jnz 	nomatch 
	test	al, al 
	jz 		matchf 
	test    ah, ah 
	jz 	    matchf
	inc 	esi 
	inc 	ecx 
	jmp 	next 
matchf: 
	xor 	eax, eax 
nomatch:
    test    eax, eax 
    pop     ecx esi eax 
    jz      done 
    add     edx, 4 
    inc     eax 
    jmp     nextproc 

done: 
	add     eax, 4
    mov     edx, [esi+0x1C] 
    add     edx, ebx 
    mov     edx, [edx+eax*4] 
    add     edx, ebx 
	mov     eax, edx
	storv   dwKernel32, ebx
	storv   dwGetProcAddress, eax
	pushv   jLoadLibraryA
	push    ebx
	callv   dwGetProcAddress
	storv   dwLoadLibraryA, eax
}

macro CEF var1, lib, proc
{
	pushstr lib
	callv   dwLoadLibraryA
	pushstr proc
	push    eax
	callv   dwGetProcAddress
	saveax  var1
}

macro SIGS offset, sig, siglen
{
	addv esi, offset
	mov esi, dword [esi]
	xor edx, edx ; Current position
nextb:
	mov al, [esi + edx]
	mov ah, [edi + sig + edx]
	inc edx
	cmp al, ah
	je isdone
	cmp ah, -0x01 ;If the sig has a -0x01 in it, this will tell us the value is not an opcode and will always be different at runtime, thus that specific byte is useless to us
	je isdone
	add esi, edx
	xor edx, edx
	jmp nextb
isdone:
	cmp edx, siglen
	jne nextb
	add esi, edx ; ESI now contains our offset to the last opcode from jMask
}

macro NopEx len ; Address to insert nops = ESI
{
	pushv lpflOldProtect
	push 0x04
	push len
	push esi
	callv dwVirtualProtect
	xor ecx, ecx
@@:
	mov byte [esi + ecx], 0x90
	inc ecx
	cmp ecx, len
	jne @b
	pushv lpflOldProtect
	pushv lpflOldProtect
	push len
	push esi
	callv dwVirtualProtect
}

section ".code" code readable writeable executable
; Variables
start:
jmp rstart
jGetProcAddress = $ - start
db 'GetProcAddress', 0
jLoadLibraryA = $ - start
db 'LoadLibraryA', 0
jSig = $ - start
db 0x8B, 0x46, 0x0C, 0x0F, 0xBF, 0x88, 0x0A, 0x01, 0x00, 0x00, 0x8B, 0x56, 0x18, 0x89, 0x0A, 0x8B, 0x76, 0x14 ;-0x01 represents an unknown variable, also formatted as \x??\ etc.
jSigLen = $ - start - jSig
dwKernel32 = $ - start
dd ?
dwGetProcAddress = $ - start
dd ?
dwLoadLibraryA = $ - start
dd ?
dwVirtualProtect = $ - start
dd ?
lpflOldProtect = $ - start
dd ?
dwGetModuleHandleA = $ - start
dd ?
dwSleep = $ - start
dd ?
dwGetAsyncKeyState = $ - start
dd ?
dwBaseAddress = $ - start
dd ?
dbOrigin = $ - start ; We'll use this to TP back to as our starting position
db 1 ; Are we at our origin, or are we just disengadging from a target
dd ? ; Z
dd ? ; X
dd ? ; Y
dbTeamMode = $ - start ; 1 if team mode, 0 if no teams
db 0
dwGameMode = $ - start ; Used for cross checking if we're still in the same matchf
dd ?
; Real code
rstart:

	; EDI will contain the base address of our 'resource' section, any time we need to access a variable, we've already calculated it's length from the base via the $ - start. So any time you need to access a variable, it's just EDI + Var offset: EX: EDI + dwVirtualProtect
	initvars ; Get the address of LoadLibraryA & GetProcAddress
	CEF dwVirtualProtect,   'Kernel32', 'VirtualProtect'
	CEF dwGetModuleHandleA, 'Kernel32', 'GetModuleHandleA'
	CEF dwSleep,            'Kernel32', 'Sleep'
	CEF dwGetAsyncKeyState, 'User32', 'GetAsyncKeyState'
	
	push 0
	callv dwGetModuleHandleA
	saveax dwBaseAddress
	
	SIGS dwBaseAddress, jSig, jSigLen ; Our signature scanning macro, it will return a pointer to the last byte of the Sig in memory, so in the example, 0xFF & 0x0E = dec [esi], and since I want to nop them...
	
	NopEx 2 ; Simple macro that in this case will, NOP out 2 bytes into the address @ ESI. (Also VirtualProtect n' stuff)
	
	mov esi, 0x463626
	
	NopEx 2 ; Fast fire
	
	mov esi, 0x463786
	
	NopEx 10 ; No recoil
	
	mov esi, 0x429C52
	
	NopEx 2 ; Insta-Kill
	
recalcConstants: ; If we've jumped game moves, update our constant values
	mov eax, [0x50F49C] ; Get Game mode, & check if it's a team game mode
	storv dwGameMode, eax
	cmp eax, 0
	je isTeam
	cmp eax, 4
	je isTeam
	cmp eax, 5
	je isTeam
	cmp eax, 7
	je isTeam
	cmp eax, 11
	je isTeam
	cmp eax, 13
	je isTeam
	cmp eax, 14
	je isTeam
	cmp eax, 16
	je isTeam
	cmp eax, 17
	je isTeam
	cmp eax, 20
	je isTeam
	cmp eax, 21
	je isTeam
	addv eax, dbTeamMode
	mov byte [eax], 0
	jmp notTeam ; If eax isn't any of these values, it's not a team based game mode
isTeam:
	addv eax, dbTeamMode
	mov byte [eax], 1
notTeam:
	loadv eax, dwBaseAddress
	mov ecx, [eax + 0x109B74] ; Local player struct
	mov ebx, [eax + 0x10F500] ; Enemy count
	sub ebx, 2 ; 1 for our player & 1 for 0-base
	mov eax, [eax + 0x110D90] ; Enemy team
	xor esi, esi ; Our current player counter
targetEnemy:
	
	; Check if use is holding right click
	pusha
	push 0x02
	callv dwGetAsyncKeyState
	test eax, eax
	popa
	je sleepWait ; If not sleep for half a second
	
	push eax
	loadv eax, dwBaseAddress
	mov eax, [eax + 0x10F500]
	sub eax, 2
	cmp ebx, eax ; Check if player count is still the same
	pop eax ; mini memory leak if we don't do this
	jne recalcConstants ; If player count isn't the same, we've been re-instanced and need to recalculate bases
	
	push eax
	loadv eax, dwGameMode
	cmp eax, [0x50F49C]
	pop eax
	jne recalcConstants ; If game modes aren't the same, recalculate bases
	
	push esi ; We need to free a register coming up, and ESI is only needed right here
	mov edx, [eax + esi * 4] ; Enemy Team pointer + x DWORD = Current enemy
	
	push eax
	addv eax, dbOrigin
	cmp byte [eax], 0
	je skipsetReset ; If our reset position is already set, don't update it
	
	mov esi, [ecx + 0x3C] ; Load our current Z position
	mov [eax + 1], esi ; Store it for later
	
	mov esi, [ecx + 0x38] ; Load our current Z position
	mov [eax + 5], esi ; Store it for later
	
	mov esi, [ecx + 0x34] ; Load our current Z position
	mov [eax + 9], esi ; Store it for later
	
	mov byte [eax], 0
skipsetReset:	
	addv eax, dbTeamMode
	cmp byte [eax], 0
	je skipTeam ; If we're not in a team mode, skip team check
	
	mov al, byte [edx + 0x32C] 
	cmp al, byte [ecx + 0x32C] ; Compare to our team
	pop eax
	je nextEnemy
	jmp reTarget 
skipTeam:
	pop eax
reTarget: ; re-Check if enemy is alive, if alive, keep targeting 

	cmp dword [edx + 0xF8], 0 ; Get health
	jle nextEnemy ; if enemy health <= 0 goto next enemy
	
	mov esi, [edx + 0x3C] ; Enemy Z coord
	mov [ecx + 0x3C], esi ; Store in our Z coord
	
	mov esi, [edx + 0x38] ; Enemy X coord
	mov [ecx + 0x38], esi ; Store in our X coord
	
	mov esi, [edx + 0x34] ; Enemy Y coord
	mov [ecx + 0x34], esi ; Store in our Y coord
	
	mov byte [ecx + 0x224], 1 ; Shoot
		
	jmp reTarget
	
sleepWait:
	pusha
	
	addv eax, dbOrigin
	cmp byte [eax], 1 ; If 1 (true), we've already been teleported back to our origin
	je noresetSleep
	
	mov esi, [eax + 1] ; Get out Z coord from when we started teleporting
	mov [ecx + 0x3C], esi ; Store in our Z coord
	
	mov esi, [eax + 5] ; Get out X coord from when we started teleporting
	mov [ecx + 0x38], esi ; Store in our X coord
	
	mov esi, [eax + 9] ; Get out Y coord from when we started teleporting
	mov [ecx + 0x34], esi ; Store in our Y coord
	
	mov byte[eax], 1 ; We've been restored to our OG position, so set it as such
noresetSleep:
	push 0xC8
	callv dwSleep
	popa
	jmp targetEnemy	
nextEnemy:
	mov byte [ecx + 0x224], 0 ; Stop shooting, enemy is dead
	pop esi 
	inc esi
	cmp esi, ebx
	jle targetEnemy ; If we're not on the last enemy, jump to next enemy
	xor esi, esi ; If we're at the last enemy reset the target counter & jump to next enemy
	jmp targetEnemy
	
