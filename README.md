# PT_LOAD Injector
This injector was developed in Python using the lief, pwntools and argparse libraries. Therefore, these libraries must be installed on your device.

(Python 3.10.x)

```
pip install lief
pip install pwntools
pip install argparse
```

# Usage & Output
```
➜  ~ ./test
Infect Me !
➜  ~ python3 main.py -f ./test
Shellcode size:  53
[+] Segment added
[+] Real EntryPoint:  0x8049070
[+] New EntryPoint:  0x10004000
➜  ~ ls
main.py  test  test.c  test_infected
➜  ~ chmod +x test_infected
➜  ~ ./test_infected
this must be rhotav!
Infect Me !
```
