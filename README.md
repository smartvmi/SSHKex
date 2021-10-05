# SSHKex: Leveraging virtual machine introspection for extracting SSH keys and decrypting SSH network traffic

Files
1. `ssh_key_extraction.cpp`: Extract SSH keys using LibVMI and self-developed library
2. `cipher_enum.py`, `packet-ssh.c`, `read_files_for_wireshark.py`: wireshark plugins
3. `decryption-poc.py`: PoC (self-made) python code with Pycryptodome

## Wireshark

Follow: https://www.wireshark.org/docs/wsdg_html_chunked/ChSetupWin32.html and put `packet-ssh.c` on wireshark/epan/dissectors folder. Then, put `read_files_for_wireshark.py` and `cipher_enum.py` inside wsbuild32\run\RelWithDebInfo