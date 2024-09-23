# ProcessInjectAutomation

**A Python script that encrypts shellcode using AES, Caesar cipher, or RC4 encryption and generates a C# template for process injection. The generated C# code decrypts the shellcode at runtime and injects it into a remote process (e.g., `explorer.exe`).**

## 🔑 Key Features:
- **Supports Multiple Encryption Methods**: Encrypts shellcode using AES (256-bit), Caesar cipher, or RC4.
- **C# Template Generation**: Automatically generates a C# file that includes decryption logic and process injection code for the chosen encryption method.
- **Process Injection**: The generated C# file injects the decrypted shellcode into a remote process (e.g., `explorer.exe`) using API calls like `VirtualAllocEx`, `WriteProcessMemory`, and `CreateRemoteThread`.

## 📝 Usage:

### Command to Run the Script:
```bash
python3 ProcessInjectAutomation.py <shellcode.bin> <output.cs> <method>
Methods: AES, Caesar, or RC4
```

## Example
```bash
python3 ProcessInjectAutomation.py shellcode.bin inject.cs AES
```
