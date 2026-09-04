# UniCryptor3 PowerShell Module  

**Hybrid certificate‑ and password‑based encryption toolkit for PowerShell**  

---  

## Table of Contents  

- [Overview](#overview)  
- [Features](#features)  
- [Prerequisites](#prerequisites)  
- [Installation](#installation)  
- [Quick Start](#quick-start)  
- [Usage Examples](#usage-examples)  
  - [Protect / Unprotect a string](#protect--unprotect-a-string)  
  - [Protect / Unprotect a file (certificate mode)](#protect--unprotect-a-file-certificate-mode)  
  - [Protect / Unprotect a file (password mode)](#protect--unprotect-a-file-password-mode)  
  - [Encrypt / Decrypt a folder](#encrypt--decrypt-a-folder)  
  - [Create an encrypted 7‑zip archive](#create-an-encrypted-7‑zip-archive)  
  - [Inspect container information](#inspect-container-information)  
- [Available Cmdlets / Functions](#available-cmdlets--functions)  
- [Configuration Options](#configuration-options)  
- [Error Handling & Logging](#error-handling--logging)  
- [Contributing](#contributing)  
- [License](#license)  
- [Contact](#contact)  

---  

## Overview  

`UniCryptor3` is a pure‑PowerShell implementation of a modern encryption container format.  
It supports:

* **AES‑256‑GCM** chunked encryption (1 MiB chunks, per‑chunk 16‑byte authentication tag).  
* **Key transport** via RSA‑OAEP‑SHA256 (multiple X.509 certificate recipients) **or** PBKDF2‑HMAC‑SHA256 derived keys (password mode).  
* Transparent **metadata encryption** (original file length, timestamps).  
* Seamless protection of **strings, files, folders** and **7‑zip archives**.  
* Automatic progress reporting, overwrite handling and timestamp restoration.  

The public API is exposed through a set of easy‑to‑use PowerShell functions prefixed with `UC`.  
All heavy lifting is done by the `UniCryptor3` .NET class defined in the script.  

---  

## Features  

| Feature | Description |
|---------|-------------|
| **Chunked AEAD** | Handles files of any size; each chunk is authenticated separately. |
| **Certificate mode** | Wraps a random AES key with one or more RSA public keys; recipients only need the matching private key to decrypt. |
| **Password mode** | Derives an AES key from a password using PBKDF2‑HMAC‑SHA256 (default ≥ 300 k iterations). |
| **Metadata block** | Stores original length and UTC timestamps inside the first plaintext chunk (optional). |
| **7‑zip integration** | Uses SevenZipSharp (`7z64.dll`) to compress folders, then encrypts the archive password in a UniCryptor container appended to the 7‑z file. |
| **Progress events** | Cmdlets display a live progress bar when the `$Options.ShowProgress` flag is `$true`. |
| **Self‑signed cert helper** | `New-UCSelfSignedCertificate` creates a suitable RSA certificate for testing. |
| **Cross‑platform** | Requires PowerShell 7.5+; works on Windows, macOS and Linux (provided the native 7‑z DLL is present). |

---  

## Prerequisites  

* PowerShell **7.5** or later (`#requires -Version 7.5`).  
* .NET 6+ runtime (bundled with PowerShell 7).  
* **SevenZipSharp** library (`SevenZipSharp.dll` + `7z64.dll`) located in `bin\7Zip4PowerShell` relative to the script.  
* For certificate mode: at least one X.509 certificate with an RSA public key in the **CurrentUser\My** or **CurrentUser\AddressBook** store.  

---  

## Installation  

### 1. Clone the repository  

```bash
git clone https://github.com/your‑account/UniCryptor3.git
cd UniCryptor3
```

### 2. Import the module  

```powershell
# Import the script directly (development)
. .\UniCryptor3.ps1

# Or, import as a module after copying to a module path
$modulePath = "$HOME\Documents\PowerShell\Modules\UniCryptor3"
Copy-Item -Recurse -Force . $modulePath
Import-Module UniCryptor3
```

### 3. Verify that the 7‑z DLL is found  

```powershell
$dll = Join-Path $PSScriptRoot 'bin\7Zip4PowerShell\7z64.dll'
Test-Path $dll   # should return True
```

---  

## Quick Start  

```powershell
# Create a test certificate (run once)
$cert = New-UCSelfSignedCertificate -Subject 'UniCryptorDemo'

# Protect a string using the default certificate store
$enc = Protect-UCString -PlainText 'Secret message'
$dec = Unprotect-UCString -ProtectedText $enc
$dec   # -> Secret message
```

---  

## Usage Examples  

### Protect / Unprotect a string  

```powershell
# Certificate mode (default)
$protected = Protect-UCString -PlainText 'My password is 1234'
$clear     = Unprotect-UCString -ProtectedText $protected

# Password mode
$protectedPwd = Protect-UCString -PlainText 'Top‑secret' -Password 'P@ssw0rd!'
$clearPwd     = Unprotect-UCString -ProtectedText $protectedPwd -Password 'P@ssw0rd!'
```

---

### Protect / Unprotect a file (certificate mode)  

```powershell
# Get a certificate (or use the helper above)
$myCert = Get-UCCertificates -Thumbprint 'ABCD1234EF567890...' -RequirePrivateKey

# Encrypt the file
$encPath = Protect-UCFile `
    -Path      'C:\Data\report.docx' `
    -Destination 'C:\Secure' `
    -Certificate $myCert `
    -Overwrite

# Decrypt the file (no need to pass the cert again – local private key is used)
$decPath = Unprotect-UCFile `
    -Path $encPath `
    -Destination 'C:\Restored' `
    -Overwrite
```

---

### Protect / Unprotect a file (password mode)  

```powershell
$encPath = Protect-UCFile `
    -Path      'C:\Secrets\notes.txt' `
    -Destination 'C:\Secure' `
    -Password 'Very$trongPwd' `
    -Overwrite

$decPath = Unprotect-UCFile `
    -Path $encPath `
    -Destination 'C:\Restored' `
    -Password 'Very$trongPwd' `
    -Overwrite
```

---

### Encrypt / Decrypt a folder  

```powershell
# Encrypt all files under a folder (recursively) using certificates
$summary = Protect-UCFile `
    -Path      'C:\Projects\MyApp' `
    -Destination 'C:\Encrypted' `
    -Recurse `
    -Overwrite

$summary.Succeeded.Count   # number of files encrypted
$summary.Failed            # any errors

# Decrypt the whole folder back
$summary = Unprotect-UCFile `
    -Path      'C:\Encrypted' `
    -Destination 'C:\Decrypted' `
    -Recurse `
    -Overwrite
```

---

### Create an encrypted 7‑zip archive  

```powershell
# Use existing certificates or let the cmdlet pick them automatically
Compress-UCArchive `
    -Folder          'C:\Projects\MyApp' `
    -DestinationPath 'C:\Backups\MyApp.7z' `
    -CompressionLevel High `
    -Overwrite

# Retrieve the password stored inside the archive (requires the private key)
$pwd = Get-UCArchivePassword -ArchivePath 'C:\Backups\MyApp.7z'

# Extract the archive
Expand-UCArchive `
    -ArchivePath 'C:\Backups\MyApp.7z' `
    -Destination 'C:\RestoredApp' `
    -Overwrite
```

---

### Inspect container information  

```powershell
$info = Get-UCFileInfo -Path 'C:\Secure\report.docx.AESPKI'
$info | Format-List

# Example output:
# File               : C:\Secure\report.docx.AESPKI
# FileLength         : 124578
# ContainerVersion   : 2
# Mode               : Certificates
# MetadataEncrypted  : True
# CiphertextLength   : 125102
# ContainerStartsAt  : 0
# Recipients         : {KeyId = 1A2B3C..., MatchedLocalCertificate = CN=UniCryptorDemo}
```

---  

## Available Cmdlets / Functions  

| Cmdlet | Description |
|--------|-------------|
| `Protect-UCString` | Encrypt a plain‑text string (certificate or password mode). |
| `Unprotect-UCString` | Decrypt a string produced by `Protect-UCString`. |
| `Protect-UCFile` | Encrypt a file, folder or recursive tree. Supports certificate or password mode. |
| `Unprotect-UCFile` | Decrypt a previously encrypted file/folder. |
| `Get-UCFileInfo` | Show container metadata without needing a private key. |
| `Compress-UCArchive` | Create an encrypted 7‑zip archive from a folder. |
| `Expand-UCArchive` | Decrypt and extract an encrypted 7‑zip archive. |
| `Get-UCArchivePassword` | Retrieve the password used to encrypt a 7‑zip archive (requires private key). |
| `Get-UCArchiveContent` | List files inside an encrypted archive (no extraction). |
| `Get-UCCertificates` | Helper to enumerate usable certificates from the current user store. |
| `New-UCSelfSignedCertificate` | Generate a self‑signed RSA certificate suitable for UniCryptor3. |

All functions accept the standard `-WhatIf` / `-Confirm` switches where applicable.  

---  

## Configuration Options  

The `UniCryptor3` class exposes an `$Options` object that can be tuned before running a command:

```powershell
$uc = [UniCryptor3]::new()
$uc.Options.ShowProgress          = $true   # display Write‑Progress bars
$uc.Options.CompressionLevel      = 'High'  # for 7‑z archives only
$uc.Options.EncryptHeaders        = $true   # encrypt 7‑z file headers
$uc.Options.OnlyFilesWithArchiveBit = $false # limit compression to files with the Archive attribute
$uc.Options.ClearArchiveBit       = $false  # clear the Archive attribute after compression
```

When using the high‑level cmdlets, you can set these options via parameters (`-CompressionLevel`, `-OnlyFilesWithArchiveBit`, `-ClearArchiveBit`).  

---  

## Error Handling & Logging  

* **Exceptions** – All low‑level errors are thrown as .NET exceptions (`System.IO.IOException`, `System.Security.Cryptography.CryptographicException`, etc.).  
* **Verbose output** – Use `-Verbose` with any cmdlet to see detailed progress messages.  
* **Progress** – Controlled by `$uc.Options.ShowProgress` (default `$true`).  

Typical error scenarios:

| Situation | What you will see |
|-----------|-------------------|
| Wrong password or missing private key | `CryptographicException: Authentication failed: wrong key, certificate or password, or the data is corrupted` |
| Destination file already exists and `-Overwrite` not specified | `IOException: Output file '…' already exists` |
| No suitable certificates found | `InvalidOperationException: No encryption certificates configured` |
| Archive password cannot be retrieved | `FileNotFoundException` or `CryptographicException` depending on the cause. |

---  

## Contributing  

Contributions are welcome! Please follow these steps:

1. Fork the repository.  
2. Create a feature branch (`git checkout -b feature/my‑new‑feature`).  
3. Add your changes, ensuring **ASCII‑only** documentation and comments.  
4. Run the built‑in PowerShell script linting (`Invoke-ScriptAnalyzer`) and unit tests (if any).  
5. Submit a Pull Request with a clear description of the change.  

All contributions must be compatible with the MIT license (see below).  

---  

## License  

This project is licensed under the **MIT License** – see the `LICENSE` file for details.  

---  

## Contact  

**Andrew Afanasiev**  
- Email: AfanasievAA@yandex.ru  
- GitHub: <https://github.com/your-account/UniCryptor3>  

Feel free to open an issue for bug reports, feature requests, or general questions.
