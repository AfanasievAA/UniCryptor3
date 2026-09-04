#requires -Version 7.5
<#
.SYNOPSIS
  UniCryptor3 – hybrid certificate‑ and password‑based encryption toolkit for PowerShell.

.DESCRIPTION
  The UniCryptor3 class implements a complete encryption solution that works on strings,
  files, folders and 7‑zip archives.  It uses AES‑256‑GCM for data encryption and supports
  two key‑transport mechanisms:
    • RSA‑OAEP‑SHA256 wrapped keys for X.509 certificates (multiple recipients supported)
    • PBKDF2‑HMAC‑SHA256 derived keys for password‑only protection

  Features include:
    • Chunked AEAD encryption (1 MiB chunks) with built‑in integrity verification.
    • Transparent container format (header, ciphertext, footer) that can be appended to
      existing files (e.g., 7‑z archives remain valid after encryption).
    • Optional metadata encryption (original file size, timestamps) stored inside the
      first plaintext chunk.
    • Automatic handling of encryption certificates, password prompting, and progress
      reporting.
    • Helper methods for protecting/unprotecting strings, files, folders and archives,
      plus utilities for inspecting container information.

.NOTES
  Version:        0.1
  Author:         Andrew Afanasiev
  Date:           03.09.2026
  Contacts:       AfanasievAA@yandex.ru
  Changes:
    • Initial release

.EXAMPLE
  # Protect a simple string with the default certificate store
  $enc = Protect-UCString -PlainText 'Sensitive data'
  $dec = Unprotect-UCString -ProtectedText $enc

.EXAMPLE
  # Protect a file using a specific certificate
  $cert = Get-UCCertificates -Thumbprint 'ABCD1234EF567890...' -RequirePrivateKey
  Protect-UCFile -Path 'C:\Data\report.docx' -Destination 'C:\Secure' -Certificate $cert -Overwrite

.EXAMPLE
  # Protect a file with a password (no certificates needed)
  Protect-UCFile -Path 'C:\Secrets\notes.txt' -Destination 'C:\Secure' -Password 'P@ssw0rd!' -Overwrite

.EXAMPLE
  # Encrypt an entire folder recursively and create an certificate-encrypted 7‑zip archive
  $certs = Get-UCCertificates -RequirePrivateKey
  Compress-UCArchive -Folder 'C:\Projects' -DestinationPath 'C:\Backups\proj.7z' -Certificate $certs -CompressionLevel High -Overwrite

.EXAMPLE
  # Decrypt an encrypted archive and extract its contents
  $pwd = Get-UCArchivePassword -ArchivePath 'C:\Backups\proj.7z'
  Expand-UCArchive -ArchivePath 'C:\Backups\proj.7z' -Destination 'C:\Restore' -Overwrite

.DETAILS
  Crypto core: AES-256-GCM chunked AEAD (1 MiB chunks, per-chunk 16-byte tag, nonce = 8 random bytes + 4-byte big-endian chunk counter).
  Key transport: RSA-OAEP-SHA256 wraps only the 32-byte AES key, one block per recipient.
  Password mode: PBKDF2-HMAC-SHA256 (>= 300k iterations, dedicated 16-byte salt); salt and iteration count travel in the envelope.
  Container v2 layout (inline footer, parsed from the end of the file):
    [header 32B: magic(8) version u16 flags u16 nonce(12) ctLength u64][ciphertext chunks][footer: envelopeLen u32 envelope ctLength u64 crc8 footerLen u32]
    footerLen (last 4 bytes) points to the footer start; the header sits right before the ciphertext (offset 0 for regular files,
    after the 7z stream for archives). flags: bit0 = password mode, bit1 = encrypted metadata present.
    Recipient entry: [keyId16 = first 16 bytes of SHA-256(thumbprint)][wrappedKeyLen u32][RSA-wrapped key].
    Original file metadata (length, timestamps) is a TLV block encrypted inside the first plaintext chunk.
   Design note: types created by Add-Type (UniCryptor.UCGcm, SevenZip.*) cannot be referenced by type literals inside
    PowerShell class bodies: classes bind types at parse time, before Add-Type runs. All such references live in the
    top-level helper functions below (functions resolve types at call time); class methods call these functions.
  No console output from library methods: progress via Write-Progress (Options.ShowProgress), errors via exceptions.

#>

 $UCScriptRoot = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
 $UC7zFolder = Join-Path $UCScriptRoot 'bin\7Zip4Powershell'
if (Test-Path -LiteralPath $UC7zFolder) {
    if (-not ('SevenZip.SevenZipCompressor' -as [type])) {
        Add-Type -Path (Join-Path $UC7zFolder 'SevenZipSharp.dll')
        [SevenZip.SevenZipCompressor]::SetLibraryPath((Join-Path $UC7zFolder '7z64.dll'))
    }
}

 $UCGcmSource = @'
using System;
using System.Security.Cryptography;

namespace UniCryptor {
    public static class UCGcm {
        // Encrypts one plaintext chunk; returns ciphertext || 16-byte GCM tag.
        public static byte[] EncryptChunk(byte[] key, byte[] nonce, byte[] plaintext, int plaintextLength, byte[] aad) {
            byte[] output = new byte[plaintextLength + 16];
            using (AesGcm gcm = new AesGcm(key, 16)) {
                gcm.Encrypt(nonce, new ReadOnlySpan<byte>(plaintext, 0, plaintextLength), new Span<byte>(output, 0, plaintextLength), new Span<byte>(output, plaintextLength, 16), aad);
            }
            return output;
        }
        // Decrypts ciphertext||tag; throws CryptographicException on authentication failure.
        public static byte[] DecryptChunk(byte[] key, byte[] nonce, byte[] ciphertextWithTag, int ciphertextLength, byte[] aad) {
            if (ciphertextLength < 17) throw new CryptographicException("Chunk too short");
            byte[] output = new byte[ciphertextLength - 16];
            using (AesGcm gcm = new AesGcm(key, 16)) {
                gcm.Decrypt(nonce, new ReadOnlySpan<byte>(ciphertextWithTag, 0, ciphertextLength - 16), new ReadOnlySpan<byte>(ciphertextWithTag, ciphertextLength - 16, 16), new Span<byte>(output), aad);
            }
            return output;
        }
        // Constant-time comparison, used for magic and footer CRC checks.
        public static bool FixedTimeEquals(byte[] left, byte[] right) {
            if (left == null || right == null || left.Length != right.Length) return false;
            return CryptographicOperations.FixedTimeEquals(left, right);
        }
    }
}
'@
if (-not ('UniCryptor.UCGcm' -as [type])) { Add-Type -TypeDefinition $UCGcmSource -Language CSharp }

# ---------- Runtime type resolution helpers ----------
# These functions are the ONLY places referencing Add-Type-loaded types: function bodies resolve type literals at call time.
function Invoke-UCGcmEncrypt {
    param([byte[]]$Key, [byte[]]$Nonce, [byte[]]$Plaintext, [int]$PlaintextLength, [byte[]]$Aad)
    return ,([UniCryptor.UCGcm]::EncryptChunk($Key, $Nonce, $Plaintext, $PlaintextLength, $Aad))
}
function Invoke-UCGcmDecrypt {
    param([byte[]]$Key, [byte[]]$Nonce, [byte[]]$Ciphertext, [int]$CiphertextLength, [byte[]]$Aad)
    return ,([UniCryptor.UCGcm]::DecryptChunk($Key, $Nonce, $Ciphertext, $CiphertextLength, $Aad))
}
function Test-UCByteArrayEqual {
    param([byte[]]$Left, [byte[]]$Right)
    return [UniCryptor.UCGcm]::FixedTimeEquals($Left, $Right)
}
function New-UCSevenZipCompressor {
    param($Options)
    $compressor = [SevenZip.SevenZipCompressor]::new()
    $compressor.ArchiveFormat = [SevenZip.OutArchiveFormat]::SevenZip
    $compressor.CompressionMethod = [SevenZip.CompressionMethod]::Lzma2
    $compressor.CompressionLevel = $Options.CompressionLevel
    $compressor.DirectoryStructure = $true
    $compressor.PreserveDirectoryRoot = $false
    $compressor.EncryptHeaders = $Options.EncryptHeaders
    $compressor.ZipEncryptionMethod = [SevenZip.ZipEncryptionMethod]::AES256
    $compressor.CustomParameters.Add('mt', 'on')
    return $compressor
}
function New-UCSevenZipExtractor {
    param([string]$ArchivePath, [string]$Password)
    return [SevenZip.SevenZipExtractor]::new($ArchivePath, $Password)
}
function Register-UC7zProgress {
    param([object]$InputObject, [string]$EventName, [string]$SourceIdentifier)
    # Remove stale subscription with the same identifier, if any
    Unregister-Event -SourceIdentifier $SourceIdentifier -ErrorAction SilentlyContinue
    $null = Register-ObjectEvent -InputObject $InputObject -EventName $EventName -SourceIdentifier $SourceIdentifier -Action { if ($null -ne $Event.SourceArgs -and $null -ne $Event.SourceArgs[1]) { $global:UniCryptor3Progress = [int]$Event.SourceArgs[1].PercentDone } }
    $global:UniCryptor3Progress = 0
}

class UCFormat {
    static [byte[]] $Magic = [byte[]](0x3C, 0x7F, 0xA2, 0x51, 0xE9, 0x0D, 0x84, 0xB6)
    static [UInt16] $Version = 2
    static [int] $HeaderSize = 32
    static [int] $ChunkSize = 1048576
    static [int] $MaxRecipients = 100
    static [UInt16] $FlagPassword = 1
    static [UInt16] $FlagMetadata = 2
    static [UInt32] $DefaultPbkdf2Iterations = 300000

    static [byte[]] BuildHeader([UInt16]$Flags, [byte[]]$Nonce, [UInt64]$CtLength) {
        if ($Nonce.Length -ne 12) { throw [System.ArgumentException]::new('Nonce must be 12 bytes') }
        $header = [byte[]]::new([UCFormat]::HeaderSize)
        [Array]::Copy([UCFormat]::Magic, 0, $header, 0, 8)
        [Array]::Copy([BitConverter]::GetBytes([UInt16][UCFormat]::Version), 0, $header, 8, 2)
        [Array]::Copy([BitConverter]::GetBytes([UInt16]$Flags), 0, $header, 10, 2)
        [Array]::Copy($Nonce, 0, $header, 12, 12)
        [Array]::Copy([BitConverter]::GetBytes([UInt64]$CtLength), 0, $header, 24, 8)
        return $header
    }
    static [object] ParseHeader([byte[]]$HeaderBytes) {
        if ($HeaderBytes.Length -ne [UCFormat]::HeaderSize) { throw [System.FormatException]::new('Invalid container header size') }
        if (-not (Test-UCByteArrayEqual ([byte[]]$HeaderBytes[0..7]) ([UCFormat]::Magic))) { throw [System.FormatException]::new('Bad magic: this is not a UniCryptor3 container') }
        # Renamed: a local variable matching a class member name is rejected by the class binder
        $parsedVersion = [BitConverter]::ToUInt16($HeaderBytes, 8)
        if ($parsedVersion -ne [UCFormat]::Version) { throw [System.FormatException]::new("Unsupported container version $parsedVersion (expected $([UCFormat]::Version))") }
        $flags = [BitConverter]::ToUInt16($HeaderBytes, 10)
        if ($flags -gt 3) { throw [System.FormatException]::new("Unsupported header flags $flags") }
        $nonce = [byte[]]::new(12)
        [Array]::Copy($HeaderBytes, 12, $nonce, 0, 12)
        $ctLength = [BitConverter]::ToUInt64($HeaderBytes, 24)
        if ($ctLength -gt [UInt64][Int64]::MaxValue) { throw [System.FormatException]::new('Invalid ciphertext length') }
        return [PSCustomObject]@{ Version = $parsedVersion; Flags = $flags; Nonce = $nonce; CtLength = $ctLength }
    }
    # AAD binds every chunk to the exact header (nonce, flags, lengths) and to its position in the stream
    static [byte[]] BuildAad([byte[]]$HeaderBytes, [UInt32]$ChunkIndex) {
        $aad = [byte[]]::new([UCFormat]::HeaderSize + 4)
        [Array]::Copy($HeaderBytes, $aad, [UCFormat]::HeaderSize)
        [Array]::Copy([BitConverter]::GetBytes([UInt32]$ChunkIndex), 0, $aad, [UCFormat]::HeaderSize, 4)
        return $aad
    }
    static [byte[]] NonceFor([byte[]]$NonceBase, [UInt32]$ChunkIndex) {
        # Low 4 bytes of the nonce carry the big-endian chunk counter
        $nonce = [byte[]]::new(12)
        [Array]::Copy($NonceBase, 0, $nonce, 0, 8)
        $counter = [BitConverter]::GetBytes([UInt32]$ChunkIndex)
        $nonce[8] = $counter[3]; $nonce[9] = $counter[2]; $nonce[10] = $counter[1]; $nonce[11] = $counter[0]
        return $nonce
    }
    static [byte[]] Slice([byte[]]$Array, [int]$Start, [int]$Length) {
        if ($Length -le 0) { return [byte[]]::new(0) }
        if ($Start -lt 0 -or $Start + $Length -gt $Array.Length) { throw [System.ArgumentOutOfRangeException]::new('Slice') }
        $result = [byte[]]::new($Length)
        [Array]::Copy($Array, $Start, $result, 0, $Length)
        return $result
    }
}

class UCRandom {
    # Printable ASCII without visually ambiguous glyphs (S, O, 0 and friends)
    static [int[]] $PasswordCharset = 49..57 + 65..72 + 74..78 + 80..82 + 84..90 + 97..104 + 106 + 107 + 109 + 110 + 112..122 + 33 + 35 + 36 + 38 + 43 + 45
    static [string] NewPassword([int]$MinLength, [int]$MaxLength) {
        $length = if ($MaxLength -gt $MinLength) { [System.Security.Cryptography.RandomNumberGenerator]::GetInt32($MinLength, $MaxLength + 1) } else { $MinLength }
        $pool = [UCRandom]::PasswordCharset.Length
        $sb = [System.Text.StringBuilder]::new($length)
        for ($i = 0; $i -lt $length; $i++) { $null = $sb.Append([char][UCRandom]::PasswordCharset[[System.Security.Cryptography.RandomNumberGenerator]::GetInt32($pool)]) }
        return $sb.ToString()
    }
    static [byte[]] NewKey() { $key = [byte[]]::new(32); [System.Security.Cryptography.RandomNumberGenerator]::Fill($key); return $key }
    static [byte[]] NewNonce() { $nonce = [byte[]]::new(12); [System.Security.Cryptography.RandomNumberGenerator]::Fill($nonce); return $nonce }
    static [byte[]] NewSalt() { $salt = [byte[]]::new(16); [System.Security.Cryptography.RandomNumberGenerator]::Fill($salt); return $salt }
}

class UCMetadata {
    # TLV block encrypted inside the first plaintext chunk:
    # [totalLen u32][ (tag u8)(len u16)(value) ]*  tags: 1 = original length u64, 2 = creation time UTC ticks i64, 3 = last write time UTC ticks i64
    static [byte[]] Build([UInt64]$OriginalLength, $CreationTimeUtc, $LastWriteTimeUtc) {
        $fields = [System.Collections.Generic.List[byte[]]]::new()
        $fields.Add([byte[]]@([byte]1) + [BitConverter]::GetBytes([UInt16]8) + [BitConverter]::GetBytes([UInt64]$OriginalLength))
        if ($null -ne $CreationTimeUtc) { $fields.Add([byte[]]@([byte]2) + [BitConverter]::GetBytes([UInt16]8) + [BitConverter]::GetBytes([Int64]$CreationTimeUtc.Ticks)) }
        if ($null -ne $LastWriteTimeUtc) { $fields.Add([byte[]]@([byte]3) + [BitConverter]::GetBytes([UInt16]8) + [BitConverter]::GetBytes([Int64]$LastWriteTimeUtc.Ticks)) }
        $total = 4; foreach ($field in $fields) { $total += $field.Length }
        $ms = [System.IO.MemoryStream]::new()
        $ms.Write([BitConverter]::GetBytes([UInt32]$total), 0, 4)
        foreach ($field in $fields) { $ms.Write($field, 0, $field.Length) }
        return $ms.ToArray()
    }
    static [object] Parse([byte[]]$Buffer) {
        if ($Buffer.Length -lt 4) { throw [System.FormatException]::new('Invalid metadata block') }
        $total = [int][BitConverter]::ToUInt32($Buffer, 0)
        if ($total -lt 4 -or $total -gt 1024 -or $total -gt $Buffer.Length) { throw [System.FormatException]::new('Invalid metadata block length') }
        $result = [PSCustomObject]@{ Length = $total; OriginalLength = $null; CreationTimeUtc = $null; LastWriteTimeUtc = $null }
        $pos = 4
        while ($pos -lt $total) {
            if ($pos + 3 -gt $total) { throw [System.FormatException]::new('Invalid metadata field') }
            $tag = $Buffer[$pos]; $pos++
            $len = [int][BitConverter]::ToUInt16($Buffer, $pos); $pos += 2
            if ($len -lt 1 -or $pos + $len -gt $total) { throw [System.FormatException]::new('Invalid metadata field length') }
            $value = [byte[]]::new($len); [Array]::Copy($Buffer, $pos, $value, 0, $len); $pos += $len
            if ($len -ne 8) { throw [System.FormatException]::new('Invalid metadata field payload length') }
            switch ($tag) {
                1 { $result.OriginalLength = [BitConverter]::ToUInt64($value, 0) }
                2 { $result.CreationTimeUtc = [DateTime]::new([BitConverter]::ToInt64($value, 0), [System.DateTimeKind]::Utc) }
                3 { $result.LastWriteTimeUtc = [DateTime]::new([BitConverter]::ToInt64($value, 0), [System.DateTimeKind]::Utc) }
                default { throw [System.FormatException]::new("Unknown metadata tag $tag") }
            }
        }
        return $result
    }
}

class UCEnvelope {
    static [byte[]] GetKeyId([object]$Certificate) {
        # 16-byte key id derived from the thumbprint: hides recipient identity from casual inspection
        return [UCFormat]::Slice([System.Security.Cryptography.SHA256]::HashData([System.Text.Encoding]::ASCII.GetBytes($Certificate.Thumbprint)), 0, 16)
    }
    static [byte[]] WrapKeyForCertificates([byte[]]$Key, [object]$Certificates) {
        if ($Key.Length -ne 32) { throw [System.ArgumentException]::new('AES-256 key expected') }
        $ms = [System.IO.MemoryStream]::new()
        $count = 0
        foreach ($cert in $Certificates) {
            $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($cert)
            if ($null -eq $rsa) { throw [System.ArgumentException]::new("Certificate '$($cert.Thumbprint)' has no usable RSA public key") }
            try {
                $wrapped = $rsa.Encrypt($Key, [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA256)
                $keyId = [UCEnvelope]::GetKeyId($cert)
                $ms.Write($keyId, 0, 16)
                $ms.Write([BitConverter]::GetBytes([UInt32]$wrapped.Length), 0, 4)
                $ms.Write($wrapped, 0, $wrapped.Length)
                $count++
                if ($count -gt [UCFormat]::MaxRecipients) { throw [System.ArgumentException]::new('Too many recipients') }
            } finally { $rsa.Dispose() }
        }
        return $ms.ToArray()
    }
    static [object] ParseRecipients([byte[]]$Envelope) {
        $list = [System.Collections.Generic.List[object]]::new()
        $pos = 0
        while ($pos -lt $Envelope.Length) {
            if ($pos + 20 -gt $Envelope.Length) { throw [System.FormatException]::new('Invalid recipient envelope') }
            $keyId = [byte[]]::new(16); [Array]::Copy($Envelope, $pos, $keyId, 0, 16); $pos += 16
            $len = [int][BitConverter]::ToUInt32($Envelope, $pos); $pos += 4
            if ($len -lt 128 -or $len -gt 1024 -or $pos + $len -gt $Envelope.Length) { throw [System.FormatException]::new('Invalid wrapped key length') }
            $wrapped = [byte[]]::new($len); [Array]::Copy($Envelope, $pos, $wrapped, 0, $len); $pos += $len
            $list.Add([PSCustomObject]@{ KeyId = ([BitConverter]::ToString($keyId)).Replace('-',''); WrappedKey = $wrapped; WrappedKeyLength = $len })
            if ($list.Count -gt [UCFormat]::MaxRecipients) { throw [System.FormatException]::new('Too many recipients') }
        }
        return $list
    }
    static [byte[]] UnwrapKey([byte[]]$Envelope, [object]$CandidateCertificates) {
        $recipients = [UCEnvelope]::ParseRecipients($Envelope)
        if ($recipients.Count -lt 1) { return $null }
        $byKeyId = @{}
        foreach ($recipient in $recipients) { $byKeyId[$recipient.KeyId] = $recipient }
        foreach ($cert in $CandidateCertificates) {
            $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
            if ($null -eq $rsa) { continue }
            try {
                $entry = $byKeyId[([BitConverter]::ToString([UCEnvelope]::GetKeyId($cert))).Replace('-','')]
                if ($null -ne $entry) {
                    $key = $rsa.Decrypt($entry.WrappedKey, [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA256)
                    if ($key.Length -eq 32) { return $key }
                    [Array]::Clear($key, 0, $key.Length)
                }
            } catch {
                Write-Verbose "Failed to unwrap the key with certificate $($cert.Thumbprint): $($_.Exception.Message)"
            } finally { $rsa.Dispose() }
        }
        return $null
    }
    static [byte[]] BuildPasswordEnvelope([byte[]]$Salt, [UInt32]$Iterations) {
        if ($Salt.Length -ne 16) { throw [System.ArgumentException]::new('Salt must be 16 bytes') }
        return [byte[]]$Salt + [BitConverter]::GetBytes([UInt32]$Iterations)
    }
    static [object] ParsePasswordEnvelope([byte[]]$Envelope) {
        if ($Envelope.Length -ne 20) { throw [System.FormatException]::new('Invalid password envelope') }
        $salt = [byte[]]::new(16); [Array]::Copy($Envelope, $salt, 16)
        $iterations = [BitConverter]::ToUInt32($Envelope, 16)
        if ($iterations -lt 1000 -or $iterations -gt 10000000) { throw [System.FormatException]::new('Invalid PBKDF2 iteration count') }
        return [PSCustomObject]@{ Salt = $salt; Iterations = [UInt32]$iterations }
    }
    static [byte[]] DeriveKeyFromPassword([string]$Password, [byte[]]$Salt, [UInt32]$Iterations) {
        # PBKDF2-HMAC-SHA256 with a dedicated salt; the iteration count is stored in the envelope and used on decrypt
        $pbkdf2 = [System.Security.Cryptography.Rfc2898DeriveBytes]::new([System.Text.Encoding]::UTF8.GetBytes($Password), $Salt, [int]$Iterations, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
        try { return $pbkdf2.GetBytes(32) } finally { $pbkdf2.Dispose() }
    }
}

class UCContainer {
    # Footer layout: [envelopeLen u32][envelope][ctLength u64][crc8 = first 8 bytes of SHA-256(envelopeLen+envelope+ctLength)][footerLen u32]
    static [byte[]] BuildFooter([byte[]]$Envelope, [UInt64]$CtLength) {
        $ms = [System.IO.MemoryStream]::new()
        $ms.Write([BitConverter]::GetBytes([UInt32]$Envelope.Length), 0, 4)
        $ms.Write($Envelope, 0, $Envelope.Length)
        $ms.Write([BitConverter]::GetBytes([UInt64]$CtLength), 0, 8)
        $ms.Write([UCFormat]::Slice([System.Security.Cryptography.SHA256]::HashData([byte[]]$ms.ToArray()), 0, 8), 0, 8)
        # Total footer size = 4 + envelope + 8 + 8 + 4; the last u32 carries it and doubles as the footer start offset from EOF
        $ms.Write([BitConverter]::GetBytes([UInt32](24 + $Envelope.Length)), 0, 4)
        return $ms.ToArray()
    }
}

class UniCryptor3 {
    static [string] $DefaultExtension = '.AESPKI'
    hidden [hashtable] $Certificates
    hidden [object] $Compressor
    [PSCustomObject] $Options
    [UInt32] $Pbkdf2Iterations

    UniCryptor3() {
        $this.Certificates = @{}
        $this.Compressor = $null
        $this.Options = [PSCustomObject]@{ ShowProgress = $true; CompressionLevel = 'Normal'; EncryptHeaders = $true; OnlyFilesWithArchiveBit = $false; ClearArchiveBit = $false }
        $this.Pbkdf2Iterations = [UCFormat]::DefaultPbkdf2Iterations
    }

    [void] AddEncryptionCertificates([object]$CertificateList) {
        foreach ($item in $CertificateList) {
            $cert = $null
            if ($item -is [string]) {
                $cert = Get-Item "Cert:\CurrentUser\My\$($item)" -ErrorAction SilentlyContinue
                if ($null -eq $cert) { $cert = Get-Item "Cert:\CurrentUser\AddressBook\$($item)" -ErrorAction SilentlyContinue }
                if ($null -eq $cert) { throw [System.ArgumentException]::new("Certificate '$($item)' not found in CurrentUser\My or CurrentUser\AddressBook") }
            } elseif ($item -is [System.Security.Cryptography.X509Certificates.X509Certificate2]) {
                $cert = $item
            } else {
                throw [System.ArgumentException]::new("Unsupported certificate item type '$($item.GetType().Name)'")
            }
            if ($null -eq [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($cert)) { throw [System.ArgumentException]::new("Certificate '$($cert.Thumbprint)' has no usable RSA public key") }
            $this.Certificates[$cert.Thumbprint] = $cert
        }
    }
    [void] SetEncryptionCertificates([object]$CertificateList) { $this.Certificates = @{}; $this.AddEncryptionCertificates($CertificateList) }
    [object] GetEncryptionCertificates() { return @($this.Certificates.Values) }
    hidden [void] AssertCertificates() { if ($this.Certificates.Count -lt 1) { throw [System.InvalidOperationException]::new('No encryption certificates configured') } }
    hidden [object] GetLocalPrivateCertificates() {
        return @(Get-ChildItem Cert:\CurrentUser\My -ErrorAction SilentlyContinue | Where-Object { $null -ne [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($_) })
    }
    hidden [object] PrepareDestinationFolder([string]$Destination) {
        $path = if ([string]::IsNullOrWhiteSpace($Destination)) { (Get-Location).Path } else { $Destination }
        $folder = Get-Item -LiteralPath $path -ErrorAction SilentlyContinue
        if ($null -eq $folder) { $folder = New-Item -ItemType Directory -Path $path -Force }
        if (-not $folder.PSIsContainer) { throw [System.ArgumentException]::new("Destination '$path' is not a folder") }
        return $folder
    }

    # ---------- Container core: write / parse / decrypt ----------
    hidden [void] WriteContainer([System.IO.Stream]$PlainStream, [System.IO.Stream]$OutputStream, [byte[]]$Key, [byte[]]$Envelope, [UInt16]$Flags, [byte[]]$MetaBytes) {
        $nonceBase = [UCRandom]::NewNonce()
        $metaLength = 0; if ($null -ne $MetaBytes) { $metaLength = $MetaBytes.Length }
        $totalPlain = [Int64]$metaLength + [Int64]$PlainStream.Length
        $chunkCount = [math]::Ceiling($totalPlain / [double][UCFormat]::ChunkSize)
        $ctLength = [UInt64]($totalPlain + 16 * $chunkCount)
        $header = [UCFormat]::BuildHeader($Flags, $nonceBase, $ctLength)
        $OutputStream.Write($header, 0, [UCFormat]::HeaderSize)
        $chunkIndex = [UInt32]0
        # First chunk starts with the metadata TLV block (when present)
        $firstPlain = [byte[]]::new([UCFormat]::ChunkSize)
        if ($metaLength -gt 0) { [Array]::Copy($MetaBytes, $firstPlain, $metaLength) }
        $firstRead = $PlainStream.Read($firstPlain, $metaLength, [UCFormat]::ChunkSize - $metaLength)
        $firstPlainLength = $metaLength + $firstRead
        if ($firstPlainLength -gt 0) {
            $chunk = Invoke-UCGcmEncrypt $Key ([UCFormat]::NonceFor($nonceBase, 0)) $firstPlain $firstPlainLength ([UCFormat]::BuildAad($header, 0))
            $OutputStream.Write($chunk, 0, $chunk.Length)
            $chunkIndex = [UInt32]1
        }
        $buffer = [byte[]]::new([UCFormat]::ChunkSize)
        while (($read = $PlainStream.Read($buffer, 0, [UCFormat]::ChunkSize)) -gt 0) {
            $chunk = Invoke-UCGcmEncrypt $Key ([UCFormat]::NonceFor($nonceBase, $chunkIndex)) $buffer $read ([UCFormat]::BuildAad($header, $chunkIndex))
            $OutputStream.Write($chunk, 0, $chunk.Length)
            $chunkIndex++
        }
        $footer = [UCContainer]::BuildFooter($Envelope, $ctLength)
        $OutputStream.Write($footer, 0, $footer.Length)
    }
    hidden [object] ReadContainerInfo([System.IO.Stream]$InputStream) {
        $fileLength = $InputStream.Length
        if ($fileLength -lt 56) { throw [System.FormatException]::new('Stream is too small to be a UniCryptor3 container') }
        $InputStream.Seek(-4, [System.IO.SeekOrigin]::End) | Out-Null
        $footerLenBytes = [byte[]]::new(4)
        if ($InputStream.Read($footerLenBytes, 0, 4) -ne 4) { throw [System.FormatException]::new('Unexpected end of stream') }
        $footerLength = [Int64][BitConverter]::ToUInt32($footerLenBytes, 0)
        if ($footerLength -lt 24 -or $footerLength -gt $fileLength) { throw [System.FormatException]::new('Invalid footer length: container is corrupt or not a UniCryptor3 file') }
        $footerStart = $fileLength - $footerLength
        $InputStream.Seek($footerStart, [System.IO.SeekOrigin]::Begin) | Out-Null
        $footerBytes = [byte[]]::new([int]$footerLength)
        if ($InputStream.Read($footerBytes, 0, [int]$footerLength) -ne [int]$footerLength) { throw [System.FormatException]::new('Unexpected end of stream') }
        $envelopeLength = [int][BitConverter]::ToUInt32($footerBytes, 0)
        if ($envelopeLength -lt 8 -or (24 + $envelopeLength) -ne [int]$footerLength) { throw [System.FormatException]::new('Invalid envelope length: container is corrupt') }
        $crcInput = [byte[]]::new(4 + $envelopeLength + 8)
        [Array]::Copy($footerBytes, $crcInput, $crcInput.Length)
        $crc = [UCFormat]::Slice([System.Security.Cryptography.SHA256]::HashData($crcInput), 0, 8)
        $storedCrc = [UCFormat]::Slice($footerBytes, 4 + $envelopeLength + 8, 8)
        if (-not (Test-UCByteArrayEqual $crc $storedCrc)) { throw [System.FormatException]::new('Footer checksum mismatch: container is corrupt') }
        $ctLength = [Int64][BitConverter]::ToUInt64($footerBytes, 4 + $envelopeLength)
        $headerStart = $footerStart - [UCFormat]::HeaderSize - $ctLength
        if ($headerStart -lt 0) { throw [System.FormatException]::new('Invalid container geometry: ciphertext length out of bounds') }
        $InputStream.Seek($headerStart, [System.IO.SeekOrigin]::Begin) | Out-Null
        $headerBytes = [byte[]]::new([UCFormat]::HeaderSize)
        if ($InputStream.Read($headerBytes, 0, [UCFormat]::HeaderSize) -ne [UCFormat]::HeaderSize) { throw [System.FormatException]::new('Unexpected end of stream') }
        $header = [UCFormat]::ParseHeader($headerBytes)
        if ([Int64]$header.CtLength -ne $ctLength) { throw [System.FormatException]::new('Ciphertext length mismatch between header and footer') }
        return [PSCustomObject]@{ Header = $header; HeaderBytes = $headerBytes; HeaderStart = $headerStart; CtLength = $ctLength; Envelope = [UCFormat]::Slice($footerBytes, 4, $envelopeLength); PayloadStart = $headerStart + [UCFormat]::HeaderSize; PayloadEnd = $footerStart }
    }
    hidden [byte[]] DecryptChunkChecked([byte[]]$Key, [byte[]]$NonceBase, [byte[]]$Ciphertext, [byte[]]$HeaderBytes, [UInt32]$Index) {
        $plain = $null
        try { $plain = Invoke-UCGcmDecrypt $Key ([UCFormat]::NonceFor($NonceBase, $Index)) $Ciphertext $Ciphertext.Length ([UCFormat]::BuildAad($HeaderBytes, $Index)) }
        catch [System.Security.Cryptography.CryptographicException] { throw [System.Security.Cryptography.CryptographicException]::new('Authentication failed: wrong key, certificate or password, or the data is corrupted') }
        return $plain
    }
    hidden [byte[]] DecryptContainerToMemory([System.IO.Stream]$InputStream, [byte[]]$Key, [object]$Info) {
        $fullChunk = [Int64]([UCFormat]::ChunkSize + 16)
        $totalChunks = [Int64][math]::Ceiling($Info.CtLength / [double]$fullChunk)
        $plainTotal = $Info.CtLength - 16 * $totalChunks
        if ($plainTotal -lt 0) { throw [System.FormatException]::new('Invalid ciphertext length') }
        $result = [byte[]]::new([int]$plainTotal)
        $InputStream.Seek($Info.PayloadStart, [System.IO.SeekOrigin]::Begin) | Out-Null
        $pos = 0
        for ([Int64]$i = 0; $i -lt $totalChunks; $i++) {
            $ctLen = if ($i -eq $totalChunks - 1) { [int]($Info.CtLength - ($totalChunks - 1) * $fullChunk) } else { [int]$fullChunk }
            $ct = [byte[]]::new($ctLen)
            if ($InputStream.Read($ct, 0, $ctLen) -ne $ctLen) { throw [System.FormatException]::new('Unexpected end of ciphertext stream') }
            $plain = $this.DecryptChunkChecked($Key, $Info.Header.Nonce, $ct, $Info.HeaderBytes, [UInt32]$i)
            [Array]::Copy($plain, 0, $result, $pos, $plain.Length)
            $pos += $plain.Length
        }
        return $result
    }
    hidden [object] DecryptContainerToPath([System.IO.Stream]$InputStream, [string]$OutputPath, [byte[]]$Key, [object]$Info) {
        # The output file is created only after the first chunk has been authenticated and is removed if any later chunk fails
        $fullChunk = [Int64]([UCFormat]::ChunkSize + 16)
        $totalChunks = [Int64][math]::Ceiling($Info.CtLength / [double]$fullChunk)
        $InputStream.Seek($Info.PayloadStart, [System.IO.SeekOrigin]::Begin) | Out-Null
        $metadata = $null
        $writer = $null
        try {
            if ($totalChunks -eq 0) { $writer = [System.IO.FileStream]::new($OutputPath, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None, [UCFormat]::ChunkSize) }
            for ([Int64]$i = 0; $i -lt $totalChunks; $i++) {
                $ctLen = if ($i -eq $totalChunks - 1) { [int]($Info.CtLength - ($totalChunks - 1) * $fullChunk) } else { [int]$fullChunk }
                if ($ctLen -lt 17 -or $ctLen -gt [UCFormat]::ChunkSize + 16) { throw [System.FormatException]::new('Invalid chunk geometry') }
                $ct = [byte[]]::new($ctLen)
                if ($InputStream.Read($ct, 0, $ctLen) -ne $ctLen) { throw [System.FormatException]::new('Unexpected end of ciphertext stream') }
                $plain = $this.DecryptChunkChecked($Key, $Info.Header.Nonce, $ct, $Info.HeaderBytes, [UInt32]$i)
                if ($i -eq 0 -and (($Info.Header.Flags -band [UCFormat]::FlagMetadata) -ne 0)) {
                    $metadata = [UCMetadata]::Parse($plain)
                    $plain = [UCFormat]::Slice($plain, $metadata.Length, $plain.Length - $metadata.Length)
                }
                if ($null -eq $writer) { $writer = [System.IO.FileStream]::new($OutputPath, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None, [UCFormat]::ChunkSize) }
                $writer.Write($plain, 0, $plain.Length)
            }
        } catch {
            if ($null -ne $writer) { $writer.Dispose(); $writer = $null }
            Remove-Item -LiteralPath $OutputPath -ErrorAction SilentlyContinue
            throw
        } finally {
            if ($null -ne $writer) { $writer.Dispose() }
        }
        return [PSCustomObject]@{ Metadata = $metadata }
    }
    hidden [byte[]] ResolveKey([object]$Info, [string]$Password, [object]$CandidateCertificates) {
        if (($Info.Header.Flags -band [UCFormat]::FlagPassword) -ne 0) {
            if ([string]::IsNullOrEmpty($Password)) { throw [System.InvalidOperationException]::new('This container was encrypted with a password: provide the -Password parameter') }
            $passwordEnvelope = [UCEnvelope]::ParsePasswordEnvelope($Info.Envelope)
            return [UCEnvelope]::DeriveKeyFromPassword($Password, $passwordEnvelope.Salt, $passwordEnvelope.Iterations)
        }
        $key = [UCEnvelope]::UnwrapKey($Info.Envelope, $CandidateCertificates)
        if ($null -eq $key) { throw [System.Security.Cryptography.CryptographicException]::new('No matching private key found for any recipient of this container') }
        return $key
    }

    # ---------- Strings ----------
    [string] ProtectString([string]$PlainText) {
        $this.AssertCertificates()
        $key = [UCRandom]::NewKey()
        try {
            $envelope = [UCEnvelope]::WrapKeyForCertificates($key, $this.Certificates.Values)
            return [System.Convert]::ToBase64String($this.ProtectStringInternal($PlainText, $key, $envelope, [UInt16]0))
        } finally { [Array]::Clear($key, 0, $key.Length) }
    }
    [string] ProtectStringWithPassword([string]$PlainText, [string]$Password) {
        if ([string]::IsNullOrEmpty($Password)) { throw [System.ArgumentException]::new('Password must not be empty') }
        $salt = [UCRandom]::NewSalt()
        $key = [UCEnvelope]::DeriveKeyFromPassword($Password, $salt, $this.Pbkdf2Iterations)
        try {
            $envelope = [UCEnvelope]::BuildPasswordEnvelope($salt, $this.Pbkdf2Iterations)
            return [System.Convert]::ToBase64String($this.ProtectStringInternal($PlainText, $key, $envelope, [UInt16][UCFormat]::FlagPassword))
        } finally { [Array]::Clear($key, 0, $key.Length) }
    }
    hidden [byte[]] ProtectStringInternal([string]$PlainText, [byte[]]$Key, [byte[]]$Envelope, [UInt16]$Flags) {
        $plainStream = [System.IO.MemoryStream]::new([System.Text.Encoding]::UTF8.GetBytes($PlainText))
        $outStream = [System.IO.MemoryStream]::new()
        try {
            $this.WriteContainer($plainStream, $outStream, $Key, $Envelope, $Flags, $null)
            return $outStream.ToArray()
        } finally { $plainStream.Dispose(); $outStream.Dispose() }
    }
    [string] UnprotectString([string]$ProtectedText, [string]$Password) {
        $container = [System.Convert]::FromBase64String($ProtectedText)
        $inStream = [System.IO.MemoryStream]::new($container)
        try {
            $info = $this.ReadContainerInfo($inStream)
            $key = $this.ResolveKey($info, $Password, $this.GetLocalPrivateCertificates())
            try {
                $plain = $this.DecryptContainerToMemory($inStream, $key, $info)
                return [System.Text.Encoding]::UTF8.GetString($plain)
            } finally { [Array]::Clear($key, 0, $key.Length) }
        } finally { $inStream.Dispose() }
    }

    # ---------- Files ----------
    hidden [string] ProtectFileInternal([System.IO.FileInfo]$InputFile, [string]$Destination, [bool]$Overwrite, [string]$Password) {
        $dstFolder = $this.PrepareDestinationFolder($Destination)
        $outputFullFileName = Join-Path $dstFolder.FullName ($InputFile.Name + [UniCryptor3]::DefaultExtension)
        if ((Test-Path -LiteralPath $outputFullFileName) -and -not $Overwrite) { throw [System.IO.IOException]::new("Output file '$outputFullFileName' already exists") }
        $metaBytes = [UCMetadata]::Build([UInt64]$InputFile.Length, $InputFile.CreationTimeUtc, $InputFile.LastWriteTimeUtc)
        if ([string]::IsNullOrEmpty($Password)) {
            $this.AssertCertificates()
            $key = [UCRandom]::NewKey()
            $envelope = [UCEnvelope]::WrapKeyForCertificates($key, $this.Certificates.Values)
            $flags = [UInt16][UCFormat]::FlagMetadata
        } else {
            $salt = [UCRandom]::NewSalt()
            $envelope = [UCEnvelope]::BuildPasswordEnvelope($salt, $this.Pbkdf2Iterations)
            $key = [UCEnvelope]::DeriveKeyFromPassword($Password, $salt, $this.Pbkdf2Iterations)
            $flags = [UInt16]([UCFormat]::FlagPassword -bor [UCFormat]::FlagMetadata)
        }
        try {
            $reader = [System.IO.FileStream]::new($InputFile.FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read, [UCFormat]::ChunkSize)
            try {
                $writer = [System.IO.FileStream]::new($outputFullFileName, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None, [UCFormat]::ChunkSize)
                try { $this.WriteContainer($reader, $writer, $key, $envelope, $flags, $metaBytes) }
                finally { $writer.Dispose() }
            } finally { $reader.Dispose() }
        } finally { [Array]::Clear($key, 0, $key.Length) }
        return $outputFullFileName
    }
    [string] ProtectFile([string]$Path, [string]$Destination, [bool]$Overwrite) {
        $inputFile = Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue
        if ($null -eq $inputFile) { throw [System.IO.FileNotFoundException]::new("File '$Path' not found") }
        if ($inputFile.PSIsContainer) { throw [System.ArgumentException]::new("'$Path' is a folder: use ProtectFolder") }
        return $this.ProtectFileInternal($inputFile, $Destination, $Overwrite, $null)
    }
    [string] ProtectFileWithPassword([string]$Path, [string]$Destination, [string]$Password, [bool]$Overwrite) {
        $inputFile = Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue
        if ($null -eq $inputFile) { throw [System.IO.FileNotFoundException]::new("File '$Path' not found") }
        if ($inputFile.PSIsContainer) { throw [System.ArgumentException]::new("'$Path' is a folder: use ProtectFolderWithPassword") }
        return $this.ProtectFileInternal($inputFile, $Destination, $Overwrite, $Password)
    }
    hidden [string] UnprotectFileInternal([System.IO.FileInfo]$InputFile, [string]$Destination, [bool]$Overwrite, [string]$Password) {
        $dstFolder = $this.PrepareDestinationFolder($Destination)
        if ($InputFile.Extension -eq [UniCryptor3]::DefaultExtension) { $outputName = $InputFile.BaseName } else { $outputName = $InputFile.BaseName + $InputFile.Extension + '_decrypted' }
        $outputFullFileName = Join-Path $dstFolder.FullName $outputName
        if ((Test-Path -LiteralPath $outputFullFileName) -and -not $Overwrite) { throw [System.IO.IOException]::new("Output file '$outputFullFileName' already exists") }
        $reader = [System.IO.FileStream]::new($InputFile.FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read, [UCFormat]::ChunkSize)
        try {
            $info = $this.ReadContainerInfo($reader)
            $key = $this.ResolveKey($info, $Password, $this.GetLocalPrivateCertificates())
            try {
                $result = $this.DecryptContainerToPath($reader, $outputFullFileName, $key, $info)
                if ($null -ne $result.Metadata) {
                    $outFile = Get-Item -LiteralPath $outputFullFileName
                    if ($null -ne $result.Metadata.CreationTimeUtc) { $outFile.CreationTimeUtc = $result.Metadata.CreationTimeUtc }
                    if ($null -ne $result.Metadata.LastWriteTimeUtc) { $outFile.LastWriteTimeUtc = $result.Metadata.LastWriteTimeUtc }
                }
            } finally { [Array]::Clear($key, 0, $key.Length) }
        } finally { $reader.Dispose() }
        return $outputFullFileName
    }
    [string] UnprotectFile([string]$Path, [string]$Destination, [bool]$Overwrite) {
        $inputFile = Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue
        if ($null -eq $inputFile) { throw [System.IO.FileNotFoundException]::new("File '$Path' not found") }
        if ($inputFile.PSIsContainer) { throw [System.ArgumentException]::new("'$Path' is a folder: use UnprotectFolder") }
        return $this.UnprotectFileInternal($inputFile, $Destination, $Overwrite, $null)
    }
    [string] UnprotectFileWithPassword([string]$Path, [string]$Destination, [string]$Password, [bool]$Overwrite) {
        $inputFile = Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue
        if ($null -eq $inputFile) { throw [System.IO.FileNotFoundException]::new("File '$Path' not found") }
        if ($inputFile.PSIsContainer) { throw [System.ArgumentException]::new("'$Path' is a folder: use UnprotectFolder") }
        return $this.UnprotectFileInternal($inputFile, $Destination, $Overwrite, $Password)
    }

    # ---------- Folders ----------
    hidden [object] ProtectFolderInternal([string]$FolderName, [string]$Destination, [bool]$Overwrite, [bool]$Recurse, [string]$Password) {
        $srcFolder = Get-Item -LiteralPath $FolderName -ErrorAction SilentlyContinue
        if ($null -eq $srcFolder -or -not $srcFolder.PSIsContainer) { throw [System.ArgumentException]::new("Source folder '$FolderName' does not exist or is not a folder") }
        $files = @(Get-ChildItem -LiteralPath $srcFolder.FullName -Force -File -Recurse:$Recurse | Where-Object { $_.Extension -ne [UniCryptor3]::DefaultExtension })
        $succeeded = [System.Collections.Generic.List[string]]::new()
        $failed = [System.Collections.Generic.List[object]]::new()
        $counter = 0
        foreach ($file in $files) {
            $counter++
            if ($this.Options.ShowProgress) { Write-Progress -Activity "Encrypting files in '$FolderName'" -Status $file.Name -PercentComplete ([int](100 * $counter / $files.Count)) }
            try { $succeeded.Add($this.ProtectFileInternal($file, $Destination, $Overwrite, $Password)) }
            catch { $failed.Add([PSCustomObject]@{ Path = $file.FullName; Message = $_.Exception.Message }) }
        }
        if ($this.Options.ShowProgress) { Write-Progress -Activity "Encrypting files in '$FolderName'" -Completed }
        return [PSCustomObject]@{ Total = $files.Count; Succeeded = $succeeded; Failed = $failed }
    }
    [object] ProtectFolder([string]$FolderName, [string]$Destination, [bool]$Overwrite, [bool]$Recurse) { return $this.ProtectFolderInternal($FolderName, $Destination, $Overwrite, $Recurse, $null) }
    [object] ProtectFolderWithPassword([string]$FolderName, [string]$Destination, [string]$Password, [bool]$Overwrite, [bool]$Recurse) { return $this.ProtectFolderInternal($FolderName, $Destination, $Overwrite, $Recurse, $Password) }
    [object] UnprotectFolder([string]$FolderName, [string]$Destination, [bool]$Overwrite, [bool]$Recurse) {
        $srcFolder = Get-Item -LiteralPath $FolderName -ErrorAction SilentlyContinue
        if ($null -eq $srcFolder -or -not $srcFolder.PSIsContainer) { throw [System.ArgumentException]::new("Source folder '$FolderName' does not exist or is not a folder") }
        $files = @(Get-ChildItem -LiteralPath $srcFolder.FullName -Force -File -Filter ('*' + [UniCryptor3]::DefaultExtension) -Recurse:$Recurse)
        $succeeded = [System.Collections.Generic.List[string]]::new()
        $failed = [System.Collections.Generic.List[object]]::new()
        $counter = 0
        foreach ($file in $files) {
            $counter++
            if ($this.Options.ShowProgress) { Write-Progress -Activity "Decrypting files in '$FolderName'" -Status $file.Name -PercentComplete ([int](100 * $counter / $files.Count)) }
            try { $succeeded.Add($this.UnprotectFileInternal($file, $Destination, $Overwrite, $null)) }
            catch { $failed.Add([PSCustomObject]@{ Path = $file.FullName; Message = $_.Exception.Message }) }
        }
        if ($this.Options.ShowProgress) { Write-Progress -Activity "Decrypting files in '$FolderName'" -Completed }
        return [PSCustomObject]@{ Total = $files.Count; Succeeded = $succeeded; Failed = $failed }
    }

    # ---------- File info (no private key required) ----------
    [object] GetFileInfo([string]$Path) {
        $inputFile = Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue
        if ($null -eq $inputFile) { throw [System.IO.FileNotFoundException]::new("File '$Path' not found") }
        # Pre-initialized: assignments inside try blocks are not seen by the class compiler's definite-assignment analysis
        $info = $null
        $reader = [System.IO.FileStream]::new($inputFile.FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read, 4096)
        try { $info = $this.ReadContainerInfo($reader) } finally { $reader.Dispose() }
        $mode = 'Certificates'; $recipients = @()
        if (($info.Header.Flags -band [UCFormat]::FlagPassword) -ne 0) {
            $mode = 'Password'
        } else {
            # keyIds are matched against the local store only: recipient identity is not exposed
            $localIds = @{}
            foreach ($cert in @(Get-ChildItem Cert:\CurrentUser\My -ErrorAction SilentlyContinue)) { $localIds[([BitConverter]::ToString([UCEnvelope]::GetKeyId($cert))).Replace('-','')] = $cert }
            $recipients = @([UCEnvelope]::ParseRecipients($info.Envelope) | ForEach-Object {
                $matched = $localIds[$_.KeyId]
                $matchSubject = $null
                if ($null -ne $matched) { $matchSubject = $matched.Subject }
                [PSCustomObject]@{ KeyId = $_.KeyId; MatchedLocalCertificate = $matchSubject }
            })
        }
        return [PSCustomObject]@{ File = $inputFile.FullName; FileLength = $inputFile.Length; ContainerVersion = $info.Header.Version; Mode = $mode; MetadataEncrypted = (($info.Header.Flags -band [UCFormat]::FlagMetadata) -ne 0); CiphertextLength = $info.CtLength; ContainerStartsAt = $info.HeaderStart; Recipients = $recipients }
    }

    # ---------- 7z archives ----------
    hidden [object] GetSevenZipCompressor() {
        if (-not ('SevenZip.SevenZipCompressor' -as [type])) { throw [System.InvalidOperationException]::new('SevenZipSharp library is not loaded: check the bin\7Zip4Powershell folder next to the script') }
        if ($null -eq $this.Compressor) { $this.Compressor = New-UCSevenZipCompressor $this.Options }
        else { $this.Compressor.CompressionLevel = $this.Options.CompressionLevel; $this.Compressor.EncryptHeaders = $this.Options.EncryptHeaders }
        return $this.Compressor
    }
    hidden [void] WaitForAsyncOperation([object]$AsyncInfo, [string]$Activity) {
        while (-not $AsyncInfo.IsCompleted -and -not $AsyncInfo.IsCanceled -and -not $AsyncInfo.IsFaulted) {
            if ($this.Options.ShowProgress) { Write-Progress -Activity $Activity -Status "$($global:UniCryptor3Progress)% complete" -PercentComplete $global:UniCryptor3Progress }
            Start-Sleep -Milliseconds 250
        }
        if ($this.Options.ShowProgress) { Write-Progress -Activity $Activity -Completed }
        if ($AsyncInfo.IsFaulted) { throw [System.InvalidOperationException]::new('The 7z engine reported an error during the operation') }
        if ($AsyncInfo.IsCanceled) { throw [System.OperationCanceledException]::new('The 7z operation was canceled') }
    }
    [string] Compress7Zip([string]$FolderName, [string]$Destination, [bool]$Overwrite) {
        $this.AssertCertificates()
        if ([string]::IsNullOrWhiteSpace($Destination)) { throw [System.ArgumentException]::new('Destination archive path not specified') }
        $dstDir = Split-Path -Parent $Destination
        if ($dstDir) { $null = $this.PrepareDestinationFolder($dstDir) }
        if ((Test-Path -LiteralPath $Destination) -and -not $Overwrite) { throw [System.IO.IOException]::new("Destination archive '$Destination' already exists") }
        $srcFolder = Get-Item -LiteralPath $FolderName -ErrorAction SilentlyContinue
        if ($null -eq $srcFolder -or -not $srcFolder.PSIsContainer) { throw [System.ArgumentException]::new("Source folder '$FolderName' does not exist or is not a folder") }
        if ($this.Options.OnlyFilesWithArchiveBit) { $files2Compress = @(Get-ChildItem -LiteralPath $srcFolder.FullName -Force -File -Recurse -Attribute A) }
        else { $files2Compress = @(Get-ChildItem -LiteralPath $srcFolder.FullName -Force -File -Recurse) }
        if ($files2Compress.Count -lt 1) { throw [System.InvalidOperationException]::new('No files found for compression') }
        # The 7z payload is protected by its own AES-256 encryption with a random password; only the password travels in our container
        $password = [UCRandom]::NewPassword(64, 128)
        # Renamed: a local variable matching the Compressor member name is rejected by the class binder
        $compressorObj = $this.GetSevenZipCompressor()
        try {
            Register-UC7zProgress $compressorObj 'Compressing' 'UniCryptor3_7zCompress'
            $async = $compressorObj.CompressFilesEncryptedAsync($Destination, $password, [string[]]($files2Compress.FullName))
            $this.WaitForAsyncOperation($async, "Compressing to $Destination")
        } finally { Unregister-Event -SourceIdentifier 'UniCryptor3_7zCompress' -ErrorAction SilentlyContinue }
        # Clear the archive bit on compressed files (incremental backup scenarios); direct FileInfo attribute update, no extra provider calls
        if ($this.Options.ClearArchiveBit) {
            $archAttr = [System.IO.FileAttributes]::Archive
            $cleared = 0
            foreach ($file in $files2Compress) { if (($file.Attributes -band $archAttr) -ne 0) { $file.Attributes = $file.Attributes -bxor $archAttr; $cleared++ } }
            Write-Verbose "Archive attribute cleared on $cleared files"
        }
        $archive = Get-Item -LiteralPath $Destination -ErrorAction SilentlyContinue
        if ($null -eq $archive) { throw [System.InvalidOperationException]::new("Compression did not produce the expected archive '$Destination'") }
        # Inline footer: the whole container block is appended after the 7z stream (the archive stays a valid 7z file with trailing data)
        $key = [UCRandom]::NewKey()
        try {
            $envelope = [UCEnvelope]::WrapKeyForCertificates($key, $this.Certificates.Values)
            $plainStream = [System.IO.MemoryStream]::new([System.Text.Encoding]::UTF8.GetBytes($password))
            $writer = [System.IO.FileStream]::new($Destination, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None, [UCFormat]::ChunkSize)
            try {
                $writer.Seek(0, [System.IO.SeekOrigin]::End) | Out-Null
                $this.WriteContainer($plainStream, $writer, $key, $envelope, [UInt16]0, $null)
            } finally { $writer.Dispose(); $plainStream.Dispose() }
        } finally { [Array]::Clear($key, 0, $key.Length) }
        return $Destination
    }
    hidden [string] GetArchivePasswordInternal([string]$ArchivePath) {
        $inputFile = Get-Item -LiteralPath $ArchivePath -ErrorAction SilentlyContinue
        if ($null -eq $inputFile) { throw [System.IO.FileNotFoundException]::new("Archive '$ArchivePath' not found") }
        $reader = [System.IO.FileStream]::new($inputFile.FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read, [UCFormat]::ChunkSize)
        try {
            $info = $this.ReadContainerInfo($reader)
            $key = $this.ResolveKey($info, $null, $this.GetLocalPrivateCertificates())
            try {
                $plain = $this.DecryptContainerToMemory($reader, $key, $info)
                return [System.Text.Encoding]::UTF8.GetString($plain)
            } finally { [Array]::Clear($key, 0, $key.Length) }
        } finally { $reader.Dispose() }
    }
    [string] GetArchivePassword([string]$ArchivePath) { return $this.GetArchivePasswordInternal($ArchivePath) }
    [object] GetArchiveContent([string]$ArchivePath) {
        $password = $this.GetArchivePasswordInternal($ArchivePath)
        $extractor = New-UCSevenZipExtractor $ArchivePath $password
        try { return $extractor.ArchiveFileData } finally { $extractor.Dispose() }
    }
    [bool] Expand7Zip([string]$ArchivePath, [string]$Destination, [bool]$Overwrite) {
        $password = $this.GetArchivePasswordInternal($ArchivePath)
        $dstFolder = $this.PrepareDestinationFolder($Destination)
        $extractor = New-UCSevenZipExtractor $ArchivePath $password
        try {
            if (-not $Overwrite) {
                foreach ($fileData in $extractor.ArchiveFileData) {
                    $target = Join-Path $dstFolder.FullName $fileData.FileName
                    if (Test-Path -LiteralPath $target) { throw [System.IO.IOException]::new("'$($fileData.FileName)' already exists in the destination folder") }
                }
            }
            try {
                Register-UC7zProgress $extractor 'Extracting' 'UniCryptor3_7zExtract'
                $async = $extractor.ExtractArchiveAsync($dstFolder.FullName)
                $this.WaitForAsyncOperation($async, "Extracting $ArchivePath")
            } finally { Unregister-Event -SourceIdentifier 'UniCryptor3_7zExtract' -ErrorAction SilentlyContinue }
        } finally { $extractor.Dispose() }
        return $true
    }
}

# ---------- Module-level functions (thin facade over UniCryptor3) ----------
function Get-UCCertificates {
    [CmdletBinding()]
    param(
        [Parameter()][string[]]$Thumbprint,
        [Parameter()][switch]$RequirePrivateKey
    )
    $certs = @(Get-ChildItem Cert:\CurrentUser\My -ErrorAction SilentlyContinue)
    if ($Thumbprint) { $certs += @(Get-ChildItem Cert:\CurrentUser\AddressBook -ErrorAction SilentlyContinue) }
    $result = @($certs | Where-Object { $null -ne [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($_) })
    if ($RequirePrivateKey) { $result = @($result | Where-Object { $null -ne [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($_) }) }
    if ($Thumbprint) { $result = @($result | Where-Object { $Thumbprint -contains $_.Thumbprint }) }
    return $result
}

function New-UCSelfSignedCertificate {
    [CmdletBinding()]
    param([Parameter()][string]$Subject = 'UniCryptor3')
    return New-SelfSignedCertificate -DnsName $Subject -CertStoreLocation 'Cert:\CurrentUser\My' -KeyUsage KeyEncipherment, DataEncipherment -Type Custom, DocumentEncryptionCert -NotAfter ((Get-Date).AddYears(2)) -KeySpec KeyExchange -Provider 'Microsoft Enhanced RSA and AES Cryptographic Provider'
}

function Protect-UCString {
    [CmdletBinding(DefaultParameterSetName = 'Certificate')]
    param(
        [Parameter(Mandatory, Position = 0)][string]$PlainText,
        [Parameter(ParameterSetName = 'Certificate')][System.Security.Cryptography.X509Certificates.X509Certificate2[]]$Certificate,
        [Parameter(ParameterSetName = 'Password')][string]$Password
    )
    $uc = [UniCryptor3]::new()
    if ($PSCmdlet.ParameterSetName -eq 'Password') { return $uc.ProtectStringWithPassword($PlainText, $Password) }
    if (-not $Certificate) { $Certificate = Get-UCCertificates -RequirePrivateKey }
    $uc.SetEncryptionCertificates($Certificate)
    return $uc.ProtectString($PlainText)
}

function Unprotect-UCString {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)][string]$ProtectedText,
        [Parameter()][string]$Password
    )
    return ([UniCryptor3]::new()).UnprotectString($ProtectedText, $Password)
}

function Protect-UCFile {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline)][string]$Path,
        [Parameter(Position = 1)][string]$Destination,
        [Parameter()][switch]$Overwrite,
        [Parameter()][System.Security.Cryptography.X509Certificates.X509Certificate2[]]$Certificate,
        [Parameter()][string]$Password,
        [Parameter()][switch]$Recurse
    )
    process {
        if (-not $PSCmdlet.ShouldProcess($Path, 'Encrypt')) { return }
        $uc = [UniCryptor3]::new()
        $item = Get-Item -LiteralPath $Path -ErrorAction Stop
        if ($item.PSIsContainer) {
            if ($Password) { return $uc.ProtectFolderWithPassword($Path, $Destination, $Password, [bool]$Overwrite, [bool]$Recurse) }
            if (-not $Certificate) { $Certificate = Get-UCCertificates -RequirePrivateKey }
            $uc.SetEncryptionCertificates($Certificate)
            return $uc.ProtectFolder($Path, $Destination, [bool]$Overwrite, [bool]$Recurse)
        }
        if ($Password) { return $uc.ProtectFileWithPassword($Path, $Destination, $Password, [bool]$Overwrite) }
        if (-not $Certificate) { $Certificate = Get-UCCertificates -RequirePrivateKey }
        $uc.SetEncryptionCertificates($Certificate)
        return $uc.ProtectFile($Path, $Destination, [bool]$Overwrite)
    }
}

function Unprotect-UCFile {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline)][string]$Path,
        [Parameter(Position = 1)][string]$Destination,
        [Parameter()][switch]$Overwrite,
        [Parameter()][string]$Password,
        [Parameter()][switch]$Recurse
    )
    process {
        if (-not $PSCmdlet.ShouldProcess($Path, 'Decrypt')) { return }
        $uc = [UniCryptor3]::new()
        $item = Get-Item -LiteralPath $Path -ErrorAction Stop
        if ($item.PSIsContainer) { return $uc.UnprotectFolder($Path, $Destination, [bool]$Overwrite, [bool]$Recurse) }
        if ($Password) { return $uc.UnprotectFileWithPassword($Path, $Destination, $Password, [bool]$Overwrite) }
        return $uc.UnprotectFile($Path, $Destination, [bool]$Overwrite)
    }
}

function Get-UCFileInfo {
    [CmdletBinding()]
    param([Parameter(Mandatory, Position = 0, ValueFromPipeline)][string]$Path)
    process { return ([UniCryptor3]::new()).GetFileInfo($Path) }
}

function Compress-UCArchive {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, Position = 0)][string]$Folder,
        [Parameter(Mandatory, Position = 1)][string]$DestinationPath,
        [Parameter()][switch]$Overwrite,
        [Parameter()][System.Security.Cryptography.X509Certificates.X509Certificate2[]]$Certificate,
        [Parameter()][ValidateSet('None', 'Fast', 'Normal', 'High', 'Ultra')][string]$CompressionLevel,
        [Parameter()][switch]$OnlyFilesWithArchiveBit,
        [Parameter()][switch]$ClearArchiveBit
    )
    if (-not $PSCmdlet.ShouldProcess($Folder, "Compress to $DestinationPath")) { return }
    $uc = [UniCryptor3]::new()
    if ($CompressionLevel) { $uc.Options.CompressionLevel = $CompressionLevel }
    $uc.Options.OnlyFilesWithArchiveBit = [bool]$OnlyFilesWithArchiveBit
    $uc.Options.ClearArchiveBit = [bool]$ClearArchiveBit
    if (-not $Certificate) { $Certificate = Get-UCCertificates -RequirePrivateKey }
    $uc.SetEncryptionCertificates($Certificate)
    return $uc.Compress7Zip($Folder, $DestinationPath, [bool]$Overwrite)
}

function Expand-UCArchive {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, Position = 0)][string]$ArchivePath,
        [Parameter(Position = 1)][string]$Destination,
        [Parameter()][switch]$Overwrite
    )
    if (-not $PSCmdlet.ShouldProcess($ArchivePath, 'Extract')) { return }
    return ([UniCryptor3]::new()).Expand7Zip($ArchivePath, $Destination, [bool]$Overwrite)
}

function Get-UCArchivePassword {
    [CmdletBinding()]
    param([Parameter(Mandatory, Position = 0)][string]$ArchivePath)
    return ([UniCryptor3]::new()).GetArchivePassword($ArchivePath)
}

function Get-UCArchiveContent {
    [CmdletBinding()]
    param([Parameter(Mandatory, Position = 0)][string]$ArchivePath)
    return ([UniCryptor3]::new()).GetArchiveContent($ArchivePath)
}