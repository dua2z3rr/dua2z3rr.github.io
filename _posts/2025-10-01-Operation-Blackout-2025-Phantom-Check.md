---
title: "Operation Blackout 2025: Phantom Check Walkthrough"
description: "Phantom Check è una challenge Sherlock che illustra alcune delle comuni tecniche di rilevamento della virtualizzazione utilizzate dagli attaccanti. I giocatori acquisiranno la capacità di creare regole di detection identificando specifiche query WMI, confrontando i processi per il rilevamento di macchine virtuali e analizzando chiavi di registro o percorsi di file associati ad ambienti virtuali."
author: dua2z3rr
date: 2025-10-08 1:00:00
categories: Sherlocks
tags: []
---

## Introduzione

### Domande

1. Quale classe WMI l'attaccante ha utilizzato per recuperare le informazioni sul modello e sul produttore per il rilevamento della virtualizzazione?
2. Quale query WMI l'attaccante ha eseguito per recuperare il valore della temperatura corrente della macchina?
3. L'attaccante ha caricato uno script PowerShell per rilevare la virtualizzazione. Qual è il nome della funzione dello script?
4. Quale chiave di registro lo script sopra menzionato ha interrogato per recuperare i dettagli dei servizi per il rilevamento della virtualizzazione?
5. Lo script di rilevamento VM può anche identificare VirtualBox. Quali processi confronta per determinare se il sistema sta eseguendo VirtualBox?
6. Lo script di rilevamento VM stampa qualsiasi rilevamento con il prefisso 'Questo è un'. Quali due piattaforme di virtualizzazione lo script ha rilevato?

### Overview

Nel file zip che ci viene fornito troviamo 2 file:
1. **Microsoft-Windows-Powershell.evtx**
2. **Windows-Powershell-Operational.evtx**

Invece di completare lo sherlock su linux, ho preferito usare windows come sistema operativo grazie al "**Visualizzatore eventi**" che ci permette chiaramente di vedere i log.

![Desktop View](/assets/img/phantom_check/operation-blackout-2025-phantom-check-visualizzatore-eventi.png)

## Risposte

### Quale classe WMI l'attaccante ha utilizzato per recuperare le informazioni sul modello e sul produttore per il rilevamento della virtualizzazione?

Nel file **Windows-Powershell-Operational.evtx** possiamo filtrare (ctrl+f) la parola class e il primo risultato che vedremo è questo evento:

```xml
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
- <System>
  <Provider Name="Microsoft-Windows-PowerShell" Guid="{a0c1853b-5c40-4b15-8766-3cf1c58f985a}" /> 
  <EventID>4103</EventID> 
  <Version>1</Version> 
  <Level>4</Level> 
  <Task>106</Task> 
  <Opcode>20</Opcode> 
  <Keywords>0x0</Keywords> 
  <TimeCreated SystemTime="2025-04-09T09:19:10.3028212Z" /> 
  <EventRecordID>2917</EventRecordID> 
  <Correlation ActivityID="{8dda4362-a927-0000-b3cf-dc8d27a9db01}" /> 
  <Execution ProcessID="6064" ThreadID="10848" /> 
  <Channel>Microsoft-Windows-PowerShell/Operational</Channel> 
  <Computer>DESKTOP-M3AKJSD</Computer> 
  <Security UserID="S-1-5-21-3999086100-426973801-4203759309-1002" /> 
  </System>
- <EventData>
  <Data Name="ContextInfo">Severity = Informational Host Name = ConsoleHost Host Version = 5.1.26100.2161 Host ID = 0fad0cf8-6cb6-4657-86f7-655ec22eed9f Host Application = C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe Engine Version = 5.1.26100.2161 Runspace ID = 2aeeba59-d0f6-4ce7-b41c-e07625b3beec Pipeline ID = 10 Command Name = Get-WmiObject Command Type = Cmdlet Script Name = Command Path = Sequence Number = 28 User = DESKTOP-M3AKJSD\User Connected User = Shell ID = Microsoft.PowerShell</Data> 
  <Data Name="UserData" /> 
  <Data Name="Payload">CommandInvocation(Get-WmiObject): "Get-WmiObject" ParameterBinding(Get-WmiObject): name="Class"; value="Win32_ComputerSystem" CommandInvocation(Select-Object): "Select-Object" ParameterBinding(Select-Object): name="ExpandProperty"; value="Model" ParameterBinding(Select-Object): name="InputObject"; value="\\DESKTOP-M3AKJSD\root\cimv2:Win32_ComputerSystem.Name="DESKTOP-M3AKJSD""</Data> 
  </EventData>
  </Event>
```

Risposta: `Win32_ComputerSystem`

### Quale query WMI l'attaccante ha eseguito per recuperare il valore della temperatura corrente della macchina?

Come la domanda precedente, possiamo filtrare per delle keyword nella domanda. Cominciamo con la parola **temperature**. Ecco il primo risultato:

```xml
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
- <System>
  <Provider Name="Microsoft-Windows-PowerShell" Guid="{a0c1853b-5c40-4b15-8766-3cf1c58f985a}" /> 
  <EventID>4103</EventID> 
  <Version>1</Version> 
  <Level>4</Level> 
  <Task>106</Task> 
  <Opcode>20</Opcode> 
  <Keywords>0x0</Keywords> 
  <TimeCreated SystemTime="2025-04-09T09:20:12.4823583Z" /> 
  <EventRecordID>2973</EventRecordID> 
  <Correlation ActivityID="{8dda4362-a927-0002-1820-dc8d27a9db01}" /> 
  <Execution ProcessID="6064" ThreadID="10848" /> 
  <Channel>Microsoft-Windows-PowerShell/Operational</Channel> 
  <Computer>DESKTOP-M3AKJSD</Computer> 
  <Security UserID="S-1-5-21-3999086100-426973801-4203759309-1002" /> 
  </System>
- <EventData>
  <Data Name="ContextInfo">Severity = Informational Host Name = ConsoleHost Host Version = 5.1.26100.2161 Host ID = 0fad0cf8-6cb6-4657-86f7-655ec22eed9f Host Application = C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe Engine Version = 5.1.26100.2161 Runspace ID = 2aeeba59-d0f6-4ce7-b41c-e07625b3beec Pipeline ID = 21 Command Name = Get-WmiObject Command Type = Cmdlet Script Name = Command Path = Sequence Number = 54 User = DESKTOP-M3AKJSD\User Connected User = Shell ID = Microsoft.PowerShell</Data> 
  <Data Name="UserData" /> 
  <Data Name="Payload">CommandInvocation(Get-WmiObject): "Get-WmiObject" ParameterBinding(Get-WmiObject): name="Query"; value="SELECT * FROM MSAcpi_ThermalZoneTemperature" ParameterBinding(Get-WmiObject): name="ErrorAction"; value="SilentlyContinue" NonTerminatingError(Get-WmiObject): "Invalid class "MSAcpi_ThermalZoneTemperature""</Data> 
  </EventData>
  </Event>
```

Possiamo vedere il contenuto della query.

Risposta: `SELECT * FROM MSAcpi_ThermalZoneTemperature`

### L'attaccante ha caricato uno script PowerShell per rilevare la virtualizzazione. Qual è il nome della funzione dello script?

Filtrando per parole che hanno a che fare con la virtualizzazione come VM, Virtualization, ecc. possiamo ridurre di molto il campo di ricerca. Successivamente, possiamo ulteriormente filtrare il risultato precedente considerando solamente gli eventi con id 4104 (Esegui un comando remoto). Otterremo fra i risultati questo evento:

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
  <TimeCreated SystemTime="2025-04-09T09:20:55.7303939Z" /> 
  <EventRecordID>3080</EventRecordID> 
  <Correlation ActivityID="{8dda4362-a927-0000-f7f2-dc8d27a9db01}" /> 
  <Execution ProcessID="6064" ThreadID="10848" /> 
  <Channel>Microsoft-Windows-PowerShell/Operational</Channel> 
  <Computer>DESKTOP-M3AKJSD</Computer> 
  <Security UserID="S-1-5-21-3999086100-426973801-4203759309-1002" /> 
  </System>
- <EventData>
  <Data Name="MessageNumber">1</Data> 
  <Data Name="MessageTotal">1</Data> 
  <Data Name="ScriptBlockText">Check-VM</Data> 
  <Data Name="ScriptBlockId">ec01d4f1-b1ad-4a78-af6b-ac18c1131c30</Data> 
  <Data Name="Path" /> 
  </EventData>
  </Event>
```

Risposta: `Check-VM`

### Quale chiave di registro lo script sopra menzionato ha interrogato per recuperare i dettagli dei servizi per il rilevamento della virtualizzazione?

Considerando lo script precedente, possiamo cercare nuovamente per keywords come **service**. Troveremo questo evento:

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
  <TimeCreated SystemTime="2025-04-09T09:20:53.0995764Z" /> 
  <EventRecordID>3047</EventRecordID> 
  <Correlation ActivityID="{8dda4362-a927-0002-b222-dc8d27a9db01}" /> 
  <Execution ProcessID="6064" ThreadID="10848" /> 
  <Channel>Microsoft-Windows-PowerShell/Operational</Channel> 
  <Computer>DESKTOP-M3AKJSD</Computer> 
  <Security UserID="S-1-5-21-3999086100-426973801-4203759309-1002" /> 
  </System>
- <EventData>
  <Data Name="MessageNumber">1</Data> 
  <Data Name="MessageTotal">1</Data> 
  <Data Name="ScriptBlockText">function Check-VM { <# .SYNOPSIS Nishang script which detects whether it is in a known virtual machine. .DESCRIPTION This script uses known parameters or 'fingerprints' of Hyper-V, VMWare, Virtual PC, Virtual Box, Xen and QEMU for detecting the environment. .EXAMPLE PS > Check-VM .LINK http://www.labofapenetrationtester.com/2013/01/quick-post-check-if-your-payload-is.html https://github.com/samratashok/nishang .NOTES The script draws heavily from checkvm.rb post module from msf. https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/checkvm.rb #> [CmdletBinding()] Param() $ErrorActionPreference = "SilentlyContinue" #Hyper-V $hyperv = Get-ChildItem HKLM:\SOFTWARE\Microsoft if (($hyperv -match "Hyper-V") -or ($hyperv -match "VirtualMachine")) { $hypervm = $true } if (!$hypervm) { $hyperv = Get-ItemProperty hklm:\HARDWARE\DESCRIPTION\System -Name SystemBiosVersion if ($hyperv -match "vrtual") { $hypervm = $true } } if (!$hypervm) { $hyperv = Get-ChildItem HKLM:\HARDWARE\ACPI\FADT if ($hyperv -match "vrtual") { $hypervm = $true } } if (!$hypervm) { $hyperv = Get-ChildItem HKLM:\HARDWARE\ACPI\RSDT if ($hyperv -match "vrtual") { $hypervm = $true } } if (!$hypervm) { $hyperv = Get-ChildItem HKLM:\SYSTEM\ControlSet001\Services if (($hyperv -match "vmicheartbeat") -or ($hyperv -match "vmicvss") -or ($hyperv -match "vmicshutdown") -or ($hyperv -match "vmiexchange")) { $hypervm = $true } } if ($hypervm) { "This is a Hyper-V machine." } #VMWARE $vmware = Get-ChildItem HKLM:\SYSTEM\ControlSet001\Services if (($vmware -match "vmdebug") -or ($vmware -match "vmmouse") -or ($vmware -match "VMTools") -or ($vmware -match "VMMEMCTL")) { $vmwarevm = $true } if (!$vmwarevm) { $vmware = Get-ItemProperty hklm:\HARDWARE\DESCRIPTION\System\BIOS -Name SystemManufacturer if ($vmware -match "vmware") { $vmwarevm = $true } } if (!$vmwarevm) { $vmware = Get-Childitem hklm:\hardware\devicemap\scsi -recurse | gp -Name identifier if ($vmware -match "vmware") { $vmwarevm = $true } } if (!$vmwarevm) { $vmware = Get-Process if (($vmware -eq "vmwareuser.exe") -or ($vmware -match "vmwaretray.exe")) { $vmwarevm = $true } } if ($vmwarevm) { "This is a VMWare machine." } #Virtual PC $vpc = Get-Process if (($vpc -eq "vmusrvc.exe") -or ($vpc -match "vmsrvc.exe")) { $vpcvm = $true } if (!$vpcvm) { $vpc = Get-Process if (($vpc -eq "vmwareuser.exe") -or ($vpc -match "vmwaretray.exe")) { $vpcvm = $true } } if (!$vpcvm) { $vpc = Get-ChildItem HKLM:\SYSTEM\ControlSet001\Services if (($vpc -match "vpc-s3") -or ($vpc -match "vpcuhub") -or ($vpc -match "msvmmouf")) { $vpcvm = $true } } if ($vpcvm) { "This is a Virtual PC." } #Virtual Box $vb = Get-Process if (($vb -eq "vboxservice.exe") -or ($vb -match "vboxtray.exe")) { $vbvm = $true } if (!$vbvm) { $vb = Get-ChildItem HKLM:\HARDWARE\ACPI\FADT if ($vb -match "vbox_") { $vbvm = $true } } if (!$vbvm) { $vb = Get-ChildItem HKLM:\HARDWARE\ACPI\RSDT if ($vb -match "vbox_") { $vbvm = $true } } if (!$vbvm) { $vb = Get-Childitem hklm:\hardware\devicemap\scsi -recurse | gp -Name identifier if ($vb -match "vbox") { $vbvm = $true } } if (!$vbvm) { $vb = Get-ItemProperty hklm:\HARDWARE\DESCRIPTION\System -Name SystemBiosVersion if ($vb -match "vbox") { $vbvm = $true } } if (!$vbvm) { $vb = Get-ChildItem HKLM:\SYSTEM\ControlSet001\Services if (($vb -match "VBoxMouse") -or ($vb -match "VBoxGuest") -or ($vb -match "VBoxService") -or ($vb -match "VBoxSF")) { $vbvm = $true } } if ($vbvm) { "This is a Virtual Box." } #Xen $xen = Get-Process if ($xen -eq "xenservice.exe") { $xenvm = $true } if (!$xenvm) { $xen = Get-ChildItem HKLM:\HARDWARE\ACPI\FADT if ($xen -match "xen") { $xenvm = $true } } if (!$xenvm) { $xen = Get-ChildItem HKLM:\HARDWARE\ACPI\DSDT if ($xen -match "xen") { $xenvm = $true } } if (!$xenvm) { $xen = Get-ChildItem HKLM:\HARDWARE\ACPI\RSDT if ($xen -match "xen") { $xenvm = $true } } if (!$xenvm) { $xen = Get-ChildItem HKLM:\SYSTEM\ControlSet001\Services if (($xen -match "xenevtchn") -or ($xen -match "xennet") -or ($xen -match "xennet6") -or ($xen -match "xensvc") -or ($xen -match "xenvdb")) { $xenvm = $true } } if ($xenvm) { "This is a Xen Machine." } #QEMU $qemu = Get-Childitem hklm:\hardware\devicemap\scsi -recurse | gp -Name identifier if ($qemu -match "qemu") { $qemuvm = $true } if (!$qemuvm) { $qemu = Get-ItemProperty hklm:HARDWARE\DESCRIPTION\System\CentralProcessor\0 -Name ProcessorNameString if ($qemu -match "qemu") { $qemuvm = $true } } if ($qemuvm) { "This is a Qemu machine." } }</Data> 
  <Data Name="ScriptBlockId">7c52679e-db36-49f4-87e0-675a6b23913e</Data> 
  <Data Name="Path" /> 
  </EventData>
  </Event>
```

Risposta: `HKLM:\SYSTEM\ControlSet001\Services`

### Lo script di rilevamento VM può anche identificare VirtualBox. Quali processi confronta per determinare se il sistema sta eseguendo VirtualBox?

Se controlliamo lo script trovato prima (distingu9bile da link in cima al codice) otterremo:

```xml
    #Virtual Box

    $vb = Get-Process
    if (($vb -eq "vboxservice.exe") -or ($vb -match "vboxtray.exe"))
        {
    
        $vbvm = $true
    
        }
    if (!$vbvm)
        {
            $vb = Get-ChildItem HKLM:\HARDWARE\ACPI\FADT
            if ($vb -match "vbox_")
                {
                    $vbvm = $true
                }
        }

    if (!$vbvm)
        {
            $vb = Get-ChildItem HKLM:\HARDWARE\ACPI\RSDT
            if ($vb -match "vbox_")
                {
                    $vbvm = $true
                }
        }
```

Possiamo vedere il nome dei processi che stanno venendo comparati.

Risposta: `vboxservice.exe, vboxtray.exe`

### Lo script di rilevamento VM stampa qualsiasi rilevamento con il prefisso 'Questo è un'. Quali due piattaforme di virtualizzazione lo script ha rilevato?

Filtriamo i log per il prefisso in inglese (**This is a**). Leggiamo il primo risultato:

```xml
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
- <System>
  <Provider Name="Microsoft-Windows-PowerShell" Guid="{a0c1853b-5c40-4b15-8766-3cf1c58f985a}" /> 
  <EventID>4103</EventID> 
  <Version>1</Version> 
  <Level>4</Level> 
  <Task>106</Task> 
  <Opcode>20</Opcode> 
  <Keywords>0x0</Keywords> 
  <TimeCreated SystemTime="2025-04-09T09:20:57.2771395Z" /> 
  <EventRecordID>3105</EventRecordID> 
  <Correlation ActivityID="{8dda4362-a927-0000-f7f2-dc8d27a9db01}" /> 
  <Execution ProcessID="6064" ThreadID="10848" /> 
  <Channel>Microsoft-Windows-PowerShell/Operational</Channel> 
  <Computer>DESKTOP-M3AKJSD</Computer> 
  <Security UserID="S-1-5-21-3999086100-426973801-4203759309-1002" /> 
  </System>
- <EventData>
  <Data Name="ContextInfo">Severity = Informational Host Name = ConsoleHost Host Version = 5.1.26100.2161 Host ID = 0fad0cf8-6cb6-4657-86f7-655ec22eed9f Host Application = C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe Engine Version = 5.1.26100.2161 Runspace ID = 2aeeba59-d0f6-4ce7-b41c-e07625b3beec Pipeline ID = 43 Command Name = Command Type = Script Script Name = Command Path = Sequence Number = 146 User = DESKTOP-M3AKJSD\User Connected User = Shell ID = Microsoft.PowerShell</Data> 
  <Data Name="UserData" /> 
  <Data Name="Payload">CommandInvocation(Out-Default): "Out-Default" ParameterBinding(Out-Default): name="InputObject"; value="This is a Hyper-V machine." ParameterBinding(Out-Default): name="InputObject"; value="This is a VMWare machine."</Data> 
  </EventData>
  </Event>
```

Leggiamo che lo script ha rilevato 2 tipi di virtualizzazione.

Risposta: `Hyper-V, Vmware`
