# My LAP deployment.  
  
Installation and configuration of the PVE nodes, will not be covered here.
  
  
# In Proxmox PVE
Create PVE API User,  
Datacenter -> Permissions -> API Tokens -> Add  
Example : User = root@pam, Token ID = PowerShell  
Save secret to "PVE-Secret.json" (See /LAB-Deployment/Proxmox Scripts/PVE-Secret - Example.json)  
  
Assign Permissions,  
Datacenter -> Permissions -> Add -> API Token Permissions.  
Example : Path = /, API Token = root@pam!PowerShell, Role = PVEAdmin  
  
Then create a temp folder on any Windows computer with browser access to any of the PVE nodes.  
Get a copy of /Proxmox Scripts/Create-PVEDeploymentServer.ps1 and the /Proxmox Scripts/Functions/* script.  
* Update the PATH in the script to match.  
  
Run or step thrugh Create-PVEDeploymentServer.ps1 to create the LAB-Deploy Server.  
The script will initiate PVE Download of Azure Local, Server 2025 (Eval), Server 2022 (Eval) and VirtIO Drivers.  
You can upload your own images to PVE datastore, just make sure they are added to the Deployment server VM.  
* Please update the download urls if changed.  
scsi2 = Server 2022  
scsi3 = Azure Local  
ide0 = VirtIO Drivers  
ide2 = Server 2025  
  
  
After creation, boot the LAB-Deploy Master server, and install Windows server, depending on the boot image selected, above.  
  
When Windows installation is done, login to the new server, and get the MS-Fabric\Server Roles\Prep-DeploymentServer.ps1 script.  
  
Copy the PVE-Secret.json created erlier to D:\Proxmox Scripts.  
Execute D:\Server Roles\Prep-DeploymentServer.ps1 to create folders, copy files, and install WinPE  
  
Open PowerShell ISE and open the following scripts.  
run PowerShell_ISE.exe "D:\Proxmox Scripts\New-PVEVMTemplate.ps1"  
* Create as many templates as needed, I create only 2025 Standard Desktop Eddition.  
  
If you want to test Azure Local, as ME, open "D:\Proxmox Scripts\Create-PVEMSLAB-Nodes.ps1".  
* This custom VM creat script creates 3(5) Azure Local nodes and 2 HyperV servers, to emulate FABRIC Hosts.  
* Please note the JSON files created, is required when the AZ nodes are installed.  

For the "Physical Servers" there is scripts to create a Boot ISO, that installes and prepare the servers for HyperV or Azure Local.  
D:\Physical Servers\Azure Local\PrepareAZLocalInstallMedia.ps1  
D:\Physical Servers\Hyper-V\PrepareHyperVInstallMedia.ps1  
You can just run both, and the ISOs will be created and ready to install all the nodes.
* The ISOs will be uploaded to the ISO datastore on the node where the VMs are created.  
* If using VL media the HyperV servers need a Datacenter key.  
  
Now the Template and ISOs are ready, the AZ-NODE* can be started and installed.
  
The Fabric Domain can be created either on the HV-NODE* or directly in PVE, I have scripts for both.  
* PVE : Open D:\Proxmox Scripts\Create-PVEFabricDomain.ps1, and change Default Password and Domain.  




  
