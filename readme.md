# My LAP deployment.  
  
After the Proxmox PVE nodes have been prepared, the following steps needed to create Fabric Domain with 3 Azure Local member nodes.  
Create an API User,  
Datacenter -> Permissions -> API Tokens -> Add  
Example : User = root@pam, Token ID = PowerShell  
Save secret to "PVE-Secret.json" (See /LAB-Deployment/Proxmox Scripts/PVE-Secret - Example.json)  
  
Assign Permissions,  
Datacenter -> Permissions -> Add -> API Token Permissions.  
Example : Path = /, API Token = root@pam!PowerShell, Role = PVEAdmin  
  
Then create a temp folder on any Windows computer with browser access to any of the PVE nodes.  
Get a copy of /LAB-Deployment/Proxmox Scripts/Create-PVEDeploymentServer.ps1 script.
  
Run or step thrugh Create-PVEDeploymentServer.ps1 to create the LAB-Deploy Server.  
The script will initiate PVE Download of Server 2025 Eval, Server 2022 Eval and VirtIO Drivers.  
or you can upload your own images to PVE datastore, just make sure they are added to the Deployment server VM.  

The Azure Local image must be downloaded from your Azure subscription, and upload to PVE storage and added to the Deployment server.  




