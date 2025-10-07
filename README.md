# New and Updated LAB deployment  
With new hardware and MDT in route to the grave, I wanted to redo the process I have of deploying my LAB, and all the diffrent workloads that I use from time to time.  
  
I have chosen to use Proxmox as Hypervisor, I know that this might be a strange desission from a MS consultant, but I like the interface and lightweight footprint, and ease of use API.  
  
Scripts in the Proxmox folder contains the functions to create Default Server Template, and later multiple VMs depending on workload.  
  
Script in the Windows Servers contains individual server scripts.  
  
  
## To get started.  
Download the Functions folder, Create-DeploymentServer.ps1 and "PVE-Secret - Example.json"  
Rename "PVE-Secret - Example.json" to "PVE-Secret.json" and update with your values.   
Change Create-DeploymentServer.ps1 variable $RootPath, to where the Functions and PVE-Secret is located.  
  
Execute Create-DeploymentServer.ps1, and the VM will be created and installation started, open PVE Console on the VM.  
When install is done, rename server, install VirtIO drivers, and set / get IP Address.  
  
  
Then VM Templates can be created with New-PVEVMTemplate.ps1.  
If you also need 2022 template, mount the 2022 ISO and rerun.  
  
Now we are ready to spin up the LAB Domain(s) using CreateFabricDomain.ps1 and CreateProdDomain.ps1  
  
  
### Azure Local and Hyper-V tests  
If you want to play with Azure Local and setup the Fabric Domain on Hyper-V, use the Create-MSLAB-Nodes.ps1 to create the required VMs  
