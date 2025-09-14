# New and Updated LAB deployment  
With new hardware and MDT in route to the grave, I wanted to redo the process I have of deploying my LAB, and all the diffrent workloads that I use from time to time.  
  
I have chosen to use Proxmox as Hypervisor, I know that this might be a strange desission from a MS consultant, but I like the interface and lightweight footprint, and ease of use API.  
  
Scripts in the Proxmox folder contains the functions to create Default Server Template, and later multiple VMs depending on workload.  
  
Script in the Windows Servers contains individual server scripts.  
  
  
## To get started.  
### I will add PS script to create the LAB-Deploy VM, and get PVE to fetch the required files, later  

Fetch latest Windows Server 2022 or 2025 ISO and upload to ISO Images data store.  
Fetch latest VirtIO drivers from "https://pve.proxmox.com/wiki/Windows_VirtIO_Drivers" and upload to ISO Images data store.  

Manually create the first VM - LAB-Deploy  
- Add 50Gb OS Disk and 100Gb Data Disk. 
- Attach Both the Win Install media and VirtIO-Win media

Install Windows Server 2022 or 2025  
  
Download content of Proxmox folder to local disk. D:\  
Fetch latest Windows Server 2022 or 2025 ISO and extract to D:\Server 2025 Files  
Fetch latest VirtIO drivers from "https://pve.proxmox.com/wiki/Windows_VirtIO_Drivers" and extract to D:\Windows VirtIO Drivers  
  
Update the Unattend.xml with YOUR installation key, Org Name and Name.  
  
Start the New-PVEVMTemplate.ps1, and