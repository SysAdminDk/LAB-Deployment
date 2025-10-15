The scripts here, can be used to prepare installation media that can be used on the Physical Nodes needed for Hyper-V and/or Azure local.  
  
ExtractDrivers.ps1  
After installing one of the servers with the Hardware supplier media, this will extract the drivers, to be injected into the custom installation media.  
  
PrepareInstallationMedias.ps1  
This script will gennerate the custom installation media, with drivers and unattended.xml foreach physical server that needs to be installed.  
Please remember to update the "Nodes" array with required information from the Physical Servers.  

PrepAzureLocalNode.ps1  
This script prepares the Azure Local install media, with drivers, and Domain Join information.  
Please remember to update the PrepareInstallationMedias.ps1 with the correct Domain credentials.  
  
PrepHyperVNode.ps1  
This scripts prepares the workgroup hyper-v nodes, they can be joined to Domain but initial they are in workgroup.  
All the required scripts to create the Fabric Domain VMs, is copied to the nodes, and will be executed after startup.  

