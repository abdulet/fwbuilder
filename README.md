# FWBuilder
##Software to deploy and migrate firewalls
It take as source a collection of csv files, it is fully modular and can use modules to create csv files as well as to import it, so it can be used to migrate from one manufacturer to other one.

At the moment it can:
* Create csv files:
    * From Junos firewall (very basic support)
        * Export: objects, users, services, and policies
        * TODO: NAT, pools, and more
* Import csv files to:
    * Checkpoint firewall R7x ( Tested only in R77.20, but it should work in others with dbedit )
        * Imports: objects, users, services, service groups and policies
        * TODO: NAT, pools, vpn and more...

* Can be used to:
    * Migrate from Juniper to Checkpoint (Basic support)
