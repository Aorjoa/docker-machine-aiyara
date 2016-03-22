# Docker Machine driver plugin for Aiyara

This plugin adds support for Aiyara Cluster and fork from Vultr project.

**Example for creating a new machine running Ubuntu 14.04:**
    docker-machine create --driver aiyara --aiyara-host-range=192.168.5.[1:100] node

Command line flags:

 - `--aiyara-host-range`: Aiyara Node IP addresses in [from:to] format.
 - `--aiyara-ssh-port`: Aiyara SSH port.
 - `--aiyara-ssh-user`: Aiyara user name to connect via SSH.
 - `--aiyara-ssh-passwd`: Aiyara host password, must be same for the whole cluster