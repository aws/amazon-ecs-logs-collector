# ECS Logs Collector

This project was created to collect [Amazon ECS](https://aws.amazon.com/ecs) log files and Operating System log files for troubleshooting Amazon ECS customer support cases.

The following functions are supported:

* Collect Operating System logs
* Collect Operating System settings
* Collect Docker logs
* Collect Amazon ECS agent Logs
* Enable debug mode for Docker and the Amazon ECS agent (only available for Systemd init systems and Amazon Linux)
* Create a tar zip file in the same folder as the script

## Usage
Run this project as the root user:

```
# curl -O https://raw.githubusercontent.com/awslabs/ecs-logs-collector/master/ecs-logs-collector.sh
# bash ecs-logs-collector.sh
```

Confirm if the tarball file was successfully created (it can be .tgz or .tar.gz)

```
#ls collect*
collect-i-ffffffffffffffffff.tgz

collect:
i-ffffffffffffffffff
```
### Retrieving the logs

Download the tarball using your favourite Secure Copy tool.

## Example output
The project can be used in normal or enable-debug mode. Enable debug is only available for Systemd init systems and Amazon Linux.

```
# bash ecs-logs-collector.sh --help
USAGE: ./ecs-logs-collector.sh [--mode=[brief|enable-debug]]
       ./ecs-logs-collector.sh --help

OPTIONS:
     --mode  Sets the desired mode of the script. For more information,
             see the MODES section.
     --help  Show this help message.

MODES:
     brief         Gathers basic operating system, Docker daemon, and Amazon
                   ECS Container Agent logs. This is the default mode.
     enable-debug  Enables debug mode for the Docker daemon and the Amazon
                   ECS Container Agent. Only supported on Systemd init systems
                   and Amazon Linux.
```

### Example output in normal mode
The following output shows this project running in normal mode.

```
# bash ecs-logs-collector.sh
Trying to check if the script is running as root ... ok
Trying to resolve instance-id ... ok
Trying to collect system information ... ok
Trying to check disk space usage ... ok
Trying to collect common operating system logs ... ok
Trying to collect kernel logs ... ok
Trying to get mount points and volume information ... ok
Trying to check SELinux status ... ok
Trying to get iptables list ... ok
Trying to detect installed packages ... ok
Trying to detect active system services list ... ok
Trying to gather Docker daemon information ... ok
Trying to inspect all Docker containers ... ok
Trying to collect Docker daemon logs ... ok
Trying to collect Amazon ECS Container Agent logs ... ok
Trying to collect Amazon ECS Container Agent state and config ... ok
Trying to collect Amazon ECS Container Agent engine data ... ok
Trying to archive gathered log information ... ok
```

### Example output in enable-debug mode
The following output shows this project enabling debug mode for the Docker daemon and the Amazon ECS Container Agent. This mode only works on Amazon Linux OS and Systemd init systems such as RHEL 7 and Ubuntu 16.04. Note that enable-debug mode restarts Docker and the Amazon ECS agent.

```
# bash ecs-logs-collector.sh --mode=enable-debug
Trying to check if the script is running as root ... ok
Trying to collect system information ... ok
Trying to enable debug mode for the Docker daemon ... ok
Trying to restart Docker daemon to enable debug mode ... ok
Trying to enable debug mode for the Amazon ECS Container Agent ... ok
Trying to restart the Amazon ECS Container Agent to enable debug mode ... ok
```

## Contributing

Please [create a new GitHub issue](https://github.com/awslabs/ecs-logs-collector/issues/new) for any feature requests, bugs, or documentation improvements.

Where possible, [submit a pull request](https://help.github.com/articles/creating-a-pull-request-from-a-fork/) for the change.

## License

Copyright 2011-2016 Amazon.com, Inc. or its affiliates. All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except in compliance with the License. A copy of the License is located at

[http://aws.amazon.com/apache2.0/](http://aws.amazon.com/apache2.0/)

or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.
