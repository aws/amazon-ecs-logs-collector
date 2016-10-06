# ECS Logs Collector
## Goals
This project has been created to automate the collection of ECS log files and OS log files in order to facilitate the troubleshooting of ECS support cases for customers.

Below are the current functions and capabilities:

* Supported OS: Amazon Linux, Red Hat Enterprise Linux 7, Debian 8, Ubuntu 14.04
* Collect normal OS Logs
* Collect normal OS settings
* Collect Docker Logs
* Collect ECS agent Logs
* Enable Debug Mode for Docker and ECS Agent ( Only availabe for Amazon Linux )
* Create a tar zip file in the same folder as the script

## Usage

* It needs to be run as root user
```
# curl -O https://raw.githubusercontent.com/awslabs/ecs-logs-collector/master/ecs-logs-collector.sh
# bash ecs-logs-collector.sh
```


### Example usage and output:
* running in normal mode
```
# bash ecs-logs-collector.sh
Trying to check if it's running as root... ok
Trying to check disk space usage... ok
Trying to collect system info... Amazon Linux AMI release 2016.03
ok
Trying to collect common system logs... ok
Trying to get mountpoints and volumes info... ok
Trying to get selinux status... ok
Trying to get iptables list... ok
Trying to get packages list... ok
Trying to get system active services list... ok
Trying to get docker info message... ok
Trying to collect ecs logs... ok
Trying to get docker inspect outputs of the containers... ok
Trying to collect docker logs... Trying to pack gathered info... ok
```
* running with debug mode ( Please note this will restart Docker and ECS Agent to take effect)
```
# bash ecs-logs-collector.sh --mode=debug
Trying to check if it's running as root... ok
Trying to check disk space usage... ok
Trying to collect system info... Amazon Linux AMI release 2016.03
ok
Trying to collect common system logs... ok
Trying to get mountpoints and volumes info... ok
Trying to get selinux status... ok
Trying to get iptables list... ok
Trying to get packages list... ok
Trying to get system active services list... ok
Trying to get docker info message... ok
Trying to collect ecs logs... ok
Trying to get docker inspect outputs of the containers... ok
Trying to collect docker logs... Trying to enable docker de[  OK  ]... Trying to restart Docker daemon to enable debug mode... Stopping docker:
Starting docker:	.                                  [  OK  ]
ok
Trying to enable ecs agent debug mode... Trying to restart ECS agent to enable debug mode... stop: Unknown instance:
ecs start/running, process 13188
ok
Trying to pack gathered info... ok
```

### Add a new item to this list

If you found yourself wishing this set of frequently asked questions had an answer for a particular problem, please [submit a pull request](https://help.github.com/articles/creating-a-pull-request-from-a-fork/). The chances are that others will also benefit from having the answer listed here.

## Contributing

Please [create a new GitHub issue](https://github.com/awslabs/ecs-logs-collector/issues/new) for any feature requests, bugs, or documentation improvements.

Where possible, please also [submit a pull request](https://help.github.com/articles/creating-a-pull-request-from-a-fork/) for the change.

## License

Copyright 2011-2016 Amazon.com, Inc. or its affiliates. All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except in compliance with the License. A copy of the License is located at

[http://aws.amazon.com/apache2.0/](http://aws.amazon.com/apache2.0/)

or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.
