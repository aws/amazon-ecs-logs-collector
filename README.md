# ECS Logs Collector

This project was created to collect [Amazon ECS](https://aws.amazon.com/ecs) log files and OS logs for troubleshooting Amazon ECS customer support cases.

The following functions are supported:

* Supported OS: Amazon Linux, Red Hat Enterprise Linux 7, Debian 8, Ubuntu 14.04
* Collect normal OS logs
* Collect normal OS settings 
* Collect Docker logs
* Collect Amazon ECS agent Logs
* Enable debug mode for Docker and the Amazon ECS agent (only available for Amazon Linux)
* Create a tar zip file in the same folder as the script

## Usage
Run this project as the root user:

```
# curl -O https://raw.githubusercontent.com/awslabs/ecs-logs-collector/master/ecs-logs-collector.sh
# bash ecs-logs-collector.sh
```

Confirm if the tarball file was successfully created ( it can be .tgz or .tar.gz )

```
#ls collect.*
collect.tgz
```
### Retrieving the logs

Download the tarball using your favorite Secure Copy tool

## Example output
The project can be used in normal or debug mode (for Amazon Linux only).

### Example output in normal mode
The following output shows this project running in normal mode:

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

### Example output in debug mode
The following output shows this project running with debug mode. Note that running in debug mode restarts Docker and the Amazon ECS agent.

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

## Contributing

Please [create a new GitHub issue](https://github.com/awslabs/ecs-logs-collector/issues/new) for any feature requests, bugs, or documentation improvements.

Where possible, [submit a pull request](https://help.github.com/articles/creating-a-pull-request-from-a-fork/) for the change.

## License

Copyright 2011-2016 Amazon.com, Inc. or its affiliates. All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except in compliance with the License. A copy of the License is located at

[http://aws.amazon.com/apache2.0/](http://aws.amazon.com/apache2.0/)

or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.
