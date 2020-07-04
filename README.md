# yGREd

Little daemon that spawns a webserver to configure GRE tunnels.
Listens on :: port 10001 for /gre on HTTP


```
usage: ygred.py [-h] [--config-file CONFIG_FILE] [--ipv6-space IPV6_SPACE] [--store-path STORE_PATH]

yGREd - GRE Automation service daemon.

optional arguments:
  -h, --help            show this help message and exit
  --config-file CONFIG_FILE
                        pass config file
  --ipv6-space IPV6_SPACE
                        ipv6 routable block
  --store-path STORE_PATH
                        path to database file for storing tunnels. defaults to $HOME/.ygred.json
```

Todo:
- expand readme
- add bind host/port config option
- add more todo
