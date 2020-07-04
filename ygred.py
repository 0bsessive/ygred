import socket
import traceback
import sys
import json
import os
import time
import subprocess
import uuid
import ipaddress
import random
import shlex
import copy
import argparse
class DatabaseController:
    def __init__(self, args, filename):
        if filename == False:
            filename = args.config_file
        try:
            self.store = json.load(open('%s' % filename,'r'))
        except json.decoder.JSONDecodeError:
            self.store = {}
        except FileNotFoundError:
            self.store = {}
        self.filename = filename
        self.last_flush = time.time()
        self.needFlush = False
        self.args = args
    def write(self):
        fd = open('%s' % self.filename,'w')
        fd.write(json.dumps(self.store))
        fd.close()
    def get_fallback(self, key):
        values = {
            'max_idle_timeout': 604800,
            'ipv4-space': '10.101.0.0/16',
            'network-ipv6-space': '0200::/7',
            "bind": {
              "host": "::",
              "port": "10001"
            },
            "tunnel-ttl": 255,
            "dump-state-interval": 300,
            "store_path": os.environ['HOME'] + "/.ygred.json"
        }
        if self.args.store_path:
            values["store_path"] = self.args.database_path
        if self.args.ipv6_space:
            values["ipv6-space"] = self.args.ipv6_space
        if key in values:
            return values[key]
        return None
    def get(self, key):
        try:
            return self.store[key]
        except:
            return self.get_fallback(key)
    def set(self, key, data):
        if key not in self.store:
            self.store[key] = data
            self.needFlush = True
        else:
            if self.store[key] != data:
                self.store[key] = data
                self.needFlush = True

    def setNeedFlush(self, boolean):
        self.needFlush = boolean
    def check_flush(self):
        if self.needFlush and time.time() - self.last_flush > 3:
            self.write()
            self.last_flush = time.time()
            self.needFlush = False

class GREController:

    def __init__(self, http):
        self.http = http
        self.config = http.getApp().getConfig()
    def getRemoteIP(self):
        return self.http.remoteIP
    def gen_interface_name(self):
        interfaceName = "ygre%s" % (str(uuid.uuid4()).split('-')[0])
        ygre_interfaces = self.http.getApp().get_ygre_interfaces()
        if interfaceName in ygre_interfaces:
            return self.gen_interface_name()
        return interfaceName
        
    def get_current_tunnel(self):
        current_tunnels = self.http.getApp().get_configured_tunnels()
        if current_tunnels:
            if self.getRemoteIP() in current_tunnels:
                return current_tunnels[self.getRemoteIP()]
        return False

    def output_tunnel_config(self, tunnelStruct):
        return """
            ip tunnel add %s mode ip6gre remote %s local %s
            ip addr add %s peer %s dev %s
            ip link set %s up
        """ % (
            tunnelStruct['interface'],
            tunnelStruct['ipv6local'],
            self.getRemoteIP(),
            tunnelStruct['ipv4remote'],
            tunnelStruct['ipv4local'],
            tunnelStruct['interface'],
            tunnelStruct['interface']
        )

   
    def gen_ipv4_space(self):
        tunnels = self.http.getApp().get_configured_tunnels()
        
        ipv4_space = ipaddress.IPv4Network(self.config.get('ipv4-space'))
        subnets = list(ipv4_space.subnets(new_prefix=24))

        for tunnel in tunnels:
            network = ipaddress.IPv4Network(tunnels[tunnel]['ipv4network'])
            subnets.remove(network)
        if len(subnets) == 0:
            return False
        return subnets[0]

    def gen_ipv6_space(self):
        ipv6_space = ipaddress.IPv6Network(self.config.get('ipv6-space'))
        tunnels = self.http.getApp().get_configured_tunnels()
        if not tunnels:
            return next(ipv6_space.hosts())
        return next(ipv6_space.hosts()) + len(tunnels) + 1
            
        

    def setup_tunnel(self):
        tunnelStruct = self.get_current_tunnel()
        if tunnelStruct:
            return self.output_tunnel_config(tunnelStruct)

        ipv4_space = self.gen_ipv4_space()
        if not ipv4_space:
            return False
        ipv6_space = self.gen_ipv6_space()
        if not ipv6_space:
            return False

        avHosts = list(ipv4_space.hosts())

        tunnelStruct = {
            'interface': self.gen_interface_name(),
            'ipv4network': str(ipv4_space),
            'ipv4remote':str(avHosts[1]),
            'ipv4local':str(avHosts[0]),
            'ipv6local': str(ipv6_space)
        }
        tunnels = self.http.getApp().get_configured_tunnels()
        tunnels[self.getRemoteIP()] = tunnelStruct

        if not IPLink().setup(tunnelStruct['interface'], tunnelStruct['ipv6local'], self.getRemoteIP(), 
                self.config.get('tunnel-ttl'),
                tunnelStruct['ipv4local'],tunnelStruct['ipv4remote']
            ):
            return False

        self.http.getApp().getDatabase().set('tunnels', tunnels)
        return self.output_tunnel_config(tunnelStruct)

    def out(self):

        try:
            in_net = ipaddress.IPv6Address(self.getRemoteIP()) in ipaddress.IPv6Network(self.http.getApp().getConfig().get('network-ipv6-space'))
        except:
            in_net = False
        
        if not in_net:
            return self.http.send_return(404, 'This only works inside %s' % self.http.getApp().getConfig().get('network-ipv6-space'))    

        tunnel_config = self.setup_tunnel()
        if tunnel_config:
            return self.http.send_return(200, tunnel_config)
        else:
            return self.http.send_return(400, 'Ran out of IP space')

    
class HTTP:
    def __init__(self, payload, remoteIP, app):
        if payload != None:
            self.payload = str(payload.decode())
            self.payload = self.payload[:self.payload.find("\\n")].strip()
        self.remoteIP = remoteIP
        self.app = app

    def getApp(self):
        return self.app

    def accepted_methods(self):
        return ['get']
    def accepted_routes(self):
        return {
            '/gre': GREController
        }
    def parse(self):
        self.method = self.payload.split()[0].lower()
        self.path   = self.payload.split()[1].lower()
        if self.validate():
            return self.route()
        return self.send_return(500,'Oops')
    def validate(self):
        if self.method not in self.accepted_methods():
            return False
        if self.path not in self.accepted_routes().keys():
            return False
        return True
    def route(self):
        return self.accepted_routes()[self.path](self).out()
    def send_return(self, returncode, data):
        if returncode == 200:
            msg = 'OK'
        else:
            msg = data
            data = ""
        msg = "HTTP/1.0 %s %s\r\n\r\n%s\r\n" % (returncode, msg, data)
        return msg.encode()

class Server:
    def __init__(self, app):
        self.socket = socket.socket(family=socket.AF_INET6)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.active = True
        self.app = app
    def setListen(self, ip, port):
        self.ip = ip
        self.port = int(port)

    def conn(self, sockaccept):
        fd, addr = sockaccept
        sock = addr[0]
        remote_ip = addr[0]
        http = HTTP(fd.recv(1024),remote_ip, self.app)
        fd.send(http.parse())
        fd.close()


    def loop(self):
        self.socket.bind((self.ip, self.port))
        self.socket.listen(1)
        self.socket.settimeout(3)
        while self.active:
            try:
                self.conn(self.socket.accept())
            except socket.timeout:
                pass
            except KeyboardInterrupt:
                break
            self.app.loop()
        self.app.getDatabase().write()

class Exec:
    def __init__(self, cmd):
        self.cmd = cmd
    def do_and_wait(self):
        os.system(self.cmd)
        return 0

class IPLink:
    def __init__(self):
        pass 
    def remove(self, interface):
        return Exec('ip tunnel del %s' % interface).do_and_wait()
    def setup(self, interface, ipv6source, ipv6remote, ttl, ipv4source, ipv4remote):
        cmds =[
            'ip -6 tunnel add name %s mode ip6gre remote %s local %s ttl %s' % (interface, ipv6remote, ipv6source, ttl),
            'ip addr add %s peer %s dev %s' % (ipv4source, ipv4remote,interface),
            'ip addr add %s/128 dev lo' % (ipv6source),
            'ip link set up dev %s' % interface
        ]
        sumrtr = 0
        for cmd in cmds:
            sumrtr = sumrtr + Exec(cmd).do_and_wait()
        return sumrtr == 0
    
class App:
    def __init__(self, args):
        args = args.parse_args()
        
        self.config   = DatabaseController(args, False)
        store_path = self.config.get('store_path')
        
        if not self.config.get("ipv6-space"):
            print("Missing IPv6-space")
            sys.exit()

        self.database = DatabaseController(args,store_path)
        
        self.last_state_dump = time.time() - self.config.get('dump-state-interval')
        self.args = args
        self.is_test_mode = True
    def getIsTestMode(self):
        return self.is_test_mode
    def getDatabase(self):
        return self.database
    def getConfig(self):
        return self.config
    def get_configured_tunnels(self):
        tunnels = self.getDatabase().get('tunnels')
        if tunnels == None:
            return {}
        return tunnels
    def get_configured_interfaces(self):
        tunnels = self.get_configured_tunnels()
        interfaces = {}
        for tunnel in tunnels:
            interfaces[tunnels[tunnel]['interface']] = tunnel
        return interfaces
    def get_ygre_interfaces(self):
        interfaces = self.get_interfaces()
        ygre_interfaces = []
        for interface in interfaces:
            if interface[:4] == 'ygre':
                ygre_interfaces.append(interface)
        return ygre_interfaces
    def get_interfaces(self):
        return os.listdir('/sys/class/net/')

    def get_tunnels_usages(self):
        configured_interfaces = self.get_configured_interfaces()
        tunnels = copy.deepcopy(self.get_configured_tunnels())
        for interface in self.get_ygre_interfaces():
            if interface not in configured_interfaces:
                continue
            rx_bytes = int(open('/sys/class/net/%s/statistics/rx_bytes' % interface).read().strip())
            keymap = configured_interfaces[interface]
            if 'rx' in tunnels[keymap]:
                if tunnels[keymap]['rx'] == rx_bytes:
                    continue
            tunnels[keymap]['rx'] = rx_bytes
            tunnels[keymap]['ts'] = int(time.time())

        return tunnels

    def get_interfaces_expiring(self):
        prev_usages = self.get_configured_tunnels()
        current_usages = self.get_tunnels_usages()
        current_time = int(time.time())
        max_idle_timeout = self.getConfig().get('max_idle_timeout')
        delete_interfaces = []

        for tunnel in prev_usages:
            try:
                prev_usages[tunnel]['ts']
            except KeyError:
                continue
            if current_time - prev_usages[tunnel]['ts'] < max_idle_timeout:
                continue
            if current_usages[tunnel]['rx'] - prev_usages[tunnel]['rx'] == 0 or True:
                delete_interfaces.append(current_usages[tunnel]['interface'])
        return delete_interfaces
    def cron(self):
        delete_interfaces = self.get_interfaces_expiring()

        if len(delete_interfaces):
            configured_interfaces = self.get_configured_interfaces()
            configured_tunnels = self.get_configured_tunnels()
 
            self.getDatabase().setNeedFlush(True)
            remove_tunnels = []
            
        for interface in delete_interfaces:
            IPLink().remove(interface)
            tunnel = configured_interfaces[interface]
            del configured_tunnels[tunnel]

        
        if time.time() - self.last_state_dump > self.config.get('dump-state-interval'):
            self.dump_state()
            self.last_state_dump = time.time()
        
    def dump_state(self):
        state = self.get_tunnels_usages()
        self.getDatabase().set('tunnels', state)

    def initial_state(self):
        current_interfaces = self.get_ygre_interfaces()
        configured_interfaces = self.get_configured_interfaces()
        configured_tunnels = self.get_configured_tunnels()

        for interface in configured_interfaces:
            if interface in current_interfaces:
                continue
            tunnel = configured_tunnels[configured_interfaces[interface]]
            IPLink().setup(
                interface, tunnel['ipv6local'], configured_interfaces[interface], self.config.get('tunnel-ttl'),
                tunnel['ipv4local'], tunnel['ipv4remote']
            )

    def run(self):
        self.initial_state()
        bind = self.getConfig().get('bind')
        s = Server(self)
        s.setListen(bind['host'],bind['port'])
        s.loop()
    def loop(self):
        self.cron()
        self.getDatabase().check_flush()


VERSION="1.0-rc1"
config_file = ''
parser = argparse.ArgumentParser(description='yGREd - GRE Automation service daemon. v' + VERSION)
parser.add_argument('--config-file',
                    default='/etc/ygred/config.json',
                    help='pass config file')
parser.add_argument('--ipv6-space',
                    help='ipv6 routable block')
parser.add_argument('--store-path',
                    help='path to database file for storing tunnels. defaults to $HOME/.ygred.json',
                    default=None
                    )

App(parser).run()


