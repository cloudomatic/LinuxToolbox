#!/bin/python

import sys,os

# TO DO: 
#     File pull from remote
#     Device list hash map
#     Command hash map
#     Shell commands containing sudo with a password will hang
#     Enable broker to listen on custom IP

if "MacBook" in str(os.environ):
  sys.path.append("./lib/requests-2.22.0")
  sys.path.append("./lib/urllib3-1.25.3/src")
  sys.path.append("./lib/chardet-3.0.4/")
  sys.path.append("./lib/certifi-2019.6.16/")
  sys.path.append("./lib/idna-2.8/")
  sys.path.append("./lib/Flask-1.1.1/src/")
  sys.path.append("./lib/Jinja2-2.10.1")
  sys.path.append("./lib/MarkupSafe-1.1.1/src")
  sys.path.append("./lib/Werkzeug-0.15.5/src/")
  sys.path.append("./lib/itsdangerous-1.1.0/src")
  sys.path.append("./lib/Click-7.0/")

import requests,datetime,os,urllib3,shutil,subprocess,time,traceback
from cmd import Cmd
from flask import Flask,request,abort
from threading import Lock

#
# Global utility functions
#


def get_local_node_name():
    """ Get the local host name, noting that ${HOSTNAME} or `hostname` may be unreliable """
    if os.environ.get("HOSTNAME") is not None:
      return os.environ.get("HOSTNAME")
    else:
      return "mystery_node"

#
# A simple logger
#
class Logger(object):

  timestamps = "on"

  log_level = "debug|error"

  _logger = None

  @staticmethod
  def get_instance():
    if Logger._logger == None:
      Logger._logger = Logger()
    return Logger._logger

  def log(self, message, level = None):
    log_line_prefix = ""
    if level is not None and level.lower() in self.log_level.lower():
      log_line_prefix += level.upper() + ": "
    elif level is not None and level.lower() not in self.log_level.lower(): 
      return
    if self.timestamps == "on":
      log_line_prefix = datetime.datetime.now().strftime('%Y%m%d.%H:%M:%S') + ": " + log_line_prefix
    message_lines = message.split('\n')
    for message_line in message_lines:
      print log_line_prefix + message_line

#
# A remote access slave.  The slave is designed to work behind a strict proxy/firewall layer, 
# and thus uses only HTTP outbound requests with no tunneling over a persistent TCP/IP
# connection.  The remote access slave enables a remote access client to run commands on the slave
# by polling a broker for a unit of work to run, including free-form Linux
# shell commands.
#
class RemoteAccessSlave(object):

  logger = Logger.get_instance()

  local_node_name = None

  broker_service_url = None

  def handle_shell_command(self, command):
    """
    Execute a simple shell command on the local slave node, and submit the response text from the command to the broker
      TO DOS:
        Have a timeout function that will abort a command (such as a sudo prompt for a password) that hangs
    """
    self.logger.log("RemoteAccessSlave.handle_shell_command(): >: Running command: <" + command + ">", level = "DEBUG")

    if command is not None and len(command) > 0:
      command_output = str(subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT).stdout.read())
    else:
      self.logger.log("RemoteAccessSlave.handle_shell_command(): Empty command: <" + command + "> passed as argument", level = "Error")

    self.logger.log("RemoteAccessSlave.handle_shell_command(): Command output: <" + command_output + ">", level = "DEBUG")
    broker_response_url = self.broker_service_url + "/response/" + self.get_local_node_name()
    response_to_broker_http_request_object = None
    self.logger.log("RemoteAccessSlave.handle_shell_command(): Sending command output to the broker at: " + broker_response_url + " (content: <" + command_output + ">)", level = "DEBUG")
    try:
      response_to_broker_http_request_object = requests.put(broker_response_url, data = command_output)
    except:
      self.logger.log("RemoteAccessSlave.handle_shell_command(): Sending the response to the broker at:" + broker_response_url + " returned an exception " + str(sys.exc_info()[0]), level = "error")
    if response_to_broker_http_request_object.text is not None and response_to_broker_http_request_object.text != "OK":
      # Something went wrong
      self.logger.log("RemoteAccessSlave.handle_shell_command(): Received " + response_to_broker_http_request_object.text +  " from the broker when sending the command output (expected 'OK')")

  def sendfile(self, filename):
    """
    If a command of type "sendfile <filename>" is received, we POST the specified file to the broker at <broker_service_url/storefile/<filename>
    """
    self.logger.log("RemoteAccessSlave.sendfile(): >: filename: <" + filename + ">")
    self.logger.log("RemoteAccessSlave.sendfile(): <")

  def pullfile(self, broker_filename, local_filename):
    """
    Pull a file from the broker and run it
    """
    self.logger.log("RemoteAccessSlave.pullfile(): >: broker_filename: " + broker_filename + ", local_filename: " + local_filename)
    self.logger.log("RemoteAccessSlave.pullfile(): <")

  def get_local_node_name(self):
    if self.local_node_name is not None:
      return self.local_node_name
    else:
      self.local_node_name = get_local_node_name()
      return self.local_node_name

  def process_command(self, command):
    """
    Process a command sent by a remote client to the hub.  If we don't have a custom function (like sendfile), we treat
    the command as a normal shell command
    """
    if command.startswith("sendfile "):
      self.sendfile(command.split("sendfile ",1)[1].strip())
    elif command.startswith("runfile "):
      self.pullfile(command.split("pullfile ",1)[1].strip(), "/var/tmp/runme")
      self.handle_shell_command("chmod u+rx /var/tmp/runme")
      self.handle_shell_command("/var/tmp/runme")
      self.handle_shell_command("rm /var/tmp/runme")
    elif command.startswith("pullfile "):
      self.pullfile(command.split("pullfile ",1)[1].strip(), command.split("pullfile ",1)[2].strip())
    else:
      self.handle_shell_command(command)

  def start_slave(self, broker_service_url):
      """
      Tell the local node to go into remote access slave mode using the HTTP host at broker_service_url to serve commands
      In slave mode, the program will poll ra_service_url/command looking for a command.  When a command is found (response != 404), run
      the comand and PUT command output to  ra_service_url/response
      """
      if broker_service_url == None or len(broker_service_url) < 5 or "http" not in broker_service_url:
        # TO DO: This should be an exception
        self.logger.log("Remote access slave mode requires a service URL (usage: ra <broker-service-url>)")
        return
      else:
        self.broker_service_url = broker_service_url.strip("/")

      # The interval through which we will poll the remote broker, to see if there is a command waiting for us.
      # See the notes below for how we modify this value in the absence of a broker, or any work for us to do
      command_polling_interval = 5

      # We wish to progressively wait longer than the polling interval, the longer we go without a command,
      #    so we'll keep track of failures, where "failure" means no one is trying to send us a command
      count_of_failed_command_access_attempts = 0

      # The polling loop
      while True:
        command_url = self.broker_service_url + "/command/" + self.get_local_node_name()
        response_to_request_for_a_command = None
        try:
          response_to_request_for_a_command = requests.get(command_url, verify = False)
        except:
          self.logger.log("RemoteAccessSlave.start_slave(): A GET on " + command_url + " returned an exception " + str(sys.exc_info()[0]), level = "error")
        if response_to_request_for_a_command is not None and response_to_request_for_a_command.status_code > 199 and response_to_request_for_a_command.status_code < 400 :
          self.logger.log("ra_slave_mode(): Received response_to_request_for_a_command: " + str(response_to_request_for_a_command.status_code), level = "debug")
          self.process_command(response_to_request_for_a_command.text)

          # We have a "session" now with the broker, so let's reduce our polling interval to a more normal terminal-session-like pace
          count_of_failed_command_access_attempts = 0
          command_polling_interval = 2
        else:
          if response_to_request_for_a_command is not None:
            if response_to_request_for_a_command.status_code == 404:
              # No command was found, but the broker is active, so just loop normally
              self.logger.log("ra_slave_mode(): " + self.get_local_node_name() + ": Service url " + command_url + " returned 404, polling_interval = " + str(command_polling_interval), level = "DEBUG")
            elif response_to_request_for_a_command.status_code < 200 or response_to_request_for_a_command.status_code > 399:
              self.logger.log("ra_slave_mode(): FAILURE: Received HTTP code " + str(response_to_request_for_a_command.status_code) + " retrieving  " + command_url, level = "error")
          # An exception (response_to_request_for_a_command == None) likely means the broker (command server) is simply down, or the network is not available
          # Whatever the reasons for the failure to get a command, we want to wait progressively longer until we're just checking daily
          count_of_failed_command_access_attempts += 1
          if (count_of_failed_command_access_attempts > 300):
            # TO DO: Put this back!
            #command_polling_interval = min(command_polling_interval + 10, 86400)
            count_of_failed_command_access_attempts = 0
          command_polling_interval+= 1
        self.logger.log("ra_slave_mode(): zzz (" + str(command_polling_interval) + " seconds)", level = "DEBUG")
        time.sleep(command_polling_interval)


#
# A remote access broker.  The broker supports slaves and remote access clients.
# The broker is invoked via GET /node/command where "command" is a Linux command 
# that is to be run on "node" (where node is a particular command slave node).  The 
# slave node runs the command and POSTs the command output to /node/out, where it 
# may be retrieved via GET /node/out by the remote access client that sent the command.
#
class RemoteAccessBroker(object):

  _instance = None

  logger = Logger.get_instance()

  node_data = {}

  node_data_lock = Lock()

  @staticmethod
  def get_instance():
    if RemoteAccessBroker._instance == None:
      RemoteAccessBroker._instance = RemoteAccessBroker()
    return RemoteAccessBroker._instance

  def put_response(self, node_name, response):
    self.node_data_lock.acquire()
    try:
      if node_name not in self.node_data:
        self.node_data[node_name] = {}
      self.node_data[node_name]['response'] = response
    finally:
      self.node_data_lock.release()

  def put_command(self, node_name, command):
    self.node_data_lock.acquire()
    try:
      if node_name not in self.node_data:
        self.node_data[node_name] = {}
      self.node_data[node_name]['command'] = command
    finally:
      self.node_data_lock.release()

  def get_command(self, node_name):
    self.node_data_lock.acquire()
    try:
      if node_name not in self.node_data:
        self.node_data[node_name] = {}
      # We want to know when a slave client has last checked in,
      # so that we can see who's active and 'listening'
      self.node_data[node_name]['access_time'] = str(datetime.datetime.now().strftime('%Y%m%d.%H:%M:%S'))
      if 'command' in self.node_data[node_name]:
        command = self.node_data[node_name]['command']
        self.node_data[node_name]['command'] = None
        return command
      return None
    finally:
      self.node_data_lock.release()

  def get_response(self, node_name):
    self.node_data_lock.acquire()
    try:
      if node_name in self.node_data:
        if 'response' in self.node_data[node_name]:
          response = self.node_data[node_name]['response']
          self.node_data[node_name]['response'] = None
          return response
      return None
    finally:
      self.node_data_lock.release()

  
  def get_node_data(self):
    self.node_data_lock.acquire()
    try:
      return str(self.node_data)
    finally:
      self.node_data_lock.release()

  def get_log(self, node_name):
    self.logger.log("RemoteAccessBroker.get_log(): Not implemented")

  def start_broker(self, listener_address = "0.0.0.0", port = "8000"):
    """
    Run as a Flask-based HTTP remote access broker, listening on <listener_address:port>.  When a POST is received at base_url/node/command, cache the request body.  
    When  GET is received for the same URL, serve the command and purge the command from the cache.  Do the same for base_url/node/response.
    """

    self.logger.log("DEBUG: start_broker(): >")

    try:
      broker_web_service = Flask(__name__)

      @broker_web_service.route('/data', methods = ['GET'])
      def show_data():
        return RemoteAccessBroker.get_instance().get_node_data()

      @broker_web_service.route('/log', methods = ['GET'])
      def show_log():
        abort(501)

      @broker_web_service.route('/command/<node>', methods=['PUT', 'GET'])
      def handle_command(node):
        self.logger.log("RemoteAccessBroker.handle_command(): >: node = " + str(node), level = "DEBUG")
        if request.method == 'GET':
          response_data = RemoteAccessBroker.get_instance().get_command(node)
          if response_data is None:
            abort(404)
          else:
            return response_data
        elif request.method == 'PUT':
          self.logger.log("RemoteAccessBroker.handle_command(): PUT request: " + str(request.get_data()), level = "DEBUG")
          RemoteAccessBroker.get_instance().put_command(node, request.get_data())
          return "OK"
        abort(400)

      @broker_web_service.route('/response/<node>', methods=['PUT', 'GET'])
      def handle_response(node):
        self.logger.log("RemoteAccessBroker.handle_response(): >: node: " + str(node) + ",  method: <" + request.method + ">", level = "DEBUG")
        if request.method == 'GET':
          self.logger.log("RemoteAccessBroker.handle_response(): GET: Calling get_response()", level = "DEBUG")
          response_data = RemoteAccessBroker.get_instance().get_response(node)
          if response_data is None:
            abort(404)
          else:
            return response_data
        elif request.method == 'PUT':
          self.logger.log("RemoteAccessBroker.handle_response(): PUT request: " + str(request.get_data()), level = "DEBUG")
          RemoteAccessBroker.get_instance().put_response(node, request.get_data())
          self.logger.log("RemoteAccessBroker.handle_response(): Returning <OK>", level = "DEBUG")
          return "OK"
        self.logger.log("RemoteAccessBroker.handle_response(): Could not handle " + str(request), level = "DEBUG")
        abort(400)

      # TO DO:
      # broker_web_service.run(host = listener_address, port = int(port), debug = False)
      #broker_web_service.run(port = int(port), debug = True)
      broker_web_service.run(host = listener_address, port = int(port))
    except:
      print("RemoteAccessBroker.start_broker(): ERROR " + str(sys.exc_info()[0]))
    self.logger.log("DEBUG: start(): <")

class Cli(Cmd):

  doc_header = ""
  undoc_header = ""

  logger = Logger.get_instance()

  broker_url = None
  nodename = None

  def default(self, line):
    """
    Called on an input line when the command prefix is not recognized.
    If this method is not overridden, it prints an error message and
    returns.
    """
    self.stdout.write("! No command handler for: %s\n"%line)

  def get_local_node_name(self):
    """ Get the local node name, noting that ${HOSTNAME} or `hostname` may be unreliable """
    if self.nodename is None:
      if os.environ.get("HOSTNAME") is not None:
        self.nodename = os.environ.get("HOSTNAME")
    return self.nodename

  def do_quit(self, args):
    """Exit"""
    raise SystemExit

  def do_exit(self, args):
    self.do_quit(args)

  def do_q(self, args):
    self.do_quit(args)

  def inspect_remote_node(self, args):
    # TO DO: Expect args to be an IP address or hostname
    print ""

  def do_devices(self, args):
    print "\nDevices:\n"
    if 'ROUTERPASS' in os.environ:
      router_admin_password = os.environ['ROUTERPASS']
    else:
      self.logger.log('The router password is not set.  Try "set ROUTERPASS=<password>"')
      return
    router_device_list_html = self.http_get("http://www.routerlogin.net/setup.cgi?todo=nbtscan&next_file=DEV_devices.htm", auth_user = "admin", auth_password = router_admin_password).text.split(' ')
    for token in router_device_list_html:
      if '.' in token:
        address = self.filter_ip_address_from_string(token)
        if "." in address:
          description = "unknown"
          self.logger.log(token + " " + address + " " + description)
          # TO DO: Ensure numeric

  def run_shell_command(self, command):
    #TO DO: Check for sudo in the command, find a way to validate sudo won't prompt for a password
    if command is not None and len(command) > 0:
      return str(subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT).stdout.read())
    else:
      raise Exception("ERROR: run_shell_command(): Empty command: <" + command + "> passed as argument")

  def do_sh(self, args):
    if 'HOSTNAME' in os.environ:
      hostname = os.environ['HOSTNAME']
    else:
      hostname = "UNKNOWN_HOSTNAME"
    if 'PWD' in os.environ:
      pwd = os.environ['PWD']
    else:
      pwd = "UNKNOWN"
    self.logger.log("hostname: " + hostname)
    self.logger.log("pwd     : " + pwd)
    self.logger.log("command : " + str(args))
    self.logger.log(self.run_shell_command(str(args)))

  def http_get(self, url, auth_user = None, auth_password = None):
    #os.environ['PYTHONWARNINGS'] = "ignore:Unverified HTTPS request"
    #urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    response = requests.get(url, auth = (auth_user, auth_password), verify = False)
    if response.status_code < 200 or response.status_code > 399:
      self.logger.log("http_get(): FAILURE: Received HTTP code response.status_code retrieving content from " + url, level = "error")
      raise Exception(
        "Exception in Cli.http_get(): Request to " + request  + " failed (HTTP response code " + str(response.status_code) + ")"
      )
    return response

  def retrieve_network_image(self, url, path, auth_user = None, auth_password = None):
    #os.environ['PYTHONWARNINGS'] = "ignore:Unverified HTTPS request"
    #urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    response = requests.get(url, auth = (auth_user, auth_password), verify = False, stream = True)
    if response.status_code < 200 or response.status_code > 399:
      self.logger.log("retrieve_network_image(): FAILURE: Received HTTP code response.status_code downloading image from " + url, level = "error")
      raise oxception(
          "Exception in Cli.retrieve_network_image(): Request to " + request  + " failed (HTTP response code " + str(response.status_code) + ")"
      )
    with open(path, 'wb') as imagefile:
      response.raw.decode_content = True
      shutil.copyfileobj(response.raw, imagefile)
      self.logger.log("Image file saved to " + path)

  def do_t(self, args):
    self.do_test(args)

  def do_test(self, args):
    self.logger.log("[test] The local hostname is: " + self.get_local_node_name())
    self.do_show("devices")
    self.do_scan("local")
    self.do_debug(None)
    self.logger.log("line1\nline2")
    self.do_timestamps("off")
    self.logger.log("line1\nline2")
    self.do_timestamps("on")
    self.logger.log("Debug message", level = "debug")
    self.logger.log("Longer\ndebug\nmessage", level = "debug")
    self.do_debug("off")
    #self.logger.log(
    #try:
    #  print self.http_get("").text
    #  self.retrieve_network_image("", "")
    #except Exception as exception:
    #  self.logger.log(str(exception.args))
    self.do_sh("ls -l")
    broker = RemoteAccessBroker.get_instance()
    broker.logger = self.logger
    self.logger.log("[test] get_command() for a node the broker doesn't know about is " + str(broker.get_command("testnode01")))
    self.logger.log("[test] get_response() for a node the broker doesn't know about is " + str(broker.get_response("testnode02")))
    self.logger.log("[test] Broker node data (expecting to see testnode01 access_time): " + str(broker.get_node_data()))
    broker.put_command("testnode03", "hostname")
    self.logger.log("[test] Broker node data after put_command(): " + str(broker.get_node_data()))
    self.logger.log("[test] get_response() for a command that is pending is (expecting None): " + str(broker.get_response("testnode03")))
    command = broker.get_command("testnode03")
    broker.put_response("testnode03", self.run_shell_command(command))
    self.logger.log("[test] Broker node data after put_response(): " + str(broker.get_node_data()))
    self.logger.log("[test] Broker response for get_command() from a client who just submitted a response is (expecting None): " + str(broker.get_command("testnode03")))
    self.logger.log("[test] Broker response for get_response() on a pending command is: <" + str(broker.get_response("testnode03")) + ">")
    self.logger.log("[test] Broker node data after get_response() (expecting 'None' for testnode03 command and response): " + str(broker.get_node_data()))

  def do_scan(self, args):
    self.logger.log("Scanning local subnet")
    self.logger.log("192.168.1.1\n192.168.1.2")

  def do_set(self, args):
    if len(args) > 0: 
      try:
        if "=" in args:
          name = args.split('=')[0]
          value = args.split('=')[1]
        else:
          name = args.split(' ')[0]
          value = args.split(' ')[1]
        if name is not None and value is not None and len(name) > 0 and len(value) > 0:
          os.environ[name] = value
          return
      except:
        self.logger.log("")
      self.logger.log("Invalid syntax for the 'set' command.  Try: set <name> <value>")
    else:
      print str(os.environ)

  def do_ra(self, args):
    self.logger.log("do_ra(): >: args: <" + str(args) + ">", level = "DEBUG")
    try:
      if args is not None and len(args) > 3:
        if args.startswith("slave"):
          ra_service_url = str(args.split(' ')[1])
          if args == None or len(args) < 5 or "http" not in args:
            self.logger.log("RA mode requires a service URL (usage: ra <service-url>)")
          else:
            RemoteAccessSlave().start_slave(ra_service_url)
            self.logger.log("do_ra(): <", level = "DEBUG")
            return
        elif args.startswith("start hub") or args.startswith("start broker"):
          argument_list = args.split(' ')
          print str(argument_list)
          listener_address = "127.0.0.1"
          listener_port = 8000
          for arg in argument_list[1:]:
            if "." in str(arg):
              listener_address = arg
            elif arg.isdigit():
              listener_port = arg
          broker = RemoteAccessBroker.get_instance()
          broker.start_broker(listener_address = listener_address, port = listener_port)
          broker.logger = self.logger
          self.logger.log("do_ra(): <", level = "DEBUG")
          return
        elif args.startswith("set hub ") or args.startswith("set broker "):
          self.broker_url = str(args.split(' ')[2])
          self.logger.log("Setting broker service URL to: " + self.broker_url)
          return
        elif args.startswith("list nodes"):
          if self.broker_url is None:
            self.broker_url = "http://localhost:8000"
            #self.logger.log("Remote access broker not set.  Try: set broker <broker-service-url>")
          print "\nHub: " + self.broker_url + "\n"
          print requests.get(self.broker_url + "/data").text + "\n"
          return
        elif args.startswith("sh "):
          if self.broker_url is None:
            self.logger.log("Remote access broker not set.  Try: set broker <broker-service-url>")
            return
          else:
            node_name = str(args.split(' ')[1])
            remote_command = args.split(node_name,1)[1].strip()
            self.ra_remote_command(node_name, remote_command)
            return
    except:
      self.logger.log("do_ra(): ERROR: " + str(sys.exc_info()[0]), level = "ERROR")
      traceback.print_exc()
    self.logger.log("Try: ra slave <broker-url>")
    self.logger.log(" or: ra start broker <port>")
    self.logger.log(" or: ra set broker <broker-url>")
    self.logger.log(" or: ra list nodes")
    self.logger.log(" or: ra sh <node> <command>")
    self.logger.log("do_ra(): <", level = "DEBUG")

  def ra_remote_command(self, node_name, command):
    self.logger.log("Cli.ra_remote_command(): >", level = "DEBUG")
    broker_request_url = self.broker_url + "/command/" + node_name
    self.logger.log("Cli.ra_remote_command(): Attempting remote command request: " + broker_request_url, level = "DEBUG")
    command_http_response = requests.put(broker_request_url, data = command)
    self.logger.log(command_http_response.text)
    # Now go into a polling loop waiting for a response
    response_received = False
    while response_received is False:
      broker_response_url = self.broker_url + "/response/" + node_name
      self.logger.log("Cli.ra_remote_command(): Waiting for a response from: " + broker_response_url, level = "DEBUG")
      command_output_http_response = requests.get(broker_response_url)
      if command_output_http_response.status_code != 404:
        response_received = True
        print command_output_http_response.text
        return
      time.sleep(2)
    return

    
  
  def filter_ip_address_from_string(self, args):
    if args is not None:
      if len(args) > 0:
        return "10.0.0.7"
        # TO DO

  def do_show(self, args):
    if len(args) > 0:
      if "devices" in args.split(' '):
        self.do_devices(args)
    else:
      print "show what?"

  def do_timestamps(self, args):
    if args == None or len(args) == 0:
      print "Timestamps on"
      self.logger.timestamps = "on"
    elif "off" in args.split(' '):
      print "Timestamps off"
      self.logger.timestamps = "off"
    elif "on" in args.split(' '):
      self.do_timestamps(None)

  def do_debug(self, args):
    if args == None or len(args) == 0:
      self.logger.log("Debug mode on")
      self.logger.log_level = "debug"
    elif "off" in args.split(' '):
      self.logger.log("Debug mode off")
      self.logger.log_level = "error"
    elif "on" in args.split(' '):
      self.do_debug(None)

  def run_command(self, command_name, args):
    command = getattr(self, "do_" + command_name, None)
    if callable(command):
      if len(args) > 0:
        command(str(args))
      else:
        command(None)

if __name__ == '__main__':
  
  # Turn off untrusted cert warnings
  os.environ['PYTHONWARNINGS'] = "ignore:Unverified HTTPS request"
  urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

  prompt = Cli()
  prompt.prompt = '> '

  if len(sys.argv) > 1:
    prompt.run_command(sys.argv[1], " ".join(sys.argv[2:]))
  else:
    prompt.cmdloop('')
