#!/usr/local/bin/python

import sys,os

# TO DO: Change "unknown syntax" to "Cannot process: "
#     Device list hash map
#     Command hash map
#     Shell commands containing sudo with a password will hang

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

import requests,datetime,os,urllib3,shutil,subprocess,time
from cmd import Cmd
from flask import Flask

#
# A remote access broker.  The broker supports slaves and remote access clients.
#    The broker is invoked via GET /node/command where "command" is a Linux command that is to be run on "node" (where node is a particular command slave node).  The 
#    slave node runs the command and POSTs the command output to /node/out, where it may be retrieved via GET /node/out by the remote access client that sent the command.
#
class RemoteAccessBroker(object):

  #def ra_put_command(self, node_name):

  #def ra_get_response(self):
  
  #def ra_get_log(self, node_name):

  def start(self, base_url, port):
    """
    Run as an HTTP remote access broker, listening on <port>.  When a POST is received at base_url/node/command, cache the request body.  
    When  GET is received for the same URL, serve the command and purge the command from the cache.  Do the same for base_url/node/response.
    """

    self.log("DEBUG: start(): >")

    try:
      hub_web_service = Flask(__name__)

      @hub_web_service.route('/')
      def service_request():
        return "<html>Hello world<html>"

      hub_web_service.run()

    except:
      self.log("start(): ERROR " + str(sys.exc_info()[0]))
    
    self.log("DEBUG: start(): <")

class Cli(Cmd):

  # These headers come from Cmd, and show in the help text
  doc_header = ""
  undoc_header = ""

  log_level = "None"
  timestamps = "on"

  def do_quit(self, args):
    """Exit"""
    raise SystemExit

  def do_exit(self, args):
    self.do_quit(args)

  def do_q(self, args):
    self.do_quit(args)

  def log(self, message, level = None):
    log_line_prefix = ""
    if (level == "error"):
      log_line_prefix += "DEBUG:"
    elif (level == "debug") and (self.log_level == "debug"):
      log_line_prefix += "DEBUG:"
    if self.timestamps == "on":
      log_line_prefix += datetime.datetime.now().strftime('%Y%m%d.%H:%M:%S') + ":"
    message_lines = message.split('\n')
    for message_line in message_lines:
      print log_line_prefix + " " + message_line

  def inspect_remote_node(self, args):
    # TO DO: Expect args to be an IP address or hostname
    print ""

  def do_devices(self, args):
    print "\nDevices:\n"
    if 'ROUTERPASS' in os.environ:
      router_admin_password = os.environ['ROUTERPASS']
    else:
      self.log('The router password is not set.  Try "set ROUTERPASS=<password>"')
      return
    router_device_list_html = self.http_get("http://www.routerlogin.net/setup.cgi?todo=nbtscan&next_file=DEV_devices.htm", auth_user = "admin", auth_password = router_admin_password).text.split(' ')
    for token in router_device_list_html:
      if '.' in token:
        address = self.filter_ip_address_from_string(token)
        if "." in address:
          description = "unknown"
          self.log(token + " " + address + " " + description)
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
    self.log("hostname: " + hostname)
    self.log("pwd     : " + pwd)
    self.log("command : " + str(args))
    self.log(self.run_shell_command(str(args)))

  def http_get(self, url, auth_user = None, auth_password = None):
    #os.environ['PYTHONWARNINGS'] = "ignore:Unverified HTTPS request"
    #urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    response = requests.get(url, auth = (auth_user, auth_password), verify = False)
    if response.status_code < 200 or response.status_code > 399:
      self.log("http_get(): FAILURE: Received HTTP code response.status_code retrieving content from " + url, level = "error")
      raise Exception(
        "Exception in Cli.http_get(): Request to " + request  + " failed (HTTP response code " + str(response.status_code) + ")"
      )
    return response

  def retrieve_network_image(self, url, path, auth_user = None, auth_password = None):
    #os.environ['PYTHONWARNINGS'] = "ignore:Unverified HTTPS request"
    #urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    response = requests.get(url, auth = (auth_user, auth_password), verify = False, stream = True)
    if response.status_code < 200 or response.status_code > 399:
      self.log("retrieve_network_image(): FAILURE: Received HTTP code response.status_code downloading image from " + url, level = "error")
      raise oxception(
          "Exception in Cli.retrieve_network_image(): Request to " + request  + " failed (HTTP response code " + str(response.status_code) + ")"
      )
    with open(path, 'wb') as imagefile:
      response.raw.decode_content = True
      shutil.copyfileobj(response.raw, imagefile)
      self.log("Image file saved to " + path)

  #def test_ra
  def do_test(self, args):
    self.do_show("devices")
    self.do_scan("local")
    self.do_debug(None)
    self.log("line1\nline2")
    self.do_timestamps("off")
    self.log("line1\nline2")
    self.do_timestamps("on")
    self.log("Debug message", level = "debug")
    self.log("Longer\ndebug\nmessage", level = "debug")
    try:
      print self.http_get("").text
      self.retrieve_network_image("", "")
    except Exception as exception:
      self.log(str(exception.args))
    self.do_sh("ls -l /")

  def do_scan(self, args):
    self.log("Scanning local subnet")
    self.log("192.168.1.1\n192.168.1.2")

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
        self.log("")
      self.log("Invalid syntax for the 'set' command.  Try: set <name> <value>")
    else:
      print str(os.environ)

  def ra_slave_mode(self, ra_service_url):
      """
      Tell the local node to go into remote access slave mode using the HTTP host at ra_service_url to serve commands

      In slave mode, the program will poll ra_service_url/command looking for a command.  When a command is found (response != 404), run
      the comand and POST command output to  ra_service_url/response
      """
      if ra_service_url == None or len(ra_service_url) < 5 or "http" not in ra_service_url:
        self.log("RA mode requires a service URL (usage: ra <service-url>)")
        return

      # Turn off untrusted cert warnings
      #os.environ['PYTHONWARNINGS'] = "ignore:Unverified HTTPS request"
      #urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

      # The interval through which we will poll the remote service, looking for a command
      command_polling_interval = 300

      # We wish to progressively wait longer than the polling interval, the longer we go without a command,
      #    so we'll keep track of failures, where "failure" means no one is trying to send us a command
      count_of_failed_command_access_attempts = 0

      # The polling loop
      #while True:
      if True:
        try:
          response = requests.get(ra_service_url, verify = False)
          if response.status_code == 404:
              # No command was found, but the server is active, so just loop normally
              self.log("ra_slave_mode(): Service url " + ra_service_url + " returned 404, polling_interval = " + command_polling_interval)
          elif response.status_code < 200 or response.status_code > 399:
              self.log("ra_slave_mode(): FAILURE: Received HTTP code " + str(response.status_code) + " retrieving a command from " + ra_service_url, level = "error")
          else:
              command = response.text
              self.log("Running command: <" + command + ">")
              std_out_err = self.run_shell_command(command)
              log("ra_slave_mode(): Command output: <" + std_out_err + ">")
              # We have a "session" now with the hub, so let's reduce our polling interval
              count_of_failed_command_access_attempts = 0
              command_polling_interval = 3
        except:
          self.log("ra_slave_mode(): Retrieving content from " + ra_service_url + " returned an invalid response " + str(sys.exc_info()[0]))
          # This most likely means that the command server is simply down, so we'll just wait progressively longer until we're waiting forever
          count_of_failed_command_access_attempts += 1
          # Increase the polling interval, so that we check progressively less often.
          if (count_of_failed_command_access_attempts > 5000):
            command_polling_interval = command_polling_interval + 100
            count_of_failed_command_access_attempts = 0
        #time.sleep(command_polling_interval)

  def do_ra(self, args):
    self.log("DEBUG: do_ra(): >", level = "DEBUG")
    try:
      if args is not None and len(args) > 3:
        mode = str(args.split(' ')[0])
        if "slave" in mode:
          ra_service_url = str(args.split(' ')[1])
          if args == None or len(args) < 5 or "http" not in args:
            self.log("RA mode requires a service URL (usage: ra <service-url>)")
          else:
            self.ra_slave_mode(ra_service_url)
            return
        elif "hub" in mode or "broker" in mode:
          hub = RemoteAccessBroker()
          hub.start(str(args.split(' ')[1]), str(args.split(' ')[2]) )
          return
        #elif "cmd" in mode:
        #  self.ra_remote_command(args)
    except:
      self.log("do_ra(): ERROR: " + str(sys.exc_info()[0]))
    self.log("Try: ra slave <service-url>")
    self.log(" or: ra hub <base-url> <port>")
    self.log("DEBUG: do_ra(): <", level = "DEBUG")

  def ra_remote_command(self, args):
    print ""
  
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
      self.timestamps = "on"
    elif "off" in args.split(' '):
      print "Timestamps off"
      self.timestamps = "off"
    elif "on" in args.split(' '):
      self.do_timestamps(None)

  def do_debug(self, args):
    if args == None or len(args) == 0:
      self.log("Debug mode on")
      log_level = "debug"
    elif "off" in args.split(' '):
      self.log("Debug mode off")
      log_level = "none"
    elif "on" in args.split(' '):
      self.do_debug(None)

if __name__ == '__main__':
  # Turn off untrusted cert warnings
  os.environ['PYTHONWARNINGS'] = "ignore:Unverified HTTPS request"
  urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

  prompt = Cli()
  prompt.prompt = '> '
  prompt.cmdloop('')
