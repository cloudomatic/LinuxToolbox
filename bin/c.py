#!/bin/python

import requests,datetime,os,urllib3,shutil,subprocess,time

from cmd import Cmd

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

  def do_devices(self, args):
    print "\nDevices:\n"

  def do_sh(self, args):
    if 'HOSTNAME' in os.environ:
      hostname = os.environ['HOSTNAME']
    else:
      hostname = "UNKNOWN_HOSTNAME"
    self.log("hostname: " + hostname)
    self.log("command: " + str(args))
    self.log(subprocess.Popen(args, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT).stdout.read())

  def http_get(self, url, auth_user = None, auth_password = None):
    os.environ['PYTHONWARNINGS'] = "ignore:Unverified HTTPS request"
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    response = requests.get(url, auth = (auth_user, auth_password), verify = False)
    if response.status_code < 200 or response.status_code > 399:
      self.log("http_get(): FAILURE: Received HTTP code response.status_code retrieving content from " + url, level = "error")
      raise Exception(
        "Exception in Cli.http_get(): Request to " + request  + " failed (HTTP response code " + str(response.status_code) + ")"
      )
    return response

  def retrieve_network_image(self, url, path, auth_user = None, auth_password = None):
    os.environ['PYTHONWARNINGS'] = "ignore:Unverified HTTPS request"
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    response = requests.get(url, auth = (auth_user, auth_password), verify = False, stream = True)
    if response.status_code < 200 or response.status_code > 399:
      self.log("retrieve_network_image(): FAILURE: Received HTTP code response.status_code downloading image from " + url, level = "error")
      raise Exception(
          "Exception in Cli.retrieve_network_image(): Request to " + request  + " failed (HTTP response code " + str(response.status_code) + ")"
      )
    with open(path, 'wb') as imagefile:
      response.raw.decode_content = True
      shutil.copyfileobj(response.raw, imagefile)
      self.log("Image file saved to " + path)

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

  def ra_slave_mode(self, ra_service_url):
      """
      Tell the local node to go into remote access slave mode using the HTTP host at ra_service_url to serve commands

      In slave mode, the program will receive commands from ra_service_url/command and POST command output to  ra_service_url/response
      """
      if ra_service_url == None or len(ra_service_url) < 5 or "http" not in ra_service_url:
        self.log("RA mode requires a service URL (usage: ra <service-url>)")
        return

      # Turn off untrusted cert warnings
      os.environ['PYTHONWARNINGS'] = "ignore:Unverified HTTPS request"
      urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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
              self.log("do_ra(): Service url " + ra_service_url + " returned 404, polling_interval = " + command_polling_interval)
          elif response.status_code < 200 or response.status_code > 399:
              self.log("do_ra(): FAILURE: Received HTTP code " + str(response.status_code) + " retrieving a command from " + ra_service_url, level = "error")
          else:
              command = response.text
              self.log("Running command: <" + command + ">")
              self.do_sh(command)
              #log("do_ra():
        except:
          self.log("do_ra(): Retrieving content from " + ra_service_url + " returned an invalid response " + str(sys.exc_info()[0]))
          # This most likely means that the command server is simply down, so we'll just wait progressively longer until we're waiting forever
          count_of_failed_command_access_attempts += 1
          # Increase the polling interval, so that we check progressively less often.
          if (count_of_failed_command_access_attempts > 5000):
            command_polling_interval = command_polling_interval + 100
            count_of_failed_command_access_attempts = 0
        #time.sleep(command_polling_interval)

  def do_ra(self, args):
    self.log("RA mode enabled")
    self.log(str(args))
    self.log(str(args.split(' ')[0]))
    ra_service_url = str(args.split(' ')[0])
    if args == None or len(args) < 5 or "http" not in args:
      self.log("RA mode requires a service URL (usage: ra <service-url>)")
    else:
      self.ra_slave_mode(ra_service_url)



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
      log("Debug mode off")
      log_level = "none"
    elif "on" in args.split(' '):
      self.do_debug(None)

if __name__ == '__main__':
  prompt = Cli()
  prompt.prompt = '> '
  prompt.cmdloop('')
