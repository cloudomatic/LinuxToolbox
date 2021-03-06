#!/bin/python

import sys,os

# TO DO: 
#     File pull from remote
#     Device list hash map
#     Command hash map
#     Shell commands containing sudo with a password will hang
#     Enable broker to listen on custom IP
#     Remote slave log retrieval

if "MacBook" in str(os.environ):
  sys.path.append("./lib/requests-2.5.2")
  sys.path.append("./lib/urllib3-1.22")
  sys.path.append("./lib/chardet-3.0.4/")
  sys.path.append("./lib/certifi-2019.6.16/")
  sys.path.append("./lib/idna-2.8/")
  sys.path.append("./lib/Flask-0.7/")
  sys.path.append("./lib/Jinja2-2.10.1")
  sys.path.append("./lib/MarkupSafe-1.1.1/src")
  sys.path.append("./lib/Werkzeug-0.10.2")
  sys.path.append("./lib/itsdangerous-1.1.0/src")
  sys.path.append("./lib/Click-7.0/")

import requests,datetime,os,urllib3,shutil,subprocess,time,traceback
from cmd import Cmd
from flask import Flask,request,abort,send_from_directory
from threading import Lock
import threading

#
# Global utility functions
#


def get_local_node_name():
    """ Get the local host name, noting that ${HOSTNAME} or `hostname` may be unreliable """
    if os.environ.get("HOSTNAME") is not None:
      return os.environ.get("HOSTNAME")
    else:
      hostname=run_shell_command("hostname")
      if hostname is not None and len(str(hostname)) > 0:
        return hostname.strip()
      else:
        return "UNKNOWN_NODE"


def run_shell_command(command):
    #TO DO: Check for sudo in the command, find a way to validate sudo won't prompt for a password
    if command is not None and len(command) > 0:
      return str(subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT).stdout.read())
    else:
      raise Exception("ERROR: run_shell_command(): Empty command: <" + command + "> passed as argument")



#
# A simple logger
#
class Logger(object):

  timestamps = "on"

  log_level = "error"

  _logger = None
  
  log_lock = Lock()


  @staticmethod
  def get_instance():
    if Logger._logger == None:
      Logger._logger = Logger()
    return Logger._logger

  def log(self, message, level = None):
    self.log_lock.acquire()
    try:
      log_line_prefix = ""
      if level is not None and level.lower() in self.log_level.lower():
        log_line_prefix += level.upper() + ": "
      elif level is not None and level.lower() not in self.log_level.lower(): 
        return
      if self.timestamps == "on":
        log_line_prefix = datetime.datetime.now().strftime('%Y%m%d.%H:%M:%S') + ": " + log_line_prefix
      message_lines = message.split('\n')
      for message_line in message_lines:
        print(log_line_prefix + message_line)
    finally:
      self.log_lock.release()

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
 
  # The shared secret between broker and slave node 
  secret = "QtKqmvoNw7zolf2VPH43eSq3qFxnL4xA31wPoBiwIDAQABAoIBA1QD2E3ApQQh7P9YHY"

  def test(self):
    #self.start_slave("http://localhost:8000")

    self.logger.log("Testing sendfile() (expecting OK): " + self.sendfile("/tmp/test.png") + "")
    
    #self.logger.log(str("Testing PUT /command/" + self.get_local_node_name() + " (expecting 404): \n\n         " +
    #  requests.put(broker_service_url + "/command/" + self.get_local_node_name(), data = "ls -l /", headers = { "secret" :  self.secret }).text.replace("\n", "\n         ")
    #))

    #self.logger.log(str("Testing GET /file/somefile.txt (expecting 404): \n\n         " +
    #          requests.get(broker_service_url + "/file/somefile.txt", headers = { "secret" :  self.secret }).text.replace("\n", "\n         ")
    #))

  def handle_shell_command(self, command):
    """
    Execute a simple shell command on the local slave node, and submit the response text from the command to the broker
      TO DOS:
        Have a timeout function that will abort a command (such as a sudo prompt for a password) that hangs
    """
    self.logger.log("RemoteAccessSlave.handle_shell_command(): >: Running command: <" + command + ">", level = "DEBUG")

    command_output = ""
    if command is not None and len(command) > 0:
      command_output = str(subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT).stdout.read())
    else:
      self.logger.log("RemoteAccessSlave.handle_shell_command(): Empty command: <" + command + "> passed as argument", level = "Error")

    self.logger.log("RemoteAccessSlave.handle_shell_command(): Command output: <" + command_output + ">", level = "DEBUG")
    broker_response_url = self.broker_service_url + "/response/" + self.get_local_node_name()
    response_to_broker_http_request_object = None
    self.logger.log("RemoteAccessSlave.handle_shell_command(): Sending command output to the broker at: " + broker_response_url + " (content: <" + command_output + ">)", level = "DEBUG")
    try:
      response_to_broker_http_request_object = requests.put(broker_response_url, data = command_output, headers = { "secret" :  self.secret })
    except:
      self.logger.log("RemoteAccessSlave.handle_shell_command(): Sending the response to the broker at:" + broker_response_url + " returned an exception " + str(sys.exc_info()[0]), level = "error")
    if response_to_broker_http_request_object.text is not None and response_to_broker_http_request_object.text != "OK":
      # Something went wrong
      self.logger.log("RemoteAccessSlave.handle_shell_command(): Received " + response_to_broker_http_request_object.text +  " from the broker when sending the command output (expected 'OK')" "ERROR")

  def sendfile(self, filename):
    """
    If a command of type "_sendfile <filename>" is received, we PUT the specified file to the broker at <broker_service_url/file/<filename>
    """
    self.logger.log("RemoteAccessSlave.sendfile(): >: filename: <" + filename + ">")
    file_put_url = self.broker_service_url + "/file/" + str(os.path.basename(os.path.normpath(filename)))
    self.logger.log("RemoteAccessSlave.sendfile(): url: file_put_url", level = "DEBUG")
    self.logger.log("RemoteAccessSlave.sendfile(): filename: " + os.path.normpath(filename))
    # TO DO: MAke sure it's a normal file
    if not os.path.isfile(os.path.normpath(filename):
      self.logger.log("RemoteAccessSlave.sendfile(): WARNING: Not a normal file (" + os.path.normpath(filename) + ")")
    else:
      put_request_response = requests.put(file_put_url, headers = { "secret" :  self.secret }, files = { "file" : open(os.path.normpath(filename), "rb") })
      self.logger.log("RemoteAccessSlave.sendfile(): <: " + put_request_response.text, level = "DEBUG")
      requests.put(self.broker_service_url + "/response/" + self.get_local_node_name(), headers = { "secret" :  self.secret }, data="sendfile() completed")
      return put_request_response.text

  def pullfile(self, broker_filename, local_filename, permissions):
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
    Process a command sent by a remote client to the hub.  If we don't have a custom function (like _sendfile), we treat
    the command as a normal shell command
    """
    if command.startswith("_sendfile "):
      self.sendfile(command.split("sendfile ",1)[1].strip())
    elif command.startswith("_runfile "):
      self.pullfile(command.split("pullfile ",1)[1].strip(), "/var/tmp/runme")
      self.handle_shell_command("chmod u+rx /var/tmp/runme")
      self.handle_shell_command("/var/tmp/runme")
      self.handle_shell_command("rm /var/tmp/runme")
    elif command.startswith("_pullfile "):
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
        raise Exception("RemoteAccessSlave.start_slave(): broker_service_url is not set")
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
          response_to_request_for_a_command = requests.get(command_url, verify = False, headers = { "secret" :  self.secret })
        except:
          self.logger.log("RemoteAccessSlave.start_slave(): A GET on " + command_url + " returned an exception " + str(sys.exc_info()[0]), level = "error")
        if response_to_request_for_a_command is not None and response_to_request_for_a_command.status_code > 199 and response_to_request_for_a_command.status_code < 400 :
          self.logger.log("ra_slave_mode(): Received response_to_request_for_a_command: (" + str(response_to_request_for_a_command.status_code) + ") <" + response_to_request_for_a_command.text + ">", level = "debug")
          self.process_command(response_to_request_for_a_command.text)

          # We have a "session" now with the broker, so let's reduce our polling interval to a more normal terminal-session-like pace
          count_of_failed_command_access_attempts = 0
          command_polling_interval = 2
        else:
          if response_to_request_for_a_command is not None:
            if response_to_request_for_a_command.status_code == 404:
              # No command was found, but the broker is active, so just loop normally
              self.logger.log("ra_slave_mode(): " + self.get_local_node_name() + ": Broker url " + command_url + " returned 404, polling_interval = " + str(command_polling_interval), level = "DEBUG")
            elif response_to_request_for_a_command.status_code < 200 or response_to_request_for_a_command.status_code > 399:
              self.logger.log("ra_slave_mode(): FAILURE: Received HTTP code " + str(response_to_request_for_a_command.status_code) + " retrieving  " + command_url, level = "error")
          # An exception (response_to_request_for_a_command == None) likely means the broker (command server) is simply down, or the network is not available
          # Whatever the reasons for the failure to get a command, we want to wait progressively longer until we're just checking daily
          count_of_failed_command_access_attempts += 1
          if (count_of_failed_command_access_attempts > 120):
            # TO DO: Production setting
            #command_polling_interval = min(command_polling_interval + 10, 43200)
            command_polling_interval = min(command_polling_interval + 10, 20)
            count_of_failed_command_access_attempts = 0
          #command_polling_interval+= 1
        self.logger.log("ra_slave_mode(): zzz (" + str(command_polling_interval) + " seconds)", level = "DEBUG")
        time.sleep(command_polling_interval)

#
# A remote access broker.  The broker runs as a process to suppport transactions between 
# slaves and remote access clients.
# The basic broker function is to accept invocations via GET /node/command where "command" is a Linux command 
# that is to be run on "node" (where node is a particular command slave node's hostname).  The 
# slave node runs the command and PUTs the command output to /node/response, where it 
# may be retrieved via GET /node/response by the remote access client that sent the command.
#
class RemoteAccessBroker(object):

  _instance = None

  logger = Logger.get_instance()

  node_data = {}

  node_data_lock = Lock()

  generic_cache = {}
  
  generic_cache_lock = Lock()

  secret = "QtKqmvoNw7zolf2VPH43eSq3qFxnL4xA31wPoBiwIDAQABAoIBA1QD2E3ApQQh7P9YHY"

  # A place to store files being sent between remote access clients and slave nodes
  file_store = "/var/tmp"

  @staticmethod
  def get_instance():
    if RemoteAccessBroker._instance == None:
      RemoteAccessBroker._instance = RemoteAccessBroker()
    return RemoteAccessBroker._instance

  def upload_form(self):
    # TO DO: Remove the secret from this field
    return 200, '\
           <html> \
              <form method="POST" action="/upload" enctype="multipart/form-data"> \
                <input type="text" name="secret" value="' + RemoteAccessBroker.get_instance().secret + '"><br><br>' + '\
                <input type="file" name="file"><br><br> \
                <input type="submit" name="upload" value="Send File"> \
              </form> \
           </html> \
           '


  def put_response(self, node_name, response):
    self.node_data_lock.acquire()
    try:
      if node_name not in self.node_data:
        self.node_data[node_name] = {}
      self.node_data[node_name]['response'] = response 
      return 200, "OK"
    finally:
      self.node_data_lock.release()

  def put_command(self, node_name, command):
    self.node_data_lock.acquire()
    try:
      if node_name not in self.node_data:
        self.node_data[node_name] = {}
      self.node_data[node_name]['command'] = command
      return 200, "OK"
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
      if 'command' in self.node_data[node_name] and self.node_data[node_name]['command'] is not None:
        command = self.node_data[node_name]['command']
        del self.node_data[node_name]['command']
        return 200, command
      else:
        return 404, "No command ready"
    finally:
      self.node_data_lock.release()

  def get_response(self, node_name):
    self.node_data_lock.acquire()
    try:
      if node_name in self.node_data:
        if 'response' in self.node_data[node_name] and self.node_data[node_name]['response'] is not None:
          response = self.node_data[node_name]['response']
          del self.node_data[node_name]['response']
          return 200, response
        else:
          return 404, "No response"
      else:
        return 404, "Unknown node"
    finally:
      self.node_data_lock.release()

  def broker_client_request(self, broker_service_url, request, request_method = "GET", headers = None, data = None):
    if not request.startswith("/"):
      error_message = "Invalid call to RemoteAccessBroker.broker_client_request(): Request <" + request + "> does not have a preceding forward slash"
      self.logger.log(error_message, "ERROR")
      raise Exception("ERROR: " + error_message)
    if headers is None:
      headers = {}
    headers['secret'] = self.secret 
    if request_method == "GET":
      response = requests.get(broker_service_url + request, headers = headers)
      return response
    elif request_method == "DELETE":
      response = requests.delete(broker_service_url + request, headers = headers)
      return response
    elif request_method == "PUT" or request_method == "POST":
      if data == None:
        error_message = "RemoteAccessBroker.broker_client_request(): " + request_method + " <" + request + "> requires a data argument"
        self.logger.log(error_message, "ERROR")
        raise Exception("ERROR: " + error_message)
      if request_method == "PUT":
        response = requests.put(broker_service_url + request, headers = headers, data = data)
      elif request_method == "POST":
        response = requests.post(broker_service_url + request, headers = headers, data = data)
      else:
        error_message = "RemoteAccessBroker.broker_client_request(): Invalid request_method argument <" + request_method + "> (GET, PUT, POST, DELETE implmented)"
        self.logger.log(error_message, "ERROR")
        raise Exception("ERROR: " + error_message)
      return response

  def test(self, broker_service_url = None):
    """
    Run a test of a RemoteAccessBroker currently running at <broker_service_url>, or only class unit tests if no broker URL is provided.
    """
    self.logger.log("RemoteAccessBroker.test(): Running unit tests")
    code, message = self.get_command("node01")
    if code != 404:
      raise Exception("ERROR: RemoteAccessBroker.test(): self.get_command() on non-existent command returned " + str(code) + " (expected 404)")
    code, message = self.put_command("node01", "c1")
    if code != 200:
      raise Exception("ERROR: RemoteAccessBroker.test(): self.put_command() on valid command returned " + str(code) + " (expected 200)")
    code, message = self.get_command("node01")
    if code != 200:
      raise Exception("ERROR: RemoteAccessBroker.test(): self.get_command() on valid command returned " + str(code) + " (expected 200)")
    if message != "c1":
      raise Exception("ERROR: RemoteAccessBroker.test(): self.get_command() on valid command returned invalid command: " + str(message) + " (expected c1)")
    code, message = self.get_command("node01")
    if code != 404:
      raise Exception("ERROR: RemoteAccessBroker.test(): self.get_command() on already consumed command returned " + str(code) + " (expected 404)")
    code, message = self.get_response("node01")
    if code != 404:
      raise Exception("ERROR: RemoteAccessBroker.test(): self.get_response() on non-existent response returned " + str(code) + " (expected 404)")
    code, message = self.put_response("node01", "r1")
    if code != 200:
      raise Exception("ERROR: RemoteAccessBroker.test(): self.put_response() on valid response returned " + str(code) + " (expected 200)")
    code, message = self.get_response("node01")
    if code != 200:
      raise Exception("ERROR: RemoteAccessBroker.test(): self.get_response on valid response returned " + str(code) + " (expected 200)")
    if message != "r1":
      raise Exception("ERROR: RemoteAccessBroker.test(): self.get_response() invalid response returned: " + str(message)  + " (expected r1)")
    code, message = self.get_response("node01")
    if code != 404:
      raise Exception("ERROR: RemoteAccessBroker.test(): self.get_response() on already consumed response returned " + str(code) + " (expected 404)")
    code, message = self.get_response("node02")
    if code != 404:
      raise Exception("ERROR: RemoteAccessBroker.test(): self.get_response() on non-existed node name returned " + str(code) + " (expected 404)")
    self.logger.log("RemoteAccessBroker.test(): Completed broker unit tests")

    if broker_service_url is not None:
            self.logger.log("RemoteAccessBroker.test(): Running broker integration tests")

            # Run integration tests

            # Test for an invalid shared secret
            response_code = requests.get(broker_service_url + "/data", headers = { "secret" :  "foobar" }).status_code
            if response_code != 401:
              raise Exception("ERROR: RemoteAccessBroker.test(): GET /data (with invalid authentication) returned a status code of " + str(response_code) + " (Expecting 401)")

            # Test for the unimplemented log function
            response_code = self.broker_client_request(broker_service_url, "/log").status_code
            if response_code != 501:
              raise Exception("ERROR: RemoteAccessBroker.test(): GET /log returned an error code of " + str(response_code) + " (Expecting 501)")

            # Test for no command/response data
            # Test is invalid, as it is not idempotent
            #response = self.broker_client_request(broker_service_url, "/data")
            #if response.status_code != 200 or response.text != "{}":
            #  raise Exception("ERROR: RemoteAccessBroker.test(): GET /data (with an empty data cache) returned <" + response.text + "> with a status code of " + str(response.status_code) + " (expecting 200 {})")
          
            # Test for an invalid cache key
            response = self.broker_client_request(broker_service_url, "/cache/somekey")
            if response.status_code != 404:
              raise Exception("ERROR: RemoteAccessBroker.test(): GET /cache/somekey (with a non-existent key) returned <" + response.text + "> with a status code of " + str(response.status_code) + " (expecting 404)")

            # Put something in the cache
            response = self.broker_client_request(broker_service_url, "/cache/somekey", request_method = "PUT", data =  "100000000000000000001")
            if response.status_code != 200:
              raise Exception("ERROR: RemoteAccessBroker.test(): PUT  /cache/somekey (with a valid key) returned <" + response.text + "> with a status code of " + str(response.status_code) + " (expecting 200)")

            # Check it's value
            response = self.broker_client_request(broker_service_url, "/cache/somekey")
            if response.status_code != 200 or  response.text != "100000000000000000001":
              raise Exception("ERROR: RemoteAccessBroker.test(): GET /cache/somekey (with a valid key) returned <" + response.text + "> with a status code of " + str(response.status_code) + " (expecting 200)")

            # Delete it
            response = self.broker_client_request(broker_service_url, "/cache/somekey", request_method = "DELETE")
            if response.status_code != 200:
              raise Exception("ERROR: RemoteAccessBroker.test(): DELETE /cache/somekey (with a valid key) returned <" + response.text + "> with a status code of " + str(response.status_code) + " (expecting 200)")

            # Make sure it's gone
            response = self.broker_client_request(broker_service_url, "/cache/somekey")
            if response.status_code != 404:
              raise Exception("ERROR: RemoteAccessBroker.test(): GET /cache/somekey (with a previously deleted key) returned <" + response.text + "> with a status code of " + str(response.status_code) + " (expecting 404)")

            # Check for a non-existent file
            response = self.broker_client_request(broker_service_url, "/file/somefile.txt")
            if response.status_code != 404:
              raise Exception("ERROR: RemoteAccessBroker.test(): GET /file/somefile.txt (with a non-existent file) returned <" + response.text + "> with a status code of " + str(response.status_code) + " (expecting 404)")
 
            # Delete a non-existent file
            response = self.broker_client_request(broker_service_url, "/file/somefile.txt", request_method = "DELETE")
            if response.status_code != 404:
              raise Exception("ERROR: RemoteAccessBroker.test(): DELETE /file/somefile.txt (with a non-existent file) returned a status code of " + str(response.status_code) + " (expecting 404)")

            # Create a test file
            random_string_to_test = "xxxxxxxxxxxxxxxxx"
            run_shell_command("echo " + random_string_to_test + " > delete-this-test-file.out")
            
            # Upload it
            response = requests.put(broker_service_url + "/file/somefile.out", headers = { "secret" :  self.secret }, files = { "file" : open("delete-this-test-file.out","rb") })
            if response.status_code != 200:
              raise Exception("ERROR: RemoteAccessBroker.test(): PUT /file/somefile.out with a valid file returned <" + response.text + "> with a status code of " + str(response.status_code) + " (expecting 200)")

            # Download it
            response = requests.get(broker_service_url + "/file/somefile.out", headers = { "secret" :  self.secret })
            with open('delete-this-test-file.copy.out', "w+") as output_file:
              for block in response.iter_content(1024):
                output_file.write(block)

            # Compare to original
            retrieved_file_contents = run_shell_command("cat delete-this-test-file.copy.out")
            if str(retrieved_file_contents).strip() != random_string_to_test:
              raise Exception("ERROR: RemoteAccessBroker.test(): A test of file upload/download did not return the same file (" + str(retrieved_file_contents).strip() + " != " + random_string_to_test + ")")
            #self.logger.log(str(run_shell_command("cksum delete-this-test-file.out delete-this-test-file.copy.out")))

            # Delete the local files
            run_shell_command("rm delete-this-test-file.copy.out")
            run_shell_command("rm delete-this-test-file.out")
         
            # Delete the remote
            response = self.broker_client_request(broker_service_url, "/file/somefile.out", request_method = "DELETE")
            if response.status_code != 200:
              raise Exception("ERROR: RemoteAccessBroker.test(): DELETE /file/somefile.out (with a valid file) returned <" + response.text + "> with a status code of " + str(response.status_code) + " (expecting 200)")

            # Make sure it's gone
            response = self.broker_client_request(broker_service_url, "/file/somefile.out")
            if response.status_code != 404:
              raise Exception("ERROR: RemoteAccessBroker.test(): GET /file/somefile.out (on a previously deleted file) returned <" + response.text + "> with a status code of " + str(response.status_code) + " (expecting 404)")

            # Retrieve a command for a non-existent node
            response = self.broker_client_request(broker_service_url, "/command/testnode01")
            if response.status_code != 404:
              raise Exception("ERROR: RemoteAccessBroker.test(): GET /command/testnode01 (on a never-accessed-node) returned  <" + response.text + "> with a status code of " + str(response.status_code) + " (expecting 404)")

            # We expect a timestamp to exist for a node, even if it was accessed for the first time
            response = self.broker_client_request(broker_service_url, "/data")
            if response.status_code != 200:
              raise Exception("ERROR: RemoteAccessBroker.test(): GET /data returned  <" + response.text + "> with a status code of " + str(response.status_code) + " (expecting 200)")
            if "access_time" not in response.text:
              raise Exception("ERROR: RemoteAccessBroker.test(): GET /data returned  <" + response.text + "> (expecting an access_time entry) with a status code of " + str(response.status_code) + "")

            # Get a response for a non-existent node
            response  = self.broker_client_request(broker_service_url, "/response/testnode02")
            if response.status_code != 404:
              raise Exception("ERROR: RemoteAccessBroker.test(): GET /response/testnode02 for an non-existent node returned  " + str(response.status_code) + " (expecting 404)")

            # Put a command
            response = requests.put(broker_service_url + "/command/testnode03", headers = { "secret" :  self.secret }, data = "foo")
            if response.status_code != 200:
              raise Exception("ERROR: RemoteAccessBroker.test(): PUT /command/testnode03 with a valid command returned " +  str(response.status_code) + " (expecting 200)")

            response = self.broker_client_request(broker_service_url, "/command/testnode03")
            if response.status_code != 200:
              raise Exception("ERROR: RemoteAccessBroker.test(): GET /command/testnode03 on a valid command returned " +  str(response.status_code) + " (expecting 200)")

            response = self.broker_client_request(broker_service_url, "/response/testnode03")
            if response.status_code != 404:
              raise Exception("ERROR: RemoteAccessBroker.test(): GET /response/testnode03 on a non-existent response returned " +  str(response.status_code) + " (expecting 404)")

            response = requests.put(broker_service_url + "/response/testnode03", headers = { "secret" :  self.secret }, data = "bar")
            if response.status_code != 200:
              raise Exception("ERROR: RemoteAccessBroker.test(): PUT /response/testnode03 with a valid response returned " +  str(response.status_code) + " (expecting 200)")

            response = self.broker_client_request(broker_service_url, "/response/testnode03")
            if response.status_code != 200:
              raise Exception("ERROR: RemoteAccessBroker.test(): GET /response/testnode03 on a valid response returned " +  str(response.status_code) + " (expecting 200)")
            if response.text != "bar":
              raise Exception("ERROR: RemoteAccessBroker.test(): GET /response/testnode03 on a valid response returned <" + str(response.text) + "> expecting <bar>")

            response = self.broker_client_request(broker_service_url, "/response/testnode03")
            if response.status_code != 404:
              raise Exception("ERROR: RemoteAccessBroker.test(): GET /response/testnode03 on an already-consumed resposne returned " +  str(response.status_code) + " (expecting 404)")

            response = self.broker_client_request(broker_service_url, "/data")
            if response.status_code != 200:
              raise Exception("ERROR: RemoteAccessBroker.test(): GET /data returned " +  str(response.status_code) + " (expecting 200)")
            if "testnode03" not in response.text and "testnode01" not in response.text and "access_time" not in response.text:
              raise Exception("ERROR: RemoteAccessBroker.test(): GET /data " +  str(response.text) + " (expecting two nodes with access times")

            self.logger.log("RemoteAccessBroker.test(): Completed broker integration tests")

  
  def get_node_data(self):
    self.node_data_lock.acquire()
    try:
      return 200, str(self.node_data)
    finally:
      self.node_data_lock.release()

  def get_log(self, node_name):
    self.logger.log("RemoteAccessBroker.get_log(): Not implemented")

  def file_put(self, filename, data):
    self.logger.log("RemoteAccessBroker.file_put(): >", "DEBUG")
    try:
      self.logger.log("RemoteAccessBroker.file_put(): Writing to " + self.file_store + "/" + filename)
      with open(self.file_store + "/" + filename, 'w+') as output_file:
        output_file.write(data)
    except:
      self.logger.log("RemoteAccessBroker.file_put(): " + str(sys.exc_info()), "ERROR")
      return 500, str(sys.exc_info()[0])
    
  def file_delete(self, filename):
    self.logger.log("RemoteAccessBroker.file_delete(): >", "DEBUG")
    self.logger.log("RemoteAccessBroker.file_delete():", "DEBUG")
    if filename is not None:
      delete_command_output = run_shell_command("rm " + self.file_store + "/" + filename)
      self.logger.log("RemoteAccessBroker.file_delete():", "DEBUG")
      self.logger.log("RemoteAccessBroker.file_delete(): output returned from the delete command: " + str(delete_command_output), "DEBUG" )
      self.logger.log("RemoteAccessBroker.file_delete():", "DEBUG")
      if delete_command_output is None or len(delete_command_output) == 0:
        self.logger.log("RemoteAccessBroker.file_delete(): Returning 200", "DEBUG")
        return 200, "OK"
      elif delete_command_output is not None and "No such file or directory" in delete_command_output:
        return 404, str("File " + filename + " not found")
      else:
        self.logger.log("RemoteAccessBroker.file_delete(): Returning 500", "DEBUG")
        return 500, str(delete_command_output)
    else:
      return 500, "Invalid filename <" + str(filename) + ">"

  def cache_get(self, key):
    if key in self.generic_cache:
      return 200, self.generic_cache[key]
    else:
      return 404, key + " not found"

  def put_cache(self, key):
    self.generic_cache[key] = request.get_data()
    return 200, "OK"

  def delete_cache(self, key):
    if key in self.generic_cache:
      del self.generic_cache[key]
      return 200, "OK"
    else:
      return 404, key + "not found"

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
        """
        Show the contents of the current command cache: node, command, response
        """
        if (request.headers.get('secret') != RemoteAccessBroker.get_instance().secret):
          abort(401)
        status_code, response = RemoteAccessBroker.get_instance().get_node_data()
        if status_code != 200:
          abort(status_code, response)
        else:
          return response

      @broker_web_service.route('/log', methods = ['GET'])
      def show_log():
        if (request.headers.get('secret') != RemoteAccessBroker.get_instance().secret):
          abort(401)
        abort(501)

      @broker_web_service.route('/cache/<key>', methods = ['PUT', 'GET', 'DELETE'])
      def handle_cache_request(key):
        """
        The "cache" refers to a generic cache of name/value pairs, suitable for storing data objects such
        as temp files or images.  Accepts GET, PUT, DELETE on any data type
        """
        if (request.headers.get('secret') != RemoteAccessBroker.get_instance().secret):
          abort(401)
        if request.method == "GET":
          status_code, response = RemoteAccessBroker.get_instance().cache_get(key)
        elif request.method == "DELETE":
          status_code, response = RemoteAccessBroker.get_instance().delete_cache(key)
        elif request.method == "PUT":
          status_code, response = RemoteAccessBroker.get_instance().put_cache(key)
        if status_code != 200:
          abort(status_code, response)
        else:
          return response

      @broker_web_service.route('/file/<filename>',  methods = ['PUT', 'GET', 'DELETE'])
      def handle_file_request(filename):
        """
        We can store/serve files too.  To send a file to the broker:
        curl -vks -XPOST -H secret:<secret> 'http://localhost:8000/file/somefile.txt' -F file=@./somefile.txt
        """
        # Comment out these two lines to turn file security off, such as when 
        # we want to use the program for simple browser-based file transfer
        if (request.headers.get('secret') != RemoteAccessBroker.get_instance().secret):
          abort(401)
        if request.method == "GET":
          if filename == "list":
            return run_shell_command("ls -l " + RemoteAccessBroker.get_instance().file_store)
          else:
            return send_from_directory(RemoteAccessBroker.get_instance().file_store, filename, as_attachment = True)
        elif request.method == "DELETE":
          status_code, response = RemoteAccessBroker.get_instance().file_delete(filename)
        elif request.method == "PUT":
          file = request.files['file']
          file.save(self.file_store + "/" + filename)
          status_code = 200
          response = "OK"
        if status_code != 200:
          abort(status_code, response)
        else:
          return response

      @broker_web_service.route('/upload', methods = ['GET', 'POST'])
      def upload_form():
        """ 
        A convenience form for uploading files
        """
        self.logger.log("RemoteAccessBroker.upload_form(): >", "DEBUG")
        if request.method == "GET":
          status_code, response = RemoteAccessBroker.get_instance().upload_form()
          if status_code is 200:
            return response
          else:
            abort(status_code)
        elif request.method == "POST":
          if str(request.form.get('secret')) != RemoteAccessBroker.get_instance().secret:
            abort(401)
          else:
            file = request.files['file']
            file.save(self.file_store + "/" + file.filename)
            return "OK"

      @broker_web_service.route('/command/<node>', methods = ['PUT', 'GET'])
      def handle_command(node):
        """
        A command execution request to/from a node.  We accept commands from anyone, 
        and serve those commands to any node which requests its command, deleting the command
        once "issued"
        """
        self.logger.log("RemoteAccessBroker.handle_command(): >: node = " + str(node), level = "DEBUG")
        if (request.headers.get('secret') != RemoteAccessBroker.get_instance().secret):
          abort(401)
        if request.method == 'GET':
          status_code, response = RemoteAccessBroker.get_instance().get_command(node)
        elif request.method == 'PUT':
          status_code, response = RemoteAccessBroker.get_instance().put_command(node, request.get_data())
        if status_code is 200:
          return response
        else:
          abort(status_code)

      @broker_web_service.route('/response/<node>', methods=['PUT', 'GET'])
      def handle_response(node):
        """
        A command execution response from a node, to be retrieved by the remote access client which submitted the last command to said node.
        We delete the response once it's retrieved
        """
        if (request.headers.get('secret') != RemoteAccessBroker.get_instance().secret):
          abort(401)
        if request.method == 'GET':
          status_code, response = RemoteAccessBroker.get_instance().get_response(node)
        elif request.method == 'PUT':
          status_code, response = RemoteAccessBroker.get_instance().put_response(node, request.get_data())
        if status_code is 200:
          return response
        else:
          abort(status_code)

      broker_web_service.run(host = listener_address, port = int(port))
    except:
      print("RemoteAccessBroker.start_broker(): ERROR " + str(sys.exc_info()[0]))
    self.logger.log("DEBUG: start(): <")

class Cli(Cmd):

  doc_header = ""
  undoc_header = ""

  logger = Logger.get_instance()


  broker_service_url = None
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
    print("")

  def do_devices(self, args):
    print("\nDevices:\n")
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
    response = requests.get(url, auth = (auth_user, auth_password), verify = False, stream = True)
    if response.status_code < 200 or response.status_code > 399:
      self.logger.log("retrieve_network_image(): FAILURE: Received HTTP code response.status_code downloading image from " + url, level = "error")
      raise oxception(
          "Exception in Cli.retrieve_network_image(): Request to " + request  + " failed (HTTP response code " + str(response.status_code) + ")"
      )
    with open(path, 'wb') as imagefile:
      response.raw.decode_content = True
      hutil.copyfileobj(response.raw, imagefile)
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
    RemoteAccessBroker.get_instance().test()

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
      print(str(os.environ))


  def do_ra(self, args):
    '\n Remote access mode. \n'
    self.logger.log("do_ra(): >: args: <" + str(args) + ">", level = "DEBUG")
    try:
      if args is not None and len(args) > 3:
        if "--debug" in args or "-d" in args:
          self.do_debug("on")
        if "--broker" in args:
          self.broker_service_url = args.split("--broker",1)[1].strip().split(' ')[0]
          self.logger.log("do_ra(): Setting broker service url to: " + self.broker_service_url)
          args = " ".join(args.split("--broker",1)[1].strip().split(' ')[1:])
          self.logger.log("do_ra(): args=" + args)
        if args.startswith("start slave"):
          ra_service_url = str(args.split(' ')[2])
          if ra_service_url == None or len(ra_service_url) < 5 or "http" not in ra_service_url:
            self.logger.log("RA slave mode requires a broker service URL (usage: ra start slave <service-url>)", "ERROR")
            return
          else:
            slave = RemoteAccessSlave()
            slave.logger = self.logger
            slave.start_slave(ra_service_url)
            self.logger.log("do_ra(): <", level = "DEBUG")
            return
        elif args.startswith("start hub") or args.startswith("start broker"):
          argument_list = args.split(' ')
          self.logger.log("do_ra(): args: " +  str(argument_list))
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
          self.broker_service_url = str(args.split(' ')[2])
          self.logger.log("Setting broker service URL to: " + self.broker_service_url)
          return
        elif args.startswith("test slave"):
          slave = RemoteAccessSlave()
          slave.broker_service_url = "http://127.0.0.1:8000"
          slave.logger = self.logger
          slave.test()
          return
        elif args.startswith("test broker"):
          arg_list = args.split(' ')
          if len(arg_list) < 3:
            self.logger.log("Try: ra test broker <broker-url>")
          else:
            self.do_set("no_proxy=*")
            RemoteAccessBroker.get_instance().test( str(args.split(' ')[2]).strip("/") )
          return
        elif args.startswith("list files"):
          if self.broker_service_url is None:
            self.broker_service_url = "http://localhost:8000"
            # TO DO: Prod setting
            #self.logger.log("Remote access broker not set.  Try: set broker <broker-service-url>")
          print( str(requests.get(self.broker_service_url + "/file/list", headers = { "secret" :  RemoteAccessBroker.get_instance().secret }).text) + "\n")
          return
        elif args.startswith("list nodes"):
          if self.broker_service_url is None:
            self.broker_service_url = "http://localhost:8000"
            #self.logger.log("Remote access broker not set.  Try: set broker <broker-service-url>")
          print("\nNodes active on broker: " + self.broker_service_url + "\n")
          print( requests.get(self.broker_service_url + "/data", headers = { "secret" :  RemoteAccessBroker.get_instance().secret }).text + "\n")
          return
        elif args.startswith("getfile "):
          # Instruct the node to send the file
          node_name = args.split(' ')[1]
          filename = args.split(' ')[2]
          self.logger.log("do_ra(): getfile command: Requesting " + filename + " from node " + node_name, "DEBUG")
          self.ra_remote_command(node_name, "_sendfile " + filename)
          time.sleep(3)
          # Now retrieve the file
          self.logger.log("do_ra(): getfile command: Retrieving " + self.broker_service_url + "/file/" + filename, "DEBUG")
          response = requests.get(self.broker_service_url + "/file/" + filename, stream = True)
          self.logger.log("do_ra(): getfile command: Retrieving " + self.broker_service_url + "/file/" + filename + "(" + str(response.status_code) + ")", "DEBUG")
          if response.status_code == 200:
            with open(filename, 'wb') as output_file:
              for block in response.iter_content(1024):
                output_file.write(block)
            self.logger.log("Download complete \n" )
            run_shell_command("ls -l " + filename) 
            self.logger.log("")
          else:
            self.logger.log("File missing from broker after command <_sendfile> sent")
          return
        elif args.startswith("sh"):
          if self.broker_service_url is None:
            self.logger.log("Remote access broker not set.  Try: set broker <broker-service-url>")
            return
          else:
            try:
              node_name = str(args.split(' ')[1])
              remote_command = args.split(node_name,1)[1].strip()
              if len(remote_command) == 0:
                raise Exception("Command required")
              else:
                self.ra_remote_command(node_name, remote_command)
            except:
              self.logger.log("do_ra(): ERROR: " + str(sys.exc_info()[0]), level = "ERROR")
              self.logger.log("Try: ra sh <node-name> <Linux shell command>")
              self.logger.log("     ra sh <node-name> _sendfile <filename>")
              self.logger.log("     ra sh <node-name> _pullfile <filename> <node-local filename> [chmod permissions]")
            return
    except:
      self.logger.log("do_ra(): ERROR: " + str(sys.exc_info()[0]), level = "ERROR")
      traceback.print_exc()
    self.logger.log("Try: ra list nodes")
    self.logger.log("     ra start slave <broker-url>")
    self.logger.log("     ra start broker <port>")
    self.logger.log("     ra set broker <broker-url>")
    self.logger.log("     ra list nodes")
    self.logger.log("     ra sh <node> <command>")
    self.logger.log("     ra getfile <node> <filename-on-node>")
    self.logger.log("     ra list files")
    self.logger.log("     ra help")
    self.logger.log("do_ra(): <", level = "DEBUG")

  def ra_remote_command(self, node_name, command):
    self.logger.log("Cli.ra_remote_command(): >", level = "DEBUG")
    broker_request_url = self.broker_service_url + "/command/" + node_name
    self.logger.log("Cli.ra_remote_command(): Attempting remote command request: " + broker_request_url, level = "DEBUG")
    command_http_response = requests.put(broker_request_url, data = command, headers = { "secret" :  RemoteAccessBroker.get_instance().secret } )
    self.logger.log(command_http_response.text)
    # Now go into a polling loop waiting for a response
    response_received = False
    while response_received is False:
      broker_response_url = self.broker_service_url + "/response/" + node_name
      self.logger.log("Cli.ra_remote_command(): Waiting for a response from: " + broker_response_url, level = "DEBUG")
      command_output_http_response = requests.get(broker_response_url,  headers = { "secret" :  RemoteAccessBroker.get_instance().secret })
      if command_output_http_response.status_code != 404:
        response_received = True
        self.logger.log(command_output_http_response.text)
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
      print("show what?")

  def do_timestamps(self, args):
    if args == None or len(args) == 0:
      self.logger.timestamps = "on"
      self.logger.log("Timestamps on")
    elif "off" in args.split(' '):
      self.logger.timestamps = "off"
      self.logger.log("Timestamps off")
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
    if command_name.startswith("-help") or command_name.startswith("--help"):
      command_name = "help"
    command = getattr(self, "do_" + command_name, None)
    if callable(command):
      if len(args) > 0:
        command(str(args))
      else:
        command(None)
      return
    print("\n   Invalid arguments: " + command_name +  "\n")


if __name__ == '__main__':
  
  # https://docs.python.org/3/library/cmd.html

  # Turn off untrusted cert warnings
  os.environ['PYTHONWARNINGS'] = "ignore:Unverified HTTPS request"
  #urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

  prompt = Cli()
  prompt.prompt = '> '

  if len(sys.argv) > 1:
    prompt.run_command(sys.argv[1], " ".join(sys.argv[2:]))
  else:
    prompt.cmdloop('')
