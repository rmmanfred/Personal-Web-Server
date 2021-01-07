# Personal Web Server
Ross Manfred

## Premise
- Facilitate a web server that allows multiple connections and the ability to authenticate a user with access to a "private" folder
- Support the HTTP 1.1 standard as well as html5 fallback and ipv6 as well as ipv4 clients
- More details on the requirements of this project can be found [here](pserver-handout.pdf)

## Execution
- Note that the totality of this project was a team effort with my partner in the class
- Made modifications to provided [socket.c](src/socket.c) to allow for ipv6 and ipv4 under dual binding
  - Future implementation may attempt to support the same without dual binding
- Added the ability to authenticate using JSON Web Tokens when the proper username and password are provided
  - Future implementation may attempt to allow for storage of multiple valid recorded logins stored
- Addressed requests for "private" information as well as attempts to access files outside of the root folder
- Added multi-client support in the form of multi-threaded execution
  - Future implementation may support a different thread based approach to improve efficiency
- Allowed for a persistent connection between a client and the server until the client is found to have closed the connection
implemented
- Added implementation for html5 fallback -  allowing requests for non-existent files to return index.html rather than fail outright

## Usage and Testing
- Demo to come
- Personal server should be run as server -p "desired port number" -r "path to root folder"; additional flags can be used in the following ways:
  - -e "seconds": Sets the expiration time of authentication tokens to the provided parameter
  - -a: Implements html5 fallback funtionality, requests to non-existent files returns index.html
  - -s: Implements silent mode; extraneous output is suppressed
  - -h: get help on how to properly structure the command
- Makefile can be used to compile program files
- Testing used by this class (provided by instructors) are contained in the [tests folder](tests)
  - server_unit_test_pserv.py can be used to properly verify basic funtionality
  - server_bench.py tests the ability to handle traffic to the server
- According to the initial contents of the provided code this command should be run to ensure any user executing this code has the proper dependencies:
To get started, run the script:

. install-dependencies.sh

Then cd into src and type make.

