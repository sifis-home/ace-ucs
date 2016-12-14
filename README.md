# README #

This is a mavenized Java project. You should be able to compile and run these
classes if you manage to figure out how Maven works (and boy do the Maven
fanboys make that hard with their crappy manuals).

### What is this repository for? ###

* This is a Java library for the functions necessary to run a client, resource
  server, and authorization server as specified in [draft-ietf-ace-oauth-authz](https://tools.ietf.org/html/draft-ietf-ace-oauth-authz). 
  The base libraries do not include network functionality, since it tries to be
  protocol agnostic. However we provide [CoAP](https://tools.ietf.org/html/rfc7252) client and server support as an example of a protocol specific adaptation based on [Californium|https://www.eclipse.org/californium/]
* Version: early_alpha


### How do I get set up? ###

* Just clone the repo, do the Maven fu and you are good to go
* Configuration: You need to set up a MySQL database to run the Junit tests. 
  To run in production you need to configure like everything, starting with
  your resource servers (out of scope here), the access control policies for
  the authorization server (KissPDP has a demo format in JSON, check the
  test resources), the discovery of AS (out of scope again). If you don't
  know where to start you probably shouldn't use this in production settings.
* Dependencies: Lots, check the .pom file
* Database configuration:  Set up an MySQL database, for running 
  the Junit tests create a file 'db.pwd' with the root password of your test 
  database at the root directory of this library. If you want an alternative 
  database you have to change the dependencies to include another JDBC and
  double check if SQLConnector uses a compatible syntax.
* How to run tests: Run the class files in the src/test folders
* Deployment instructions: Depends ... TBD

### Contribution guidelines ###

* Writing tests: Yes please!
* Code review: Yes please!
* Other guidelines: Follow the java coding style guidelines, don't add new depenencies.

### Who do I talk to? ###

* This code is owned by SICS Swedish ICT AB and released as Open Source under the [BSD 3 license](https://opensource.org/licenses/BSD-3-Clause).
* Please contact ludwig at sics dot se if you have questions or suggestions.