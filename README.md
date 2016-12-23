# README #

This is a mavenized Java project. You should be able to compile and run these
classes if you manage to figure out how Maven works (which is non-trivial due 
to the lack of good introductory manuals for Maven).

### What is this repository for? ###

* This is a Java library for the functions necessary to run a client, resource
  server, and authorization server as specified in [draft-ietf-ace-oauth-authz](https://tools.ietf.org/html/draft-ietf-ace-oauth-authz). 
  The base libraries do not include network functionality, since it tries to be
  protocol agnostic. However we provide [CoAP](https://tools.ietf.org/html/rfc7252) client and server support as an example of a protocol specific adaptation based on [Californium](https://www.eclipse.org/californium).
* Version: early_alpha


### How do I get set up? ###

* Just clone the repo, do the Maven fu and you are good to go
* Configuration: You need to set up a MySQL database to run the Junit tests. 
  To run in production you need to configure everything, starting with
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
* How to run tests: Run the Test* class files in the src/test folders. The CoAP 
  tests require you to run TestCoAPServer (as normal program not as Junit test)
  first.  Also note that you need to restart TestCoAPServer for each Coap test, 
  since the Server sets up the database and the test cleans it up (I might fix
  that in a future version).
* Deployment instructions: TBD. You should be able to set up the code for testing
  by just using the maven pom.xml and configuring the database (as explained 
  above).

### Contribution guidelines ###

* Writing tests: Yes please! I'd be happy to support you if you have ideas about 
  which tests would be needed.
* Code review: Yes please! Please use the Issue tracker and/or Pull requests.
* Other guidelines: Follow the [Code Conventions for Java]
  (http://www.oracle.com/technetwork/java/codeconvtoc-136057.html), don't add 
  new dependencies unless there is a really good reason.

### Who do I talk to? ###

* This code is owned by SICS Swedish ICT AB and released as Open Source under the [BSD 3 license](https://opensource.org/licenses/BSD-3-Clause).
* Please contact ludwig at sics dot se if you have questions or suggestions.