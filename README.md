# README #

### Overview ###
This is a Java prototype for the Accountable Mobile System (AMS) protocol 
for message forwarding i the BAR (Byzantine, Altruistic, Rational) mode in P2P systems. 
The protocol is described in the document "protocol.pdf" in the same repository.
(I will try to provide more details about the code as time permits; however, reading 
the document with the code would probably make it easy to understand what 
is done.)


### Brief description for AMS protocol ###
The code implements the protocol used in the Accountable Messaging System (AMS). The propose of the protocol is to force any contributing node in message forwarding, in a P2P systems, not to discard forwarding other's messages (e.g., in order to save its own resources like energy, CPU, and network bandwidth). The main idea is to forward the message through a chain of nodes from the source to destination where each node sends the message to its successor in two round-trips: the first round-trip hides the destination of the message (using encryption) and the second sends the decryption key. In this way, the receiver won't be able to deny the message if he is not the final destination, since the preceding node holds a proof that he actually received this message. This simplifies tracking rational (selfish) nodes and evicting them. This is made possible by using an incremental secure log as in PeerReview protocol in cooperative systems.


## How to get it set up? ##

### Dependencies ###
* The code is tested on Java 6 on MAC XOS 10.6, but can also work on other machines.
* If 3rd party encryption is needed, then include the flexiprovider encryption 
library from here: http://www.flexiprovider.de/ 
(or just remove flexiprovider imports in the Cryptography class in the code). 

### Installation ###
* Install eclipse and include flexiprovider libraries in the class path (if needed).
* Import in eclipse an "Existing Projects to Workspace"  indicating the AMS folder. 
This will import the project smoothly into eclipse.
* Make sure that all class paths are ok. The code should not have any error.

### Configuration ###
Change the IPs of your machines in the config folder and assign suitable keys 
for encryption.

## How to run tests? ##
The code is tested on a single MAC machine using multi-processes. It is trivial 
to run it on multiple machines too. Running the application is straightforward, 
just make sure to give a reasonable time between nodes you lunch as they are 
configured to immediately start sending messages (by default node1 starts).

## Future Work ##

* Improve documentation
* Write more test scenarios
* Experiment the protocol using ONE simulator (some of them are already implemented in the "simulation" folder)
* Code review

## Contribution ##
Please feel free to ping me if you are interested to contribute.