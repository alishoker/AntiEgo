/**
 * 
 */
package fr.cnrs.liris.drim.AMS;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OptionalDataException;
import java.io.StreamCorruptedException;
import java.net.ConnectException;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.Scanner;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import fr.cnrs.liris.drim.AMS.Cryptography.EncryptionType;
import fr.cnrs.liris.drim.AMS.Messaging.AccountMsg;
import fr.cnrs.liris.drim.AMS.Messaging.AnonymContent;
import fr.cnrs.liris.drim.AMS.Messaging.AnonymPayload;
import fr.cnrs.liris.drim.AMS.Messaging.Briefcase;
import fr.cnrs.liris.drim.AMS.Messaging.KeyContent;
import fr.cnrs.liris.drim.AMS.Messaging.Misbehavior;
import fr.cnrs.liris.drim.AMS.Messaging.MsgType;
import fr.cnrs.liris.drim.AMS.Messaging.ValidContent;
import fr.cnrs.liris.drim.AMS.SecureLogging.*;
import fr.cnrs.liris.drim.AMS.Tools.AMSTimer;
import fr.cnrs.liris.drim.AMS.Tools.Timing;
import fr.cnrs.liris.drim.AMS.Tools.Trace;
/**
 * @author Ali Shoker
 *
 */
public class Node {

	private static long id;// node identifier
	static String TAG= "Node";
	static final int KEY_LENGTH=10;
	static final EncryptionType ENCRYPTION_TYPE=EncryptionType.RSA;
	static final int NB_OF_INIT_MSGS=1;
	// for now give Ids starting from 0, and IPs
	static final String HOSTS_ECC=
			"/Volumes/data/Development/workspace/AMSLaptop/config/hostsECC.dat";// "file:///android_asset/serversList.dat";
	static final String HOSTS_RSA=
			"/Volumes/data/Development/workspace/AMSLaptop/config/hostsRSA.dat";
	static final int SERVER_PORT=8080;
	ServerSocket serverSocket;


	private static AccountValidInfoBase validInfoBase;//information base of validated secure logs of
	// the same node and other nodes which were validated by this node.
	private static AccountUSecureLog uLog;// the unverified log with entries and ...
	private static Blacklist blacklist=new Blacklist();//this is needed to best upon validation
	//to convince the receiver that the wrong entries correspond to selfish sender 
	public static PrivateKey privateKey;
	public static PublicKey publicKey;
	private static  Map<Long,NodeIdentity> nodeIdentityMap;
	public static BlockingQueue<Briefcase> inQueue;
	public static BlockingQueue<Briefcase> outQueue;

	private static AtomicInteger sequenceNumber;// sequence nb for unique messages and entries
	private static AtomicInteger operationNumber;// operation number for unique operation correspondence anonym+key+ask

	private static Map<Long,List<AccountHashEntry>> chalengeMap=null;//Long corresponds to senderId

	//default test message and destination, and intermediary
	///////////////////////////////////////////////
	public static final int PAYLOAD_SIZE=150; //nb of bytes should be > KEY_LENGTH,
	//it should divide 30 (PAYLOAD length), and less than 180.
	public static final String PAYLOAD="This is a test message payload";
	public static final Long DEST=(long) 2;
	public static final Long INTERMEDIATE=(long) 2;
	/////////////////////////////////////////////

	public void addChalenge(AccountHashEntry receivedHashEntry){
		Long sender=receivedHashEntry.getHashSource();
		if(!chalengeMap.containsKey(sender))
			chalengeMap.put(sender,new ArrayList<AccountHashEntry>());
		chalengeMap.get(sender).add(receivedHashEntry);
	}

	public static Map<Long, List<AccountHashEntry>> getChalengeMap(){
		return chalengeMap;
	}

	public static long getId(){
		return id;
	}


	public static PrivateKey getPrivateKey(){
		return privateKey;
	}

	public static PublicKey getPublicKey(){
		return publicKey;
	}


	public static  AccountUSecureLog getULog(){
		return uLog;
	}
	public static AccountValidInfoBase getInfoBase(){
		return validInfoBase;
	}

	public static void executeOperation(String operation){
		//here we can execute final operation in any format, text, video, etc.
		//TODO: see if we node decoding and so...
		//a.print(operation);
		Trace.d(TAG+" executeOperation:", "This is the PAYLOAD:"+operation);
	}

	public static AnonymPayload newAnonymPayload(String payload){
		//here we get a payload to send in any format, text, video, etc, after
		// decoding it to String.

		//Trace.d(TAG+"newAnonymPayload:", nodeIdentityMap.get(DEST).pubKey.toString());

		String encrypted="";

		if(ENCRYPTION_TYPE==EncryptionType.NONE)
			encrypted=payload;
		else if(ENCRYPTION_TYPE==EncryptionType.ECC)
			encrypted=Cryptography.encryptMessage(nodeIdentityMap.get(DEST).pubKey, payload);
		else if(ENCRYPTION_TYPE==EncryptionType.RSA)
			encrypted=Cryptography.encryptMessage(nodeIdentityMap.get(DEST).pubKey, payload);

		return new AnonymPayload(encrypted, DEST, INTERMEDIATE);//suppose no inter for now
	}

	public static class NodeIdentity{
		String ipAddress;
		PublicKey pubKey;
		PrivateKey prvKey;

	}

	// use this message on one node only to start testing
	public static void initializeOutQueue(int nbOfAnonymMsgs){

		//enlarge payload as required
		String sendPayload = new String();
		int folds=PAYLOAD_SIZE/PAYLOAD.length();
		for (int i = 0; i <folds ; i++) {
			sendPayload+=PAYLOAD;
		}
		while(sendPayload.length()%4!=0)
			sendPayload+="+";

		//Trace.d(TAG, "Payload:"+sendPayload);
		//Trace.d(TAG, "Payload size:"+sendPayload.length()+" Bytes.");
		//a.print("Payload size:"+sendPayload.length()+" Bytes.");

		for (int i = 0; i < nbOfAnonymMsgs; i++) {

			long newSeqNb=Node.generateSeqId();
			long newOpId=Node.generateOpId();
			AnonymPayload anPayload=Node.newAnonymPayload(sendPayload);
			long dest=anPayload.destination;
			long inter=anPayload.intermediary;

			/*
			 *  here we split the encrypted message into two and send one part in anonym, and
			 *  another part in the key the receiver can only decrypt the msg if it has
			 *  the private key and concatenated the anonymPart+keyPart.
			 *   we might change this latter and send a cryptographic key
			 */

			String anonymPart= new String(anPayload.payload.substring(Node.KEY_LENGTH));
			String keyPart=new String(anPayload.payload.substring(0,Node.KEY_LENGTH));

			/*
			 * 1: here we use destination in Content and we use intermediary inter in the log
			 * since the client thread relies on entry destination to send to, while the
			 * content should contain the final destination. 
			 * 2: we use opId=0 since we need to adjust it later on while sending content by
			 * setting the opId of the dest
			 */
			KeyContent kContent=new KeyContent(0,newSeqNb,keyPart, dest, Node.getId());
			Node.getULog().addKeyContents(kContent);
			//Trace.d(TAG+"initializeOutQueue", "keyPart:"+ 
			//	Node.getULog().getKeyContent(newSeqNb).getKey());

			// now prepare Anonym
			AnonymContent anContent=new AnonymContent(anonymPart);
			AccountMsg anonymMsg=new AccountMsg(newOpId, MsgType.ANONYM,
					newSeqNb, 0, anContent, true);

			//add entry to ulog, 
			Node.getULog().addOutEntry(anonymMsg,inter);
			//Trace.d(TAG, "added to outLog.");

			//create Briefcase to send
			Briefcase newBcase=new Briefcase(Node.getULog().getLastEntry(),
					Node.getULog().getBeforeLastHash(),
					Node.getULog().getLastHash());
			//Trace.d(TAG+"initializeOutQueue", "BriefCase created.");
			/*Trace.d(TAG, Node.getULog().getLastEntry().toString() +"and"+
					Node.getULog().getBeforeLastHash().getHashContent()+"and"+
					Node.getULog().getLastHash().getHashContent());
			 */

			// add to outQueue to send by client thread.
			Node.outQueue.add(newBcase);
			// add here to inQueue for testing only.
			//Node.inQueue.add(newBcase);
			if(i==0 || i==999){
				Trace.d(TAG, "Anonym message:"+ nbOfAnonymMsgs +" prepared.");
			}
		}
	}

	public static void initializeValid(){
		
		Trace.d(TAG, "Preparing Valid");
		long newSeqNb=Node.generateSeqId();
		long newopId=Node.generateOpId();
		Long toSeq;
		Long fromSeq = null;
		AMSTimer timer=new AMSTimer();

		if(getULog().getEntryList().size() !=0)
			fromSeq=Node.getULog().getEntryList().get(0).getEntrySequence();
		timer.start();
		toSeq=Node.getULog().getLastDeadSeqId();
		Trace.d(TAG, "getLastDeadSeqId time"+ timer.stop());
		if(toSeq==-1){
			Trace.e(TAG, "initializeValid: no last dead entry.");
			return;
		}

		//send digest too in the certificate, we should send null later to ensure
		// that the receiver calculates the chain if it is selfish.
		timer.start();
		String digest=Cryptography.digestHashMap(((TreeMap<Long, AccountHashEntry>)
				Node.getULog().getHashList()).subMap(fromSeq, true, toSeq, true));
		Trace.d(TAG, "digestHashMap time"+ timer.stop());
		timer.start();
		ValidContent vContent=new ValidContent(getInfoBase(), Node.getULog(),
				new AccountCertificate(fromSeq, toSeq, id, digest));
		Trace.d(TAG, "new ValidContent time"+ timer.stop());

		AccountMsg validMsg=new AccountMsg(newopId, MsgType.VALID,
				newSeqNb, 0, vContent, true);

		//add entry to ulog, 
		//NOTE: We assume no intermediary  node for now.
		Node.getULog().addOutEntry(validMsg,DEST);
		//create Briefcase to send
		Briefcase newBcase=new Briefcase(Node.getULog().getLastEntry(),
				Node.getULog().getBeforeLastHash(),
				Node.getULog().getLastHash());

		// add to outQueue to send by client thread.
		Node.outQueue.add(newBcase);
		Trace.d(TAG, "Finished preparing Valid");

	}


	public static void fillIdentityMap(){

		Scanner scanner = null;
		File file = null;
		if(ENCRYPTION_TYPE==EncryptionType.ECC)
			file=new File(HOSTS_ECC);
		else if(ENCRYPTION_TYPE==EncryptionType.RSA)
			file=new File(HOSTS_RSA);
		else if(ENCRYPTION_TYPE==EncryptionType.NONE)
			file=new File(HOSTS_ECC);//default
		Trace.d(TAG, "Hosts file read successfully.");

	
		try {
			scanner = new Scanner(new FileInputStream(file));
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			Trace.e(TAG, "Reading hosts file error");
			e.printStackTrace();
		}

		while (scanner.hasNextLine()) {

			//Trace.d(TAG, scanner.next());
			Long id;

			String[] columns = scanner.next().split(":");
			id=Long.valueOf(columns[0]);
			//Trace.d(TAG, columns[0]+columns[1]+columns[2]+columns[3]);
			NodeIdentity identity=new NodeIdentity();
			identity.ipAddress=columns[1];
			Cryptography.readKeys(identity,columns[2],columns[3]);

			nodeIdentityMap.put(id, identity);

			//Trace.d(TAG, id + "  "+ nodeIdentityMap.get(id).ipAddress +
			//	nodeIdentityMap.get(id).prvKey.toString());
		}

	}


	public static int generateSeqId(){
		return sequenceNumber.getAndIncrement();
	}
	public static int generateOpId(){
		return operationNumber.getAndIncrement();
	}

	public static Blacklist getBlacklist(){
		return blacklist;
	}

	public Node(List<Thread> threadsPool)
	{

		Trace.d(TAG, "Starting Node...");
		Trace.d(TAG, "Starting Node...");
		Trace.d(TAG, "Testing the trace.");
		validInfoBase=new AccountValidInfoBase();
		uLog= new AccountUSecureLog();
		blacklist=new Blacklist();
		inQueue=new LinkedBlockingQueue<Briefcase>();
		outQueue=new LinkedBlockingQueue<Briefcase>();
		nodeIdentityMap= new HashMap<Long, NodeIdentity>();
		chalengeMap= new TreeMap<Long, List<AccountHashEntry>>();

		Trace.d(TAG, "Data structures created..");

		//Cryptography.generateRSAKeys();

		//fill ipMap list
		fillIdentityMap();

		if(ENCRYPTION_TYPE==EncryptionType.RSA && (
				PAYLOAD_SIZE< PAYLOAD.length() ||
				(PAYLOAD_SIZE % PAYLOAD.length()!=0))){
			Trace.e(TAG, "PAYLOAD_SIZE:"+PAYLOAD_SIZE + " must divide" +
					" PAYLOAD.length():"+PAYLOAD.length());
			return;
		}

		if(nodeIdentityMap==null)
			Trace.e(TAG, "Ip map filling error.");
		else
			Trace.d(TAG, "Ip map filled with " + nodeIdentityMap.size() +" nodes");


		//read my own id
		String myIp=getIPAddress(true);
		Trace.d(TAG, "Device IP address: "+ myIp);
		for (Long  anId: nodeIdentityMap.keySet()) 
			if(nodeIdentityMap.get(anId).ipAddress.equals(myIp)){
				Node.id=anId;
				break;
			}
		/*Trace.d(TAG, anId+"   "+ nodeIdentityMap.get(anId).ipAddress
					+"   "+ nodeIdentityMap.get(anId).pubKey.toString()
					+"   "+ nodeIdentityMap.get(anId).prvKey.toString());
		 */
		publicKey=nodeIdentityMap.get(id).pubKey;
		privateKey=nodeIdentityMap.get(id).prvKey;


		//Trace.d(TAG, "Node Id: "+ String.valueOf(Node.id)+" and IP: "+getIPAddress(true));

		TAG +=  " "+String.valueOf(Node.id);

		//here we can use system time to initialize counters if we need unique number after restart
		sequenceNumber= new AtomicInteger((int) (Node.id*1000000));
		operationNumber=new AtomicInteger((int) (Node.id*1000000));

		/*
		 * Now for testing, we initialize the node of id=1 with some anonym messages
		 * so that other nodes can respond
		 */


		AMSTimer timer=new AMSTimer();
		timer.start(TimeUnit.NANOSECONDS);


		Trace.d(TAG, "========================================================");
		Trace.d(TAG, "=================== Node Configuration =================");
		Trace.d(TAG, "========================================================");
		Trace.d(TAG, "Initializing node:"+ id);
		Trace.d(TAG, "Node IP:"+myIp);
		Trace.d(TAG, "Using encryption type:"+ENCRYPTION_TYPE.toString());
		Trace.d(TAG, "Anonynous KEY msg length:"+ KEY_LENGTH);
		Trace.d(TAG, "Nb of initial messages:"+NB_OF_INIT_MSGS);
		Trace.d(TAG, "========================================================");


	//	if(Node.id==1)
		//	initializeOutQueue(1);


		// now create threads for send/receive
		Thread sender=new Thread(new ClientThread());
		Thread receiver=new Thread(new ServerThread(threadsPool));
		threadsPool.add(sender);
		threadsPool.add(receiver);
		sender.start();
		receiver.start();
		Trace.d(TAG, "Send/Receive threads started.");

		Trace.d(TAG, "Now entering main thread loop.");

		// main thread to handle messages. 
		//This is a way to avoid remaining in AMSActivity onStart
		Thread main=new Thread(new Runnable() {
			@Override
			public void run() {

				int uslSize;
				int anonyms;
				Briefcase briefcase=null;
				AccountEntry entry=null;
				Long source=null;
				long operationId;
				int uslINITSize=4*NB_OF_INIT_MSGS;
				AMSTimer timer=new AMSTimer();
				while (true)
				{
					//delay messages to test Valid
					if (id==1)
					{
						uslSize=getULog().getEntryList().size();//nb of operations
						anonyms=uslSize % 4;
						if(anonyms==0)
						{
							if(uslSize<uslINITSize){
								initializeOutQueue(1);
							} 
							else if(uslSize==uslINITSize)
							{
								try {
									Trace.d(TAG, "Log size is "+uslSize+
											" entries, sleeping for "+
											(Timing.ASK_WAITING_TIME+5000)/1000+" seconds");
									//should be more than Timing.ASK_WAITING_TIME for testing
									Thread.sleep(Timing.ASK_WAITING_TIME+5000);
								} catch (InterruptedException e1) {
									// TODO Auto-generated catch block
									e1.printStackTrace();
								}

								initializeOutQueue(1);
							} 
							// here we test validation
							else if(uslSize==uslINITSize+4)//the last operation counted
							{
								try {
									Thread.sleep(3000);
								} catch (InterruptedException e) {
									// TODO Auto-generated catch block
									e.printStackTrace();
								}
								timer.start();
								initializeValid();
								Trace.d(TAG, "Main thread-- Init Valid time:"+timer.stop());
							}

						}
					}

					
					try {
						briefcase = inQueue.take();
					} catch (InterruptedException e) {
						Trace.e(TAG, " Reading from inQueue.");
						e.printStackTrace();
					}
					//TODO: verify briefcase signature
					//check if sender is in blacklist

					entry=briefcase.getEntry();
					source=entry.getEntrySource();
					//if not me, check if true hash calculation of last entry
					if(source!=Node.id && !briefcase.ifCorrectHash())
					{
						Trace.d(TAG, "Adding inEntry to blacklist proofs log.");
						blacklist.add(source,briefcase,Misbehavior.BAD_HASH_COMPUTATION);

						//add to log; the proof is in blacklist			
						uLog.addInEntry(entry.getEntryContent(),source);
						Trace.d(TAG, "Added inEntry to blacklist proofs log.");
					}
					else{
						// now add received msg to log and handle AccountMsg
						Trace.d(TAG, "Adding inEntry secure log.");
						operationId=uLog.addInEntry(entry.getEntryContent(), source);

						if(operationId!=0){
							/*
							 * add to challenge
					later ensuring no log duplicates are used by the other party. No need to
					add all received hashes, selecting some of them is enough since the other party wont know
					what is the saved hashes. So this is safe.
							 */

							if((operationId % 100)==1)
								addChalenge(briefcase.getLastHash());

							//all handled messages will use the
							//generated OpId of the received req 
							Messaging.handle(briefcase,operationId);
						}
						else {
							Trace.d(TAG, "addInEntry returned 0.");
						}
					}

				}

			}
		});

		threadsPool.add(main);
		main.start();

	}

	public class ServerThread implements Runnable {

		List<Thread> threadsPool;

		public ServerThread(List<Thread> threadsPool){
			this.threadsPool=threadsPool;
		}
		public void run() {

			//Trace.d(TAG, "Entered server thread.");
			Trace.d(TAG,"Server thread started.");

			//Check if local ip is correct
			String serverIP=getIPAddress(true);
			if (serverIP == null ||
					!serverIP.equals(nodeIdentityMap.get(Node.getId()).ipAddress)) {
				Trace.e(TAG, "Wrong localhost Ip: " + serverIP);
				return;
			}
			Trace.d(TAG, "Listening on IP: " + 
					serverIP + " and port:" + String.valueOf(SERVER_PORT));

			try {
				serverSocket = new ServerSocket(SERVER_PORT);
			} catch (IOException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
			// listen for clients

			while (true) {

				try {
					Thread thr= new Thread(new PeerConnectionHandler(serverSocket.accept()));
					threadsPool.add(thr);
					thr.start();
					Trace.d(TAG, "Server Thread: new PeerConnecionHandler thread created.");
				} catch (IOException e1) {
					Trace.e(TAG, "Server Thread: Failed to get new socket.");
					e1.printStackTrace();
				}

			}

		}
	}

	public class PeerConnectionHandler implements Runnable{

		Socket clientSocket;
		ObjectInputStream ois;

		public PeerConnectionHandler(Socket acceptSocket){
			clientSocket=acceptSocket;
			try {
				clientSocket.setTcpNoDelay(true);
			} catch (SocketException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}

		@Override
		public void run() {

			Object recObject=null;

			while(true){

				try {
					ois = new ObjectInputStream(clientSocket.getInputStream());
				} catch (StreamCorruptedException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				} catch (IOException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}

				// get serialized object 
				try {
					
					recObject = ois.readObject();
					Trace.d(TAG, "PeerConnectionHandler: received request");

				} catch (ClassNotFoundException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (OptionalDataException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (IOException e) {
					// TODO Auto-generated catch block

					Trace.e(TAG, "PeerConnectionHandler: oops. Connection interrupted.");
					e.printStackTrace();
					return;
				}


				//object sanity check
				if (!(recObject instanceof Briefcase)){
					Trace.e(TAG, "PeerConnectionHandler: wrong message received from " +
							clientSocket.getInetAddress().getHostAddress());
					continue;
				}

				//add Briefcase to inQueue
				Briefcase bf=(Briefcase) recObject;
				Trace.d(TAG, "PeerConnectionHandler: received message ("+ 
						bf.getMessage().getMsgSequence() + 
						","+bf.getEntry().getEntryID() +
						") from node IP: "+
						clientSocket.getInetAddress().getHostAddress());
				if(bf.getMessage().getMsgID() % 1000==0 ||
						bf.getMessage().getMsgID() % 999==0){
					Trace.d(TAG, "PeerConnectionHandler: received message ("+ 
							bf.getMessage().getMsgSequence() + 
							","+bf.getEntry().getEntryID() +
							") from node IP: "+
							clientSocket.getInetAddress().getHostAddress());

				}

				if (blacklist.contains(bf.getEntry().getEntrySource())){
					Trace.e(TAG, "PeerConnectionHandler: node is in blacklist.");
					continue;
				} else
					inQueue.add(bf);

			}
		}
	}

	// gets the ip address of your phone's network
	private String getLocalIpAddress() {
		try {
			for (Enumeration<NetworkInterface> en = NetworkInterface.
					getNetworkInterfaces(); en.hasMoreElements();) {
				NetworkInterface intf = en.nextElement();
				for (Enumeration<InetAddress> enumIpAddr = intf.
						getInetAddresses(); enumIpAddr.hasMoreElements();) {
					InetAddress inetAddress = enumIpAddr.nextElement();
					if (!inetAddress.isLoopbackAddress()) 
						return inetAddress.getHostAddress().toString(); 
				}
			}

		} catch (SocketException ex) {
			Trace.e("Server Thread", ex.toString());
		}
		return null;
	}

	/**
	 * Get IP address from first non-localhost interface
	 * @param ipv4  true=return ipv4, false=return ipv6
	 * @return  address or empty string
	 */
	public static String getIPAddress(boolean useIPv4) {
		try {
			List<NetworkInterface> interfaces =
					Collections.list(NetworkInterface.getNetworkInterfaces());
			for (NetworkInterface intf : interfaces) {
				List<InetAddress> addrs = Collections.list(intf.getInetAddresses());
				for (InetAddress addr : addrs) {
					if (!addr.isLoopbackAddress() && addr instanceof Inet4Address) {
						String sAddr = addr.getHostAddress().toUpperCase();
						boolean isIPv4 =true; //Suppose this is always true
						if (useIPv4) {
							if (isIPv4) 
								return sAddr;
						} else {
							if (!isIPv4) {
								int delim = sAddr.indexOf('%'); // drop ip6 port suffix
								return delim<0 ? sAddr : sAddr.substring(0, delim);
							}
						}
					}
				}
			}
		} catch (Exception ex) { ex.printStackTrace(); } // for now eat exceptions
		return null;
	}

	public class ClientThread implements Runnable {

		public void run() {
			//create pool for open sockets
			Map<Long, Socket> socketPool=new HashMap<Long, Socket>();

			long wait=10000;//wait 10 sec for the servers to get ready.
			Trace.d(TAG+"Client Thread ", "Waiting for servers "+wait+" to come up.");
			try {
				Thread.sleep(wait);
			} catch (InterruptedException e2) {
				// TODO Auto-generated catch block
				e2.printStackTrace();
			}
			while(true){

				Briefcase bf=null;
				try {
					bf = outQueue.take();
				} catch (InterruptedException e1) {
					Trace.e(TAG+"Client Thread "," Taking from inQueue failed.");
					e1.printStackTrace();
				}
				try {
					long receiver=bf.getEntry().getEntryReceiver();
					Socket socket=null;

					//check for existing socket
					if(socketPool.containsKey(receiver)){
						socket=socketPool.get(receiver);
						if(socket.isClosed()){
							socketPool.remove(receiver);
							socket=null;
						}
					}

					if(socket==null)//no or empty socket
					{
						String serverAddr = nodeIdentityMap.get(
								receiver).ipAddress;
						int connectTry=0;
						for (connectTry = 0; connectTry < 100; connectTry++) {
							Trace.d(TAG+"Client Thread: ", "connecting to "+ serverAddr);
							try {
								socket = new Socket(serverAddr, SERVER_PORT);
							} catch (ConnectException e) {
								// TODO: handle exception
								e.printStackTrace();
							}

							if(socket!=null){
								Trace.d(TAG+"Client Thread "," Connection established to "+ serverAddr);
								break;
							}

							Thread.sleep(500);//sleep 1/2 sec then try reconnect.
						}

						if(connectTry==100){
							Trace.d(TAG+"Client Thread ", " Connection failed to "+ serverAddr);
							continue;
						}
						else{
							//add to pool
							socketPool.put(receiver, socket);
						}
					}


					Trace.d(TAG+"Client Thread ", " sending message ("+ 
							bf.getMessage().getMsgSequence() + 
							","+bf.getEntry().getEntryID() +
							") to node: "+ receiver);
					if(bf.getMessage().getMsgID() % 1000==0 ||
							bf.getMessage().getMsgID() % 999==0){
						Trace.d(TAG+"Client Thread ", " sending message ("+ 
								bf.getMessage().getMsgSequence() + 
								","+bf.getEntry().getEntryID() +
								") to node: "+ receiver);

					}
					try {
						socket.setTcpNoDelay(false);//Disable Nagle's algorithm
						ObjectOutputStream oos=new ObjectOutputStream(socket.getOutputStream());

						ByteArrayOutputStream bOut = new ByteArrayOutputStream();  
						ObjectOutputStream oOut = new ObjectOutputStream(bOut);  

						oOut.writeObject(bf);  
						oOut.close();  
						Trace.d(TAG,"The size of the BF is: "+bOut.toByteArray().length); 

						AMSTimer timer=new AMSTimer();
						timer.start();

						oos.writeObject(bf);
						
						oos.flush();// because we need a faster handling for messaging pattern
						Trace.d(TAG+"Client Thread ", " message sending time:"+timer.stop());
						
					} catch (IOException e) {
						Trace.d(TAG+"Client Thread "," socket Error.");
						e.printStackTrace();
					}

				} catch (Exception e) {
					Trace.d(TAG+"Client Thread ", "error while sending message.");
					e.printStackTrace();
				}

			}
		}
	}


}
