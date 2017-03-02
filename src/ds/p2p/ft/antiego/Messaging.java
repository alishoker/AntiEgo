package ds.p2p.ft.antiego;

import java.io.Serializable;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.Map.Entry;

import ds.p2p.ft.antiego.Cryptography;
import ds.p2p.ft.antiego.Cryptography.EncryptionType;
import ds.p2p.ft.antiego.SecureLogging.*;
import ds.p2p.ft.antiego.Tools.AMSTimer;
import ds.p2p.ft.antiego.Tools.Trace;
/**
 * @author Ali Shoker
 *
 */

public class Messaging implements Serializable {

	/**
	 * 
	 */


	private static final long serialVersionUID = 1L;


	static public enum MsgType {ANONYM, ASK, KEY, ACK, VALID, VACK, VANONYM, ANY;}
	static public enum Misbehavior {BAD_SIGNATURE, BAD_HASH_COMPUTATION, BAD_CERTIFICATE, CERT_NOT_MATCHING, LOG_ALTERING;}

	static public class Briefcase  implements Serializable{

		/**
		 * A Briefcase is a general message to be sent or received over the channel, it holds
		 *  an AccountEntry which contains an AccountMsg of diff. types, and it holds 
		 *  necessary hash values to verify that this entry was added to the senders' log.
		 */
		private static final long serialVersionUID = 1L;
		private AccountEntry lastEntry;
		private AccountHashEntry beforeLastHash;
		private AccountHashEntry lastHash;

		public Briefcase(AccountEntry lastEntry, AccountHashEntry beforeLastHash,
				AccountHashEntry lastHash){
			this.lastEntry=new AccountEntry(lastEntry);
			this.beforeLastHash= new AccountHashEntry(beforeLastHash);
			this.lastHash= new AccountHashEntry(lastHash);
		}
		public Briefcase(Briefcase bCase){
			this.lastEntry=new AccountEntry(bCase.lastEntry);
			this.beforeLastHash= new AccountHashEntry(bCase.beforeLastHash);
			this.lastHash= new AccountHashEntry(bCase.lastHash);
		}


		public AccountMsg getMessage(){

			return lastEntry.getEntryContent();
		}
		public AccountEntry getEntry(){

			return lastEntry;
		}		
		public void setMessage(AccountMsg accMsg){

			lastEntry.setEntryContent(accMsg);
		}

		public AccountHashEntry getBeforeLastHash(){

			return beforeLastHash;
		}
		public AccountHashEntry getLastHash(){

			return lastHash;
		}		
		//verify if the entry was added by the sender to its log
		public Boolean ifCorrectHash(){
			Trace.d(Node.TAG, "ifCorrectHash:"+
					Cryptography.digestEntry(beforeLastHash.getHashContent(),
							lastEntry.getEntrySequence())+
					"and"+ lastHash.getHashContent()+"and"+ lastEntry.toString());
			if(Cryptography.digestEntry(beforeLastHash.getHashContent(),
					lastEntry.getEntrySequence()).
					equals(lastHash.getHashContent()))
				return true;
			else
				return false;
		}

	}


	static public class AccountMsg implements Serializable{


		/**
		 * 
		 */
		private static final long serialVersionUID = 1L;

		private long msgID=0;// msg identifier is unique across all Anonym->Ask->Key chain
		private MsgType msgType=null; // msg type, it is one of the static values ANONYM, ASK, etc.
		private long msgSequence=0;// msg sequence number to ensure unique ordering.
		private int msgSize=0;// size of the message payload msgPayload in bytes
		private AccountContent msgContent=null;// msg content to send, it could be encrypted
		//private long msgDestination;// msg final destination
		//private long msgSource;// msg original source
		private boolean isAlive=true;//ANONYM msg is alive or not?

		public void setMsgID(long newMsgId) {this.msgID=newMsgId;}
		public long getMsgID() {return msgID;}

		public void setMsgType(MsgType newMsgType) {this.msgType=newMsgType;}
		public MsgType getMsgType() {return msgType;}

		public void setMsgSequence(long newMsgSequence) {this.msgSequence=newMsgSequence;}
		public long getMsgSequence() {return msgSequence;}

		public void setMsgSize(int newMsgSize) {this.msgSize=newMsgSize;}
		public int getMsgSize() {return msgSize;}

		public void setMsgContent(AccountContent newMsgContent)
		{this.msgContent=newMsgContent;}
		public String toString(){
			return msgContent.toString();
		}

		public AccountContent getMsgContent() {return msgContent;}
		/*
		public void setMsgDestination(long newMsgDestination) {this.msgDestination=newMsgDestination;}
		public long getMsgDestination() {return msgDestination;}

		public void setMsgSource(long newMsgSource) {this.msgSource=newMsgSource;}
		public long getMsgSource() {return msgSource;}*/

		public void isAlive(Boolean state){isAlive=state;}
		public boolean isAlive() {return isAlive;}

		public AccountMsg(AccountMsg newAccountMsg){


			msgID=newAccountMsg.msgID;
			msgType=newAccountMsg.msgType;
			msgSequence=newAccountMsg.msgSequence;
			msgSize=newAccountMsg.msgSize;
			//msgDestination=newAccountMsg.msgDestination;
			//msgSource=newAccountMsg.msgSource;
			isAlive=newAccountMsg.isAlive;

			switch (msgType) { //do shalow copy here because all calls of AccountMsg do newAccountMsg.content hardcopy
			case  ANONYM:
				msgContent= (AnonymContent) newAccountMsg.msgContent;//new AnonymContent((AnonymContent) newAccountMsg.content);
				break;
			case ASK:
				msgContent=(AskContent) newAccountMsg.msgContent;//new AskContent((AskContent) newAccountMsg.content);
				break;
			case KEY:
				msgContent=(KeyContent) newAccountMsg.msgContent;// new KeyContent((KeyContent) newAccountMsg.content);
				break;
			case ACK:
				msgContent=(AckContent) newAccountMsg.msgContent;//new AckContent((AckContent) newAccountMsg.content);
				break;
			case VALID:
				msgContent= (ValidContent) newAccountMsg.msgContent; //new ValidContent((ValidContent) newAccountMsg.content);
				break;
			case VACK:
				msgContent=(VackContent) newAccountMsg.msgContent;// new VackContent((VackContent) newAccountMsg.content);
				break;
			case VANONYM:
				msgContent=(VanonymContent) newAccountMsg.msgContent;// new VanonymContent((VanonymContent) newAccountMsg.content);
				break;
			default:
				break;
			}

		}

		public AccountMsg(long id,MsgType type,long seq,int size,
				AccountContent content, Boolean state){

			msgID=id;
			msgType=type;
			msgSequence=seq;
			msgSize=size;		
			//msgDestination=dest;
			//msgSource=source;
			isAlive=state;

			switch (msgType) { //do shalow copy here because all calls of AccountMsg do content hardcopy
			case  ANONYM:
				msgContent= (AnonymContent) content;//new AnonymContent((AnonymContent) content);
				break;
			case ASK:
				msgContent=(AskContent) content;//new AskContent((AskContent) content);
				break;
			case KEY:
				msgContent=(KeyContent) content;// new KeyContent((KeyContent) content);
				break;
			case ACK:
				msgContent=(AckContent) content;//new AckContent((AckContent) content);
				break;
			case VALID:
				msgContent= (ValidContent) content; //new ValidContent((ValidContent) content);
				break;
			case VACK:
				msgContent=(VackContent) content;// new VackContent((VackContent) content);
				break;
			case VANONYM:
				msgContent=(VanonymContent) content;// new VanonymContent((VanonymContent) content);
				break;
			default:
				break;
			}

		}


	}


	public interface AccountContent {

		//public static class AccountContent1 implements AccountContent, Serializable
		public long getCorrId();
		public long getSeqId();
		public String toString();
	}

	static public class AnonymContent implements AccountContent,Serializable{
		/**
		 * 
		 */
		private static final long serialVersionUID = 1L;
		private String encryptedContent=null;

		//remove destination now send it later in Key message
		//public String encryptedDestination=null;

		public AnonymContent(AnonymContent content){

			encryptedContent=content.encryptedContent;
			//encryptedDestination=content.encryptedDestination;	
		}

		public AnonymContent(String content){
			encryptedContent=content;
			//encryptedDestination=dest;	
		}
		public String toString(){
			return encryptedContent;
		}
		public void setContent(String encryptedContent){this.encryptedContent=encryptedContent;}
		public String getContent(){ return encryptedContent;}

		@Override
		public long getCorrId() {
			// TODO Auto-generated method stub
			return 0;
		}

		@Override
		public long getSeqId() {
			// TODO Auto-generated method stub
			return 0;
		}
	}

	static public class AskContent implements AccountContent,Serializable{
		/**
		 * 
		 */
		private static final long serialVersionUID = 1L;
		//public AccountHashEntry hashEntry=null;// hashEntry to ensure correct correspondence
		//is replace with msgID in accountMsg
		private long corrID;
		private long seqID;

		public AskContent(){
			corrID=0;
			seqID=0;
		}
		public AskContent(long corrID, long seqId){
			this.corrID=corrID;
			seqID=seqId;
		}
		public long getCorrId(){
			return corrID;
		}
		public AskContent(AskContent content){
			corrID=content.corrID;
			seqID=content.seqID;
		}

		public String toString(){
			return String.valueOf(corrID)+String.valueOf(seqID);
		}

		@Override
		public long getSeqId() {
			// TODO Auto-generated method stub
			return seqID;
		}

	}

	static public class KeyContent implements AccountContent,Serializable{
		/**
		 * 
		 */
		private static final long serialVersionUID = 1L;
		private String key=null;// key
		private long corrID;//corresponding msgId replaced hash
		//private AccountHashEntry hashEntry=null;// hashEntry of the corresponding ASK
		private long seqID;
		private long destination;
		private long source;

		public KeyContent(KeyContent content){
			key=content.key;
			corrID=content.corrID;
			seqID=content.seqID;
			source=content.source;
			//hashEntry=new AccountHashEntry(content.hashEntry);
			destination=content.destination;
		}

		public String toString(){
			return String.valueOf(corrID)+
					String.valueOf(seqID)+
					String.valueOf(source)+
					String.valueOf(destination)+
					key;
		}

		public KeyContent(long corrId, long seqId, String key, long destination, long source){
			this.key=key;
			this.corrID=corrId;
			this.seqID=seqId;
			this.source=source;
			//this.hashEntry=new AccountHashEntry(hashEntry);	
			this.destination=destination;
		}		

		public String getKey(){return key;}
		public void setKey(String newKey) {key=newKey;}

		//public AccountHashEntry getHashEntry(){return hashEntry;}
		//public void setHashEntry(AccountHashEntry entry) {hashEntry=new AccountHashEntry(entry);}
		public long getCorrId(){return corrID;}
		public void setCorrId(long id) {corrID=id;}

		public long getDestination(){return destination;}
		public void setDestination(long dest) {destination=dest;}
		public long getSource(){return source;}
		public void setSource(long source) {this.source=source;}

		@Override
		public long getSeqId() {
			// TODO Auto-generated method stub
			return seqID;
		}
		public void setSeqId(long id) {seqID=id;}
	}



	static public class AckContent implements AccountContent,Serializable{
		/**
		 * 
		 */
		private static final long serialVersionUID = 1L;
		//public AccountHashEntry hashEntry=null;// hashEntry to ensure correct correspondence
		//is replace with msgID in accountMsg
		private long corrID;
		private long seqID;

		public AckContent(){
			corrID=0;
			seqID=0;
		}
		public AckContent(long corrID, long seqID){
			this.corrID=corrID;
			this.seqID=seqID;
		}
		public long getCorrId(){
			return corrID;
		}
		public AckContent(AckContent content){
			corrID=content.corrID;
			seqID=content.seqID;
		}

		public String toString(){
			return String.valueOf(corrID)+
					String.valueOf(seqID);
		}

		@Override
		public long getSeqId() {
			// TODO Auto-generated method stub
			return seqID;
		}

	}



	static public class ValidContent implements AccountContent,Serializable{
		/**
		 * 
		 */
		private static final long serialVersionUID = 1L;
		public AccountValidInfoBase vib=null;// all verified logs in hash table including self
		public AccountUSecureLog usl=null;// all entries of USL log with setting hashList=null;
		public AccountCertificate myCertificate=null;// certificate from sender to receiver intended
		// to make sure the latter wont lie about the sender's log,

		public ValidContent(AccountValidInfoBase newVIB, AccountUSecureLog newUsl, 
				AccountCertificate newCert)
		{
			vib= newVIB;
			usl=new AccountUSecureLog(newUsl.getEntryList(),newUsl.getOperationMap(),newUsl.getHashList());
			myCertificate=newCert;//yes shadow copy

		}



		public ValidContent(ValidContent content)
		{
			vib=new AccountValidInfoBase(content.vib);
			usl=new AccountUSecureLog(content.usl);
			myCertificate=new AccountCertificate(content.myCertificate);

		}

		//TODO:include other fields in toString
		public String toString(){
			return myCertificate.toString();
		}

		@Override
		public long getCorrId() {
			return 0;
		}



		@Override
		public long getSeqId() {
			return 0;
		}

	}

	static public class VackContent implements AccountContent,Serializable{
		/**
		 * 
		 */
		private static final long serialVersionUID = 1L;
		public AccountValidInfoBase vib=null;// all verified logs in hash table including self.
		public AccountUSecureLog usl=null;// all entries of USL log with setting hashList=null;
		public AccountCertificate myCertificate=null;// certificate from sender to receiver intended
		// to make sure the latter wont lie about the sender's log,
		public AccountCertificate yourCertificate=null;// certificate from sender to receiver intended
		// to make sure the latter has a valid log and can delete entries from USL.
		private long corrID;//corresponding msgId replaced hash
		private long seqID;

		public VackContent(VackContent content){
			vib=new AccountValidInfoBase(content.vib);
			usl=new AccountUSecureLog(content.usl);

			myCertificate=new AccountCertificate(content.myCertificate);
			yourCertificate=new AccountCertificate(content.yourCertificate);
			corrID=content.corrID;
			seqID=content.seqID;
		}

		//TODO: add other fields to toString
		public String toString(){
			return myCertificate.toString()+yourCertificate.toString();
		}

		public VackContent(AccountValidInfoBase newVIB, AccountUSecureLog newUsl, 
				AccountCertificate newMyCert, AccountCertificate newYourCert,long opId, long seqID)
		{
			vib= newVIB;
			usl=new AccountUSecureLog(newUsl.getEntryList(),newUsl.getOperationMap(),newUsl.getHashList());
			myCertificate=newMyCert;//yes shadow copy
			yourCertificate=newYourCert;
			corrID=opId;
			this.seqID=seqID;

		}

		public long getCorrId(){return corrID;}
		public void setCorrId(long id) {corrID=id;}

		@Override
		public long getSeqId() {
			return seqID;
		}
	}

	static public class VanonymContent extends AnonymContent implements
	AccountContent,Serializable{// first Anonym msg with certificate
		/**
		 * 
		 */
		private static final long serialVersionUID = 1L;
		private AccountCertificate yourCertificate=null;// certificate from sender to receiver intended
		// to make sure the latter has a valid log and can delete entries from USL.
		private long corrID;//corresponding msgId replaced hash
		private long seqID;
		public VanonymContent(VanonymContent content)
		{
			super(content.getContent());
			yourCertificate=new AccountCertificate(content.yourCertificate);
			//encryptedDestination=content.encryptedDestination;
			corrID=content.corrID;
			seqID=content.seqID;
		}


		public VanonymContent(String content,AccountCertificate cert,long opId,long seqId)
		{
			super(content);
			yourCertificate=new AccountCertificate(cert);
			//encryptedDestination=content.encryptedDestination;
			corrID=opId;
			this.seqID=seqId;
		}

		//TODO: add other fields to toString
		public String toString(){
			return yourCertificate.toString();
		}
		public AccountCertificate getCertificate(){
			return yourCertificate;
		}

		public long getCorrId(){return corrID;}
		public void setCorrId(long id) {corrID=id;}

		public long getSeqId() {
			return seqID;
		}
	}

	static public class AnonymPayload implements Serializable{

		/**
		 * 
		 */
		private static final long serialVersionUID = 1L;
		public String payload;
		public long destination;
		public long intermediary;

		public AnonymPayload(String payload, long dest, long interm){
			this.payload=payload;
			destination=dest;
			intermediary=interm;
		}

	}
	public static void handle(Briefcase breifCase, long operationId){

		switch (breifCase.getMessage().msgType) {
		case  ANONYM:
			handleAnonym(breifCase, operationId);
			break;
		case ASK:
			handleAsk(breifCase,operationId);
			break;
		case KEY:
			handleKey(breifCase,operationId);
			break;
		case VALID:
			handleValid(breifCase,operationId);
			break;
		case VACK:
			handleVack(breifCase,operationId);
			break;
		case VANONYM:
			handleVanonym(breifCase,operationId);
			break;
		default:
			break;
		}

	}

	private static void handleAnonym(Briefcase bCase, long operationId) {
		Trace.d(Node.TAG +" handleAnonym", "started");
		//Create ASK message with same operationID as added in usl.
		long newSeqNb=Node.generateSeqId();
		AccountMsg askMsg=new AccountMsg(operationId, MsgType.ASK,newSeqNb, 0,
				new AskContent(bCase.getMessage().getMsgID(),
						bCase.getMessage().getMsgSequence()), true);
		Trace.d(Node.TAG +" handleAnonym", "ASK created.");
		//TODO: do we need to schedule old entry to resend?
		//add entry to ulog
		Node.getULog().addOutEntry(askMsg,bCase.getEntry().getEntrySource());
		Trace.d(Node.TAG +" handleAnonym", "ASK added to Log.");
		//create Briefcase to send
		Briefcase newBcase=new Briefcase(Node.getULog().getLastEntry(),
				Node.getULog().getBeforeLastHash(),
				Node.getULog().getLastHash());

		// add to outQueue to send by client thread.
		Node.outQueue.add(newBcase);
		Trace.d(Node.TAG +" handleAnonym", "ASK added to outQueue.");

	}

	//same as handleAnonym() but receives a certificate too.
	private static void handleVanonym(Briefcase bCase, long operationId) {
		//TODO: {think what should be done if receiver did not receive this 
		//certificate at all.}

		// note: no need to check correspondence here since certificate already does that.

		//if Certificate is correct, add USL part to VSL, and delete the USL content.

		if(!Node.getInfoBase().getVLog().addVerifiedUSL(
				((VanonymContent) bCase.getMessage().getMsgContent()).getCertificate())){

			Node.getBlacklist().add(bCase.getEntry().getEntrySource(),
					bCase,Misbehavior.BAD_CERTIFICATE);
			Trace.e("handleVanonym", "1.Added to blacklist");
			return;
		}
		else{

			//Create ASK message with same operationID as added in usl.
			long newSeqNb=Node.generateSeqId();
			AccountMsg askMsg=new AccountMsg(operationId, MsgType.ASK,newSeqNb, 0,
					new AskContent(bCase.getMessage().getMsgID(),
							bCase.getMessage().getMsgSequence()), true);

			//TODO: do we need to schedule old entry to resend?
			//add entry to ulog
			Node.getULog().addOutEntry(askMsg,bCase.getEntry().getEntrySource());
			//create Briefcase to send
			Briefcase newBcase=new Briefcase(Node.getULog().getLastEntry(),
					Node.getULog().getBeforeLastHash(),
					Node.getULog().getLastHash());

			// add to outQueue to send by client thread.
			Node.outQueue.add(newBcase);

		}
	}

	private static void handleAsk(Briefcase bCase, long operationId) {

		Trace.d(Node.TAG +" handleAsk", "started");
		AccountMsg msg=bCase.getMessage();

		long newSeqNb=Node.generateSeqId();
		//Create a KEY content
		KeyContent keyContent= new KeyContent(Node.getULog().getKeyContent(
				msg.getMsgContent().getSeqId()));
		keyContent.setCorrId(msg.getMsgID());//this tells the other party the correspondence
		keyContent.setSeqId(msg.getMsgSequence());


		//Create KEY message, set the real anonym source and set isEncrypted = true
		AccountMsg keyMsg=new AccountMsg(operationId,
				MsgType.KEY, newSeqNb, 0, keyContent, true);
		//add entry to ulog
		Node.getULog().addOutEntry(keyMsg,bCase.getEntry().getEntrySource());
		//create Briefcase to send
		Briefcase newBcase=new Briefcase(Node.getULog().getLastEntry(),
				Node.getULog().getBeforeLastHash(),
				Node.getULog().getLastHash());

		// add to outQueue to send by client thread.
		Node.outQueue.add(newBcase);
		Trace.d(Node.TAG +" handleAsk", "ASK added to outQueue");

	}

	private static void handleAck(Briefcase bCase, long operationId) {

		//remove keyContent of anonym message
		Node.getULog().removeKeyContents(bCase.getEntry().getEntrySequence());


	}

	private static void handleKey(Briefcase bCase, long operationId) {

		Trace.d(Node.TAG +" handleKey", "started");
		long newSeqNb=Node.generateSeqId();
		//new content to store it to forward
		KeyContent keyContent= (KeyContent) bCase.getMessage().getMsgContent();

		if(keyContent.getDestination()!=Node.getId()){//msg is not mine, forward
			Trace.d(Node.TAG +" handleKey", "msg is not mine");

			Node.getULog().addKeyContents(new KeyContent(operationId,newSeqNb,
					keyContent.getKey(),keyContent.getDestination(),
					keyContent.getSource()));// add keycontent to forward later

			//Create Anonym message from stored one
			AnonymContent anonymContent=new AnonymContent(Node.getULog().
					getAnonymContent(operationId, true));
			AccountMsg anonymMsg=new AccountMsg(operationId, MsgType.ANONYM,
					newSeqNb, 0, anonymContent, true);

			keyContent.setCorrId(operationId);//this tells me how too search  for it later
			keyContent.setSeqId(newSeqNb);

			//add entry to ulog, 
			//NOTE: We assume no intermediary  node for now.
			Node.getULog().addOutEntry(anonymMsg,keyContent.getDestination());
			//create Briefcase to send
			Briefcase newBcase=new Briefcase(Node.getULog().getLastEntry(),
					Node.getULog().getBeforeLastHash(),
					Node.getULog().getLastHash());

			// add to outQueue to send by client thread.
			Node.outQueue.add(newBcase);
			Trace.d(Node.TAG +" handleKey", "forwarding Anonym message");

			//now move to send Ack below
			newSeqNb=Node.generateSeqId();

		}

		else{//message is mine, execute
			Trace.d(Node.TAG +" handleKey", "msg is mine");
			//decrypt and use message, we assume that msg+key= the real message
			// so, we split the original message
			//TODO: check whether decoding should be done here or not?
			String operation="";

			if(Node.ENCRYPTION_TYPE==EncryptionType.NONE)
				operation=new String(keyContent.getKey()+
						Node.getULog().getAnonymContent(operationId,true).encryptedContent);
			if(Node.ENCRYPTION_TYPE==EncryptionType.ECC)
				operation=Cryptography.decryptMessage(Node.getPrivateKey(),
						new String(keyContent.getKey()+
								Node.getULog().getAnonymContent(operationId,true).encryptedContent));
			else if(Node.ENCRYPTION_TYPE==EncryptionType.RSA)
				operation=Cryptography.decryptMessage(Node.getPrivateKey(),
						new String(keyContent.getKey()+
								Node.getULog().getAnonymContent(operationId,true).encryptedContent));

			Node.executeOperation(operation);
			Trace.d(Node.TAG +" handleKey", "Operation executed on destination.");
		}
		//Create Ack message from stored one
		AckContent ackContent=new AckContent(bCase.getMessage().getMsgID(), 
				bCase.getMessage().getMsgSequence());
		AccountMsg ackMsg=new AccountMsg(operationId, MsgType.ACK,
				newSeqNb, 0, ackContent, true);

		//add entry to ulog, 
		//NOTE: We assume no intermediary  node for now.
		Node.getULog().addOutEntry(ackMsg,bCase.getEntry().getEntrySource());
		//create Briefcase to send
		Briefcase newBcase=new Briefcase(Node.getULog().getLastEntry(),
				Node.getULog().getBeforeLastHash(),
				Node.getULog().getLastHash());

		// add to outQueue to send by client thread.
		Node.outQueue.add(newBcase);
		Trace.d(Node.TAG +" handleAsk", "Sending Ack");

	}


	private static void handleValid(Briefcase bCase, long operationId) {
		// 0: validate hash sequence calculation and return certificate
		// 1: check if alive entries are covered and certificate corresponds to alive messages.
		// 2: validate operation sequence
		// 3: validate correct hashes in vib vs certificates.
		// 4: check whether my saved challenges are present in all logs, and sender log.
		// 5: save hash sequence and certificate in vib
		// 6: create and send VACK message to sender.

		// TODO: we need to check whether certificates are signed correctly

		// 0: validate hash sequence calculation and return certificate
		Trace.d("handleValid", "Entring handleValid.");
		AMSTimer timer=new AMSTimer();
		long newSeqNb=Node.generateSeqId();
		long source=bCase.getEntry().getEntrySource();

		ValidContent recValidContent=(ValidContent) bCase.getEntry().getEntryContent().msgContent;
		AccountUSecureLog recUSL=(AccountUSecureLog) recValidContent.usl;
		AccountValidInfoBase recVIB=(AccountValidInfoBase) recValidContent.vib;
		AccountCertificate recCert=(AccountCertificate) recValidContent.myCertificate;
		Map<Long, AccountHashEntry> recHashList=recVIB.getVLog().hashList;
		List<AccountCertificate> recCertList=recVIB.getVLog().certificateList;

		String lastVSLHashContent="";
		timer.start();
		if(recCertList.size()>0)
			lastVSLHashContent=recHashList.get(recCertList.get(recCertList.
					size()-1).getToSeqNb()).getHashContent();
		Trace.d("handleValid", "lastVSLHashContent time:"+timer.stop());
		//steps 0 and 1
		timer.start();
		AccountCertificate sendCert=recUSL.getYourValidCertificate(
				lastVSLHashContent,	bCase.lastHash.getHashContent(), recCert);
		Trace.d("handleValid", "getYourValidCertificate time:"+timer.stop());
		//step 2
		timer.start();
		int toIndex=recUSL.isCorrectSenderAndForwarder();
		Trace.d("handleValid", "isCorrectSenderAndForwarder time:"+timer.stop());
		//we may use this index later too
		if(toIndex==-1){
			//sending node miss-behaved
			Node.getBlacklist().add(source,
					bCase, Misbehavior.BAD_CERTIFICATE);
			Trace.e("handleValid", "1.Added to blacklist.");
			return;
		}

		//steps 3 and 4
		timer.start();
		if(recVIB.getVHT().keySet()!=null &&
				recVIB.getVHT().keySet().size()!=0)
			for (Entry<Long, AccountVSecureLog> entry : recVIB.getVHT().entrySet()) {
				if(!entry.getValue().isValidVSL()){// sender miss-behaved
					Node.getBlacklist().add(source,
							bCase, Misbehavior.CERT_NOT_MATCHING);
					Trace.e("handleValid", "2.Added to blacklist.");
					return;
				}
				if(!entry.getValue().challenge(entry.getKey())){//entry.getKey() miss-behaved
					Node.getBlacklist().add(entry.getKey(),
							bCase, Misbehavior.LOG_ALTERING);
					Trace.e("handleValid", "3.Added to blacklist.");
					return;
				}
			}
		Trace.d("handleValid", "VHT verification time:"+timer.stop());
		timer.start();
		//now do the same for sender VSL
		if(recVIB.getVLog().hashList!=null &&
				recVIB.getVLog().hashList.size()!=0)
		{
			if(!recVIB.getVLog().isValidVSL()){// sender miss-behaved
				Node.getBlacklist().add(source,
						bCase, Misbehavior.CERT_NOT_MATCHING);
				Trace.e("handleValid", "4.Added to blacklist.");
				return;
			}
			if(!recVIB.getVLog().challenge(source)){//entry.getKey() miss-behaved
				Node.getBlacklist().add(source,
						bCase, Misbehavior.LOG_ALTERING);
				Trace.e("handleValid", "5.Added to blacklist.");
				return;
			}
		}
		Trace.d("handleValid", "validating Vlog time:"+timer.stop());
		
		Trace.d("handleValid", "Finished validating, now creating VACK reply.");

		timer.start();
		//step 5
		// first add the verified USL range to senders VSL.
		recVIB.getVLog().hashList.putAll(((TreeMap<Long, AccountHashEntry>)
				recUSL.getHashList()).subMap(recCert.getFromSeqNb(), true,
						recCert.getToSeqNb(),true));
		Trace.d("handleValid", "recVIB.getVLog().hashList.putAll time:"+timer.stop());

		//also add received certificate for this validation portion
		recVIB.getVLog().certificateList.add(recCert);

		//now add this verified log to my VHT
		Node.getInfoBase().getVHT().put(source,	recVIB.getVLog());

		//step 6
		//create new data to send in VACK 

		AccountUSecureLog newUSL=new AccountUSecureLog(
				Node.getULog().getEntryList(),Node.getULog().getOperationMap(),
				Node.getULog().getHashList());
		Long fromSeq=Node.getULog().getEntryList().get(0).getEntrySequence();
		Long toSeq=Node.getULog().getLastDeadSeqId();
		//send digest too in the certificate, we should send null later to ensure
		// that the receiver calculates the chain if it is selfish.
		timer.start();
		String digest=Cryptography.digestHashMap(((TreeMap<Long, AccountHashEntry>)
				Node.getULog().getHashList()).subMap(fromSeq, true, toSeq, true));
		Trace.d("handleValid", "digestHashMap time:"+timer.stop());

		AccountCertificate newMyCert=new AccountCertificate(fromSeq,toSeq,Node.getId(),digest);

		//use opId and seqId of sender for correspondence
		VackContent vackContent= new VackContent(Node.getInfoBase(), newUSL, newMyCert, sendCert,
				bCase.getEntry().getEntryID(), bCase.getEntry().getEntrySequence());

		AccountMsg vackMsg=new AccountMsg(operationId, MsgType.VACK,
				newSeqNb, 0, vackContent, true);

		//add entry to ulog, 
		//NOTE: We assume no intermediary  node for now.
		Node.getULog().addOutEntry(vackMsg,source);
		//create Briefcase to send
		Briefcase newBcase=new Briefcase(Node.getULog().getLastEntry(),
				Node.getULog().getBeforeLastHash(),
				Node.getULog().getLastHash());

		// add to outQueue to send by client thread.
		Node.outQueue.add(newBcase);
		Trace.d("handleValid", "Added VACK to outQueue.");

	}




	private static void handleVack(Briefcase bCase, long operationId) {
		/*
		// 0: validate hash sequence calculation and return certificate
		// 1: check if alive entries are covered and certificate corresponds to alive messages.
		// 2: validate operation sequence
		// 3: validate correct hashes in vib vs certificates.
		// 4: check whether my saved challenges are present in all logs, and sender log.
		// 5: save hash sequence and certificate in vib
		// 6: create and send Vanonym message to sender if exists.
		 */
		// TODO: we need to check whether certificates are signed correctly
		Trace.d("handleVack", "Entring handleVack.");
		long source=bCase.getEntry().getEntrySource();

		VackContent recVackContent=(VackContent) bCase.getEntry().getEntryContent().msgContent;
		AccountUSecureLog recUSL=(AccountUSecureLog) recVackContent.usl;
		AccountValidInfoBase recVIB=(AccountValidInfoBase) recVackContent.vib;
		AccountCertificate recMyCert=(AccountCertificate) recVackContent.myCertificate;
		AccountCertificate recYourCert=(AccountCertificate) recVackContent.yourCertificate;
		Map<Long, AccountHashEntry> recHashList=recVIB.getVLog().hashList;
		List<AccountCertificate> recCertList=recVIB.getVLog().certificateList;

		String lastVSLHashContent="";

		if(recCertList.size()>0)
			lastVSLHashContent=recHashList.get(recCertList.get(recCertList.
					size()-1).getToSeqNb()).getHashContent();

		//if Certificate is correct, add USL part to VSL, and delete the USL content.
	
		if(!Node.getInfoBase().getVLog().addVerifiedUSL(recYourCert)){

			Node.getBlacklist().add(source,	bCase,Misbehavior.BAD_CERTIFICATE);
			Trace.e("handleVack", "1.Added to blacklist.");
			return;
		}
		
		//steps 0 and 1
		AccountCertificate sendCert=recUSL.getYourValidCertificate(
				lastVSLHashContent,	bCase.lastHash.getHashContent(), recMyCert);
		
		//step 2
		int toIndex=recUSL.isCorrectSenderAndForwarder();
		//we may use this index later too
		if(toIndex==-1){
			//sending node miss-behaved
			Node.getBlacklist().add(source,	bCase, Misbehavior.BAD_CERTIFICATE);
			Trace.e("handleVack", "2.Added to blacklist.");
			return;
		}

		//steps 3 and 4
		for(Entry<Long, AccountVSecureLog> entry : recVIB.getVHT().entrySet()) {
			if(!entry.getValue().isValidVSL()){// sender miss-behaved
				Node.getBlacklist().add(source,
						bCase, Misbehavior.CERT_NOT_MATCHING);
				Trace.e("handleVack", "3.Added to blacklist.");
				return;
			}
			if(!entry.getValue().challenge(entry.getKey())){//entry.getKey() miss-behaved
				Node.getBlacklist().add(entry.getKey(),
						bCase, Misbehavior.LOG_ALTERING);
				Trace.e("handleVack", "4.Added to blacklist.");
				return;
			}
		}
		//now do the same of sender VSL
		if(!recVIB.getVLog().isValidVSL()){// sender miss-behaved
			Node.getBlacklist().add(source,
					bCase, Misbehavior.CERT_NOT_MATCHING);
			Trace.e("handleVack", "5.Added to blacklist.");
			return;
			
		}
		if(!recVIB.getVLog().challenge(source)){//entry.getKey() miss-behaved
			Node.getBlacklist().add(source,
					bCase, Misbehavior.LOG_ALTERING);
			Trace.e("handleVack", "6.Added to blacklist.");
			return;
		}
		Trace.d("handleVack", "Finished validating now preparing Vanonym.");

		//step 5
		// first add the verified USL range to senders VSL.
		recVIB.getVLog().hashList.putAll(((TreeMap<Long, AccountHashEntry>)
				recUSL.getHashList()).subMap(recMyCert.getFromSeqNb(), true,
						recMyCert.getToSeqNb(),true));

		//also add received certificate for this validation portion
		recVIB.getVLog().certificateList.add(recMyCert);

		//now add this verified log to my VHT
		Node.getInfoBase().getVHT().put(source,	recVIB.getVLog());

		//step 6

		long newSeqNb=Node.generateSeqId();
		//enlarge payload as required
		String sendPayload = new String();
		int folds=Node.PAYLOAD_SIZE/Node.PAYLOAD.length();
		for (int i = 0; i <folds ; i++) {
			sendPayload+=Node.PAYLOAD;
		}
		while(sendPayload.length()%4!=0)
			sendPayload+="+";

		AnonymPayload anPayload=Node.newAnonymPayload(sendPayload);
		// here we split the encrypted message into two and send one part in anonym, and
		// another part in the key the receiver can only decrypt the msg if it has
		// the private key and concatenated the anonymPart+keyPart
		//NOTE: we might change this latter and send a cryptographic key
		String anonymPart= new String(anPayload.payload.substring(Node.KEY_LENGTH));
		String keyPart=new String(anPayload.payload.substring(0,Node.KEY_LENGTH));

		KeyContent kContent=new KeyContent(0,newSeqNb,//use 0 to update content later
				keyPart, source, Node.getId());
		Node.getULog().addKeyContents(kContent);
		// now prepare Vanonym
		VanonymContent vContent=new VanonymContent(anonymPart,sendCert,
				bCase.getEntry().getEntryID(),bCase.getEntry().getEntrySequence());

		AccountMsg vanonymMsg=new AccountMsg(operationId, MsgType.VANONYM,
				newSeqNb, 0, vContent, true);

		//add entry to ulog, 
		//NOTE: We assume no intermediary  node for now.
		Node.getULog().addOutEntry(vanonymMsg,source);
		//create Briefcase to send
		Briefcase newBcase=new Briefcase(Node.getULog().getLastEntry(),
				Node.getULog().getBeforeLastHash(),
				Node.getULog().getLastHash());

		// add to outQueue to send by client thread.
		Node.outQueue.add(newBcase);
		Trace.d("handleVack", "Vanonym added to outQueue.");


	}


}

