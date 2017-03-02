package fr.cnrs.liris.drim.AMS;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.TreeMap;


import fr.cnrs.liris.drim.AMS.Cryptography;
import fr.cnrs.liris.drim.AMS.Messaging.*;
import fr.cnrs.liris.drim.AMS.SecureLogging.AccountEntry;
import fr.cnrs.liris.drim.AMS.Tools.AMSTimer;
import fr.cnrs.liris.drim.AMS.Tools.Timing;
import fr.cnrs.liris.drim.AMS.Tools.Trace;
/**
 * @author Ali Shoker
 *
 */

public class SecureLogging implements Serializable{

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	static public enum EntryType {SEND, RECV;}

	public static int getHashIndex(List<AccountHashEntry> list, long seqNb){
		for (int i = 0; i < list.size(); i++) {
			if(list.get(i).getHashSequence()==seqNb)
				return i;
		}
		return -1;
	}

	public static int getEntryIndex(List<AccountEntry> list, long seqNb){
		for (int i = 0; i < list.size(); i++) {
			if(list.get(i).getEntrySequence()==seqNb)
				return i;
		}
		return -1;
	}

	static public class AccountValidInfoBase implements Serializable{

		/**
		 * 
		 */
		private static final long serialVersionUID = 1L;
		private AccountVSecureLog myVSL=null;// VSL log of the node with all certificates.
		private Map<Long,AccountVSecureLog> vht=null;// validated map of VSLs. Long corresponds to nodeId.
		//a list of VSL logs of other nodes; the elements of this table should have only one certificate each;

		public AccountValidInfoBase(AccountValidInfoBase newVIB)
		{
			myVSL= new AccountVSecureLog(newVIB.myVSL);
			vht=new TreeMap<Long, AccountVSecureLog>();
			for (Entry<Long,AccountVSecureLog> entry : newVIB.vht.entrySet()) {
				vht.put(entry.getKey(),new AccountVSecureLog(entry.getValue()));
			}

		}

		public AccountValidInfoBase()
		{
			myVSL= new AccountVSecureLog();
			vht=new TreeMap<Long, AccountVSecureLog>();

		}

		public AccountVSecureLog getVLog(){
			return myVSL;
		}

		public Map<Long,AccountVSecureLog> getVHT(){
			return vht;
		}

	}

	static public class AccountUSecureLog implements Serializable{

		/**
		 * 
		 */
		private static final long serialVersionUID = 1L;
		private Map<Long,AccountHashEntry> hashList=null;
		private List<AccountEntry> entryList=null;
		private List<Blacklist> blacklist=null;
		private List<KeyContent> keyContents=null;//holding the keys and destination of Anonym alive messages
		private Map<Long, List<Integer>> operationMap=null;


		public AccountUSecureLog(AccountUSecureLog newUSL){

			hashList=new TreeMap<Long,AccountHashEntry>();
			entryList=new ArrayList<AccountEntry>();
			blacklist=null;//new ArrayList<Blacklist>(newUSL.blacklist);
			keyContents=new ArrayList<KeyContent>();
			operationMap=new TreeMap<Long, List<Integer>>();

			List<Integer> list=null;

			for (Long id : newUSL.hashList.keySet()) 
				hashList.put(id, new AccountHashEntry(newUSL.hashList.get(id)));
			for (AccountEntry entry : newUSL.entryList) 
				entryList.add(new AccountEntry(entry));
			for (KeyContent content : newUSL.keyContents) 
				keyContents.add(new KeyContent(content));

			for (Long id : newUSL.operationMap.keySet()) {
				list=newUSL.operationMap.get(id);
				List<Integer> newList=new ArrayList<Integer>();
				for (int i = 0; i < list.size(); i++) 
					newList.add(list.get(i));

				operationMap.put(id,newList);
			}
		}

		public AccountUSecureLog(){

			hashList=new TreeMap<Long,AccountHashEntry>();
			entryList=new ArrayList<AccountEntry>();
			blacklist=new ArrayList<Blacklist>();
			keyContents=new ArrayList<KeyContent>();
			operationMap=new TreeMap<Long, List<Integer>>();
		}

		//use this upon sending USL
		public AccountUSecureLog(List<AccountEntry> entryLst,Map<Long, List<Integer>> opMap,Map<Long, AccountHashEntry> hashMap){

			hashList=hashMap;
			blacklist=null;
			keyContents=null;
			entryList=entryLst;//yes shadow
			operationMap=opMap;//new TreeMap<Long, List<Integer>>();

			/*List<Integer> list;
			for (Long id : opMap.keySet()) {
				 list = opMap.get(id);
				List<Integer> newList=new ArrayList<Integer>();
				for (int i = 0; i < list.size(); i++) 
					newList.add(list.get(i));

				operationMap.put(id,newList);
			}
			 */

		}

		public String getKeyByOp(long opId){
			for (Iterator<KeyContent> iterator = keyContents.iterator(); iterator.hasNext();) {
				if(( ((KeyContent) iterator.next()).getCorrId()==opId)){
					return ((KeyContent) iterator.next()).getKey();
				}
			}
			return null;
		}

		public String getKey(long seqId){
			for (int i = 0; i < keyContents.size(); i++) {
				if(keyContents.get(i).getSeqId()==seqId){
					return keyContents.get(i).getKey();
				}
			}
			return null;
		}

		public KeyContent getKeyContentByOp(long opId){
			for (Iterator<KeyContent> iterator = keyContents.iterator(); iterator.hasNext();) {
				if(( ((KeyContent) iterator.next()).getCorrId()==opId)){
					return ((KeyContent) iterator.next());
				}
			}
			return null;
		}

		public KeyContent getKeyContent(long seqId){

			for (int i = 0; i < keyContents.size(); i++) {
				if(keyContents.get(i).getSeqId()==seqId){
					return keyContents.get(i);
				}
			}
			return null;
		}


		//sent certificate by Valid sender contains first qnd last dead seq Ids
		// and getHashValue  null
		public AccountCertificate getYourValidCertificate(String lastVerifiedHash,
				String lastUslHash,  AccountCertificate certificate){
			AMSTimer timer=new AMSTimer();

			String allHashDigest=null;
			String previousHashValue=lastVerifiedHash;
			Long sum=Long.valueOf(0);
			Long seqId = null;
			
			timer.start();
			int fromEntryIndex=getEntryIndex(entryList, certificate.getFromSeqNb());
			int toEntryIndex=getEntryIndex(entryList, certificate.getToSeqNb());
			Trace.d("getYourValidCertificate", "getIndex time:"+timer.stop());
			
			timer.start();
			int size=entryList.size();
			for (int i = fromEntryIndex; i < size; i++) {
				seqId=entryList.get(i).entrySequence;
				previousHashValue=Cryptography.digestEntry(previousHashValue,
						seqId);
				if(i <= toEntryIndex)
					sum+=seqId;
			}
			Trace.d("getYourValidCertificate", "getIndex time:"+timer.stop());
			allHashDigest=Cryptography.digestMessage(String.valueOf(sum));
			if(allHashDigest==null){
				Trace.e(String.valueOf(Node.getId()), "getYourValidCertificate: Wrong all HashDigest.");
				return null;
			}


			AccountCertificate newCert=new AccountCertificate(certificate.getFromSeqNb(),
					certificate.getToSeqNb(),Node.getId(), allHashDigest);

			return newCert;
		}

		public long getLastDeadSeqId(){

			int beforeLastDeadIndex=entryList.size();// (last entry index + 1)
			int tmp;
			List<Integer> opList=null;

			for (Iterator<List<Integer>> iterator = getOperationMap().values().iterator();
					iterator.hasNext();) {

				opList=iterator.next();
				if(!isDead(opList.get(opList.size()-1))) {
					beforeLastDeadIndex=opList.get(0);
					break;
				}
			}

			//now iterate over non dead items, item by item
			for (int i = beforeLastDeadIndex+1; i < entryList.size()-1; i++) {

				if(isDead(i))
				{
					tmp=getOperationMap().get(entryList.get(i).getEntryID()).get(0);
					if(tmp<beforeLastDeadIndex)
						beforeLastDeadIndex=tmp;
				}
			}

			// get just the one before anonym
			return entryList.get(beforeLastDeadIndex-1).getEntrySequence();
		}

		/*
		 * checks whether a send anonym operation is correct or not recursively, start=true only when called from outside.
		 * i is the beginning of anonym messages index of the next call (recursive).
		 * indexes is the list of indexes in operationList, and anonyms is the list of anonym messages in indexes.
		 */

		public int isCompleteCorrectSend(List<Integer> indexes, int i, List<Integer> anonyms){

			try {
				if(entryList.get(indexes.get(i+1)).getEntryContent().getMsgType()==MsgType.ASK &&
						entryList.get(indexes.get(i+1)).getEntryContent().getMsgContent().
						getSeqId()==entryList.get(indexes.get(i)).getEntrySequence()){
					if(	entryList.get(indexes.get(i+2)).getEntryReceiver()==
							entryList.get(indexes.get(i+1)).getEntrySource()&&
							entryList.get(indexes.get(i+2)).getEntryContent().
							getMsgType()==MsgType.KEY){
						if(entryList.get(indexes.get(i+3)).getEntryContent().getMsgContent().
								getSeqId()==entryList.get(indexes.get(i+2)).getEntrySequence()&&
								entryList.get(indexes.get(i+3)).getEntryContent().getMsgType()==MsgType.ACK){
							return i;
						} else//did not receive ack, should send key in another anonym message
							if(entryList.get(indexes.get(i+3)).getEntryContent().getMsgType()==MsgType.ANONYM||
							entryList.get(indexes.get(i+3)).getEntryContent().getMsgType()==MsgType.VANONYM)
								return isCompleteCorrectSend(indexes, anonyms.get(i+1), anonyms);
							else return -1;

					}
					else return -1; // it should send a KEY if received ask
				}
				else
					if(entryList.get(indexes.get(i+1)).getEntryContent().getMsgType()==MsgType.ANONYM||
					entryList.get(indexes.get(i+1)).getEntryContent().getMsgType()==MsgType.VANONYM)
						return isCompleteCorrectSend(indexes, anonyms.get(i+1), anonyms);
					else return i;

			} catch (IndexOutOfBoundsException e) {
				return -1;
			}

		}

		/*
		 * checks whether a forward anonym operation is correct or not recursively, start=true only when called from outside.
		 * i is the beginning of anonym messages index of the next call (recursive).
		 */

		public int isCompleteCorrectForward(List<Integer> indexes, int i, List<Integer> anonyms){

			try {

				if(entryList.get(indexes.get(i+1)).getEntryContent().getMsgType()==MsgType.ASK &&
						entryList.get(indexes.get(i+1)).getEntryContent().getMsgContent().
						getSeqId()==entryList.get(indexes.get(i)).getEntryContent().getMsgSequence()){
					if(	entryList.get(indexes.get(i+2)).getEntryReceiver()==
							entryList.get(indexes.get(i+1)).getEntrySource()&&
							entryList.get(indexes.get(i+2)).getEntryContent().
							getMsgType()==MsgType.KEY){
						if(entryList.get(indexes.get(i+3)).getEntryContent().getMsgContent().
								getSeqId()==entryList.get(indexes.get(i+2)).
								getEntryContent().getMsgSequence()&&
								entryList.get(indexes.get(i+3)).getEntryContent()
								.getMsgType()==MsgType.ACK){
							return i;
						} 
						else return -1;

					}//punish if not received key, now punishment requires n=2 consecutive complete sends.
					else {
						int j;
						if((j=isCompleteCorrectForward(indexes, anonyms.get(i+1), anonyms))!=-1)
							return	isCompleteCorrectForward(indexes, anonyms.get(j+1), anonyms);
					}
				}//it should send ask
				else return -1;

			} catch (IndexOutOfBoundsException e) {
				return -1;
			}
			return -1;
		}

		/*
		 * checks whether log sender is correct by checking all the USL.
		 * Dead operations should be complete. Alive ones are not important since
		 * they will not be included in the certificate.
		 * the function returns -1 if the node is not correct otherwise it returns
		 * the index of entryList to which the certificate should be sent.
		 * Note: an additional work is done in this method to ensure that the certified
		 * log has contiguous dead operations (no overlapped Alive ops are found)
		 */
		public int isCorrectSenderAndForwarder(){

			int lastDeadIndex=-1;
			AccountEntry entry;
			List<Integer> opList=null;
			List<Integer> anonyms=new ArrayList<Integer>();


			for (Iterator<Long> iterator = getOperationMap().keySet().iterator(); iterator.hasNext();) {

				opList=getOperationMap().get(iterator.next());
				anonyms.clear();

				if(isDead(opList.get(0))) { 
					for (int i = 0; i < opList.size()-1; i++) {
						if(entryList.get(opList.get(i)).getEntryContent().getMsgType()==MsgType.ANONYM ||
								entryList.get(opList.get(i)).getEntryContent().getMsgType()==MsgType.VANONYM)
							anonyms.add(i);
					}
					if(entryList.get(opList.get(0)).getEntryType()==EntryType.RECV){
						if(isCompleteCorrectForward(opList, 0, anonyms)!=anonyms.size()-1)
							return -1;
					}
					else//SEND
						if(isCompleteCorrectSend(opList, 0, anonyms)!=anonyms.size()-1)
							return -1;
				}
				else{
					lastDeadIndex=opList.get(0);
					break;
				}
			}

			//now iterate over non dead items, item by item
			int tmp;
			for (int i = lastDeadIndex+1; i < entryList.size()-1; i++) {
				if(isDead(i))
				{
					tmp=getOperationMap().get(entryList.get(i).getEntryID()).get(0);
					if(tmp<lastDeadIndex)
						lastDeadIndex=tmp;
				}
			}

			return lastDeadIndex--;//return just the one before anonym

		}




		public AnonymContent getAnonymContent(long opId, Boolean isAlive){

			List<Integer> opList=operationMap.get(opId);
			AccountEntry entry=null;
			for (int i = 0; i < opList.size(); i++) {
				entry=entryList.get(opList.get(i));
				if(isAlive(opId)==isAlive)
					if(entry.getEntryContent().getMsgType()==MsgType.ANONYM)
						return (AnonymContent) entry.getEntryContent().getMsgContent();
					else if (entry.getEntryContent().getMsgType()==MsgType.VANONYM)
						return (AnonymContent) entry.getEntryContent().getMsgContent();
			}

			return null;

		}

		public long getFinalDest(long seqID){
			for (Iterator<KeyContent> iterator = keyContents.iterator(); iterator.hasNext();) {
				if( iterator.next().getSeqId()==seqID){
					return ((KeyContent) iterator.next()).getDestination();
				}
			}
			return 0;
		}

		//avoid this, it is costly
		//returns if operation is alive, i,e, at least one msg in operation is not timedOut.
		public Boolean isAlive(long opId){

			List<Integer> opList=operationMap.get(opId);
			long lastTime=entryList.get(entryList.size()-1).getTime();

			if(opList!=null)
				for (int i = 0; i < opList.size() ; i++) {
					if(lastTime < (entryList.get(opList.get(i)).getTime()+Timing.ASK_WAITING_TIME))
						return true;
				}
			return false;
		}

		public Boolean isDead(int index){

			//int index=operationMap.get(opId).get(operationMap.get(opId).size()-1);//last entry in operation
			long lastTime=entryList.get(entryList.size()-1).getTime();//last entry time in log

			if(lastTime >= (entryList.get(index).getTime()+Timing.ASK_WAITING_TIME))
				return true;
			return false;
		}


		public Boolean containsMsg(long opId, MsgType msgType,EntryType entryType,  long source, Boolean isAlive){

			List<Integer> op=operationMap.get(opId);
			AccountEntry entry;
			for (int i = 0; i < op.size(); i++) {
				entry=entryList.get(op.get(i));
				if( entry.getEntryType()==entryType &&
						entry.getEntrySource()==source &&
						entry.getEntryContent().getMsgType()==msgType &&
						isAlive(opId)==isAlive)
					return true;
			}

			return false;
		}

		public Boolean containsMsg(long opId, long seqId, MsgType msgType,
				EntryType entryType, long source, Boolean isAlive){

			List<Integer> op=operationMap.get(opId);
			AccountEntry entry;
			for (int i = 0; i < op.size(); i++) {
				entry=entryList.get(op.get(i));
				if( entry.getEntrySequence()==seqId &&
						entry.getEntrySource()==source &&
						entry.getEntryType()==entryType &&
						entry.getEntryContent().getMsgType()==msgType &&
						isAlive(opId)==isAlive)
					return true;
			}

			return false;
		}


		public Boolean containsFinalMsg(long opId,long seqId, MsgType msgType,
				EntryType entryType, long source, Boolean isAlive){

			List<Integer> opMap=operationMap.get(opId);
			AccountEntry entry=entryList.get(opMap.get(opMap.size()-1));
			if(entry.getEntrySequence()==seqId &&
					entry.getEntrySource()==source &&
					entry.getEntryContent().getMsgType()==msgType &&
					entry.getEntryType()==entryType && isAlive(opId)==isAlive)
				return true;

			return false;
		}



		public Map<Long,AccountHashEntry> getHashList(){
			return hashList;
		}
		public List<AccountEntry> getEntryList(){
			return entryList;
		}
		public List<KeyContent> getKeyContentList(){
			return keyContents;
		}
		public List<Blacklist> getBlackList(){
			return blacklist;
		}

		public TreeMap<Long, List<Integer>> getOperationMap(){
			return (TreeMap<Long, List<Integer>>) operationMap;
		}


		public AccountEntry getLastEntry(){
			if(!entryList.isEmpty())
				return entryList.get(entryList.size()-1);
			else return null;
		}
		
		public AccountHashEntry getLastHash(){
			if(!hashList.isEmpty())
				return ((TreeMap<Long, AccountHashEntry>) hashList).lastEntry().getValue();
			else return new AccountHashEntry(0, "", 0);
		}	

		
		public AccountHashEntry getBeforeLastHash(){
			TreeMap<Long, AccountHashEntry> map=(TreeMap<Long, AccountHashEntry>) hashList;
			if(hashList.size()>=2)
				return map.lowerEntry(map.lastKey()).getValue();
			else return new AccountHashEntry(0, "", 0);
		}	

		/*	public void addEntry(AccountEntry entry){
			entryList.add(entry);
			AccountHashEntry newHash=new AccountHashEntry(entry.getEntrySequence(), 
					Cryptography.digestEntry(hashList.getLast().getHashContent(), entry),
					entry.getEntrySource());
			hashList.add(newHash);

		}
		 */

		public void addKeyContents(KeyContent keyContent){

			keyContents.add(new KeyContent(keyContent));
		}

		public void removeKeyContents(long seqId){

			for (Iterator<KeyContent> iterator = keyContents.iterator(); iterator.hasNext();) {
				if(iterator.next().getSeqId()==seqId)
					iterator.remove();
			}
		}

		public int getLastDeadIndex(Long opId){

			int last=-1;
			try {
				List<Integer> list=getOperationMap().get(opId);
				last=list.get(list.size()-1);

			} catch (IndexOutOfBoundsException e) {
				// TODO: handle exception
				e.printStackTrace();
				return -1;
			}

			return last;
		}

		//dont use this too much, it is not efficient
		public int getIndexOfSeqId(Long seqId){

			try {
				Long[] list=(Long[]) hashList.keySet().toArray();
				// do it reversely better, most probably index is at the end
				for (int i = list.length; i >=0; i--) {
					if(list[i]==seqId) return i;
				}

			} catch (IndexOutOfBoundsException e) {
				// TODO: handle exception
				e.printStackTrace();
				return -1;
			}

			return -1;
		}

		//returns the new operationId to use in handle, or 0 if failed to add
		public long addInEntry(AccountMsg msg, Long source){

			long newSeqNb=0;
			long newOpId=0;
			//update the sequence nb and operation nb and then add to log

			long opId=msg.getMsgContent().getCorrId();
			long seqId=msg.getMsgContent().getSeqId();

			switch (msg.getMsgType()) {
			case ASK:
				if(containsFinalMsg(opId,seqId, MsgType.ANONYM, EntryType.SEND, Node.getId(), true) ||
						containsFinalMsg(opId,seqId, MsgType.VANONYM,EntryType.SEND,  Node.getId(),true)){
					newOpId=opId;
					break;
				}
			case KEY:
				if(containsFinalMsg(opId,seqId, MsgType.ASK, EntryType.SEND, Node.getId(), true)){
					newOpId=opId;
					break;
				}
			case ACK:
				if(containsFinalMsg(opId,seqId, MsgType.KEY, EntryType.SEND, Node.getId(), true)){
					newOpId=opId;
					break;
				}
			case VACK:
				if(containsFinalMsg(opId,seqId, MsgType.VALID, EntryType.SEND, Node.getId(), true)){
					newOpId=opId;
					break;
				}
			case VANONYM:
				if(containsFinalMsg(opId,seqId, MsgType.VACK, EntryType.SEND, Node.getId(), true)){
					newOpId=opId;
					break;
				}
			case ANONYM:
			case VALID:
				newOpId=Node.generateOpId();//anonym or valid take a new operation id.
				break;
			default:
				break;
			}

			if(newOpId!=-1){
				newSeqNb=Node.generateSeqId();
				AccountEntry newEntry=new AccountEntry(newOpId, EntryType.RECV, newSeqNb, 0,
						source,Node.getId(), msg);
				AccountHashEntry newHash=new AccountHashEntry(newSeqNb, 
						Cryptography.digestEntry(getLastHash().getHashContent(),
								newEntry.entrySequence),
						source);

				entryList.add(newEntry);

				if(newOpId==opId)//add index of last entry to op
					operationMap.get(newOpId).add(entryList.size()-1);
				else {// new operation
					List<Integer> list=new ArrayList<Integer>();
					list.add(entryList.size()-1);
					operationMap.put(newOpId,list);
				}

				hashList.put(newSeqNb,newHash);

			} else{
				Trace.e("AddEntry", "Add into USL failed.");
				return -1;
			}

			return newOpId;//returns 0 if not added
		}

		public long addOutEntry(AccountMsg msg, Long toNode){

			long opId=msg.getMsgID();
			long seqId=msg.getMsgSequence();

			try {
				AccountEntry newEntry=new AccountEntry(opId, EntryType.SEND, seqId, 0,
						Node.getId(),toNode, msg);
				//Trace.d("addOutEntry", "before adding to entryList.");
				AccountHashEntry newHash=new AccountHashEntry(seqId, 
						Cryptography.digestEntry(getLastHash().getHashContent(),
								newEntry.entrySequence),
						Node.getId());

				entryList.add(newEntry);

				if(operationMap.containsKey(opId))//add index of last entry to op
					operationMap.get(opId).add(entryList.size()-1);
				else {// new operation
					List<Integer> list=new ArrayList<Integer>();
					list.add(entryList.size()-1);
					operationMap.put(opId,list);
				}

				hashList.put(seqId,newHash);

				return opId;//returns 0 if not added

			} catch (Exception e) {
				Trace.e("addOutEntry", "Failed to add.");
				e.printStackTrace();
				return 0;
			}

		}

	}

	static public class Blacklist implements Serializable{
		/**
		 * 
		 */
		private static final long serialVersionUID = 1L;
		private ArrayList<Long> nodeIds=null;
		private ArrayList<Briefcase> proofs = null;
		private ArrayList<Misbehavior> misbehavior=null;

		public Blacklist(Blacklist blacklist){
			for (Iterator<Long> iterator = blacklist.nodeIds.iterator(); iterator.hasNext();) {
				nodeIds.add((Long) iterator.next());
				proofs.add(new Briefcase(blacklist.proofs.iterator().next()));
				misbehavior.add(blacklist.misbehavior.iterator().next());

			}
		}

		public Blacklist(){

			nodeIds=new ArrayList<Long>();
			proofs=new ArrayList<Briefcase>();
			misbehavior=new ArrayList<Misbehavior>();

		}


		public void add(long id, Briefcase proof, Misbehavior misbehavior){
			nodeIds.add(id);
			proofs.add(proof);
			this.misbehavior.add(misbehavior);
		}

		public Boolean contains(long id){
			return nodeIds.contains(id);
		}
	}
	static public class AccountVSecureLog implements Serializable {

		/**
		 * 
		 */
		private static final long serialVersionUID = 1L;
		public Map<Long, AccountHashEntry> hashList = null;
		public List<AccountCertificate> certificateList = null;// use list since certificates are not too
		//much so it does not harm performance

		public AccountVSecureLog(AccountVSecureLog newVSL) {

			hashList= new TreeMap<Long, AccountHashEntry>();
			for (Entry<Long, AccountHashEntry> entry : newVSL.hashList.entrySet()) {
				hashList.put(entry.getKey(), new AccountHashEntry(entry.getValue()));
			}

			certificateList=new ArrayList<AccountCertificate>();
			for (Iterator<AccountCertificate> iterator = newVSL.certificateList.iterator();
					iterator.hasNext();) {
				certificateList.add(iterator.next());
			}			

		}

		public AccountVSecureLog() {

			hashList= new TreeMap<Long, AccountHashEntry>();
			certificateList=new ArrayList<AccountCertificate>();
		}

		//return false if Certificate is wrong
		
		public Boolean addVerifiedUSL(AccountCertificate cert){

			AccountVSecureLog myVSL=Node.getInfoBase().myVSL;
			AccountUSecureLog myUSL=Node.getULog();
			Long toSeqNb=cert.getToSeqNb();

			TreeMap<Long, AccountHashEntry> uslHashMap=(TreeMap<Long, AccountHashEntry>) myUSL.hashList;
			TreeMap<Long, List<Integer>> opMap=(TreeMap<Long, List<Integer>>) myUSL.operationMap;

			if(cert.getHashValue().equals(Cryptography.digestHashMap(
					uslHashMap.headMap(cert.getToSeqNb(), true)))){
				//copy verified usl.hashlist to vsl
				for (Entry<Long, AccountHashEntry> entry : uslHashMap.headMap(
						toSeqNb, true).entrySet()) 				
					myVSL.hashList.put(entry.getKey(), new AccountHashEntry(entry.getValue()));

				myVSL.certificateList.add(cert);

				// hashes and entries to delete......
				int offset=0;
				uslHashMap.headMap(toSeqNb, true).clear();
				for (Iterator<AccountEntry> iterator = myUSL.entryList.iterator(); iterator
						.hasNext();) {
					if(iterator.next().entrySequence==toSeqNb)
					{
						iterator.remove();
						offset++;
						break;
					}
					else iterator.remove();
					offset++;

				}

				Trace.d("addVerifiedUSL", "Validating and Deleting "+offset+" log entries.");
				// Delete the operationMap here until the first entry (exclusive) in
				//entryList since it is the first alive now
				opMap.headMap(myUSL.entryList.get(0).getEntryID()).clear();
				//now decrement offset to keep correct mapping to entryList
				//TODO: change entyList to LinkedHashMap
				for (List<Integer> list : opMap.values()) {
					for (int i = 0; i < list.size(); i++) 
						list.set(i, list.get(i)-offset);
				}

				return true;
			}

			return false;
		}

		//returns true if the certificates match the log
		// returns false if not, then the sender is miss-behaving.
	
		public boolean isValidVSL(){

			List<AccountCertificate> certList=this.certificateList;
			TreeMap<Long, AccountHashEntry> hashTree= (TreeMap<Long,AccountHashEntry>) this.hashList;


			for (AccountCertificate cert : certList)
				if(!Cryptography.digestHashMap(
						hashTree.subMap(cert.getFromSeqNb(), true, cert.getToSeqNb(), true)).
						equals(cert.getHashValue()))
					return false; //this node miss-behaved

			return true;
		}

		//return true if all the saved challenges are in the node
		// if returns false, then nodeId is miss-behaving not the sender
		public Boolean challenge(Long nodeId){

			List<AccountHashEntry> chList= 
					(List<AccountHashEntry>) Node.getChalengeMap().get(nodeId);
			if(chList!=null && hashList!=null && hashList.size()>0){
				for (AccountHashEntry entry : chList)
					if(!hashList.containsKey(entry) ||
							!hashList.get(entry.hashSequence).hashContent.equals(entry.hashContent))
						return false;
			}

			return true;

		}


	}

	static public class AccountEntry implements Serializable{

		/**
		 * 
		 */
		private static final long serialVersionUID = 1L;
		/**
		 * 
		 */


		private long entryID=0;// entry identifier
		private long time;//sending time
		private EntryType entryType=null; // entry type, SEND or RECV.
		private long entrySequence=0;// entry sequence number in the log.
		private int entrySize=0;// size of the entry contents entryContent in bytes
		private AccountMsg entryContent=null;// entry content usually an AccountMsg
		private long entrySource;// msg sender
		private long entryReceiver;// msg sender

		public AccountEntry(AccountEntry newEntry) {
			entryID=newEntry.entryID;
			time=newEntry.time;
			entryType=newEntry.entryType;
			entrySequence=newEntry.entrySequence;
			entrySize=newEntry.entrySize;
			entrySource=newEntry.entrySource;
			entryReceiver=newEntry.entryReceiver;
			entryContent= new AccountMsg(newEntry.entryContent);
		}
		public AccountEntry(long id,EntryType type,long seqNb,int size,long source,long receiver,AccountMsg msg) {
			entryID=id;
			time=System.currentTimeMillis();// if time is not
			//equal to current time +Timing.ASK_WAITING_TIME, then the entry is dead.
			entryType=type;
			entrySequence=seqNb;
			entrySize=size;
			entrySource=source;
			entryReceiver=receiver;
			entryContent= new AccountMsg(msg);
		}		

		public void setEntryID(long newEntryId) {this.entryID=newEntryId;}
		public long getEntryID() {return entryID;}

		public void setTime(long newTime) {this.time=newTime;}
		public long getTime() {return time;}

		public void setEntryType(EntryType newEntryType) {this.entryType=newEntryType;}
		public EntryType getEntryType() {return entryType;}

		public void setEntrySequence(long newEntrySequence) {this.entrySequence=newEntrySequence;}
		public long getEntrySequence() {return entrySequence;}

		public void setEntrySize(int newEntrySize) {this.entrySize=newEntrySize;}
		public int getEntrySize() {return entrySize;}

		public void setEntryContent(AccountMsg newEntryContent) {this.entryContent= new AccountMsg(newEntryContent);}
		public AccountMsg getEntryContent() {return entryContent;}

		public void setEntrySource(long newEntrySource) {this.entrySource=newEntrySource;}
		public long getEntrySource() {return entrySource;}

		public void setEntryReceiver(long entryReceiver) {this.entryReceiver=entryReceiver;}
		public long getEntryReceiver() {return entryReceiver;}

		public String toString(){
			return String.valueOf(entryID)+
					String.valueOf(entrySequence)+
					String.valueOf(entrySource)+
					String.valueOf(entryType)+
					entryContent.toString();

		}
	}

	static public class AccountHashEntry implements Serializable{


		/**
		 * 
		 */
		private static final long serialVersionUID = 1L;
		private long hashSequence=0;// hash sequence equivalent to sequence number of AccountEntry 
		private String hashContent=null;// hash content usually a hash of AccountEntry
		private long hashSource;// hash sender as in AccountEntry Source

		public void setHashSequence(long newHashSequence) {this.hashSequence=newHashSequence;}
		public long getHashSequence() {return hashSequence;}

		public void setHashContent(String newHashContent) {this.hashContent=newHashContent;}
		public String getHashContent() {return hashContent;}

		public void setHashSource(long newHashSource) {this.hashSource=newHashSource;}
		public long getHashSource() {return hashSource;}

		public AccountHashEntry(AccountHashEntry newHashEntry){
			hashSequence= newHashEntry.hashSequence;
			hashContent = newHashEntry.hashContent;
			hashSource= newHashEntry.hashSource;
		}

		public AccountHashEntry(long newHashSequence,String newHashContent, long source){
			hashSequence= newHashSequence;
			hashContent = newHashContent;
			hashSource= source;
		}

		public void copy(AccountHashEntry newHashEntry){
			hashSequence= newHashEntry.hashSequence;
			hashContent = newHashEntry.hashContent;
			hashSource= newHashEntry.hashSource;
		}

		public Boolean isEqual(AccountHashEntry newHashEntry){
			if(hashContent.equals(newHashEntry.hashContent)&&
					hashSequence==newHashEntry.hashSequence&&
					hashSource==newHashEntry.hashSource){
				return true;
			}
			else
				return false;
		}


	}

	static public class AccountCertificate implements Serializable, Cloneable{


		/**
		 * 
		 */
		private static final long serialVersionUID = 1L;
		private long fromSeqNb;// certified from AccountHAshEntry sequence number in VSL. 
		private long toSeqNb;// certified to AccountHAshEntry sequence number in VSL. 
		private long certificateSource;// certificate sender (the validator node)
		private String sectionHashValue=null;// the hash value of all log section hashes starting
		//from fromHashEntry until toHashEntry

		public void setFromSeqNb(long fromSeq) {fromSeqNb=fromSeq;}
		public long getFromSeqNb() {return fromSeqNb;}

		public void setToSeqNb(long toSeq) {toSeqNb=toSeq;}
		public long getToSeqNb() {return toSeqNb;}

		public void setCertificateSource(long newCertificateSource) 
		{this.certificateSource=newCertificateSource;}
		public long getCertificateSource() {return certificateSource;}

		public void setHashValue(String hashValue) 
		{this.sectionHashValue=hashValue;}
		public String getHashValue() {return sectionHashValue;}

		public String toString(){
			return String.valueOf(fromSeqNb)+
					String.valueOf(toSeqNb)+
					String.valueOf(certificateSource)+
					sectionHashValue;
		}
		public AccountCertificate(AccountCertificate newCertificate) {
			fromSeqNb= newCertificate.fromSeqNb;
			toSeqNb= newCertificate.toSeqNb;
			certificateSource= newCertificate.certificateSource;
			sectionHashValue= newCertificate.sectionHashValue;
		}

		public AccountCertificate(long fromSeq, long toSeq, 
				long newCertificateSource, String newSectionHashValue) {
			fromSeqNb= fromSeq;
			toSeqNb= toSeq;
			certificateSource= newCertificateSource;
			sectionHashValue= newSectionHashValue;
		}

	}


}
