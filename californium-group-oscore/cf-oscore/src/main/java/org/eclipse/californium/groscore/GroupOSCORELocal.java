package org.eclipse.californium.groscore;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map.Entry;

import org.eclipse.californium.core.Utils;
import org.eclipse.californium.groscore.ByteId;
import org.eclipse.californium.groscore.HashMapCtxDB;
import org.eclipse.californium.groscore.group.GroupCtx;
import org.eclipse.californium.groscore.group.GroupRecipientCtx;
import org.eclipse.californium.groscore.group.GroupSenderCtx;
public class GroupOSCORELocal {




	public static void printGroupCtx(GroupCtx ctx, HashMapCtxDB db) {

		GroupSenderCtx senderCtx = ctx.senderCtx;
		HashMap<ByteId, GroupRecipientCtx> recipientCtxMap = ctx.recipientCtxMap;

		byte[] senderID = senderCtx.getSenderId();
		List<GroupRecipientCtx> recipientIDs = new ArrayList<GroupRecipientCtx>();
		for (Entry<ByteId, GroupRecipientCtx> entry : recipientCtxMap.entrySet()) {
			recipientIDs.add(entry.getValue());
		}
		
		System.out.println("Sender ID: " + Utils.toHexString(senderID));
		System.out.println("Full key: " + senderCtx.ownPrivateKey.AsCBOR().toString());

		System.out.println("Recipient IDs: ");
		for(int i = 0 ; i < recipientIDs.size() ; i++) {
			System.out.println(Utils.toHexString(recipientIDs.get(i).getRecipientId()));
			System.out.println("Key: " + (recipientIDs.get(i).otherEndpointPubKey.AsCBOR().toString()));
		}
		

	}



}
