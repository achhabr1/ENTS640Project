import java.security.SecureRandom;
import java.util.*;
import java.net.*;
import java.io.*;

	/*

	*INIT Packet Structure

	________________________________
	| packet   |packet |  Integrity |
	| code	   | seq.  |	check	|
	|(2-bytes)|(2-byte)|__(2-byte)__|

	*Data Packet Structure
	____________________________________________________________
	| packet  |packet  |   length	|	payload    | integrity  |
	| code	  | seq.   |	        |	check	   |  check     |
	|(2-bytes)|(2-byte)|__(2-byte)__|__(40-byte)___|_(2-byte)___|

	*/
	public class Transmitter { 

		// method to convert and return short integer to byte array
		public static byte[] shortToByte(short short_Var) {

			byte[] byte_Var = new byte[2];
			byte_Var[0] = (byte) (short_Var >> 8);
			byte_Var[1] = (byte) short_Var;
			return byte_Var;
		}

		// method to generate encrypted and return a data stream packet of 48 bytes
		public static byte[] generateRC4_EncryptedDataStream(byte[] secretKey,
				byte[] nonce, byte[] payload) {

			byte[] rc4_Key = new byte[16];
			// creating 128-bit RC4 Key with nonce and secret key
			for (int i = 0; i < secretKey.length; i++) {
				rc4_Key[i * 2] = secretKey[i];
				rc4_Key[(i * 2) + 1] = nonce[i];
			}
			// Initialization Phase
			byte[] S = new byte[256];
			byte[] T = new byte[256];
			for (int i = 0; i < 256; i++) {
				S[i] = (byte) i;
				T[i] = rc4_Key[i % rc4_Key.length];
			}
			int j = 0;
			byte temp1, temp2;
			for (int i = 0; i < 256; i++) {
				j = (j + (S[i] & 0xFF) + (T[i] & 0xFF)) % 256;
				temp1 = S[i];
				S[i] = S[j];
				S[j] = temp1;
			}
			// Stream generation and encryption
			int k = 0, l = 0, count = 0;
			while (count < payload.length) {
				k = (k + 1) % 256;
				l = (l + (S[k] & 0xFF)) % 256;
				temp2 = S[k];
				S[k] = S[l];
				S[l] = temp2;
				int t = ((S[k] & 0xFF) + (S[l] & 0xFF)) % 256;
				int w = S[t];
				payload[count] = (byte) (payload[count] ^ w);
				count++;
			}
			return payload;
		}

		/*
		 * method to extract nonce and return corresponding byte array from IACK
		 * acknowledgment(argument of the method)
		 */
		public static byte[] extractNonce(byte[] init) {

			byte[] nonce = new byte[8];
			for (int i = 0; i < 8; i++) {
				nonce[i] = init[i + 4];
			}
			return nonce;
		}

		/*
		 * method to send and receive packets and return the corresponding byte
		 * array. method is handling both acknowledgments (IACK, DACK) and sending
		 * INIT and data packets
		 */
		public static byte[] timer(DatagramSocket socket1, int count,
				byte[] packet, InetAddress transmitIpAddress, int port,
				byte[] receivedPacketByte) throws IOException {

			boolean packetVerification;
			int timer = 1000;
			// creating the UDP packed to be sent
			DatagramPacket iack_PacketTemp = new DatagramPacket(receivedPacketByte,
					receivedPacketByte.length);

			// Start of loop to considering possible 4 retransmission

			loop1: while (count <= 4) {

				System.out.print("\nSending packet...");
				// calling method to send packet
				sendData(socket1, packet, transmitIpAddress, port);
				// setting timer
				socket1.setSoTimeout(timer);
				try {

					//System.out
						//	.println("\n"
							//		+ "\nReceiving the acknowledgement from the receiver...");
					// receive packet
					socket1.receive(iack_PacketTemp);
					// get byte array from packet
					receivedPacketByte = iack_PacketTemp.getData();
					// calling method to verify packet integrity
					packetVerification = processACK_Packet(receivedPacketByte,
							packet);
					// condition to process code according to packet verification
					// results
					// if true then exit while loop otherwise go to while loop with
					// increased counter
					
					if (packetVerification == false) {

						count++;
						// if retransmission count is 5 then exit with connection
						// failure message
						if (count == 5) {
							System.err
									.println("\nClient socket timeout! Exception message: Connection Failure");
							System.exit(0);
						}
						// resetting timer
						timer = timer + timer;
						System.out.println("\nTimer:" + timer);
						continue loop1;
					} else
						break loop1;
				}// end try block
				catch (IOException ee) {

					if (count == 4) {
						System.out.println("\nTimeout response:" + count);
						System.err
								.println("Client socket timeout! Exception message: Connection Failure");
						System.exit(0);
					} else {
						System.out.println("\nTimeout response:" + count);
						count++;
						// resetting timer
						timer = timer + timer;
						System.out.println("\nTimer:" + timer);
					}
				}// end catch block
			}// end while loop1
			receivedPacketByte = IntegrityBitGenertorTransmitter(receivedPacketByte);
			return receivedPacketByte;
		}

		// method to send packets
		public static void sendData(DatagramSocket clientSocket, byte[] packetByte,
				InetAddress address, int port) throws IOException {
			// create packet
			DatagramPacket sentPacket = new DatagramPacket(packetByte,
					packetByte.length, address, port);
			System.out.print("\nSent:" + Arrays.toString(packetByte));
			// send packet
			clientSocket.send(sentPacket);
		}

		// method to check integrity of acknowledgment packets (IACK and DACK)
		public static boolean processACK_Packet(byte[] ack, byte[] sequenceNumber) {

			boolean flag = false;
			// calling method to generate integrity check bits and put them in last
			// two positions of corresponding byte array
			boolean result = IntegrityBitGenertorReceiver(ack);
			// condition to identify IACK or DACK
			// IACK
			if (result == true) {
				if ((ack[0] == 0x00 && ack[1] == 0x01)) {
					if ((ack[2] == sequenceNumber[2] && ack[3] == sequenceNumber[3])) {
						flag = true;
						System.out.println("\nCorrect IACK");
					}
				} else if ((ack[0] == 0x00 && ack[1] == 0x04)) {
					if ((ack[2] == sequenceNumber[2] && ack[3] == sequenceNumber[3])) {
						flag = true;
						System.out.println("\nCorrect DACK");
					}
				}
			}  
			if(flag==false){
				System.out.println("\nIncorrect acknowledgement");
			}
				return flag;
		}

		/*
		 * method to calculate integrity bit and return the send packet byte with
		 * calculated field bytes at the end
		 */
		public static byte[] IntegrityBitGenertorTransmitter(byte[] ack) {

			int counter = 0;
			short temp = 0;

			while (counter < ack.length - 2) {
				short msb, lsb;
				// convert to short integer or 16 bit number
				msb = (short) (ack[counter] & 0x00ff);
				lsb = (short) (ack[counter + 1] & 0x00ff);
				short b = (short) ((msb << 8) + lsb);
				// XOR two bytes together
				temp = (short) (temp ^ b);
				counter = counter + 2;
			}
			ack[ack.length - 2] = (byte) (temp >> 8);
			ack[ack.length - 1] = (byte) temp;
			return ack;
		}

		// method to calculate integrity bit and return the received packet byte
		// with calculated field bytes at the end
		public static boolean IntegrityBitGenertorReceiver(byte[] ack) {

			int counter = 0;
			short temp = 0;
			boolean result = true;
			while (counter < ack.length) {
				short high, low;
				high = (short) (ack[counter] & 0x00ff);
				low = (short) (ack[counter + 1] & 0x00ff);
				short b = (short) ((high << 8) + low);
				temp = (short) (temp ^ b);
				counter = counter + 2;
			}
			if (temp != 0) {
				result = false;
			}
			// ack[ack.length - 2] = (byte) (temp >> 8);
			// ack[ack.length - 1] = (byte) temp;
			return result;
		}

		// method to create INIT packet and return the byte array
		public static byte[] generateINIT_Packet(byte[] sequenceNo) {

			byte[] initPacket = new byte[6];

			initPacket[0] = 0x00;
			initPacket[1] = 0x00;
			initPacket[2] = sequenceNo[0];
			initPacket[3] = sequenceNo[1];
			// calling method to generate and finalize INIT packet
			initPacket = IntegrityBitGenertorTransmitter(initPacket);
			return initPacket;
		}

		// generating data packet 48 byte blocks and returning the byte array
		public static byte[] generateDataPacketStream(byte[] data,
				short sequenceNo, short counter, int noOfDataBytes) {

			byte[] seqNum = new byte[2];
			byte[] dataPacket = new byte[48];
			short lastDataBlcokLength;
			int condition = noOfDataBytes / 40;// calculate the no of data blocks
												// required
			sequenceNo = (short) (sequenceNo + counter);
			seqNum = shortToByte(sequenceNo);
			lastDataBlcokLength = (short) (noOfDataBytes - condition * 40);// calculate
																			// the
			// check condition for last data block
			// data packet block formation with specified filed
			int j = 0;		
			if (counter != condition) {
				dataPacket[0] = 0x00;// normal data byte
				dataPacket[1] = 0x02;// normal data byte
				dataPacket[2] = seqNum[0];
				dataPacket[3] = seqNum[1];
				dataPacket[4] = 0;
				dataPacket[5] = 40;
				int temp = 6;
				int i = counter;

				for (j = i * 40; j < (i + 1) * 40; j++) {
					dataPacket[temp] = data[j];
					temp++;
				}

				if (j == noOfDataBytes) {
					dataPacket[0] = 0x00;// normal data byte	
					dataPacket[1] = 0x03;// normal data byte
				}// last data packet block
			}
			else if (counter == condition) {
					dataPacket[0] = 0x00;// last data block
					dataPacket[1] = 0x03;// last data block
					dataPacket[2] = seqNum[0];
					dataPacket[3] = seqNum[1];
					int i = counter;
					dataPacket[4] = (byte) (lastDataBlcokLength >> 8);
					dataPacket[5] = (byte) lastDataBlcokLength;
					int temp = 6;
					for (j = i * 40; j < (i + 1) * 40 - (40 - lastDataBlcokLength); j++) {
						dataPacket[temp] = data[j];
						temp++;
					}
				}

			// calling method to generate integrity bits and include them to last
			// two positions
			dataPacket = IntegrityBitGenertorTransmitter(dataPacket);
			return dataPacket;
		}

		// this function generates the 351 bytes of random data and return
		// corresponding byte array
		public static byte[] generateRandomData(byte[] data) {

			SecureRandom rand = new SecureRandom();
			rand.nextBytes(data);
			return data;
		}

		// This function generates the initial sequence number,sent in the INIT
		public static short initialSequenceNumber() {

			SecureRandom rand = new SecureRandom();
			short seq_num = (short) rand.nextInt();
			return seq_num;
		}

		public static void main(String[] args) throws Exception {

			final byte[] secretKeyArray = { 94, 14, 44, -109, -44, 119, 103, -84 };
			final int portNumber = 5004;
			final int noOfDataBytes = 351;
			byte[] initPacketByte = new byte[6];
			byte[] iackAcknowledgement = new byte[14];
			byte[] dackAcknowledgement = new byte[6];
			byte[] sequenceNumber = new byte[2];
			byte[] dataPacketByte = new byte[48];
			byte[] nonce = new byte[8];
			byte[] data = new byte[noOfDataBytes];
			int counter = 1;

			// generating and printing random data 351 bytes
			data = generateRandomData(data);
			System.out.print("\nPayload Data:\n" + Arrays.toString(data));

			// Initial Handshake Phase
			// INIT packet formation
			// generating 16 bit random sequence number
			short initSequenceNumber = initialSequenceNumber();
			sequenceNumber = shortToByte(initSequenceNumber);

			// INIT Packet creation
			initPacketByte = generateINIT_Packet(sequenceNumber);

			// IP address setting
			InetAddress address = InetAddress.getLocalHost();

			DatagramSocket transmitterSocket = new DatagramSocket();

			// 2-way Handshake process
			iackAcknowledgement = timer(transmitterSocket, counter,
					initPacketByte, address, portNumber, iackAcknowledgement);
			System.out.println("\nReceived INIT packet acknowledgement"+Arrays.toString(iackAcknowledgement));
			System.out.println("\nHanshake completed!!!!!!!!!!!!!");

			// Extracting nonce
			nonce = extractNonce(iackAcknowledgement);

			// Encrypting data byte stream using RC4 algorithm
			data = generateRC4_EncryptedDataStream(secretKeyArray, nonce, data);

			// Data transmission phase
			for (short i = 0; i < ((noOfDataBytes / 40) + 1); i++) {

				dataPacketByte = generateDataPacketStream(data, initSequenceNumber,
						i, noOfDataBytes);
				System.out.print("\nData Block:"+ Arrays.toString(dataPacketByte));
				dackAcknowledgement = timer(transmitterSocket, counter,
						dataPacketByte, address, portNumber, dackAcknowledgement);
				System.out.println("Received Data Packet acknowledgement:"+Arrays.toString(dackAcknowledgement));
				if (dataPacketByte[1] == 0x03) {
					break;
				}
			}// end for loop
			transmitterSocket.close();
		}// end main
	}// end Transmitter classclass

