///comments for byte to short and short to byte conversion

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.util.Arrays;
import java.util.Random;

public class Receiver {

	// this method takes in arrays of bytes of size 2 and convert them into a 16
	// bit Short type variable
	public static short byte_To_Short(byte[] byte_Var) {
		/*
		 * Initializing and Declaring short_Var,the short of the 2 byte array
		 */
		short short_Var = 0;

		short high = (short) (byte_Var[0] & 0x00ff);

		short low = (short) (byte_Var[1] & 0x00ff);

		short_Var = (short) ((high << 8) + low);

		return short_Var;
	}

	/*
	 * this takes in the Iack packet and assigns 8random bytes to its Nonce
	 * field This method return an 8 byte random nonce
	 */
	public static byte[] generate_Nonce(){
		// creating object random_Byte of Random class
		Random random_Byte = new Random();
		// Declaring variable to hold and return the randomly generated values
		byte[] random_Nonce = new byte[8];
		// creating random bytes using nextBytes method of random class
		random_Byte.nextBytes(random_Nonce);
		// returning the values
		return random_Nonce;
	}

	/*
	 * This method receives packets sent from transmitter,and take decision
	 * based on their integrity test,packet code and hand shake flag
	 */
	public static byte[] recievePacket(DatagramSocket serverSocket,
			byte[] data, int counter, byte[] nonce, byte[] sequence_num,
			int hand_shake_flag) throws IOException {

		/*
		 * declaring byte array of size 48 to receive data packets,irrespective
		 * of the their size which can be 6 or 48
		 */
		final byte[] secretKeyArray = { 94, 14, 44, -109, -44, 119, 103, -84 };

		byte[] temp = new byte[48];
		// declaring byte array to store INIT packet
		byte[] init = new byte[6];
		// declaring byte array to store IACK packet
		byte[] iack = new byte[14];
		// declaring byte array to store DACK packet
		byte[] dack = new byte[6];
		// declaring object receivePacket of DatagramPacket class
		DatagramPacket receivePacket = new DatagramPacket(temp, temp.length);
		// receiving packet from transmitter ......
		serverSocket.receive(receivePacket);
		// extracting data from received packet
		temp = receivePacket.getData();
		// applying integrity Check on the received packet
		boolean decision= integrityBitGenertorReceiver(temp);
		/*
		 * checks if last two bytes of the received packet after integrity test
		 * are equal to zero or not
		 */
		if (decision) {
			// check code of the packet,if 0h00,then extract first 6 bytes
			if (temp[0] == 0x00 && temp[1] == 0x00) {
				for (int i = 0; i < 6; i++){
					init[i] = temp[i];// extracting byte by byte through looping
				}
				
					// extracting sequence No.of the packet received
					sequence_num[0] = init[2];
					sequence_num[1] = init[3];
					// calling method to generate Iack packet
					iack = generate_Iack_packet(init, iack, nonce);
					// displaying generated nonce
					System.out
							.print("\nnonce=" + Arrays.toString(nonce) + "\n");
					// displaying received init packet
					System.out.print("recieved init packet :"
							+ Arrays.toString(init) + "\n");
					// sending the corresponding iack
					send_Data(receivePacket, serverSocket, iack);
			}
			// check code of the packet ,to know its data packets or not
			else if (temp[0] == 0x00 && (temp[1] == 0x02 | temp[1] == 0x03)) {
				System.out.print("\nrecieved data packet :"
						+ Arrays.toString(temp) + "\n");
				if (check_Data_Packet(temp, sequence_num, hand_shake_flag) == 0) {

					// ------------------- handshake
					// complete----------------------//
					/*
					 * if received the first data packet correctly , then
					 * handshake is complete
					 */
					hand_shake_flag = 1;
					// ------------------------------------------------------------//
					/*
					 * extracting sequence no. of the data packet would be used
					 * for discarding out of sequence packets
					 */
					sequence_num[0] = temp[2];
					sequence_num[1] = temp[3];
					// calling generate dack method
					dack = generate_Dack_packet(temp, dack);
					// sending the dack.....
					send_Data(receivePacket, serverSocket, dack);
					/*
					 * calling payload methhos to extract the payload from data
					 * packets
					 */
					payload(data, temp, counter);
					// incrementing counter to receive next packet
					counter++;

					/*
					 * if the packet received is last then displaying the
					 * decrypt data
					 */
					if (temp[1] == 0x03) {
						data = generate_RC4encrypted_data_stream(
								secretKeyArray, nonce, data);
						System.out.println("\n\nPyload Data:" + Arrays.toString(data));
					}

					/*
					 * recursively calling the receive function to accept next
					 * packet
					 */
					recievePacket(serverSocket, data, counter, nonce,
							sequence_num, hand_shake_flag);

				}

				/*
				 * if packet check fails,then receive it againcalling receive
				 * function for it again
				 */

				else {

					recievePacket(serverSocket, data, counter, nonce,
							sequence_num, hand_shake_flag);

				}

			}

		}

		// if integrity test fails then receive packet again
		else

		{
			recievePacket(serverSocket, data, counter, nonce, sequence_num,
					hand_shake_flag);

		}
		return data;

	}

	public static byte[] generate_RC4encrypted_data_stream(byte[] secretKey,
			byte[] nonce, byte[] payload) {

		byte[] RC4key = new byte[16];

		// creating 128-bit RC4 Key

		for (int i = 0; i < secretKey.length; i++) {

			RC4key[i * 2] = secretKey[i];

			RC4key[(i * 2) + 1] = nonce[i];

		}

		// Initialization Phase

		byte[] S = new byte[256];

		byte[] T = new byte[256];

		for (int i = 0; i < 256; i++) {

			S[i] = (byte) i;

			T[i] = RC4key[i % RC4key.length];

		}

		int j = 0;

		byte temp1, temp2;

		for (int i = 0; i < 256; i++) {

			j = (j + (S[i] & 0xFF) + (T[i] & 0xFF)) % 256;

			temp1 = S[i];

			S[i] = S[j];

			S[j] = temp1;

		}

		// Stream generation and encrypted data formation

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
	 * This method takes in data byte array , Datagrampacket and Datagramsocket
	 * as arguments and send the packet to the receiver
	 */
	public static void send_Data(DatagramPacket receivePacket,

	DatagramSocket serverSocket, byte data[]) throws IOException {

		DatagramPacket sentPacket = new DatagramPacket(data, data.length);

		InetAddress clientAddress = receivePacket.getAddress();

		int clientPort = receivePacket.getPort();

		sentPacket.setAddress(clientAddress); // destination IP address

		sentPacket.setPort(clientPort); // destination port number

		sentPacket.setLength(data.length); // actual data length

		System.out.print("sent:" + Arrays.toString(data) + "\n");

		serverSocket.send(sentPacket);

	}

	// this method checks the validity of the Init packet received
	public static int check_Init_packet(byte[] init) {

		/*
		 * declaring variable to store the validity check result 1 for pass and
		 * 0 for fail
		 */
		int decision_Flag = 1;

		// storing length of the inti packet
		int len = init.length;

		if (init[len - 2] == 0x00 && init[len - 1] == 0x00) {

			System.out.print("recieved init can be accepted \n");

			decision_Flag = 0;// pass

		} else {

			System.out.print("recieved init cannot be accepted \n");

			decision_Flag = 1;// fail

		}

		return decision_Flag;

	}

	/*
	 * this method applies integrity check on messages to be sent over the
	 * network
	 */

	public static int check_Data_Packet(byte[] data_packet, byte[] sequence_no,
			int hand_shake_flag) {

		int decision_Flag = 0;
		/*
		 * convert previous sequence no.to short for doing arithmetic operations
		 */
		short prev_Seq_Num = byte_To_Short(sequence_no);
		// declaring temperory byte to store current sequence no.
		byte[] temp = new byte[2];

		temp[0] = data_packet[2];
		temp[1] = data_packet[3];
		/*
		 * convert current sequence no.to short for doing arithmetic operations
		 */
		short next_Seq_Num = byte_To_Short(temp);

		/*
		 * if handshake flag is 0 then first data packet is received is first
		 * and its sequence o ,is compared to sequence no. of init packetelse
		 * the sequence no. is compared with (prev sequence no.1+1)s
		 */
		if (hand_shake_flag == 1) {
			if (next_Seq_Num == (prev_Seq_Num + 1)
					|| next_Seq_Num == (prev_Seq_Num)) {
				System.out.print("Data Packet can be accepted\n");
				decision_Flag = 0;// pass
			}

			else {

				System.out.print("Data Packet cannot be accepted\n");

				decision_Flag = 1;// fail

			}
		} else {

			if (next_Seq_Num == prev_Seq_Num) {

				System.out.print("Data Packet can be accepted\n");
				decision_Flag = 0;// pass

			}

			else {

				System.out.print("Data Packet cannot be accepted\n");

				decision_Flag = 1;// fail

			}

		}
		return decision_Flag;

	}

	/*
	 * This method applies integrity check on the received messages excluding
	 * the last two bytes
	 */

	public static byte[] integrityBitGenertorTransmitter(byte[] ack) {
		// variable for looping
		int counter = 0;

		short temp = 0;
		/*
		 * declaring temporary variable for storing 16 bit conversion of 2 8
		 * bytes
		 */
		while (counter < ack.length - 2) {

			short high, low;

			high = (short) (ack[counter] & 0x00ff);

			low = (short) (ack[counter + 1] & 0x00ff);

			short b = (short) ((high << 8) + low);

			temp = (short) (temp ^ b);

			counter = counter + 2;

		}

		ack[ack.length - 2] = (byte) (temp >> 8);

		ack[ack.length - 1] = (byte) temp;

		return ack;

	}

	/*
	 * This method applies integrity check on the received messages including
	 * the last two bytes
	 */
	public static boolean integrityBitGenertorReceiver(byte[] packet) {
		// variable for looping
		int counter = 0;
		// variable
		short temp = 0;
		/*
		 * declaring temporary variable for storing 16 bit conversion of 2 8
		 * bytes
		 */
		
		short short_Var = 0;

		boolean decision=false;
		while (counter < packet.length) {

			short high, low;

			high = (short) (packet[counter] & 0x00ff);

			low = (short) (packet[counter + 1] & 0x00ff);

			short_Var = (short) ((high << 8) + low);

			temp = (short) (temp ^ short_Var);

			counter = counter + 2;

		}

		packet[packet.length - 2] = (byte) (temp >> 8);

		packet[packet.length - 1] = (byte) temp;

		

	
		if(packet[packet.length - 1] == 0x00 && packet[packet.length - 2] == 0x00)
		{
			decision=true;
		}
	
	
	return decision;
	
	}

	public static byte[] generate_Iack_packet(byte[] init, byte[] iack,

	byte[] nonce) {

		//assigning the code for packet type

		iack[0] = 0x00;

		iack[1] = 0x01;

		/*
		 * assigning Initial sequence number received from the transmitter,INIt
		 * packet for echoing it back
		 */

		iack[2] = init[2];

		iack[3] = init[3];

		/*
		 * generating 8 byte nonce and assigning it to 4th to 11th byte
		 */

		for (int j = 0; j < 8; j++) {

			iack[j + 4] = nonce[j];

		}

		/*
		 * calling the Integrity generator methodfor transmitted packets that
		 * excludesthe last two bytes
		 */
		iack = integrityBitGenertorTransmitter(iack);
		// returning the generated iack Packet
		return iack;

	}

	public static byte[] generate_Dack_packet(byte[] data, byte[] Dack) {

		byte[] dack = new byte[6];

		// assigning the code for packet type

		dack[0] = 0x00;

		dack[1] = 0x04;

		// assigning Initial sequence number received from the transmitter,INIt

		// packet

		dack[2] = data[2];

		dack[3] = data[3];

		// generating and assigning integrity bits

		Dack = integrityBitGenertorTransmitter(dack);

		return Dack;

	}

	/*
	 * this method extracts the data from the data packet and store in the data
	 * array
	 */
	public static byte[] payload(byte[] data, byte[] data_packet, int counter) {

		//check packet code
		if (data_packet[0] == 0x00 && data_packet[1] == 0x02)
		
		/*
		 * if packet code is 0x02
		 * coyping payload into data array in chunks of 40
		 */
		{
			/*declaring temperory variable ,and initializing it to
			 * 6 ,as data starts from 6th byte
			 */
			int temp = 6;

			int i = counter;
			//looping  to copy payload in data array byte by byte
			for (int j = i * 40; j < (i + 1) * 40; j++) {

				data[j] = data_packet[temp];

				temp++;

			}

		}
		//check if code is 0x03
		else if (data_packet[0] == 0x00 && data_packet[1] == 0x03)

		{
			//variable to sore the byte position while looping
			int temp = 0;
			//byte array to store packet length extracted from data packet
			byte[] packet_len = new byte[2];
			// assigning sequence length
			packet_len[0] = data_packet[4];
			packet_len[1] = data_packet[5];
			//decraring byte array num to store max payload length
			//that is 40
			byte[] num = new byte[2];
			//assiging value to the array
			num[0] = 0;
			num[1] = 40;
			//variable to store zero paddning
			int zero_padding = byte_To_Short(num)-byte_To_Short(packet_len);
			int i = counter;

			{
				temp = 6;
				for (int j = i * 40; j < (i + 1) * 40 - zero_padding; j++) {
					data[j] = data_packet[temp];
					temp++;
				}
			}
		}
		return data_packet;
	}

	public static void main(String[] args) throws IOException {

		// Declaring array to store the nonce bytes

		byte[] nonce = new byte[8];
		// Calling Generate_Nonce Method and storing the returned value in
		// 8-byte variable nonce
		nonce = generate_Nonce();

		// Declaring array to hold Data
		final int noOfBytes=351;
		final int portNumber =5004;
		byte[] data = new byte[noOfBytes];

		// variable for looping

		int counter = 0;

		/*
		 * variable to store handshake status hand_Shake_Flag=1 if handshake
		 * complete else 0
		 */
		int hand_Shake_Flag = 0;

		// Creating serverSocket Object of DatagramSocket class
		DatagramSocket serverSocket = new DatagramSocket(portNumber);

		// a byte array to store the sequence no. of correctly received packets
		byte[] sequence_Num = new byte[2];

		// Looping infinitely to continuously receive Packets
		while (true)

		{
			// calling method to receive the packets and process them
			recievePacket(serverSocket, data, counter, nonce, sequence_Num,
					hand_Shake_Flag);

		}// end of while loop

	}// end of main

}// end of Receiver class

