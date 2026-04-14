//finalScanner.cxx
//Brandon Zettek, Yusuf Oner, Jacob Doose, Mohammad Khan

//Port scanning lab CSCI 350
//connect via NIU VPN
//Scans UDP and TCP ports on blitz.cs.niu.edu
//find open UDP port send query get secret key
//find open TCP port then send query get encrypted mesage
//decrypt message with RC4 using the secret key

#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <ctime>
#include <iostream>
using namespace std;


//rc4 decryption
//works the same as encryption since its just XOR
void rc4_crypt(unsigned char *key, int keylen,
               unsigned char *input, int inputlen,
               unsigned char *output)
{
	unsigned char S[256];
	int i, j;
	unsigned char temp;

	//fill S with 0 to 255
	for (i = 0; i < 256; i++)
	{
		S[i] = i;
	}

	//mix up S using the key
	//this is the KSA part
	j = 0;
	for (i = 0; i < 256; i++) 
	{
		j = (j + S[i] + key[i % keylen]) % 256;
		temp = S[i];
		S[i] = S[j];
		S[j] = temp;
	}

	//now generate keystream bytes and XOR with input
	//this is PRGA
	i = 0;
	j = 0;
	for (int n = 0; n < inputlen; n++) 
	{
		i = (i + 1) % 256;
		j = (j + S[i]) % 256;
		temp = S[i];
		S[i] = S[j];
		S[j] = temp;

		//get one keystream byte and xor it
		output[n] = input[n] ^ S[(S[i] + S[j]) % 256];
	}
}

int main() 
{

	int rc;
	unsigned int addrlen;

	//secret key from UDP 16 bytes = 128 bit key strength
	unsigned char key[16];
	int keylen = 0;

	//encrypted message from TCP
	unsigned char message[1024];
	int msglen = 0;

	//times and ports to report at the end
	time_t start_time = time(0);
	time_t udp_time = 0;
	time_t tcp_time = 0;
	int udp_port = 0;
	int tcp_port = 0;

	cout << "Start time: " << ctime(&start_time);
	cout << "1. UDP port scan" << endl;

	//create the UDP socket
	int udp_sock;
	if ((udp_sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) 
    {

		perror("Failed to create socket");
		exit(EXIT_FAILURE);
	}

	//construct the target sockaddr_in structure
	struct sockaddr_in target; // structure for address of target
	memset(&target, 0, sizeof(target)); /* Clear struct */
	target.sin_family = AF_INET;			/* Internet/IP */
	target.sin_addr.s_addr = inet_addr("10.158.56.43"); /* IP address */

	//set socket to timeout mode
	//(UDP recvfrom() default behavior is  block if no packet
	//use timeout as alternative)
	struct timeval read_timeout;
	read_timeout.tv_sec = 0;
	read_timeout.tv_usec = 200000;	//varies depending on network connectivity
	setsockopt(udp_sock, SOL_SOCKET, SO_RCVTIMEO, &read_timeout, sizeof read_timeout);

	bool got_key = false;

	//loop probe for response
	for (int port = 9000; port <= 9100; port++) 
    {
		target.sin_port = htons(port); //target port

		//send the packet to target
		rc = sendto(udp_sock, "group 2", 7, 0, (struct sockaddr *) &target, sizeof(target));
		if (rc < 0)
		{
			perror("sendto");
			exit(EXIT_FAILURE);
		}

		addrlen = sizeof(target);
		rc = recvfrom(udp_sock, key, 16, 0, (struct sockaddr *)&target, &addrlen);

		if (rc < 0)
		{
			//timeout means no response port is closed
			if (errno == EWOULDBLOCK) 
            {
				cout << "." << flush;
				continue;
			} 
            else 
            {
				perror("recvfrom");
				exit(EXIT_FAILURE);
			}
		}

		//got a response
		//server sends plain text starting with "Error" on problems
		if (rc >= 5 && strncmp((char *)key, "Error", 5) == 0) 
        {
			cout << "\n Server error on port " << port << ": " << (char *)key << endl;
			continue;
		}

		//success we have secret key
		keylen = rc;
		udp_time = time(0);
		udp_port = ntohs(target.sin_port);

		cout << "\n Target port " << ntohs(target.sin_port) << " sent: " << rc << " bytes" << endl;
		cout << " Secret key (hex): ";
		for (int i = 0; i < keylen; i++)
			printf("%02x", key[i]);
		cout << endl;
		got_key = true;
		break;
	}
	close(udp_sock);

	if (!got_key) 
    {
		cerr << "\nFailed to get secret key from UDP scan." << endl;
		return 1;
	}

	 //2. TCP find open port and get encrypted message

	cout << "\n2. TCP port scan" << endl;

	bool got_msg = false;
	char buffer[1024];

	//loop to probe for response
	for (int port = 9000; port <= 9100; port++) 
    {

		//ocket that gets ECONNREFUSED cannot be reused
		int tcp_sock;
		if ((tcp_sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) 
        {
			perror("Failed to create socket");
			exit(EXIT_FAILURE);
		}

		struct sockaddr_in target; //structure for address of target
		memset(&target, 0, sizeof(target)); /* Clear struct */
		target.sin_family = AF_INET;			/* Internet/IP */
		target.sin_addr.s_addr = inet_addr("10.158.56.43"); /* IP address */
		target.sin_port = htons(port); /* target port */

		//connect to target
		rc = connect(tcp_sock, (struct sockaddr *) &target, sizeof(target));
		if (rc < 0) 
        {
			if (errno == ECONNREFUSED) 
            {
				cout << "." << flush;
				close(tcp_sock);
				continue;
			} 
            else 
            {
				perror("connect");
				close(tcp_sock);
				exit(EXIT_FAILURE);
			}
		}

		cout << "\n Target port " << port << " accepted connection" << endl;

		//send the message to the server
		if (write(tcp_sock, "group 2", 7) < 0) 
        {
			perror("write");
			close(tcp_sock);
			exit(EXIT_FAILURE);
		}

		//receive the message back from the server
		rc = read(tcp_sock, message, sizeof(message));

		if (rc < 0) 
        {
			perror("read");
			close(tcp_sock);
			exit(EXIT_FAILURE);
		}

		//check for server error message
		if (rc >= 5 && strncmp((char *)message, "Error", 5) == 0) {
			message[rc] = '\0';
			cout << " Server error: " << (char *)message << endl;
			close(tcp_sock);
			continue;
		}

		//success we have encrypted message
		msglen = rc;
		tcp_time = time(0);
		tcp_port = port;
		cout << " Received encrypted message: " << rc << " bytes" << endl;
		cout << " Ciphertext (hex): ";
		for (int i = 0; i < msglen; i++)
			printf("%02x", message[i]);
		cout << endl;
		got_msg = true;
		close(tcp_sock);
		break;
	}

	if (!got_msg) 
    {
		cerr << "\nFailed to get encrypted message from TCP scan." << endl;
		return 1;
	}

	 //3. Decrypt the mesage using RC4

	cout << "\n3. RC4 Decryption" << endl;

	unsigned char decrypted[1024];
	rc4_crypt(key, keylen, message, msglen, decrypted);
	decrypted[msglen] = '\0';

	//print summary of times and ports response
	cout << "\nSummary" << endl;
	cout << "Connect start time: " << ctime(&start_time);
	cout << "UDP response time:  " << ctime(&udp_time);
	cout << "TCP response time:  " << ctime(&tcp_time);
	cout << "UDP port: " << udp_port << endl;
	cout << "TCP port: " << tcp_port << endl;
	cout << "\nDecrypted message: " << (char *)decrypted << endl;

	return 0;
}