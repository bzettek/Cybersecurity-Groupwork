/*
 * udp_example.cxx
 * 
 * 	illustrates UPD port scanning
 *  via timeout
 * 	      
 */
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <iostream>
using namespace std;

int main() {

	// Create the UDP socket
	int sock, rc;
	unsigned int addrlen;
	char buffer[1024];
	
	// Create the socket
	if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("Failed to create socket");
		exit(EXIT_FAILURE);
	}
	
	// Construct the target sockaddr_in structure
	struct sockaddr_in target; // structure for address of target	
	memset(&target, 0, sizeof(target)); /* Clear struct */
	target.sin_family = AF_INET;			/* Internet/IP */
	target.sin_addr.s_addr = inet_addr("10.158.56.43"); /* IP address */

	// set socket to timeout mode
	struct timeval read_timeout;
	read_timeout.tv_sec = 0;
	read_timeout.tv_usec = 200000;	// varies depending of network connectivity
	setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &read_timeout, sizeof read_timeout);

	// loop to probe for responses
	for (int port=9000; port <= 9100; port++) {
		target.sin_port = htons(port); /* target port */

		// Send the packet to the target
		rc = sendto(sock, "group X", 7, 0, (struct sockaddr *) &target, sizeof(target));
		if (rc < 0)
		{
			perror("sendto");
			exit(EXIT_FAILURE);
		}

		// Receive the message back from the server
		addrlen = sizeof(target);
		rc = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr *)&target, &addrlen);
		if (rc < 0)
		{		
			if (errno == EWOULDBLOCK) {
				cout << "." << flush;
				continue;
			} else {
				perror("sendto");
				exit(EXIT_FAILURE);
			}
		}
		cout << " Target port " << ntohs(target.sin_port) << " sent: " << rc << " bytes\n";
		break;
	}
	close(sock);
	return 0;
}