/*
 * tcp_example.cxx
 * 
 * 	illustrates TCP port scanning
 *  via connect time out
 * 	      
 */
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstring>
#include <iostream>
using namespace std;

int main() {

	// Create the TCP socket
	int sock, rc;
	unsigned int addrlen;
	char buffer[1024];

	// Create the socket
	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("Failed to create socket");
		exit(EXIT_FAILURE);
	}

	// Construct the target sockaddr_in structure
	struct sockaddr_in target; // structure for address of target	
	memset(&target, 0, sizeof(target)); /* Clear struct */
	target.sin_family = AF_INET;			/* Internet/IP */
	target.sin_addr.s_addr = inet_addr("10.158.56.43"); /* IP address */
	
	// loop to probe for responses
	for (int port=9000; port <= 9100; port++) {			
		target.sin_port = htons(port); /* target port */	

		// Connect to target
		rc = connect(sock, (struct sockaddr *) &target, sizeof(target));
		if (rc < 0) {
			if (errno == ECONNREFUSED) {
				cout << "." << flush;
				continue;
			} else {
				perror("connect");
				exit(EXIT_FAILURE);
			}
		}

		// Send the message to the server 
		if (write(sock, "group X", 7) < 0) {
			perror("write");
			exit(EXIT_FAILURE);
		}
		// Receive the message back from the server 
		rc = read(sock, buffer, sizeof(buffer));
		if (rc < 0) {
			perror("read");
			exit(EXIT_FAILURE);
		}
		cout << " Target port " << ntohs(target.sin_port) << " sent: " << rc << " bytes\n";
		break;
	}
	close(sock);
	return 0;
}