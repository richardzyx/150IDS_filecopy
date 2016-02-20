#include "c150nastydgmsocket.h"
#include "c150debug.h"
#include <fstream>
#include <cstdlib>

using namespace C150NETWORK;

int
main(int argc, char *argv[])
{
	ssize_t readlen;
	char incomingMessage[512];
	int nastiness;
	if(argc != 2){
		fprintf(stderr, "Correct syntax is: %s <nastiness_number>\n", argv[0]);
			exit(1);	
	}
	if (strspn(argv[1], "0123456789") != strlen(argv[1])) {
		fprintf(stderr, "Nastiness %s is not numeric\n", argv[1]);
		fprintf(stderr, "Correct syntax is: %s <nastiness_number>\n", argv[0]);
		exit(4);
	}
	nastiness = atoi(argv[1]);
	try {
		C150DgmSocket *sock = new C150NastyDgmSocket(nastiness);
		while(1){
			readlen = sock -> read(incomingMessage, sizeof(incomingMessage)-1);
			if (readlen ==0) {
				continue;
			}
			incomingMessage[readlen] = '\0';
			string incoming(incomingMessage);
			cleanString(incoming);
			string response = "Received " + incoming;
			sock -> write(response.c_str(), response.length()+1);
		}
	}
	catch(C150NetworkException e){
		cerr << argv[0] << ": caught C150NetworkException: " << e.formattedExplanation() << endl;		
	}
}
