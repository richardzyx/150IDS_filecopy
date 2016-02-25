#include "c150nastyfile.h"        // for c150nastyfile & framework
#include "c150grading.h"
#include "c150nastydgmsocket.h"
#include "c150debug.h"
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <cstring>                // for errno string formatting
#include <cerrno>
#include <cstring>               // for strerro
#include <iostream>               // for cout
#include <fstream>
#include <cstdlib>
#include <openssl/sha.h>


using namespace std;          // for C++ std library
using namespace C150NETWORK;  // for all the comp150 utilities

const int serverArg = 1;
const int netNastinessArg = 2;
const int fileNastinessArg = 3;
const int srcDirArg = 4;

void checkSha(ssize_t readlen, char *msg, ssize_t bufferlen, char *srcDir, C150DgmSocket *sock);
string computeSha(string fileName, char * srcDir);
bool sendResult(bool result, string fileName, C150DgmSocket *sock);
void checkMessage(ssize_t readlen, char *msg, ssize_t bufferlen);

int 
main(int argc, char *argv[])
{
	//will use these to read back later
	//ssize_t readlen;
	//char incomingMessage[512];

	if (argc != 5) {
		fprintf(stderr, "Correct syntax is: %s <servername> <networknastiness> <filenastiness> <srcdir>\n", argv[0]);
		exit(1);
	}
	
	ssize_t readlen;
	char incomingMessage[512];
	DIR *SRC;
	SRC = opendir(argv[srcDirArg]);
        struct dirent *sourceFile;
	int netNastiness = atoi(argv[netNastinessArg]);
        if (SRC == NULL) {
                fprintf(stderr,"Error opening source directory %s\n",
                                                argv[srcDirArg]);
                exit(8);
        }
	try {
	
		C150DgmSocket *sock = new C150NastyDgmSocket(netNastiness);
		sock -> setServerName(argv[serverArg]);
		sock -> turnOnTimeouts(3000);
		while ((sourceFile = readdir(SRC)) != NULL) {
			string srcName = sourceFile->d_name;
			const char *msg = srcName.c_str();
	                if ((strcmp(sourceFile->d_name, ".") == 0) ||
        	            (strcmp(sourceFile->d_name, "..")  == 0 ))
			continue;
			sock -> write(msg, strlen(msg) + 1);
			readlen = sock -> read(incomingMessage,
						 sizeof(incomingMessage));
			int i = 0;
			while(sock->timedout() && i < 5){
				sock->write(msg, strlen(msg) + 1);
	                        readlen = sock -> read(incomingMessage,
                                                 sizeof(incomingMessage));
				i++;
			}
			if( i >= 5){
				throw C150NetworkException("Server not responding.");
			}
			do{
				checkSha(readlen, incomingMessage,
					sizeof(incomingMessage), 
					argv[srcDirArg], sock);
			        readlen = sock -> read(incomingMessage,
                                                 sizeof(incomingMessage));
			}while(!sock->timedout());

 
			
		}	
		// Get sha1 of file and send to server
		// wait for response saying files match or not
	
	}
	catch (C150NetworkException e){
		cerr << argv[0] << ": caught C150NetworkException: " << e.formattedExplanation() << endl;
	}
	return 0;
}

void checkSha(ssize_t readlen, char *msg, ssize_t bufferlen, char *srcDir,
		C150DgmSocket *sock){

	checkMessage(readlen, msg, bufferlen);
	string fileName = "";
	string sha1 = "";
	bool isFileName = true;
	for(int i=0; i < readlen - 1; i++){
		if(msg[i] == '/') {
			isFileName = false;
			continue;
		}
		if( isFileName ) fileName += msg[i];
		else sha1 += msg[i];
	} 
	cout << fileName << " " << sha1 << '\n';
	string clientSha = computeSha(fileName, srcDir);
	bool result;
	if (clientSha == sha1) result = true;
	else result = false;
	int j = 0;
	while(!sendResult(result, fileName, sock) && j < 5)
	{
		j++; 
	}
}

void checkMessage(ssize_t readlen, char *msg, ssize_t bufferlen){
        if (readlen == 0) {
                throw C150NetworkException("Unexpected zero length read in client");
        }

        if (readlen > (int)(bufferlen)) {
                throw C150NetworkException("Unexpected over length read in client");
        }

        if(msg[readlen-1] != '\0') {
                throw C150NetworkException("Client received message that was not null terminated");
        }

}

string computeSha(string fileName, char * srcDir)
{
        char sha1hex[40];
        std::string path = srcDir;
        if(path[path.length() - 1] != '/') path += '/';
        ifstream *t;
        stringstream *buffer;
        unsigned char obuf[20];
        t = new ifstream((path+fileName).c_str());
        buffer = new stringstream;
        *buffer << t->rdbuf();
        SHA1((const unsigned char *)buffer->str().c_str(),
             (buffer->str()).length(), obuf);
        for (int i = 0; i < 20; i++)
        {
                sprintf (sha1hex + (i*2), "%02x", (unsigned int) obuf[i]);
        }
        delete t;
        delete buffer;
        std::string sha1 = sha1hex;
        return sha1;

}

bool sendResult(bool result, string fileName, C150DgmSocket *sock)
{
	ssize_t readlen;
	char incomingMessage[512];	
	string msg = fileName + '/';
	if(result) msg += "SUCCESS";
	else msg += "FAILURE";
	sock->write(msg.c_str(), msg.length() + 1);
        readlen = sock -> read(incomingMessage,
			        sizeof(incomingMessage));
        int i = 0;
        while(sock->timedout() && i < 5){
      		sock->write(msg.c_str(), msg.length() + 1);
      		readlen = sock -> read(incomingMessage,
            			sizeof(incomingMessage));
                i++;
        }
        if( i >= 5){
       		throw C150NetworkException("Server not responding.");
        }

	do {
		checkMessage(readlen, incomingMessage, sizeof(incomingMessage));
		std::string finalResponse = incomingMessage;
		if(finalResponse == (fileName + "/OK")) return true;
                readlen = sock -> read(incomingMessage,
				sizeof(incomingMessage));
	}while(!sock->timedout());
	return false;		
} 
