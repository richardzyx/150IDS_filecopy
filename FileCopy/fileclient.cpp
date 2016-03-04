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
//index for each command line argument
const int serverArg = 1;
const int netNastinessArg = 2;
const int fileNastinessArg = 3;
const int srcDirArg = 4;
//Max amount of data to send in each packet
const size_t MAX_DATA_BYTES = 480;
//This struct holds all of the information for each packet
struct packetStruct {
    //flags include 'S' for start packet 'A' for acknowledge 'D' for data
    //'E' for end and 'C' for checksum
    char flag;  
    //this is only used in an Ack packet and tells what type of packet is 
    //being acknowledged
    char ackFlag;
    //Each file has a unique file number
    uint32_t fileNum;
    //This multiplied by MAX_DATA_BYTES gives where to write data into a file
    uint32_t fileOffset;
    //This is the number of data bytes sent
    size_t numBytes;
    //this size makes the packet 504 bytes leaving room for NULL termination
    char data[MAX_DATA_BYTES];
};

void checkSha(ssize_t readlen, char *msg, ssize_t bufferlen, string srcName, 
		char *srcDir, C150DgmSocket *sock, int fileNastiness,
		char *argv[], uint32_t fileNum, int attemptNum);
string computeSha(string fileName, char * srcDir, int fileNastiness);
bool sendResult(bool result, string fileName, C150DgmSocket *sock, 
		int fileNastiness, char *argv[], uint32_t fileNum, int attemptNum);
void checkMessage(ssize_t readlen, char *msg, ssize_t bufferlen);
void fileCopy(C150DgmSocket *sock, char *argv[]);
void startCopy(string srcName, C150DgmSocket *sock, int fileNastiness,
		 char *argv[], uint32_t fileNum, int attemptNum);
bool getResponse(C150DgmSocket *sock, string srcName, int fileNastiness, 
		packetStruct packet, char *argv[], int attemptNum);
void endCopy(string srcName, C150DgmSocket *sock, int fileNastiness,
                char *argv[], uint32_t fileNum, int attemptNum);
void makePacket(packetStruct *packet, char flag, char ackFlag, uint32_t fileNum,
                uint32_t fileOffset, size_t numBytes, const char* data);
void sendFile(string srcName, C150DgmSocket *sock, int fileNastiness,
                char *argv[], uint32_t fileNum, int attemptNum);

int main(int argc, char *argv[])
{
    GRADEME(argc, argv);
	if (argc != 5) {
		fprintf(stderr, "Correct syntax is: %s <servername> <networknastiness> <filenastiness> <srcdir>\n", argv[0]);
		exit(1);
	}

	int netNastiness = atoi(argv[netNastinessArg]);

	try {
        // Setting up Socket with nastiness in network
		C150DgmSocket *sock = new C150NastyDgmSocket(netNastiness);
		sock -> setServerName(argv[serverArg]);
		sock -> turnOnTimeouts(100);
        //execute main file copy
	    fileCopy(sock, argv);
	
	}
	catch (C150NetworkException e){
		cerr << argv[0] << ": caught C150NetworkException: " << e.formattedExplanation() << endl;
	}
	return 0;
}
//Loops through files in the source directory and passes them to be copied
void fileCopy(C150DgmSocket *sock, char *argv[])
{
    DIR *SRC;
    SRC = opendir(argv[srcDirArg]);
    struct dirent *sourceFile;
    int fileNastiness = atoi(argv[fileNastinessArg]);
    if (SRC == NULL) {
        fprintf(stderr,"Error opening source directory %s\n", argv[srcDirArg]);
        exit(8);
    }
    uint32_t fileNum = 0;
    while ((sourceFile = readdir(SRC)) != NULL) {
        // Get the string version of current file name, and send as message
        string srcName = sourceFile->d_name;
        if ((strcmp(sourceFile->d_name, ".") == 0) ||
                    (strcmp(sourceFile->d_name, "..")  == 0 ))
            continue;
            
        // Copy this file
        startCopy(srcName, sock, fileNastiness, argv, fileNum, 1);
	   fileNum++;
    }
}

//send the initial start packet for this file to the server
//calls sendFile and endCopy when sendFile has finished
void startCopy(string srcName, C150DgmSocket *sock, int fileNastiness,
		 char *argv[], uint32_t fileNum, int attemptNum)
{
    const char *msg = srcName.c_str();
    packetStruct packet;
    makePacket(&packet, 'S', 0, fileNum, 0, sizeof(msg),  msg);
    char msgBuffer[sizeof(packet)];
    //copy the packet into a msgbuffer to be sent
    memcpy(msgBuffer, &packet, sizeof(packet));
    //since our packets are 504 Bytes the + 8 makes the size 512 and
    //ensures NULL termination
    sock -> write(msgBuffer, sizeof(msgBuffer) + 8); 
    *GRADING << "File: " << srcName << ", beginning transmission, attempt " 
            << attemptNum <<endl;
    //read packets until we get an ack for this start packet
    while(!getResponse(sock, srcName, fileNastiness, packet, argv, attemptNum));
    sendFile(srcName, sock, fileNastiness, argv, fileNum, attemptNum);
    endCopy(srcName, sock, fileNastiness, argv, fileNum, attemptNum);
}
//Sends the file over to the server
void sendFile(string srcName, C150DgmSocket *sock, int fileNastiness,
		char *argv[], uint32_t fileNum, int attemptNum)
{
    NASTYFILE inputFile(fileNastiness);
    void *fopenretval;
    size_t sourceSize;
    char *buffer;
    size_t len;
	//get the full path for the file
    std::string path = argv[srcDirArg];
    if(path[path.length() - 1] != '/') path += '/';
    //open the file for reading
    fopenretval = inputFile.fopen((path+srcName).c_str(), "rb");
    if (fopenretval == NULL) {
	cerr << "Error opening input file " << (path+srcName).c_str() <<
	    " errno=" << strerror(errno) << endl;
	exit(12);
    }
    //this tells us the size of the file
    inputFile.fseek(0, SEEK_END);
    sourceSize = inputFile.ftell();
    //create a buffer large enough for the entire file
    buffer = (char*)malloc(sourceSize);
    if(buffer == NULL) exit(1);
    //move pointer back to the beginning of the file
    inputFile.fseek(0, SEEK_SET);
    len = inputFile.fread(buffer, 1, sourceSize);
    if(len != sourceSize) {
	cerr << "Error reading file " << (path+srcName).c_str() <<
            "  errno=" << strerror(errno) << endl;
        exit(16);
    }
    if(inputFile.fclose() != 0) {
        cerr << "Error closing input file " << (path+srcName).c_str() <<
            " errno=" << strerror(errno) << endl;
        exit(16);
    }
    uint32_t i = 0;
    int bytestosend = MAX_DATA_BYTES;
    //send data until the entire file has been sent
    while(i * MAX_DATA_BYTES <= len){
        //if there is less than MAX_DATA_BYTES left to send then
        //only send what is left
	    if((i+1)* MAX_DATA_BYTES > len){
	       bytestosend = len - (i*MAX_DATA_BYTES);
	    }
	    char data[bytestosend];
        //copy file data at offset (i*MAX_DATA_BYTES) to data buffer
	    memcpy(data, buffer + (i*MAX_DATA_BYTES), bytestosend);
	    packetStruct dataPacket;
	    makePacket(&dataPacket, 'D', 0, fileNum, i, 
		          sizeof(data),  data);
	    char msgBuffer[sizeof(dataPacket)];
	    memcpy(msgBuffer, &dataPacket, sizeof(dataPacket));
	    sock -> write(msgBuffer, sizeof(msgBuffer) + 8);
        //wait to get response for this packet
	    while(!getResponse(sock, srcName, fileNastiness, dataPacket, argv, attemptNum)); 
   	    i++;
    }
}
//send end packet for this file 
void endCopy(string srcName, C150DgmSocket *sock, int fileNastiness, 
		char *argv[], uint32_t fileNum, int attemptNum)
{
    *GRADING << "File: " << srcName <<
     " transmission complete, waiting for end-to-end check, attempt " 
             << attemptNum <<endl;
    const char *msg = srcName.c_str();
    packetStruct packet;
    makePacket(&packet, 'E', 0, fileNum, 0, sizeof(msg), msg);
    char msgBuffer[sizeof(packet)];
    memcpy(msgBuffer, &packet, sizeof(packet));
    sock -> write(msgBuffer, sizeof(msgBuffer) + 8);
    getResponse(sock, srcName, fileNastiness, packet, argv, attemptNum);
}

//create a packet with the given fields
void makePacket(packetStruct *packet, char flag, char ackFlag, uint32_t fileNum,
		uint32_t fileOffset, size_t numBytes,  const char* data)
{
    packet -> flag = flag;
    packet -> ackFlag = ackFlag;
    packet -> fileNum = fileNum;
    packet -> fileOffset = fileOffset;
    packet -> numBytes = numBytes;
    strcpy(packet -> data, data);
}

//get response from server that acknowledges the packet that was just sent
bool getResponse(C150DgmSocket *sock, string srcName, int fileNastiness,
		 packetStruct packet, char *argv[], int attemptNum)
{
    ssize_t readlen;
    char incomingMessage[512];
    readlen = sock -> read(incomingMessage, sizeof(incomingMessage));
    int i = 0;
    char msgBuffer[sizeof(packet)];
    memcpy(msgBuffer, &packet, sizeof(packet));
    while(sock->timedout() && i < 5){
        sock->write( msgBuffer, sizeof(msgBuffer) + 8);
        i++;
        readlen = sock -> read(incomingMessage, sizeof(incomingMessage));
    }
    if( i >= 5){
        throw C150NetworkException("Server not responding.");
    }
    //do if not timedout, and make sure got the right type of message
    do{
        packetStruct incomingPacket;
	    memcpy(&incomingPacket, incomingMessage, sizeof(incomingMessage));
	    if(incomingPacket.flag == 'A'){
		  if(incomingPacket.ackFlag == packet.flag && 
		      incomingPacket.fileNum == packet.fileNum &&
		      incomingPacket.fileOffset == packet.fileOffset){
			    return true;
		  }
	   }
	   else if(incomingPacket.flag == 'C'){

            //check received sha against sha of file we copied
            checkSha(readlen, incomingMessage,
                sizeof(incomingMessage), srcName, 
                argv[srcDirArg], sock, fileNastiness, argv, 
		        incomingPacket.fileNum, attemptNum);
	   }
	   readlen = sock -> read(incomingMessage, sizeof(incomingMessage));
    } while(!sock->timedout());
    return false;
}

//check the received sha against the client sha
void checkSha(ssize_t readlen, char *msg, ssize_t bufferlen, string srcName, 
		char *srcDir, C150DgmSocket *sock, int fileNastiness,
		char *argv[], uint32_t fileNum, int attemptNum)
{

	checkMessage(readlen, msg, bufferlen);
	const char *sha1;
	packetStruct checksumPacket;
	memcpy(&checksumPacket, msg, bufferlen);
	sha1 = checksumPacket.data;

	string clientSha = computeSha(srcName, srcDir, fileNastiness);
	bool result;
	std::string serversha = sha1;
	if (clientSha == serversha){
	    result = true;
	    cout << "TRANSFER SUCCEEDED" << endl;
	}
	else{
	    result = false;
	    cout << "TRANSFER FAILED" << endl;
	}
    //send the result to the server and get acknowledgement
	if(!sendResult(result, srcName, sock, fileNastiness, argv, fileNum, 
			attemptNum)){
		//if failed then resend file
		startCopy(srcName, sock, fileNastiness, argv, fileNum, 
			attemptNum + 1);
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

//compute the sha for the current file in the source directory
string computeSha(string fileName, char * srcDir, int fileNastiness)
{
    NASTYFILE inputFile(fileNastiness);
    void *fopenretval;
    string errorString;
    size_t sourceSize;
    char *buffer;
    size_t len;
    unsigned char obuf[20];

    char sha1hex[40];
    std::string path = srcDir;
    //add '/' to end of path if it is not there
    if(path[path.length() - 1] != '/') path += '/';

    printf ("SHA1 (\"%s\") is computed\n ", (path+fileName).c_str());
       
    fopenretval = inputFile.fopen((path+fileName).c_str(), "rb");

    if (fopenretval == NULL) {
        cerr << "Error opening input file " << (path+fileName).c_str() << 
        " errno=" << strerror(errno) << endl;
        exit(12);
    }
    //get file size
    inputFile.fseek(0, SEEK_END);
    sourceSize = inputFile.ftell();
    buffer = (char *)malloc(sourceSize);
    if(buffer == NULL) exit(1);
    inputFile.fseek(0, SEEK_SET);
    //read entire file into buffer
    len = inputFile.fread(buffer, 1, sourceSize);

    if (len != sourceSize) {
        cerr << "Error reading file " << (path+fileName).c_str() << 
          "  errno=" << strerror(errno) << endl;
        exit(16);
    }
    if (inputFile.fclose() != 0 ) {
        cerr << "Error closing input file " << (path+fileName).c_str() << 
          " errno=" << strerror(errno) << endl;
        exit(16);
    }
    //compute sha 
    SHA1((const unsigned char *)buffer, len, obuf);
    for (int i = 0; i < 20; i++)
    {
        sprintf (sha1hex + (i*2), "%02x", (unsigned int) obuf[i]);
    }
    printf ("\n");

    free(buffer);

    std::string sha1 = sha1hex;
    return sha1;
}

//sends either the filename and PASS or FAIL based on the checksum
bool sendResult(bool result, string fileName, C150DgmSocket *sock, 
		int fileNastiness, char *argv[], uint32_t fileNum, 
		int attemptNum)
{	
    packetStruct resultPacket;
    string msg;
    if(result) msg = fileName + "/PASS"; //passed the checksum
    else msg = fileName + "/FAIL"; //failed the checksum
    makePacket(&resultPacket, 'C', 0, fileNum, 0, sizeof(msg.c_str()), 
		 msg.c_str());
    char msgBuffer[sizeof(resultPacket)];
    memcpy(msgBuffer, &resultPacket, sizeof(resultPacket));	
	
    sock->write(msgBuffer, sizeof(msgBuffer) + 8);
    if(result) *GRADING << "File: " << fileName << 
                " end-to-end check succeeded, attempt " 
                        << attemptNum <<endl;
    else *GRADING << "File: " << fileName << 
                " end-to-end check failed, attempt " 
                        << attemptNum <<endl;
    if(getResponse(sock, fileName, fileNastiness, resultPacket, argv, attemptNum) && result)
    {
	cout << "end-to-end succeeded" << endl;
	return true;
    }
    else cout << "end-to-end fails" << endl;
    return false; 	
} 
