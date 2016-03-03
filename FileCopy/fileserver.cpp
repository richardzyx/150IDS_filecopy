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

using namespace std;
using namespace C150NETWORK;

const int netNastinessArg = 1;
const int fileNastinessArg = 2;
const int targetDirArg = 3;
const size_t MAX_DATA_BYTES = 480;

struct packetStruct {
    char flag;
    char ackFlag;
    uint32_t fileNum;
    uint32_t fileOffset;
    size_t numBytes;
    char data[MAX_DATA_BYTES]; //this makes the packet 508 bytes allowing for Null at the end
};

struct currentFile{
    uint32_t fileNum;
    char fileName[255];
    bool readyForNew; //are we ready for a new file
};

void checkDirectory(char *dirname);
string checkFiles(C150DgmSocket *sock, char *targetDir, string fileName, int fileNastiness);
string computeSha(string fileName, char *targetDir, int fileNastiness);
void listen(char* argv[], C150DgmSocket *sock, int fileNastiness, 
		currentFile *file, NASTYFILE *outputfile);
void makePacket(packetStruct *packet, char flag, char ackFlag, uint32_t fileNum, 		uint32_t fileOffset, const char* data);
void writeData(packetStruct packet, char *argv[], int fileNastiness, 
		currentFile *file, NASTYFILE *outputFile);

int main(int argc, char *argv[])
{
    cout << sizeof(packetStruct) << endl;
    GRADEME(argc, argv);

    if(argc != 4){
	fprintf(stderr, "Correct syntax is: %s <networknastiness> <filenastiness> <target_directory>\n", argv[0]);
	exit(1);	
    }
    if (strspn(argv[1], "0123456789") != strlen(argv[1])) {
	fprintf(stderr, "Nastiness %s is not numeric\n", argv[1]);
	fprintf(stderr, "Correct syntax is: %s <nastiness_number>\n", argv[0]);
	exit(4);
    }
    int networkNastiness = atoi(argv[netNastinessArg]);
    int fileNastiness = atoi(argv[fileNastinessArg]);
    try {
	C150DgmSocket *sock = new C150NastyDgmSocket(networkNastiness);
	currentFile file;
	//sock -> turnOnTimeouts(300);

	file.readyForNew = true;
	NASTYFILE outputFile(fileNastiness);
	while(1){
            listen(argv, sock, fileNastiness, &file, &outputFile);
            //TODO: inconsistent hanlding of incoming messages
			//TODO: the current version only works in nastiness 0 and 1
	}
    }
    catch(C150NetworkException e){
	cerr << argv[0] << ": caught C150NetworkException: " << e.formattedExplanation() << endl;		
    }
}

void listen(char * argv[], C150DgmSocket *sock,  int fileNastiness, 
		currentFile *file, NASTYFILE *outputFile)
{
    ssize_t readlen;
    char incomingMessage[512];
    readlen = sock -> read(incomingMessage, sizeof(incomingMessage)-1);
    if (readlen == 0) {
        return;
    }
    incomingMessage[readlen] = '\0';
//    cout << incomingMessage << " <- sock message " << endl;
    //string incoming(incomingMessage);
    //TODO: add possible checkMessage function, and check transaction ID
    //cleanString(incoming);
    // cout << "incoming: " << incoming << "\n";
    // printf("incomingMessage: %s", incomingMessage); 
    packetStruct incomingPacket;
    memcpy(&incomingPacket, incomingMessage, sizeof(incomingMessage));

    //Assume the messag is not first stage message, which only has file without any flag

    //Since we read backwards, the checking string is backward. Will improve in later version
    if(incomingPacket.flag == 'S'){ //if this is a start packet
        cout << "START PACKET RECEIVED FOR FILE: " << incomingPacket.data << endl;
        if(!(file -> readyForNew)){
	    if(incomingPacket.fileNum == file -> fileNum){
	        packetStruct responsePacket;
        	makePacket(&responsePacket, 'A', 'S', incomingPacket.fileNum, 0, 0); //A for ack, S for start
        	char msgBuffer[sizeof(responsePacket)];
        	memcpy(msgBuffer, &responsePacket, sizeof(responsePacket));
		sock -> write(msgBuffer, sizeof(msgBuffer) + 8);
	    }
	    return;
	}
	file -> fileNum = incomingPacket.fileNum;
	strcpy(file -> fileName, incomingPacket.data);
	file -> readyForNew = false;
	printf("filename: %s", file -> fileName);
	std::string targetDir = argv[targetDirArg];
	if(targetDir[targetDir.length() - 1] != '/') targetDir += '/';
    	std::string fileName = file -> fileName;
    	string path = targetDir + fileName;
	void *fopenretval;
	fopenretval = outputFile->fopen(path.c_str(), "wb+"); //open for read and write binary
	if (fopenretval == NULL) {
            cerr << "Error opening input file " << path << "errno=" <<
                strerror(errno) << endl;
            exit(12);
    	}
	 
	packetStruct responsePacket;
        makePacket(&responsePacket, 'A', 'S', incomingPacket.fileNum, 0, 0); //A for ack, S for start
	char msgBuffer[sizeof(responsePacket)];
	memcpy(msgBuffer, &responsePacket, sizeof(responsePacket));
	//int temp_AS = 0;
	//do{
	//    temp_AS++;
	sock -> write(msgBuffer, sizeof(msgBuffer) + 8);
	//}while(!sock->timedout()&& temp_AS < 5);
	
    }
    else if(incomingPacket.flag == 'E'){
        cout << "END PACKET RECIEVED FOR FILE: " << incomingPacket.data 
        << "---computing checksum" << endl;
	if(!file -> readyForNew){
	    if (outputFile->fclose() != 0){
                cerr << "Error closing output file " <<
                    " errno=" << strerror(errno) << endl;
                exit(16);
            }
	    file -> readyForNew = true;
	}
        string sha = checkFiles(sock, argv[targetDirArg], incomingPacket.data, fileNastiness);
        packetStruct responsePacket;
        makePacket(&responsePacket, 'C', 0, incomingPacket.fileNum, 0,
			 sha.c_str());
        char msgBuffer[sizeof(responsePacket)];
        memcpy(msgBuffer, &responsePacket, sizeof(responsePacket));
        sock -> write(msgBuffer, sizeof(msgBuffer) + 8);
    }
    else if(incomingPacket.flag == 'C'){
	cout << "END-TO-END RESULTS RECEIVED--RESULT: " 
	<< incomingPacket.data << endl;
	packetStruct responsePacket;
	makePacket(&responsePacket, 'A', 'C', incomingPacket.fileNum, 0, 0);
	char msgBuffer[sizeof(responsePacket)];
	memcpy(msgBuffer, &responsePacket, sizeof(responsePacket));
	sock -> write(msgBuffer, sizeof(msgBuffer) + 8);
	file -> readyForNew = true;
    }
    else if(incomingPacket.flag == 'D'){
	cout << "DATA PACKET RECEIVED" << endl;
	writeData(incomingPacket, argv, fileNastiness, file, outputFile);
	packetStruct responsePacket;
	makePacket(&responsePacket, 'A', 'D', incomingPacket.fileNum,
		incomingPacket.fileOffset, 0);
	char msgBuffer[sizeof(responsePacket)];
	memcpy(msgBuffer, &responsePacket, sizeof(responsePacket));
	sock -> write(msgBuffer, sizeof(msgBuffer) + 8);
    } 
   /* if (flag ==  "SSECCUS" || flag == "ERULIAF"){
        // cout << "finalAck: " << incoming << '\n';
        if (flag ==  "SSECCUS") *GRADING << "File: " << incoming << " end-to-end check succeeded" << endl;
        if (flag ==  "ERULIAF") *GRADING << "File: " << incoming << " end-to-end check failed" << endl;
        sock -> write(incoming.c_str(), incoming.length()+1);
    }
    //If this is not a message with flag, this is a request to check new file sha1
    else
    {
        //TODO: add process for accepting the entire file
        *GRADING << "File: " << incoming << " starting to receive file" << endl;
        //TODO: pass filenastiness
        string response = incoming + '/' + checkFiles(sock, argv[targetDirArg], incoming, fileNastiness);
        sock -> write(response.c_str(), response.length()+1);
    }*/
}

void writeData(packetStruct packet, char *argv[], int fileNastiness, 
		currentFile *file, NASTYFILE *outputFile)
{
    size_t len;
//    NASTYFILE outputFile(fileNastiness);
//    void *fopenretval;
//    std::string targetDir = argv[targetDirArg];
//    printf("filename when writing: %s", file ->fileName);
    //add '/' to end of path if it is not there
/*    if(targetDir[targetDir.length() - 1] != '/') targetDir += '/';
    std::string fileName = file -> fileName;
    string path = targetDir + fileName;
    fopenretval = outputFile.fopen(path.c_str(), "wb+"); //open for read and write binary
    if (fopenretval == NULL) {
	cerr << "Error opening input file " << path << "errno=" <<
		strerror(errno) << endl;
	exit(12);
    }
*/
    outputFile->fseek((packet.fileOffset * MAX_DATA_BYTES), SEEK_SET);
    //cout << "offset: " << packet.fileOffset << endl;
    //printf("Data: %s\n", packet.data);
    len = outputFile->fwrite(packet.data, 1, packet.numBytes);
    if(len != packet.numBytes){
	cerr << "error when writing" << endl;
    }
/*
    if (outputFile.fclose() != 0){
        cerr << "Error closing output file " << path <<
            " errno=" << strerror(errno) << endl;
        exit(16);
    }
  */  
    
}
void makePacket(packetStruct *packet, char flag, char ackFlag, uint32_t fileNum, 
                uint32_t fileOffset, const char* data)
{
    packet -> flag = flag;
    packet -> ackFlag = ackFlag;
    packet -> fileNum = fileNum;
    packet -> fileOffset = fileOffset;
    if(data){
    	strcpy(packet -> data, data);
    }  
}
string checkFiles(C150DgmSocket* sock, char *targetDir, string fileName, int fileNastiness)
{
    *GRADING << "File: " << fileName << " received, beginning end-to-end check" << endl;
    checkDirectory(targetDir);
    DIR *TARGET;
    TARGET = opendir(targetDir);
    if (TARGET == NULL) {
   	fprintf(stderr,"Error opening source directory %s\n", 
			targetDir);
	exit(8);
    }

    string response = computeSha(fileName, targetDir, fileNastiness);
    closedir(TARGET);
    return response;
}

void checkDirectory(char *dirname) {
    struct stat statbuf;
    if (lstat(dirname, &statbuf) != 0) {
        fprintf(stderr,"Error stating supplied source directory %s\n", dirname);
        exit(8);
    }

    if (!S_ISDIR(statbuf.st_mode)) {
        fprintf(stderr,"File %s exists but is not a directory\n", dirname);
        exit(8);
    }
}

string computeSha(string fileName, char *targetDir, int fileNastiness)
{
    NASTYFILE inputFile(fileNastiness);
    void *fopenretval;
    string errorString;
    size_t sourceSize;
    char *buffer;
    size_t len;
    unsigned char obuf[20];

    char sha1hex[40];
    std::string path = targetDir;
    //add '/' to end of path if it is not there
    if(path[path.length() - 1] != '/') path += '/';

    // const char *full_path = (path+fileName).c_str();
    printf ("SHA1 (\"%s\") is computed\n ", (path+fileName).c_str());
     
       
    fopenretval = inputFile.fopen((path+fileName).c_str(), "rb");


    if (fopenretval == NULL) {
        cerr << "Error opening input file " << (path+fileName).c_str() << 
            " errno=" << strerror(errno) << endl;
        exit(12);
    }
    inputFile.fseek(0, SEEK_END);
    sourceSize = inputFile.ftell();
    buffer = (char *)malloc(sourceSize);
    if(buffer == NULL) exit(1);
    inputFile.fseek(0, SEEK_SET);
    len = inputFile.fread(buffer, 1, sourceSize);
    cout << sourceSize << " " << sizeof(*buffer) << endl;

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

    SHA1((const unsigned char *)buffer, len, obuf);
    for (int i = 0; i < 20; i++)
    {
        sprintf (sha1hex + (i*2), "%02x", (unsigned int) obuf[i]);
    }
    printf ("\n");

    free(buffer);

    std::string sha1 = sha1hex;
    return sha1hex;
}
