#include "c150nastyfile.h"
#include "c150grading.h"
#include "c150nastydgmsocket.h"
#include "c150debug.h"
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <cstring>
#include <cerrno>
#include <cstring>
#include <iostream>
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
    bool renamed;
    bool readyForNew; //are we ready for a new file
};

void listen(char* argv[], C150DgmSocket *sock, int fileNastiness, 
        currentFile *file, NASTYFILE *outputfile);
void checkDirectory(char *dirname);
string checkFiles(C150DgmSocket *sock, char *targetDir, string fileName, int fileNastiness);
string computeSha(string fileName, char *targetDir, int fileNastiness);
void makePacket(packetStruct *packet, char flag, char ackFlag, uint32_t fileNum, uint32_t fileOffset, const char* data);
void writeData(packetStruct packet, char *argv[], int fileNastiness, 
		currentFile *file, NASTYFILE *outputFile);
bool renameTemp(packetStruct packet, char *argv[]);

int main(int argc, char *argv[])
{
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

    	file.readyForNew = true;
    	file.renamed = false;
    	NASTYFILE outputFile(fileNastiness);
    	while(1){
            listen(argv, sock, fileNastiness, &file, &outputFile);
            //TODO: inconsistent hanlding of incoming messages
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
    packetStruct incomingPacket;
    memcpy(&incomingPacket, incomingMessage, sizeof(incomingMessage));

    if(incomingPacket.flag == 'S'){ //if this is a start packet
        if(!(file -> readyForNew)){
    	    if(incomingPacket.fileNum == file -> fileNum){
                *GRADING << "File " << file->fileName << " starting to receive file" << endl;
    	        packetStruct responsePacket;
            	makePacket(&responsePacket, 'A', 'S', incomingPacket.fileNum, 0, 0); //A for ack, S for start
            	char msgBuffer[sizeof(responsePacket)];
            	memcpy(msgBuffer, &responsePacket, sizeof(responsePacket));
    		    sock -> write(msgBuffer, sizeof(msgBuffer) + 8);
	       }
	       return;
        }
        file -> renamed = false;
        file -> fileNum = incomingPacket.fileNum;
        strcpy(file -> fileName, incomingPacket.data);
        file -> readyForNew = false;
        *GRADING << "File " << file->fileName << " starting to receive file" << endl;
        
        std::string targetDir = argv[targetDirArg];
        if(targetDir[targetDir.length() - 1] != '/') targetDir += '/';
        
        std::string fileName = file -> fileName;
        string path = targetDir + fileName + ".TMP";
        
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
        sock -> write(msgBuffer, sizeof(msgBuffer) + 8);	
    }
    else if(incomingPacket.flag == 'E'){//if this is the end of file
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
        makePacket(&responsePacket, 'C', 0, incomingPacket.fileNum, 0, sha.c_str());
        char msgBuffer[sizeof(responsePacket)];
        memcpy(msgBuffer, &responsePacket, sizeof(responsePacket));
        sock -> write(msgBuffer, sizeof(msgBuffer) + 8);
    }
    else if(incomingPacket.flag == 'C'){//if this contains sha1 check result
        *GRADING << "File " << file->fileName << " end-to-end check " << incomingPacket.data << endl;
    	if(!(file -> renamed)){
    		if(renameTemp(incomingPacket, argv)){
    			file -> renamed = true;
    		}
    	}
    	packetStruct responsePacket;
    	makePacket(&responsePacket, 'A', 'C', incomingPacket.fileNum, 0, 0);
    	char msgBuffer[sizeof(responsePacket)];
    	memcpy(msgBuffer, &responsePacket, sizeof(responsePacket));
    	sock -> write(msgBuffer, sizeof(msgBuffer) + 8);
    	file -> readyForNew = true;
    }
    else if(incomingPacket.flag == 'D'){//if this is a data packet for file
    	writeData(incomingPacket, argv, fileNastiness, file, outputFile);
    	packetStruct responsePacket;
    	makePacket(&responsePacket, 'A', 'D', incomingPacket.fileNum,
    		incomingPacket.fileOffset, 0);
    	char msgBuffer[sizeof(responsePacket)];
    	memcpy(msgBuffer, &responsePacket, sizeof(responsePacket));
    	sock -> write(msgBuffer, sizeof(msgBuffer) + 8);
    }
}

bool renameTemp(packetStruct packet, char *argv[])
{
    // for renaming .TMP suffix
	std::string data = packet.data;
	string fileName = "";
	string result = "";
	bool isFileName = true;
	for(unsigned int i = 0; i < data.length(); i++){
		if(data[i] == '/'){
			isFileName = false;
			continue;
		}
		if(isFileName){
			fileName += data[i];
		}
		else
			result += data[i];
	}
	std::string targetDir = argv[targetDirArg];
	string tempPath = targetDir + fileName + ".TMP";
	if(result == "PASS"){
		string path = targetDir + fileName;
		int renameretval = rename(tempPath.c_str(), path.c_str());
		if (renameretval != 0){
			cerr << "Error renaming " << tempPath << " to " 
			<< path << " errno=" << strerror(errno) << endl;
			exit(1);
		}
		return true;
	}
	return false;				
}

void writeData(packetStruct packet, char *argv[], int fileNastiness, 
		currentFile *file, NASTYFILE *outputFile)
{
    size_t len;
    outputFile->fseek((packet.fileOffset * MAX_DATA_BYTES), SEEK_SET);
    len = outputFile->fwrite(packet.data, 1, packet.numBytes);
    if(len != packet.numBytes){
	cerr << "error when writing" << endl;
    }
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
    string tempPath = path + fileName + ".TMP";

    fopenretval = inputFile.fopen(tempPath.c_str(), "rb");

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

    free(buffer);

    std::string sha1 = sha1hex;
    return sha1hex;
}
