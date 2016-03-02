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

void checkDirectory(char *dirname);
string checkFiles(C150DgmSocket *sock, char *targetDir, string fileName, int fileNastiness);
string computeSha(string fileName, char *targetDir, int fileNastiness);

int main(int argc, char *argv[])
{
    GRADEME(argc, argv);
	ssize_t readlen;
	char incomingMessage[512];

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
		while(1){

            //TODO: inconsistent hanlding of incoming messages
			readlen = sock -> read(incomingMessage, sizeof(incomingMessage)-1);
			if (readlen == 0) {
				continue;
			}
			incomingMessage[readlen] = '\0';
			string incoming(incomingMessage);
            //TODO: add possible checkMessage function, and check transaction ID
			cleanString(incoming);
			// cout << "incoming: " << incoming << "\n";
			// printf("incomingMessage: %s", incomingMessage);

            //Assume the messag is not first stage message, which only has file without any flag
			string flag = "";
			bool isflag = true;
			for(int i = incoming.length() - 1; i >= 0; i--){
				if(incoming[i] == '/') isflag= false;
				if(isflag) flag += incoming[i];
				else break; //Finished getting the all flag
			}

            //Since we read backwards, the checking string is backward. Will improve in later version
            if (flag ==  "SSECCUS" || flag == "ERULIAF"){
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
			}
			//TODO: the current version only works in nastiness 0 and 1
		}
	}
	catch(C150NetworkException e){
		cerr << argv[0] << ": caught C150NetworkException: " << e.formattedExplanation() << endl;		
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
    return sha1;
}
