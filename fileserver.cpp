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


using namespace C150NETWORK;

void checkDirectory(char *dirname);
string checkFiles(C150DgmSocket *sock, char *targetDir, string fileName);
string computeSha(string fileName, char *targetDir);

int
main(int argc, char *argv[])
{
	ssize_t readlen;
	char incomingMessage[512];
	int nastiness;
	if(argc != 3){
		fprintf(stderr, "Correct syntax is: %s <nastiness_number> <target_directory>\n", argv[0]);
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
			string response = incoming + '/' + checkFiles(sock,
							 argv[2], incoming);
			sock -> write(response.c_str(), response.length()+1);
			readlen = sock -> read(incomingMessage, sizeof(incomingMessage)-1);
			fprintf(stderr, "Incoming: %s", incomingMessage);
			cout << incoming << '\n';
			if (incomingMessage == (incoming + "/SUCCESS")
                                 || incomingMessage == (incoming + "/FAILURE" 
								))
			{	
				fprintf(stderr, "fssdfwdsdfsdsdf\n");	
				string finalAck = incoming + "/OK";
				sock -> write(finalAck.c_str(), 
					finalAck.length()+1);
			}
			
		}
	}
	catch(C150NetworkException e){
		cerr << argv[0] << ": caught C150NetworkException: " << e.formattedExplanation() << endl;		
	}
}

string checkFiles(C150DgmSocket* sock, char *targetDir, string fileName)
{
	checkDirectory(targetDir);
	DIR *TARGET;
//	struct dirent *sourceFile;
	TARGET = opendir(targetDir);
	if (TARGET == NULL) {
   		fprintf(stderr,"Error opening source directory %s\n", 
						targetDir);
   		exit(8);
 	}
  //	while ((sourceFile = readdir(TARGET)) != NULL) {
   		// skip the . and .. names
       // 	if ((strcmp(sourceFile->d_name, ".") == 0) ||
       //     	    (strcmp(sourceFile->d_name, "..")  == 0 ))
       //   	continue;          // never copy . or ..
    
       	   	 // do the copy -- this will check for and
        	 // skip subdirectories
        string response = computeSha(fileName, targetDir);
     //	}
        closedir(TARGET);
	return response;
}

void
checkDirectory(char *dirname) {
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

string computeSha(string fileName, char *targetDir)
{
	char sha1hex[40];
	std::string path = targetDir;
	//add '/' to end of path if it is not there
	if(path[path.length() - 1] != '/') path += '/';
	ifstream *t;
	stringstream *buffer;
	unsigned char obuf[20];
	printf ("SHA1 (\"%s\") = ", (path+fileName).c_str());
	t = new ifstream((path+fileName).c_str());
	buffer = new stringstream;
	*buffer << t->rdbuf();
	SHA1((const unsigned char *)buffer->str().c_str(),
	     (buffer->str()).length(), obuf);
        for (int i = 0; i < 20; i++)
        {
        	sprintf (sha1hex + (i*2), "%02x", (unsigned int) obuf[i]);
        }
        printf ("\n");
        delete t;
        delete buffer;
	std::string sha1 = sha1hex;
	return sha1;
}
