#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/ip.h> //ip hdeader library (must come before ip_icmp.h)
#include <netinet/ip_icmp.h> //icmp header
#include <arpa/inet.h> //internet address library
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <signal.h>
#include <error.h>
#include <errno.h>
#include <openssl/sha.h>
#include <ctype.h>
#include <sys/time.h>
#include <pthread.h>


#include "bencode.h"
#include "bt_lib.h"
#include "bt_setup.h"
#include "bt_sock.h"
#include "peer.h"
#include "bt_file.h"


extern double save_percent;
extern int num_saved_pieces;
int bytes_downloaded = 0;
char savefile[FILE_NAME_MAX];
extern char logfile[FILE_NAME_MAX];

static int **have_piece;

//implements logger functionality
void logger(int flag,const char* tag, const char* fmt, ...)
{
	FILE *log, *start;
	//int timeout = 0, error;
	//time_t now;
	va_list ap;                                /* special type for variable    */
	char format[1024];                /* argument lists               */
	//char buff[100];
	int count = 0;
	int i, j;                                  /* Need all these to store      */
	char c;                                    /* values below in switch       */
	double d;
	unsigned u;
	char *s;
	void *v;

	struct timeval tv;
	struct tm* ptm;
	char time_string[40];
	long milliseconds;

	if (pthread_mutex_lock(&lock)) {
		perror("pthread_mutex_lock");
		exit(1);
	}

	if (flag == LOG)
	{
		//fails if file exists and returns NULL
		//if the file does not exist, it will create new file and return the file pointer
		log = fopen(logfile, "wx");

		//Close the file if a new one was created
		if (log)
			fclose(log);

		
		if ((log = acquirelockon(logfile, "rb+")) == NULL)
		{
			printf("Timeout occurred while trying to log...Discarding the log message!!\n");
			return;
		}
						
		//Print log entry at the end
		fseek(log, 0, SEEK_END);

		start = log;

	}
	else if (flag == STDOUT)
	{
		log = stdout;
	}
	else if (flag == STDERR)
	{
		log = stderr;
	}


	/* Obtain the time of day, and convert it to a tm struct.  */
	gettimeofday(&tv, NULL);
	ptm = localtime(&tv.tv_sec);
	/* Format the date and time, down to a single second.  */
	bzero(time_string, 40);
	strftime(time_string, sizeof (time_string), "%Y-%m-%d %H:%M:%S", ptm);
	/* Compute milliseconds from microseconds.  */
	milliseconds = tv.tv_usec / 1000;


	fprintf(log, "%s.%03ld [%s]: ", time_string, milliseconds, tag);

	//Write the log file...
	va_start(ap, fmt);                         /* must be called before work   */
	while (*fmt) {
		for (j = 0; fmt[j] && fmt[j] != '%'; j++)
			format[j] = fmt[j];                    /* not a format string          */
		if (j) {
			format[j] = '\0';
			count += fprintf(log, format);    /* log it verbatim              */
			fmt += j;
		}
		else {
			for (j = 0; !isalpha(fmt[j]); j++) {   /* find end of format specifier */
				format[j] = fmt[j];
				if (j && fmt[j] == '%')              /* special case printing '%'    */
					break;
			}
			format[j] = fmt[j];                    /* finish writing specifier     */
			format[j + 1] = '\0';                  /* don't forget NULL terminator */
			fmt += j + 1;

			switch (format[j]) {                   /* cases for all specifiers     */
			case 'd':
			case 'i':                              /* many use identical actions   */
				i = va_arg(ap, int);                 /* process the argument         */
				count += fprintf(log, format, i); /* and log it                 */
				break;
			case 'o':
			case 'x':
			case 'X':
			case 'u':
				u = va_arg(ap, unsigned);
				count += fprintf(log, format, u);
				break;
			case 'c':
				c = (char)va_arg(ap, int);          /* must cast!                   */
				count += fprintf(log, format, c);
				break;
			case 's':
				s = va_arg(ap, char *);
				count += fprintf(log, format, s);
				break;
			case 'f':
			case 'e':
			case 'E':
			case 'g':
			case 'G':
				d = va_arg(ap, double);
				count += fprintf(log, format, d);
				break;
			case 'p':
				v = va_arg(ap, void *);
				count += fprintf(log, format, v);
				break;
			case 'n':
				count += fprintf(log, "%d", count);
				break;
			case '%':
				count += fprintf(log, "%%");
				break;
			default:
				fprintf(stderr, "Invalid format specifier in log().\n");
			}
		}
	}

	va_end(ap);                                /* clean up                     */

	if (flag == LOG)
	{
		rewind(start);
		//Close file
		fclose(log);
		//Unlock the block
		lockf(fileno(log), F_ULOCK, 0);
	}

	if (pthread_mutex_unlock(&lock)) {
		perror("pthread_mutex_unlock");
		exit(1);
	}

	return;
}

//checks if the file with the given filename exists
//if file does not exist, creates a new file and returns appropriate value
int preparefile(char * filename, off_t size)
{
	
	FILE *downloadfile = NULL;
	//make file (fails if file exists)
	downloadfile = fopen(filename, "wx");
	
	//Close the file if a new one was created
	if (downloadfile == NULL)
	{//file already exists!!
		//fclose(downloadfile);
		return FILE_EXISTS;
	}
	else
	{   //open a new file and set the file length.
		downloadfile = fopen(filename, "w");
		ftruncate(fileno(downloadfile), size);
		fclose(downloadfile);
		return NEW_FILE_CREATED;
	}
	
}


//allocates a global array have_piece to maintain whether a particular piece exists or not
void preparehavepiece(int no_of_pieces)
{
	int i = 0;

	if (have_piece != NULL)
	{
		return;
	}

	have_piece = (int **)malloc(no_of_pieces * sizeof(int *));

	for (i = 0; i < no_of_pieces; i++)
	{
		have_piece[i] = (int *)malloc(sizeof(int));
		have_piece[i][0] = NO;
	}

}

//Sets the piece state based on the input argument
void sethavepiece(int index, int as)
{
	if (have_piece != NULL) 
	{
		have_piece[index - 1][0] = as;
	}
}

//sets the bitfield variable
void bitfield_set(bt_bitfield_t *newbitfield, int bit)
{
	
	int byte = bit / 8;
	int mask = 0x80 >> (bit % 8);
	//printf("%s : %d %s byte: %d, bit : %d\n", __FILE__, __LINE__, __func__, byte, bit);
	newbitfield->bitfield[byte] |= mask;

}

//computes the bitfield 
bt_bitfield_t * computebitfield(int no_of_pieces)
{
	int i = 0, no_of_bytes = 0;
	int temp;
	bt_bitfield_t * newbitfield = NULL;

	//calculating the number of bytes to be allocated to store bitfield	
	temp = no_of_pieces / 8;
	if (no_of_pieces % 8 != 0)
		no_of_bytes = temp + 1;
	else
		no_of_bytes = temp;

	//allocating memory for bitfield
	newbitfield = (bt_bitfield_t *)malloc(sizeof(bt_bitfield_t));
	newbitfield->bitfield = (char *)malloc(no_of_bytes);
	newbitfield->size = (size_t)(no_of_bytes);
	
	//initialize the bitfield to zero
	bzero(newbitfield->bitfield, newbitfield->size);
	
	//set the bitfield
	for (i = 0; i < no_of_pieces; i++)
	{
		if (have_piece[i][0] == YES)
		{
			bitfield_set(newbitfield, i);
		}
		
	}
	return newbitfield;
}

//extracts the bitfield 
bt_bitfield_t * get_bitfield(bt_args_t * bt_args)
{
	int i = 0, ret = 0, len = 0;
	FILE *downloadfile = NULL;
	char *tempSHA1 = NULL;
	char *piecebuf = NULL;
	bt_info_t * bt_info = bt_args->bt_info;
	bt_bitfield_t * bitfield = NULL;
	int temp_num_saved_pieces = 0, temp_bytes_downloaded = 0;

	memset(savefile, 0x00, FILE_NAME_MAX);

	if (strlen(bt_args->save_file) == 0)
	{
		ret = preparefile(bt_info->name, bt_info->length);
		memcpy(savefile, bt_info->name, strlen(bt_info->name));
	}
	else
	{
		ret = preparefile(bt_args->save_file, bt_info->length);
		memcpy(savefile, bt_args->save_file, strlen(bt_args->save_file));
	}
	
	
	
	if (ret == NEW_FILE_CREATED)
	{//set all the bitfields to zero, also update the global structure with zeros
		preparehavepiece(bt_args->bt_info->num_pieces);
		bitfield = computebitfield(bt_args->bt_info->num_pieces);//, bitfield);
	}
	else if (ret == FILE_EXISTS)
	{   //restart the download!!...check for corrupt pieces and update accordingly
		//open the file
		preparehavepiece(bt_args->bt_info->num_pieces);
		do
		{
			if ((downloadfile = acquirelockon(savefile,"r")) == NULL)
				logger(LOG,"TIMEOUT","Timeout occurred while trying to acquire lock on downloadfile. Retrying again!!");
		} while (downloadfile == NULL);
		//lock acquired!! continue to read the file
		rewind(downloadfile);
		piecebuf = (char *)malloc(bt_args->bt_info->piece_length);
		tempSHA1 = (char *)malloc(ID_SIZE);
		for (i = 0; i < bt_args->bt_info->num_pieces; i++)
		{
			fseek(downloadfile, (i * bt_args->bt_info->piece_length), SEEK_SET);
			//read piece by piece into a buffer
			bzero(piecebuf, bt_args->bt_info->piece_length);
			bzero(tempSHA1, ID_SIZE);
					
			if ((len = readData(fileno(downloadfile), (unsigned char *)piecebuf, bt_args->bt_info->piece_length)) == FAILURE)
			{
				printf("Failed to read piece from the download file");
				logger(LOG,"ERROR","Failed to read piece from the download file");
				return NULL;
			}
			//compute sha1 for the piece
			SHA1((unsigned char *)piecebuf, len, (unsigned char *)tempSHA1);
			//compare the calculated sha1 with that in the bt_info
			if (!compare((unsigned char*)tempSHA1, (unsigned char*)bt_args->bt_info->piece_hashes[i], 20))
			{//not matched
				sethavepiece(i + 1, NO);
			}
			else
			{//if matching update the global stucture
				sethavepiece(i + 1, YES);
				temp_num_saved_pieces++;
				temp_bytes_downloaded += len;
			}
		}
		num_saved_pieces = temp_num_saved_pieces;
		bytes_downloaded = temp_bytes_downloaded;
		
		//cleanup#
		free(piecebuf);
		free(tempSHA1);
		releaselock(downloadfile);
		
		bitfield = computebitfield(bt_args->bt_info->num_pieces);// , bitfield);
	}
	
	return bitfield;
}


//open the file and return SUCCESS if acquires lock, else return FAILURE
FILE * acquirelockon(char *filename,char *access)
{
	FILE *file = NULL;
	FILE *filecopy = NULL;
	int timeout = 0, error;

	file = fopen(filename, access);
	filecopy = file;
	//Lock file (with timeout)
	rewind(filecopy);
	error = lockf(fileno(filecopy), F_TLOCK, 0);
	while (error == EACCES || error == EAGAIN)
	{
		//sleep for a bit
		usleep(LOCKED_FILE_RETRY_TIME);
		//Incremement timeout
		timeout += LOCKED_FILE_RETRY_TIME;
		//Check for time out
		if (timeout > LOCKED_FILE_TIMEOUT)
		{
			logger(LOG,"TIMEOUT", "Timeout occurred while trying to acquiring lock on download file");
			return NULL;
		}
		//Retry the lock operation
		error = lockf(fileno(filecopy), F_TLOCK, 0);
	}

	return file;
}


void releaselock(FILE *file)
{
	fclose(file);
	//Unlock the block
	lockf(fileno(file), F_ULOCK, 0);
}


/* save a piece of the file */
int save_piece(bt_args_t * bt_args, bt_piece_t * piece, int piecelen)
{
	FILE *fptr;
	long offset;
	int fd;
	

	do
	{
		if ((fptr = acquirelockon(savefile, "rb+")) == NULL)
			logger(LOG,"TIMEOUT", "Timeout occurred while trying to acquire lock on downloadfile and save piece. Retrying again!!");
	} while (fptr == NULL);

	if (fptr == NULL)
	{
		perror("File Open failed\n");
		return FAILURE;
	}

	fd = fileno(fptr);

	offset = (long)((piece->index) * (bt_args->bt_info->piece_length) + piece->begin);
	if (fseek(fptr, offset, SEEK_SET) != 0)
	{
		perror("Seek Error\n"); releaselock(fptr); return FAILURE;
	}

	if (sendData(fileno(fptr), (unsigned char*)piece->piece, piecelen) == FAILURE)
	{
		printf("Sending message type failed\n");
		return FAILURE;
	}

	num_saved_pieces += 1;
	save_percent = ((double)num_saved_pieces/bt_args->bt_info->num_pieces) * 100;
	bytes_downloaded += piecelen;
	printf("File: %s Progress: %.2f%% Downloaded: %.2f KB\n",savefile,save_percent,(float)bytes_downloaded/1024);
	logger(LOG,"DOWNLOAD STATUS","File: %s Progress: %.2f%% Downloaded: %.2f KB\n",savefile,save_percent,(float)bytes_downloaded/1024);
			
	releaselock(fptr);
	return SUCCESS;
}

//copies the piece from the file and writes into a piece message based on the request
int load_piece(bt_info_t * bt_info, bt_request_t *request, bt_piece_t * piece)
{
	FILE *fptr;
	long offset;
	char * buffer;
	int len;
	
	do
	{
		if ((fptr = acquirelockon(savefile, "r")) == NULL)
			logger(LOG,"TIMEOUT", "Timeout occurred while trying to acquire lock on downloadfile and load piece. Retrying again!!");
	} while (fptr == NULL);

	if (fptr == NULL)
	{
		return FAILURE;
	}
	

	offset = (long)((request->index) * (bt_info->piece_length) + request->begin);

	if (fseek(fptr, offset, SEEK_SET) != 0)
	{
		perror("fseek error\n"); releaselock(fptr); return FAILURE;
	}

	piece->index = request->index;
	piece->begin = request->begin;

	buffer = (char *)malloc(request->length);

	if ((len = readData(fileno(fptr), (unsigned char *)buffer, request->length)) == FAILURE)
	{
		printf("Failed to read piece from the download file");
		logger(LOG,"ERROR", "Failed to read piece from the download file");
		return FAILURE;
	}

	piece->piece = (char *)malloc(request->length);
	bzero(piece->piece, request->length);
	memcpy(piece->piece, buffer, request->length);

	free(buffer);
	releaselock(fptr);
	return SUCCESS;
}
