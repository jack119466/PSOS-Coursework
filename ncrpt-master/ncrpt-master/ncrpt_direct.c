// Vladislav Smirnov, 11/27/2018

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>

#define BUF_SIZE 1048576

char crypt(char c) {
	return c ^ 0b10101010;
}

void crypt_file(const char* path) {
	FILE *file = fopen(path, "r+b");
	_fseeki64(file, 0L, SEEK_END);
	__int64 size = _ftelli64(file);
	_fseeki64(file, 0L, SEEK_SET);

	char *b = (char*)malloc(sizeof(char)*BUF_SIZE);
	__int64 br = 0;
	
	__int64 pctg = 0;
	__int64 pctgn = 0;
	
	for (__int64 i = 0; i < size; i+=br) {
		_fseeki64(file, i, SEEK_SET);
		br = fread(b, 1, BUF_SIZE, file);
		_fseeki64(file, i, SEEK_SET);
		for (int k = 0; k < br; k++) b[k] = crypt(b[k]);
		fwrite(b, 1, br, file);
		
#ifndef NO_PROGRESS
		// printing progress
		pctgn = (i + br)*100/size;
		if (pctgn != pctg) {
			pctg = pctgn;
			printf("Progress: %I64d%%\r", pctg);
		}
#endif
	}
	
	printf("\nCleaning up...");
	fclose(file);
	free(b);
}

int main(int argc, char* argv[]) {
	if (argc < 2) return -1;

	crypt_file(argv[1]);

	return 0;
}
