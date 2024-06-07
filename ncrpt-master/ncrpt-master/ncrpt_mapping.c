// Vladislav Smirnov, 11/27/2018

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <windows.h>

void crypt(char *c) {
	*c = (*c) ^ 0b10101010;
}

DWORD64 conv32to64(DWORD hi, DWORD lo) {
	return (DWORD64) lo + ((DWORD64)(0xFFFFFFFF) + 1) * hi;
}

void crypt_file(const char* sp, DWORD64 sz) {
	char *cp = sp;
	DWORD64 iv = sz / 1000;

	for (DWORD64 i = 0; i < sz; i++) {
		if ((i % iv) == 0) {
			printf("Progress: %I64d.%I64d%%\r", i/iv/10, i/iv%10);
		}

		crypt(cp);
		cp++;
	}
}

char* mmap(char* fn, HANDLE *fh, HANDLE *mh, DWORD *szhi, DWORD *szlo) {
	*fh = CreateFileA(fn, GENERIC_READ|GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	*mh = CreateFileMappingA(*fh, NULL, PAGE_READWRITE, 0, 0, NULL);
	*szlo = GetFileSize(*fh, szhi);
	return (char*) MapViewOfFile(*mh, FILE_MAP_ALL_ACCESS, 0, *szhi, *szlo);
}

void unmap(const char *map, HANDLE *fh, HANDLE *mh) {
	FlushViewOfFile(map, 0);
	CloseHandle(*fh);
	CloseHandle(*mh);
}

int main(int argc, char* argv[]) {
	if (argc < 2) return -1;

	HANDLE fh, mh;
	DWORD szhi, szlo;

	const char *map = mmap(argv[1], &fh, &mh, &szhi, &szlo);

	printf("hi: %d, lo: %d\n", szhi, szlo);

	crypt_file(map, conv32to64(szhi, szlo));

	printf("\nCleaning up...");
	unmap(map, &fh, &mh);

	return 0;
}
