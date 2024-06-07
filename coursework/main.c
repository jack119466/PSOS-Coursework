#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>
#include <stdlib.h>

#define KEY_FILENAME "keyfile.dat"

// global variable
HCRYPTPROV hCryptProv;
HCRYPTKEY hKey;
HCRYPTHASH hHash;



// Error-handling function
void HandleError(const char *msg) {
    DWORD errCode = GetLastError();
    printf("%s Error code: %lu\n", msg, errCode);
    exit(1);
}

// Initialize the encryption component and generate the key
void InitializeCrypto(const char *password) {
    if (!CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        HandleError("Error acquiring context");
    }

    if (!CryptCreateHash(hCryptProv, CALG_SHA_256, 0, 0, &hHash)) {
        HandleError("Error creating hash");
    }

    if (!CryptHashData(hHash, (BYTE *)password, strlen(password), 0)) {
        HandleError("Error hashing data");
    }

    if (!CryptDeriveKey(hCryptProv, CALG_AES_256, hHash, CRYPT_EXPORTABLE, &hKey)) {
        HandleError("Error deriving key");
    }
}

// Clean up cryptographic components
void CleanupCrypto() {
    if (hKey) CryptDestroyKey(hKey);
    if (hHash) CryptDestroyHash(hHash);
    if (hCryptProv) CryptReleaseContext(hCryptProv, 0);
}

// Save the key and username to a file
void SaveKeyToFile(const char *username) {
    HANDLE hFile = CreateFile(KEY_FILENAME, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        HandleError("Error creating key file");
    }

    DWORD keyBlobLen;
    if (!CryptExportKey(hKey, 0, PLAINTEXTKEYBLOB, 0, NULL, &keyBlobLen)) {
        CloseHandle(hFile);
        HandleError("Error getting key blob length");
    }

    BYTE *keyBlob = (BYTE *)malloc(keyBlobLen);
    if (!CryptExportKey(hKey, 0, PLAINTEXTKEYBLOB, 0, keyBlob, &keyBlobLen)) {
        free(keyBlob);
        CloseHandle(hFile);
        HandleError("Error exporting key blob");
    }

    DWORD bytesWritten;
    if (!WriteFile(hFile, &keyBlobLen, sizeof(DWORD), &bytesWritten, NULL)) {
        free(keyBlob);
        CloseHandle(hFile);
        HandleError("Error writing key blob length to file");
    }

    if (!WriteFile(hFile, keyBlob, keyBlobLen, &bytesWritten, NULL)) {
        free(keyBlob);
        CloseHandle(hFile);
        HandleError("Error writing key blob to file");
    }

    // Write the username in
    DWORD usernameLen = strlen(username) + 1;
    if (!WriteFile(hFile, &usernameLen, sizeof(DWORD), &bytesWritten, NULL)) {
        free(keyBlob);
        CloseHandle(hFile);
        HandleError("Error writing username length to file");
    }

    if (!WriteFile(hFile, username, usernameLen, &bytesWritten, NULL)) {
        free(keyBlob);
        CloseHandle(hFile);
        HandleError("Error writing username to file");
    }

    free(keyBlob);
    CloseHandle(hFile);
}

// Read the key and username from the file and verify
void LoadKeyFromFile(const char *username) {
    HANDLE hFile = CreateFile(KEY_FILENAME, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        HandleError("Error opening key file");
    }

    DWORD keyBlobLen;
    DWORD bytesRead;
    if (!ReadFile(hFile, &keyBlobLen, sizeof(DWORD), &bytesRead, NULL) || bytesRead != sizeof(DWORD)) {
        CloseHandle(hFile);
        HandleError("Error reading key blob length from file");
    }

    BYTE *keyBlob = (BYTE *)malloc(keyBlobLen);
    if (!ReadFile(hFile, keyBlob, keyBlobLen, &bytesRead, NULL) || bytesRead != keyBlobLen) {
        free(keyBlob);
        CloseHandle(hFile);
        HandleError("Error reading key blob from file");
    }

    if (!CryptImportKey(hCryptProv, keyBlob, keyBlobLen, 0, 0, &hKey)) {
        free(keyBlob);
        CloseHandle(hFile);
        HandleError("Error importing key from blob");
    }

    free(keyBlob);

    // Read and validate the username
    DWORD usernameLen;
    if (!ReadFile(hFile, &usernameLen, sizeof(DWORD), &bytesRead, NULL) || bytesRead != sizeof(DWORD)) {
        CloseHandle(hFile);
        HandleError("Error reading username length from file");
    }

    //This is where the logic for user authentication takes place
    //If the verification passes, the encryption or decryption operation can proceed
    char *storedUsername = (char *)malloc(usernameLen);
    if (!ReadFile(hFile, storedUsername, usernameLen, &bytesRead, NULL) || bytesRead != usernameLen) {
        free(storedUsername);
        CloseHandle(hFile);
        HandleError("Error reading username from file");
    }

    if (strcmp(username, storedUsername) != 0) {
        free(storedUsername);
        CloseHandle(hFile);
        HandleError("\nUsername does not match. Decryption not allowed.");
    }

    free(storedUsername);
    CloseHandle(hFile);
}

// Encryption function
void EncryptFileCustom(const char *inputFilePath, const char *outputFilePath) {
    // Open the input file
    HANDLE hInputFile = CreateFile(inputFilePath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hInputFile == INVALID_HANDLE_VALUE) {
        HandleError("Error opening input file");
    }

    // Creating an output file
    HANDLE hOutputFile = CreateFile(outputFilePath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hOutputFile == INVALID_HANDLE_VALUE) {
        CloseHandle(hInputFile);
        HandleError("Error creating output file");
    }

    BYTE buffer[1024];
    DWORD bytesRead, bytesWritten;
    BOOL finalBlock = FALSE;

    // Encrypting file contents
    while (ReadFile(hInputFile, buffer, sizeof(buffer), &bytesRead, NULL) && bytesRead > 0) {
        if (bytesRead < sizeof(buffer)) {
            finalBlock = TRUE;
        }

        DWORD dataLen = bytesRead;
        if (!CryptEncrypt(hKey, 0, finalBlock, 0, buffer, &dataLen, sizeof(buffer))) {
            CloseHandle(hInputFile);
            CloseHandle(hOutputFile);
            HandleError("Error encrypting data");
        }

        if (!WriteFile(hOutputFile, buffer, dataLen, &bytesWritten, NULL)) {
            CloseHandle(hInputFile);
            CloseHandle(hOutputFile);
            HandleError("Error writing encrypted data");
        }
    }



    CloseHandle(hInputFile);
    CloseHandle(hOutputFile);
}

// Decryption function
void DecryptFileCustom(const char *inputFilePath, const char *outputFilePath) {
    // Open the input file
    HANDLE hInputFile = CreateFile(inputFilePath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hInputFile == INVALID_HANDLE_VALUE) {
        HandleError("Error opening input file");
    }

    // Creating an output file
    HANDLE hOutputFile = CreateFile(outputFilePath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hOutputFile == INVALID_HANDLE_VALUE) {
        CloseHandle(hInputFile);
        HandleError("Error creating output file");
    }

    BYTE buffer[1024];
    DWORD bytesRead, bytesWritten;
    BOOL finalBlock = FALSE;

    // Decrypt file contents
    while (ReadFile(hInputFile, buffer, sizeof(buffer), &bytesRead, NULL) && bytesRead > 0) {
        finalBlock = bytesRead < sizeof(buffer);

        DWORD dataLen = bytesRead;
        if (!CryptDecrypt(hKey, 0, finalBlock, 0, buffer, &dataLen)) {
            CloseHandle(hInputFile);
            CloseHandle(hOutputFile);
            HandleError("Error decrypting data");
        }

        if (!WriteFile(hOutputFile, buffer, dataLen, &bytesWritten, NULL)) {
            CloseHandle(hInputFile);
            CloseHandle(hOutputFile);
            HandleError("Error writing decrypted data");
        }
    }

    CloseHandle(hInputFile);
    CloseHandle(hOutputFile);
}

void loginUser(char *username, char *password) {


    printf("Enter username: ");
    scanf("%s", username);
    printf("Enter password: ");
    scanf("%s", password);

}

void getInputFilePath(char *filePath) {
    printf("Enter input file path: ");
    scanf("%s", filePath);
}

void getOutputFilePath(char *filePath) {
    printf("Enter output file path: ");
    scanf("%s", filePath);
}

int main() {

    int choice;
    char username[100];
    char password[100];

    // users login
    loginUser(username,password);


    while (1) {
        printf("Enter 1 to encrypt or 0 to decrypt: ");
        scanf("%d", &choice);

        if (choice == 1) {
            // encrypt file
            char inputFilePath[1000];
            char encryptedFilePath[1000];

            getInputFilePath(inputFilePath);
            getOutputFilePath(encryptedFilePath);

            InitializeCrypto(password);

            printf("\nEncrypting file: %s\n", inputFilePath);
            EncryptFileCustom(inputFilePath, encryptedFilePath);
            printf("Encryption completed. Encrypted file: %s\n", encryptedFilePath);

            SaveKeyToFile(username);
            printf("Username and Key saved to file: %s\n", KEY_FILENAME);

            CleanupCrypto();
        } else if (choice == 0) {
            // deencrypt File
            char encryptedFilePath[1000];
            char decryptedFilePath[1000];

            getInputFilePath(encryptedFilePath);
            getOutputFilePath(decryptedFilePath);

            if (!CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
                HandleError("Error acquiring context");
            }

            LoadKeyFromFile(username);
            printf("\nDecrypting file: %s\n", encryptedFilePath);

            DecryptFileCustom(encryptedFilePath, decryptedFilePath);
            printf("Decryption completed. Decrypted file: %s\n", decryptedFilePath);

            CleanupCrypto();
        } else {
            printf("Invalid choice.\n");
        }

        printf("\nDo you want to continue? (1 for Yes, 0 for No): ");
        scanf("%d", &choice);
        while (getchar() != '\n');  // 清空输入缓冲区中的残留字符
        if (choice == 0) {
            break;
        }
    }

    return 0;
}
