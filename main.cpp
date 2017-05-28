#include <iostream>
#include <cstring>
#include <fstream>
#include <algorithm>

#include "RC6.h"

#define RC6_W 32
#define RC6_R 20

unsigned int keylength(std::string key) {
    return key.length() / 2;
}

std::string remove_whitespace(std::string str) {
    std::string tmp = str.substr(0, str.length());
    tmp.erase(std::remove_if(tmp.begin(), tmp.end(), isspace), tmp.end());
    return tmp;
}

int main() {
    std::string text = "010203040506070809101213141516", userkey = "01020304";
    RC6 *rc6 = new RC6(RC6_W, RC6_R, keylength(userkey));
    std::string encryptResult = rc6->run(RC6_ENCRYPT_MODE, text, userkey);
    std::string decryptResult = rc6->run(RC6_DECRYPT_MODE, remove_whitespace(encryptResult), userkey);
    std::cout << encryptResult << std::endl;
    std::cout << decryptResult << std::endl;
}