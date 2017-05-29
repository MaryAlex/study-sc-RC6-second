#include <iostream>
#include <cstring>
#include <fstream>
#include <algorithm>
#include <ctime>
#include <bitset>

#include "RC6.h"

#define RC6_W 32
#define RC6_R 20
#define bitsInByte 8
#define bitsInInt (sizeof(int) * bitsInByte)

char ourXor(std::string what, std::string with) {
    return what.compare(with) ? '1' : '0';
}

std::string remove_whitespace(std::string str) {
    std::string tmp = str.substr(0, str.length());
    tmp.erase(std::remove_if(tmp.begin(), tmp.end(), isspace), tmp.end());
    return tmp;
}

std::string getVector(int n, bool isZeroes, std::string par, bool hamming) {
    std::string x;
    if (isZeroes) {
        for (int i = 0; i < n; ++i) {
            x.append("0");
        }
        return x;
    }
    if (!hamming) {
        for (int i = 0; i < n; ++i) {
            int tmp = round((rand() * 1.) / RAND_MAX);
            x.append(std::to_string(tmp));
        }
        return x;
    }
    for (int i = 0; i < n; ++i) {
        x.append(par);
    }
    int number = rand() % 3;
    for (int j = 0; j < number; ++j) {
        int ind = rand() % n;
        x[ind] = ourXor(par, "1");
    }
    return x;
}

std::string *getNVectors(long N, int n, bool isZeroes, std::string par, bool hamming) {
    std::string *vectors = new std::string[N];
    for (long i = 0; i < N; ++i) {
        vectors[i] = getVector(n, isZeroes, par, hamming);
    }
    return vectors;
};

std::string stringToHex(std::string str) {
    std::string result = "";
    unsigned long n = str.length();
    for (unsigned long i = 0; i < n; i += bitsInByte) {
        std::string number = str.substr(i, bitsInByte);
        int a = std::strtol(number.c_str(), NULL, 2);
        std::stringstream stream;
        stream << std::setfill('0') << std::setw(2) << std::hex << a;
        result.append(stream.str());
    }
    return result;
}

std::string hexToString(std::string str) {
    std::string result = "";
    unsigned long n = str.length();
    for (unsigned long i = 0; i < n; i += 2) {
        std::string number = str.substr(i, 2);
        int a = std::strtol(number.c_str(), NULL, 16);
        std::string binary = std::bitset<bitsInByte>(a).to_string();
        result.append(binary);
    }
    return result;
}

std::string *encryptBlocks(RC6 *rc6, std::string *vectors, long N, std::string key) {
    std::string hexKey = stringToHex(key);
    std::string *encrypted = new std::string[N];
    for (long i = 0; i < N; i++) {
        std::string str = stringToHex(vectors[i]);
        std::string encrypted_line = rc6->run(RC6_ENCRYPT_MODE, str, hexKey);
        encrypted[i] = hexToString(remove_whitespace(encrypted_line));
    }
    return encrypted;
}

std::string *encryptBlocksForNine(RC6 *rc6, long N, int n, std::string key) {
    std::string hexKey = stringToHex(key);
    std::string *encrypted = new std::string[N + 1];
    for (int i = 0; i < n; i++) {
        encrypted[0].append("0");
    }
    for (long i = 1; i <= N; i++) {
        std::string str = stringToHex(encrypted[i - 1]);
        std::string encrypted_line = rc6->run(RC6_ENCRYPT_MODE, str, hexKey);
        encrypted[i] = hexToString(remove_whitespace(encrypted_line));
    }
    return encrypted;
}

std::string xorVectros(std::string a, std::string b) {
    std::string result = a;
	//it used to be 
	//std::string result;
	//but it didn't work that way, so I changed it to this

    for (int i = 0; i < a.length(); ++i) {
        result[i] = ourXor(std::to_string(a[i]), std::to_string(b[i]));
    }
    return result;
}

std::string **encryptBlocksForSix(RC6 *rc6, long N, int n, int m, std::string *keys) {
    std::string tmp;
    for (int k = 0; k < n; ++k) {
        tmp.append("0");
    }
    tmp = stringToHex(tmp);
	
    std::string **encrypted = new std::string *[N];
    for (int i = 0; i < N; i++) {
		encrypted[i] = new std::string [m];
        std::string hexKey = stringToHex(keys[i]);
        std::string encr = rc6->run(RC6_ENCRYPT_MODE, tmp, hexKey);
        encr = hexToString(remove_whitespace(encr));
        for (int j = 0; j < m; j++) {
            std::string key_j = keys[i];
            key_j[j] = ourXor(std::to_string(key_j[j]), "1");
            std::string encr_j = rc6->run(RC6_ENCRYPT_MODE, tmp, stringToHex(key_j));
            encr_j = hexToString(remove_whitespace(encr_j));
            encrypted[i][j] = xorVectros(encr, encr_j);
        }
    }
    return encrypted;
}

std::string **encryptBlocksForSeven(RC6 *rc6, long N, int n, int m, std::string *vectors) {
    std::string tmp;
    for (int k = 0; k < m; ++k) {
        tmp.append("0");
    }
    tmp = stringToHex(tmp);
    std::string **encrypted = new std::string *[N];
    for (int i = 0; i < N; i++) {
        encrypted[i] = new std::string[m];
    }
    for (int i = 0; i < N; i++) {
        std::string text = stringToHex(vectors[i]);
        std::string encr = rc6->run(RC6_ENCRYPT_MODE, text, tmp);
        encr = hexToString(remove_whitespace(encr));
        for (int j = 0; j < n; j++) {
            std::string text_j = vectors[i];
            text_j[j] = ourXor(std::to_string(text_j[j]), "1");
            std::string encr_j = rc6->run(RC6_ENCRYPT_MODE, stringToHex(text_j), tmp);
            encr_j = hexToString(remove_whitespace(encr_j));
            encrypted[i][j] = xorVectros(encr, encr_j);
        }
    }
    return encrypted;
}

std::string *encryptBlocksForEight(RC6 *rc6, std::string *vectors, long N, std::string key) {
	
	std::string hexKey = stringToHex(key);
    std::string *encrypted = new std::string[N];
    for (long i = 0; i < N; i++) {
        std::string str = stringToHex(vectors[i]);
		
        std::string encrypted_line = rc6->run(RC6_ENCRYPT_MODE, str, hexKey);
        encrypted[i] = hexToString(remove_whitespace(encrypted_line));
        encrypted[i] = xorVectros(encrypted[i], vectors[i]);
		
    }
    return encrypted;
}

unsigned int *bitStringToIntArray(std::string str) {
    int n = str.length() / bitsInInt;
    unsigned int *numbers = new unsigned int[n];
    for (unsigned long i = 0; i < n; i++) {
        std::string number = str.substr(i * bitsInInt, bitsInInt);
        numbers[i] = std::strtol(number.c_str(), NULL, 2);
    }
    return numbers;
}

void writeInFile(std::string filename, std::string *vectors, long N) {
    std::ofstream output;
    output.open(filename, std::ios::binary | std::ios::out);
    for (long i = 0; i < N; ++i) {
        int n = (vectors[i].length() / bitsInInt);
        unsigned int *toFile = bitStringToIntArray(vectors[i]);
        for (int j = 0; j < n; ++j) {
            unsigned int a = toFile[j];
            std::stringstream stream;
            stream << std::setfill('0') << std::setw(2) << std::hex << a;
            std::cout << stream.str() << " ";
            output.write((char *) &a, sizeof(int));
        }
        std::cout << std::endl;
    }
    output.close();
}

int main() {
    srand(time(NULL));
    int keyLength = 16;
	int m = keyLength * bitsInByte;
    RC6 *rc6 = new RC6(RC6_W, RC6_R, keyLength);
	long N = 625000;
    int n = 128;
    std::ofstream output;
    output.open("keys.txt", std::ios::out);
	
    std::string *vectors = getNVectors(N, n, false, "0", false);

    std::string key = getVector(keyLength * bitsInByte, false, "0", false);
    std::string hexKey = stringToHex(key);
    std::cout << "key 1 = " << hexKey << std::endl;
    output.write(hexKey.c_str(), hexKey.length());

    std::string *encryptResult = encryptBlocks(rc6, vectors, N, key);

    writeInFile("result1.bin", encryptResult, N);
    delete[] vectors;
    delete[] encryptResult;

    vectors = getNVectors(N, n, false, "0", true);
    key = getVector(keyLength * bitsInByte, false, "0", false);
    hexKey = stringToHex(key);
    std::cout << "key 2 = " << stringToHex(key) << std::endl;
    output.write(hexKey.c_str(), hexKey.length());
    encryptResult = encryptBlocks(rc6, vectors, N, key);
    writeInFile("result2.bin", encryptResult, N);
    delete[] vectors;
    delete[] encryptResult;

    vectors = getNVectors(N, n, false, "1", true);
    key = getVector(keyLength * bitsInByte, false, "0", false);
    hexKey = stringToHex(key);
    std::cout << "key 3 = " << stringToHex(key) << std::endl;
    output.write(hexKey.c_str(), hexKey.length());
    encryptResult = encryptBlocks(rc6, vectors, N, key);
    writeInFile("result3.bin", encryptResult, N);
    delete[] vectors;
    delete[] encryptResult;

    vectors = getNVectors(N, n, false, "1", false);
    key = getVector(keyLength * bitsInByte, false, "0", true);
    hexKey = stringToHex(key);
    std::cout << "key 4 = " << stringToHex(key) << std::endl;
    output.write(hexKey.c_str(), hexKey.length());
    encryptResult = encryptBlocks(rc6, vectors, N, key);
    writeInFile("result4.bin", encryptResult, N);
    delete[] vectors;
    delete[] encryptResult;

    vectors = getNVectors(N, n, false, "1", false);
    key = getVector(keyLength * bitsInByte, false, "1", true);
    hexKey = stringToHex(key);
    std::cout << "key 5 = " << stringToHex(key) << std::endl;
    output.write(hexKey.c_str(), hexKey.length());
    encryptResult = encryptBlocks(rc6, vectors, N, key);
    writeInFile("result5.bin", encryptResult, N);
    delete[] vectors;
    delete[] encryptResult;
	

	N = 4882;//?
	
	std::string *keys = getNVectors(N, m, false, "1", false);
	std::string **encryptResults = encryptBlocksForSix(rc6, N, n, m, keys);
	
	for (int i = 0; i < N; i++) {
		writeInFile("result6.bin", encryptResults[i], m);
	}
	
	delete[] keys;
	//for reason unknown, it doesn't work with the commented part, though it should
//	for (int j = 0; j < n; j++) {
//		delete[] encryptResults[j];
//	}
	delete[] encryptResults; //but do we need this then?

	vectors = getNVectors(N, n, false, "1", false);
	encryptResults = encryptBlocksForSeven(rc6, N, n, m, vectors);
	for (int i = 0; i < N; i++) {
		writeInFile("result7.bin", encryptResults[i], m);
	}

	delete[] vectors;
//	for (int j = 0; j < n; j++) {
//		delete[] encryptResults[j];
//	}
	delete[] encryptResults;//same questions
	

	vectors = getNVectors(N, n, false, "1", false);
	key = getVector(m, false, "1", false);
	hexKey = stringToHex(key);
	std::cout << "key 8 = " << stringToHex(key) << std::endl;
	output.write(hexKey.c_str(), hexKey.length());

	encryptResult = encryptBlocksForEight(rc6, vectors, N, key);
	writeInFile("result8.bin", encryptResult, N);

	delete[] vectors;
	delete[] encryptResult;


	key = getVector(m, false, "1", false);
	hexKey = stringToHex(key);
	std::cout << "key 9 = " << stringToHex(key) << std::endl;
	output.write(hexKey.c_str(), hexKey.length());

	encryptResult = encryptBlocksForNine(rc6, N, n, key);
	writeInFile("result9.bin", encryptResult, N);

	delete[] encryptResult;


    output.close();
	return 0;
}