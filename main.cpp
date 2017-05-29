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
#define FOUR 4
#define ONE 1
#define bitsInInt (sizeof(int) * bitsInByte)

int N;

std::string remove_whitespace(std::string str) {
    std::string tmp = str.substr(0, str.length());
    tmp.erase(std::remove_if(tmp.begin(), tmp.end(), isspace), tmp.end());
    return tmp;
}

int *getVector(int n, bool isZeroes, int par, bool hamming) {
    N = n / bitsInInt;
    int *x = new int[N];
    if (isZeroes) {
        for (int i = 0; i < N; ++i) {
            x[i] = 0;
        }
        return x;
    }
    if (!hamming) {
        for (int i = 0; i < N; ++i) {
            x[i] = rand();
        }
        return x;
    }
    for (int i = 0; i < N; ++i) {
        if (par) {
            x[i] = INT32_MAX;
        } else {
            x[i] = 0;
        }

    }
    int number = rand() % 3;
    for (int j = 0; j < number; ++j) {
        int ind = rand() % n;
        x[ind / bitsInInt] = x[ind / bitsInInt] ^ (ONE << (ind % bitsInInt));
    }
    return x;
}

int **getNVectors(long M, int n, bool isZeroes, int par, bool hamming) {
    int **vectors = new int *[M];
    for (long i = 0; i < M; ++i) {
        vectors[i] = getVector(n, isZeroes, par, hamming);
    }
    return vectors;
};

std::string stringToHex(int *str) {
    std::string result = "";
    for (unsigned long i = 0; i < N; i++) {
        std::stringstream stream;
        stream << std::setfill('0') << std::setw(8) << std::hex << str[i];
        result.append(stream.str());
    }
    return result;
}

int *hexToString(std::string str) {
    int *result = new int[N];
    unsigned long n = str.length();
    for (unsigned long i = 0; i < n; i += 8) {
        std::string number = str.substr(i, 8);
        result[i / 8] = std::strtol(number.c_str(), NULL, 16);
    }
    return result;
}

int **encryptBlocks(RC6 *rc6, int **vectors, long M, int *key) {
    std::string hexKey = stringToHex(key);
    int **encrypted = new int *[M];
    for (long i = 0; i < M; i++) {
        std::string a = stringToHex(vectors[i]);
        std::string encrypted_line = remove_whitespace(rc6->run(RC6_ENCRYPT_MODE, a, hexKey));
        encrypted[i] = hexToString(encrypted_line);
    }
    return encrypted;
}

int **encryptBlocksForNine(RC6 *rc6, long M, int n, int *key) {
    std::string hexKey = stringToHex(key);
    int **encrypted = new int *[M + 1];
    encrypted[0] = new int [N];
    for (int i = 0; i < N; i++) {
        encrypted[0][i] = 0;
    }
    for (long i = 1; i <= M; i++) {
        std::string str = stringToHex(encrypted[i - 1]);
        std::string encrypted_line = rc6->run(RC6_ENCRYPT_MODE, str, hexKey);
        encrypted[i] = hexToString(remove_whitespace(encrypted_line));
    }
    return encrypted;
}

int *xorVectros(int *a, int *b) {
    int *result = new int[N];

    for (int i = 0; i < N; ++i) {
        result[i] = a[i] ^ b[i];
    }
    return result;
}

int ***encryptBlocksForSix(RC6 *rc6, long M, int n, int m, int **keys) {
    int *tmp = new int[N];
    for (int k = 0; k < N; ++k) {
        tmp[k] = 0;
    }
    std::string hexTmp = stringToHex(tmp);

    int ***encrypted = new int **[M];
    for (int i = 0; i < M; i++) {
        encrypted[i] = new int*[m];
        std::string hexKey = stringToHex(keys[i]);
        int *encr = hexToString(remove_whitespace(rc6->run(RC6_ENCRYPT_MODE, hexTmp, hexKey)));
        for (int j = 0; j < m; j++) {
            int *key_i = keys[i];
            key_i[j / bitsInInt] = key_i[j / bitsInInt] ^ (ONE << (j % bitsInInt));
            int *encr_j = hexToString(remove_whitespace(rc6->run(RC6_ENCRYPT_MODE, hexTmp, stringToHex(key_i))));
            encrypted[i][j] = xorVectros(encr, encr_j);
        }
    }
    return encrypted;
}

int ***encryptBlocksForSeven(RC6 *rc6, long M, int n, int m, int **vectors) {
    int *tmp = new int[N];
    for (int k = 0; k < N; ++k) {
        tmp[k] = 0;
    }
    std::string hexTmp = stringToHex(tmp);
    int ***encrypted = new int **[M];
    for (int i = 0; i < M; i++) {
        encrypted[i] = new int *[n];
        std::string text = stringToHex(vectors[i]);
        int *encr = hexToString(remove_whitespace(rc6->run(RC6_ENCRYPT_MODE, text, hexTmp)));
        for (int j = 0; j < n; j++) {
            int *text_i = vectors[i];
            text_i[j / bitsInInt] = text_i[j / bitsInInt] ^ (ONE << (j % bitsInInt));
            int *encr_j = hexToString(remove_whitespace(rc6->run(RC6_ENCRYPT_MODE, stringToHex(text_i), hexTmp)));
            encrypted[i][j] = xorVectros(encr, encr_j);
        }
    }
    return encrypted;
}

int **encryptBlocksForEight(RC6 *rc6, int **vectors, long M, int *key) {
    std::string hexKey = stringToHex(key);
    int **encrypted = new int *[M];
    for (long i = 0; i < M; i++) {
        std::string str = stringToHex(vectors[i]);
        std::string encrypted_line = rc6->run(RC6_ENCRYPT_MODE, str, hexKey);
        encrypted[i] = hexToString(remove_whitespace(encrypted_line));
        encrypted[i] = xorVectros(encrypted[i], vectors[i]);
    }
    return encrypted;
}

void writeInFile(std::string filename, int **vectors, long M) {
    std::ofstream output;
    output.open(filename, std::ios::binary | std::ios::out);
    for (long i = 0; i < M; ++i) {
        for (int j = 0; j < N; ++j) {
            int a = vectors[i][j];
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
    long M = 312500;
    int n = 128;
    std::ofstream output;
    output.open("keys.txt", std::ios::out);

    int **vectors = getNVectors(M, n, false, 0, false);

    int * key = getVector(keyLength * bitsInByte, false, 0, false);
    std::string hexKey = stringToHex(key);
    std::cout << "key 1 = " << hexKey << std::endl;
    output.write(hexKey.c_str(), hexKey.length());

    int **encryptResult = encryptBlocks(rc6, vectors, M, key);

    writeInFile("result1.bin", encryptResult, M);
    for (int j = 0; j < M; ++j) {
        delete[] vectors[j];
        delete[] encryptResult[j];
    }
    delete[] vectors;
    delete[] encryptResult;

    std::cout << "second ______________________________________________" << std::endl;
    vectors = getNVectors(M, n, false, 0, true);
    std::cout << "second ______________________________________________" << std::endl;
    key = getVector(keyLength * bitsInByte, false, 0, false);
    std::cout << "second ______________________________________________" << std::endl;
    hexKey = stringToHex(key);
    std::cout << "key 2 = " << hexKey << std::endl;
    output.write(hexKey.c_str(), hexKey.length());
    encryptResult = encryptBlocks(rc6, vectors, M, key);
    writeInFile("result2.bin", encryptResult, M);
    for (int j = 0; j < M; ++j) {
        delete[] vectors[j];
        delete[] encryptResult[j];
    }
    delete[] vectors;
    delete[] encryptResult;

    vectors = getNVectors(M, n, false, 1, true);
    key = getVector(keyLength * bitsInByte, false, 0, false);
    hexKey = stringToHex(key);
    std::cout << "key 3 = " << stringToHex(key) << std::endl;
    output.write(hexKey.c_str(), hexKey.length());
    encryptResult = encryptBlocks(rc6, vectors, M, key);
    writeInFile("result3.bin", encryptResult, M);
    for (int j = 0; j < M; ++j) {
        delete[] vectors[j];
        delete[] encryptResult[j];
    }
    delete[] vectors;
    delete[] encryptResult;

    vectors = getNVectors(M, n, false, 1, false);
    key = getVector(keyLength * bitsInByte, false, 0, true);
    hexKey = stringToHex(key);
    std::cout << "key 4 = " << stringToHex(key) << std::endl;
    output.write(hexKey.c_str(), hexKey.length());
    encryptResult = encryptBlocks(rc6, vectors, M, key);
    writeInFile("result4.bin", encryptResult, M);
    for (int j = 0; j < M; ++j) {
        delete[] vectors[j];
        delete[] encryptResult[j];
    }
    delete[] vectors;
    delete[] encryptResult;

    vectors = getNVectors(M, n, false, 1, false);
    key = getVector(keyLength * bitsInByte, false, 1, true);
    hexKey = stringToHex(key);
    std::cout << "key 5 = " << stringToHex(key) << std::endl;
    output.write(hexKey.c_str(), hexKey.length());
    encryptResult = encryptBlocks(rc6, vectors, M, key);
    writeInFile("result5.bin", encryptResult, M);
    for (int j = 0; j < M; ++j) {
        delete[] vectors[j];
        delete[] encryptResult[j];
    }
    delete[] vectors;
    delete[] encryptResult;


    M = 2441;//?

    std::cout << "6" << std::endl;
    int **keys = getNVectors(M, m, false, 1, false);
    int ***encryptResults = encryptBlocksForSix(rc6, M, n, m, keys);

    for (int i = 0; i < M; i++) {
        writeInFile("result6.bin", encryptResults[i], m);
    }
    for (int i = 0; i < M; i++) {
        delete[] keys[i];
        delete[] encryptResults[i];
    }
    delete[] keys;
    delete[] encryptResults;

    std::cout << "7" << std::endl;
    vectors = getNVectors(M, n, false, 1, false);
    std::cout << "7a" << std::endl;
    encryptResults = encryptBlocksForSeven(rc6, M, n, m, vectors);
    std::cout << "7b" << std::endl;
    for (int i = 0; i < M; i++) {
        writeInFile("result7.bin", encryptResults[i], n);
    }
    std::cout << "7c" << std::endl;
    for (int i = 0; i < M; i++) {
        delete[] vectors[i];
        delete[] encryptResults[i];
    }
    delete[] vectors;
    delete[] encryptResults;

    M = 312500;

    std::cout << "8" << std::endl;
    vectors = getNVectors(M, n, false, 1, false);
    key = getVector(m, false, 1, false);
    hexKey = stringToHex(key);
    std::cout << "key 8 = " << stringToHex(key) << std::endl;
    output.write(hexKey.c_str(), hexKey.length());

    encryptResult = encryptBlocksForEight(rc6, vectors, M, key);
    writeInFile("result8.bin", encryptResult, M);

    for (int j = 0; j < M; ++j) {
        delete[] vectors[j];
        delete[] encryptResult[j];
    }
    delete[] vectors;
    delete[] encryptResult;

    std::cout << "9" << std::endl;
    key = getVector(m, false, 1, false);
    hexKey = stringToHex(key);
    std::cout << "key 9 = " << stringToHex(key) << std::endl;
    output.write(hexKey.c_str(), hexKey.length());
    std::cout << "9b" << std::endl;
    encryptResult = encryptBlocksForNine(rc6, M, n, key);
    std::cout << "9c" << std::endl;
    writeInFile("result9.bin", encryptResult, M);

    for (int j = 0; j < M; ++j) {
        delete[] encryptResult[j];
    }
    delete[] encryptResult;


    output.close();
    std::cout << "The End" << std::endl;
    return 0;
}