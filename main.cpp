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
	return what.compare("1") ? '0' : '1';
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
		//std::cout << i << std::endl;
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
	//std::cout << "here" << std::endl;
	std::string hexKey = stringToHex(key);
	std::string *encrypted = new std::string[N];
	for (long i = 0; i < N; i++) {
		std::string str = stringToHex(vectors[i]);
		std::string encrypted_line = remove_whitespace(rc6->run(RC6_ENCRYPT_MODE, str, hexKey));
		encrypted[i] = hexToString(encrypted_line);
	}
	return encrypted;
}

std::string xorVectros(std::string a, std::string b) {
	std::string result;
	for (int i = 0; i < a.length(); ++i) {
		result[i] = ourXor(std::to_string(a[i]), std::to_string(b[i]));
	}
	return result;
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
	for (int i = 0; i < N; ++i) {
		int n = (vectors[i].length() / bitsInInt);
		unsigned int *toFile = bitStringToIntArray(vectors[i]);
		for (int j = 0; j < n; ++j) {
			unsigned int a = toFile[j];
			output.write((char *)&a, sizeof(int));
		}
	}
	output.close();
}

int main() {
	srand(time(NULL));
	int keyLength = 16;
	RC6 *rc6 = new RC6(RC6_W, RC6_R, keyLength);
	long N = 78125;
	int n = 128;
	std::ofstream output;
	output.open("keys.txt", std::ios::out);
	std::cout << "generation: " << clock() << std::endl;
	std::string *vectors = getNVectors(N, n, false, "0", false);
	std::cout << clock() << std::endl;
	std::string key = getVector(keyLength * bitsInByte, false, "0", false);
	std::string hexKey = stringToHex(key);
	std::cout << "key 1 = " << hexKey << std::endl;
	output.write(hexKey.c_str(), hexKey.length());
	std::cout << "encryption: " << clock() << std::endl;
	std::string *encryptResult = encryptBlocks(rc6, vectors, N, key);
	std::cout << clock() << std::endl;
	writeInFile("result1.bin", encryptResult, N);
	delete[]vectors;
	delete[]encryptResult;

	vectors = getNVectors(N, n, false, "0", true);
	key = getVector(keyLength * bitsInByte, false, "0", false);
	hexKey = stringToHex(key);
	std::cout << "key 2 = " << stringToHex(key) << std::endl;
	output.write(hexKey.c_str(), hexKey.length());
	encryptResult = encryptBlocks(rc6, vectors, N, key);
	writeInFile("result2.bin", encryptResult, N);
	delete[]vectors;
	delete[]encryptResult;

	vectors = getNVectors(N, n, false, "1", true);
	key = getVector(keyLength * bitsInByte, false, "0", false);
	hexKey = stringToHex(key);
	std::cout << "key 3 = " << stringToHex(key) << std::endl;
	output.write(hexKey.c_str(), hexKey.length());
	encryptResult = encryptBlocks(rc6, vectors, N, key);
	writeInFile("result3.bin", encryptResult, N);
	delete[]vectors;
	delete[]encryptResult;

	vectors = getNVectors(N, n, false, "1", false);
	key = getVector(keyLength * bitsInByte, false, "0", true);
	hexKey = stringToHex(key);
	std::cout << "key 4 = " << stringToHex(key) << std::endl;
	output.write(hexKey.c_str(), hexKey.length());
	encryptResult = encryptBlocks(rc6, vectors, N, key);
	writeInFile("result4.bin", encryptResult, N);
	delete[]vectors;
	delete[]encryptResult;

	vectors = getNVectors(N, n, false, "1", false);
	key = getVector(keyLength * bitsInByte, false, "1", true);
	hexKey = stringToHex(key);
	std::cout << "key 5 = " << stringToHex(key) << std::endl;
	output.write(hexKey.c_str(), hexKey.length());
	encryptResult = encryptBlocks(rc6, vectors, N, key);
	writeInFile("result5.bin", encryptResult, N);
	delete[]vectors;
	delete[]encryptResult;

	output.close();

}