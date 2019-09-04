#include <iostream>
#include <string>
#include <random>
#include <bitset>
#include <unordered_map>
#include <fstream>
#include "hash-library/sha1.h"
#include "hash-library/sha1.cpp"
#include "hash-library/sha256.h"
#include "hash-library/sha256.cpp"
#include "hash-library/sha3.h"
#include "hash-library/sha3.cpp"
#include "hash-library/keccak.h"
#include "hash-library/keccak.cpp"
#include "hash-library/md5.h"
#include "hash-library/md5.cpp"
#include "hash-library/crc32.h"
#include "hash-library/crc32.cpp"
#include <sstream>
#include <chrono>
#include <future>


std::random_device rd;
std::mt19937_64 gen(rd());
std::uniform_int_distribution<> dis(1, 60); // Random interval (a, b ili c)
std::uniform_int_distribution<> intDis(48, 57); // a) Znakovi [0, 9]
std::uniform_int_distribution<> upCDis(65, 90); // b) Znakovi [A, Z]
std::uniform_int_distribution<> lowCDis(97, 122); // c) Znakovi [a, z]
std::uniform_int_distribution<> allASCII(32, 126); //Svi ASCII znakovi

enum menuTypes {MAIN, GENMSG, CUSTOMMSG, COLLIDE, NCOLLIDE, CONFIG, TYPESIZE, MSGTYPE, MSGSIZE, MSGNUM, FIRSTPRT, DYNAMICPRT, SECONDPRT, MHASHES, HASHWEAK, DYNAMIN, DYNAMAX, HASHWOPT};
enum settTypes {TYPE, SIZE, NUM, FIRST, DYNAM, MIN, MAX, HASHES, SHA_1, SHA_2, SHA_3, KEccAK, MD_5, CRC_32};

struct Menu {
	menuTypes id=MAIN;
	std::string menu;
	Menu* child = NULL;
	Menu* neighbour = NULL;
};

struct Hashes {
	std::string sha_1, sha_2, sha_3, kecak, md_5, crc_32;
	std::string sha_1H, sha_2H, sha_3H, kecakH, md_5H, crc_32H;
	//std::string sha_1B, sha_2B, sha_3B, kecakB, md_5B, crc_32B;
};

Menu* men = new Menu;
Hashes mainHash;
const std::string ender = "\nx. Return\n>>";

std::string msg;
int settings[] = { 0, 1024, 2000, 0, 0, 2, 5, 1, 20, 1, 1, 1, 1, 1};
const int settSize = sizeof(settings) / sizeof(*settings);

std::string GetAlgName(int i) {
	switch (i) {
	case SHA_1: return "SHA1";
	case SHA_2: return "SHA2";
	case SHA_3: return "SHA3";
	case KEccAK: return "KECCAK";
	case MD_5: return "MD5";
	case CRC_32: return "CRC32";
	default: return "Unknown hashing algorithm.";
	}
}

bool CheckIfUsingHashAlg(int alg) {
	return ((settings[HASHES] >> (alg - SHA_1)) & 1) ? true : false;
}

std::string WeakenHash40(std::string hash, int alg) {
	long long bin;
	std::bitset<40> bits;
	int part = 40 / settings[alg];
	if (part <= 10) {
		for (int i = 0; i <= 40; i += part) {
			std::stringstream ss;
			ss << std::hex << hash.substr(i, part);
			ss >> bin;
			std::bitset<40> b(bin);
			bits ^= b;
		}
		std::stringstream ss;
		ss << std::hex << bits.to_ullong();
		return ss.str();
	}
	else if (part == 40) hash;
	else {
		std::string weakHash;
		for (int i = 0; i < 2; ++i) {
			std::stringstream ss;
			ss << std::hex << hash.substr(i * 10, 10);
			ss >> bin;
			std::bitset<40> b(bin);
			ss.str(""); ss.clear();
			ss << std::hex << hash.substr((i + 2) * 10, 10);
			ss >> bin;
			b ^= std::bitset<40>(bin);
			ss.str(""); ss.clear();
			ss << std::hex << b.to_ullong();
			weakHash += ss.str();
			while (weakHash.length() < (i+1) * 10) weakHash.insert(i * 10, "0");
		}
		return weakHash;
	}
}

std::string WeakenHash64(std::string hash, int alg) {
	unsigned long long bin;
	std::bitset<64> bits;
	int part = 64 / settings[alg];
	if (part <= 16) {
		for (int i = 0; i <= 64; i += part) {
			std::stringstream ss;
			ss << std::hex << hash.substr(i, part);
			ss >> bin;
			std::bitset<64> b(bin);
			bits ^= b;
		}
		std::stringstream ss;
		ss << std::hex << bits.to_ullong();
		return ss.str();
	}
	else if (part == 64) return hash;
	else {
		std::string weakHash;
		for (int i = 0; i < 2; ++i) {
			std::stringstream ss;
			ss << std::hex << hash.substr(i * 16, 16);
			ss >> bin;
			std::bitset<64> b(bin);
			ss.str(""); ss.clear();
			ss << std::hex << hash.substr((i + 2) * 16, 16);
			ss >> bin;
			b ^= std::bitset<64>(bin);
			ss.str(""); ss.clear();
			ss << std::hex << b.to_ullong();
			weakHash += ss.str();
			while (weakHash.length() < (i + 1) * 16) weakHash.insert(i * 16, "0");
		}
		return weakHash;
	}
}

std::string WeakenHash32(std::string hash, int alg) {
	unsigned long long bin;
	std::bitset<64> bits;
	int part = 32 / settings[alg];
	if (part == 32) return hash;
	for (int i = 0; i <= 32; i += part) {
		std::stringstream ss;
		ss << std::hex << hash.substr(i, part);
		ss >> bin;
		std::bitset<64> b(bin);
		bits ^= b;
	}
	std::stringstream ss;
	ss << std::hex << bits.to_ullong();
	return ss.str();
}

std::string WeakenHash8(std::string hash, int alg) {
	long long bin;
	std::bitset<32> bits;
	int part = 8 / settings[alg];
	if (part == 8) return hash;
	for (int i = 0; i <= 8; i += part) {
		std::stringstream ss;
		ss << std::hex << hash.substr(i, part);
		ss >> bin;
		std::bitset<32> b(bin);
		bits ^= b;
	}
	std::stringstream ss;
	ss << std::hex << bits.to_ullong();
	return ss.str();
}

Hashes GenHashes(std::string toHash) {
	Hashes hashes;
	for (int i = SHA_1; i < settSize; i++) {
		if (CheckIfUsingHashAlg(i)) {
			switch(i) {
			case SHA_1: {
				SHA1 sha1;
				hashes.sha_1 = sha1(toHash);
				//auto start = std::chrono::high_resolution_clock::now();
				hashes.sha_1H = WeakenHash40(hashes.sha_1, i);
				/*auto end = std::chrono::high_resolution_clock::now();
				std::fstream f;
				f.open("time.txt", std::fstream::out | std::fstream::app);
				f << std::to_string((end - start) / std::chrono::microseconds(1)) + ", ";
				f.close();*/
				break;
			}
			case SHA_2: {
				SHA256 sha256;
				hashes.sha_2 = sha256(toHash);
				hashes.sha_2H = WeakenHash64(hashes.sha_2, i);
				//hashes.sha_2B = weakHash.second;
				break;
			}
			case SHA_3: {
				SHA3 sha3;
				hashes.sha_3 = sha3(toHash);
				hashes.sha_3H = WeakenHash64(hashes.sha_3, i);
				//hashes.sha_3B = weakHash.second;
				break;
			}
			case KEccAK: {
				Keccak kec;
				hashes.kecak = kec(toHash);
				hashes.kecakH = WeakenHash64(hashes.kecak, i);
				//hashes.kecakB = weakHash.second;
				break;
			}
			case MD_5: {
				MD5 md5;
				hashes.md_5 = md5(toHash);
				hashes.md_5H = WeakenHash32(hashes.md_5, i);
				//hashes.md_5B = weakHash.second;
				break;
			}
			case CRC_32: {
				CRC32 crc32;
				hashes.crc_32 = crc32(toHash);
				hashes.crc_32H = WeakenHash8(hashes.crc_32, i);
				//hashes.crc_32B = weakHash.second;
				break;
			}
			}
		}
	}
	return hashes;
}

void Config(int i) {
	std::fstream configuration;
	configuration.open("CollAttConf.txt", std::fstream::in | std::fstream::out);
	if (!configuration || i == 1) {
		configuration.close();
		configuration.open("CollAttConf.txt", std::fstream::out | std::fstream::trunc);
		configuration << "MESSAGE_TYPE: " + std::to_string(settings[TYPE]) + "|" + std::to_string(settings[FIRST]) + "," + std::to_string(settings[DYNAM]) + "." + std::to_string(settings[MIN]) + "-" + std::to_string(settings[MAX])
			+ "\nMESSAGE_SIZE: " + std::to_string(settings[SIZE])
			+ "\nMESSAGE_AMOUNT: " + std::to_string(settings[NUM])
			+ "\nHASH: " + std::to_string(settings[HASHES])
			+ "\nWEAKENINGS: " + std::to_string(settings[SHA_1]) + "," + std::to_string(settings[SHA_2]) + "," + std::to_string(settings[SHA_3]) + ","
								+ std::to_string(settings[KEccAK]) + "," + std::to_string(settings[MD_5]) + "," + std::to_string(settings[CRC_32]) +","
			+ "\nMESSAGE: "+msg+"\n";
	}
	else {
		std::string confLine, value;
		for (int j = 0; std::getline(configuration, confLine); j++) {
			value = value = confLine.substr(confLine.find(' ') + 1);
			switch (j) {
			case 0:
				if ((settings[TYPE] = value[0] - 48) == 2) {
					settings[FIRST] = stoi(value.substr(2, value.find(',') - 2));
					settings[DYNAM] = stoi(value.substr(value.find(',') + 1));
					settings[MIN] = stoi(value.substr(value.find('.') + 1));
					settings[MAX] = stoi(value.substr(value.find('-') + 1));
				}
				break;
			case 3: 
				settings[HASHES] = stoi(value);
				break;
			case 4: {
				std::string opt;
				for (int k = 0, h = SHA_1; k < value.length(); k++) {
					if (value[k] == ',') {
						settings[h++] = stoi(opt);
						opt = "";
					}
					else opt += value[k];
				}
				break;
			}
			case 5:
				msg = value;
				mainHash = GenHashes(msg);
				break;
			default:
				settings[j] = stoi(value);
				break;
			}
		}
	}
	configuration.close();
}

std::string GenPassLikeMsg() {
	std::string nMsg;
	for (int i = 0; i < settings[SIZE]; i++) {
		int j = dis(gen);
		if(j>35) nMsg += (char)lowCDis(gen);
		else if(j>10) nMsg += (char)upCDis(gen);
		else nMsg += (char)intDis(gen);
	}
	return nMsg;
}

std::string GenAllASCIIMsg() {
	std::string nMsg;
	for (int i = 0; i < settings[SIZE]; i++) nMsg += (char)allASCII(gen);
	return nMsg;
}

std::string GenNumericMsg() {
	std::uniform_int_distribution<> d(settings[MIN], settings[MAX]);
	std::string nMsg;
	if (dis(gen) <= 30)	nMsg = "-";
	for (int j = d(gen), i= 0; i < j; i++) nMsg += (char)intDis(gen);
	if (nMsg[0] == '-') while (nMsg[1] == '0') nMsg.erase(1, 1);
	else while (nMsg[0] == '0') nMsg.erase(0, 1);
	int msgSize = nMsg.length();
	if (nMsg[0] == '-') msgSize = nMsg.length() - 1;
	if (msgSize<settings[MIN]) nMsg = GenNumericMsg();
	return nMsg;
}

void InsertMenu(Menu* node, menuTypes i, std::string m) {
	if (!node->child) {
		node->child = new Menu;
		node->child->menu = m;
		node->child->id = i;
	}
	else {
		node = node->child;
		while (node->neighbour) node = node->neighbour;
		node->neighbour = new Menu;
		node->neighbour->menu=m;
		node->neighbour->id = i;
	}
}

std::string WriteHashes(Hashes h) {
	std::string toWrite;
	if (!h.sha_1.empty()) toWrite += "SHA1: " + h.sha_1 + "\nSHA1h: " + h.sha_1H + /*"\nSHA1b: " + h.sha_1B +*/ "\n";
	if (!h.sha_2.empty()) toWrite += "SHA256: " + h.sha_2 + "\nSHA256h: " + h.sha_2H + /*"\nSHA256b: " + h.sha_2B +*/ "\n";
	if (!h.sha_3.empty()) toWrite += "SHA3: " + h.sha_3 + "\nSHA3h: " + h.sha_3H +/* "\nSHA3b: " + h.sha_3B + */"\n";
	if (!h.kecak.empty()) toWrite += "KECCAK: " + h.kecak + "\nKECCAKh: " + h.kecakH +/* "\nKECCAKb: " + h.kecakB +*/ "\n";
	if (!h.md_5.empty()) toWrite += "MD5: " + h.md_5 + "\nMD5h: " + h.md_5H + /*"\nMD5b: " + h.md_5B +*/ "\n";
	if (!h.crc_32.empty()) toWrite += "CRC32: " + h.crc_32 + "\nCRC32h: " + h.crc_32H + /*"\nCRC32b: " + h.crc_32B + */"\n";
	return toWrite + "\n";
}

std::vector<std::pair<int, std::vector<int>>> Collide(bool disp) {
	std::unordered_map<std::string, Hashes> mapa;
	std::vector<std::pair<std::pair<int, std::string>, Hashes>> colls[settSize - SHA_1];
	std::vector<std::pair<int, std::vector<int>>> hits;
	std::vector<std::pair<std::string, Hashes>> collection;
	mapa[msg] = mainHash;
	for (int i = 0; i < settings[NUM]; i++) {
		if (i % 1000 == 0) std::cout << i << std::endl;
		std::string nMsg;
		switch (settings[TYPE]) {
		case 0:
			nMsg = GenPassLikeMsg();
			break;
		case 1:
			nMsg = GenAllASCIIMsg();
			break;
		case 2:
			std::string dynam = GenNumericMsg();
			nMsg = msg;
			nMsg.replace(settings[FIRST], settings[DYNAM], dynam);
			break;
		}
		Hashes nHash = GenHashes(nMsg);
		std::pair<std::unordered_map<std::string, Hashes>::iterator, bool> rez = mapa.insert(std::pair<std::string, Hashes>(nMsg, nHash));
		if (!rez.second) i--;
		else {
			for (int j = SHA_1; j < settSize; j++) {
				if (CheckIfUsingHashAlg(j)) {
					int k = j - SHA_1;
					switch (j) {
					case SHA_1:
						if (nHash.sha_1H == mainHash.sha_1H) 
							colls[k].push_back(std::pair<std::pair<int, std::string>, Hashes>(std::pair<int, std::string>(i + 1, nMsg), nHash));
						break;
					case SHA_2:
						if (nHash.sha_2H == mainHash.sha_2H) 
							colls[k].push_back(std::pair<std::pair<int, std::string>, Hashes>(std::pair<int, std::string>(i + 1, nMsg), nHash));
						break;
					case SHA_3:
						if (nHash.sha_3H == mainHash.sha_3H) 
							colls[k].push_back(std::pair<std::pair<int, std::string>, Hashes>(std::pair<int, std::string>(i + 1, nMsg), nHash));
						break;
					case KEccAK:
						if (nHash.kecakH == mainHash.kecakH)
							colls[k].push_back(std::pair<std::pair<int, std::string>, Hashes>(std::pair<int, std::string>(i + 1, nMsg), nHash));
						break;
					case MD_5:
						if (nHash.md_5H == mainHash.md_5H)
							colls[k].push_back(std::pair<std::pair<int, std::string>, Hashes>(std::pair<int, std::string>(i + 1, nMsg), nHash));
						break;
					case CRC_32:
						if (nHash.crc_32H == mainHash.crc_32H)
							colls[k].push_back(std::pair<std::pair<int, std::string>, Hashes>(std::pair<int, std::string>(i + 1, nMsg), nHash));
						break;
					}
				}
			}
		}
	}
	if (disp) {
		std::fstream msgs;
		msgs.open("Messages.txt", std::fstream::out | std::fstream::trunc);
		std::unordered_map<std::string, Hashes>::iterator itr;
		system("cls");
		std::cout << "Messages written into Messages.txt\ncollisions written into collisions.txt\n\n";
		int k = 0;
		for (itr = mapa.begin(); itr != mapa.end(); itr++) {
			if (itr->first.compare(msg) != 0) {
				msgs << std::to_string(++k) + ". MSG: " + itr->first + "\n";
				msgs << WriteHashes(itr->second);
			}
		}
		msgs << "-------------------\nMSG: " + msg + "\n" + WriteHashes(mainHash);
		msgs.close();
		std::fstream collisions;
		std::string collisionsString = "-------Main message----------\nMSG: " + msg + "\n" + WriteHashes(mainHash) + "-----------------------------\n", summary = "\nSummary:\n-------";
		collisions.open("Collisions.txt", std::fstream::out | std::fstream::trunc);
		collisions << collisionsString;
		std::cout << collisionsString;
		collisionsString.clear();
		for (int h = SHA_1; h < settSize; h++) {
			int j = 0, k = h - SHA_1;
			if (!colls[k].empty()) {
				collisionsString += "\n" + GetAlgName(h) + "(" + std::to_string(colls[k].size()) + ")" + " Hit msg:";
				for (std::pair<std::pair<int, std::string>, Hashes> hit : colls[k]) collisionsString += " #" + std::to_string(hit.first.first);
				summary += collisionsString;
				collisionsString += "\n";
				for (std::pair<std::pair<int, std::string>, Hashes> hit : colls[k]) collisionsString += "\n" + std::to_string(++j) + ". (msg #" + std::to_string(hit.first.first) + ")" + " MSG: " + hit.first.second + "\n" + WriteHashes(hit.second);
				collisionsString += "-----------------------\n";
				collisions << collisionsString;
				std::cout << collisionsString;
				collisionsString.clear();
			}
		}
		summary += "\n-------\n";
		collisions << summary;
		std::cout << summary;
		collisions.close();
	}
	for (int i = SHA_1; i < settSize; i++) {
		if (CheckIfUsingHashAlg(i)) {
			std::vector<int> c;
			for (std::pair<std::pair<int, std::string>, Hashes> hAlg : colls[i-SHA_1]) {
				c.push_back(hAlg.first.first);
			}
			hits.push_back(std::pair<int, std::vector<int>>(i, c));
		}
	}
	return hits;
}

std::vector<std::pair<int, std::vector<int>>> callMeAsync() {
	std::vector<std::pair<int, std::vector<int>>> oneRun = Collide(false);
	return oneRun;
}

void CollideNTimes(int n) {
	std::fstream analasysFile;
	std::string fileName = std::to_string(settings[TYPE]) + ";SHA1-" + std::to_string(settings[SHA_1]) +";SHA2-"+ std::to_string(settings[SHA_2]) + ";SHA3-"+ std::to_string(settings[SHA_3]) + ";" + std::to_string(settings[SIZE]) + ";" + std::to_string(settings[NUM]) + ";" + std::to_string(n) + ".txt";
	analasysFile.open(fileName, std::fstream::out | std::fstream::trunc);
	int z = n;
	std::vector<std::pair<int, std::vector<std::vector<int>>>> hitCollection;
	std::vector<std::pair<double, double>> firstAvrgs;
	for (int i = SHA_1; i < settSize; i++)
		if (CheckIfUsingHashAlg(i)) hitCollection.push_back(std::pair<int, std::vector<std::vector<int>>>(i, std::vector<std::vector<int>>()));
	std::vector<std::future<std::vector<std::pair<int, std::vector<int>>>>> fut;
	int wait = 0;
	
	while (n>0) {
		int i = 0;
		for (; i < 6 && n-i > 0; i++) {
			fut.push_back(std::async(std::launch::async, callMeAsync));
		}
		fut[fut.size() - 1].wait();
		n -= 6;
	}
	for (int i = 0; i < fut.size(); i++) {
		std::vector<std::pair<int, std::vector<int>>> oneRun = fut[i].get();
		for (int j = 0; j < hitCollection.size(); j++) {
			for (std::pair<int, std::vector<int>> hAlg : oneRun) {
				if (hAlg.first == hitCollection[j].first) hitCollection[j].second.push_back(hAlg.second);
			}
		}
	}
	std::cout << "First collision analasys:" << std::endl;
	for (std::pair<int, std::vector<std::vector<int>>> h : hitCollection) {
		std::vector<int> firstHits;
		std::string algName = GetAlgName(h.first);
		std::cout << algName << std::endl;
		analasysFile << algName + "(weakness: " + std::to_string(settings[h.first]) + ")\n";
		bool artihemticMiddle = true;
		double sumOfFirsts = 0;
		for (std::vector<int> c : h.second) {
			if (c.size()) {
				sumOfFirsts += c.front();
				firstHits.push_back(c.front());
				for (int d : c) {
					std::cout << d << " ";
					analasysFile << d << " ";
				}
			}
			else {
				artihemticMiddle = false;
				std::cout << "No collisions found!";
				analasysFile << "No collisions found!";
			}
			std::cout << std::endl;
			analasysFile << "\n";
		}
		std::cout << std::endl;
		analasysFile << "\n";
		double median = 0;
		if (firstHits.size()) {
			std::nth_element(firstHits.begin(), firstHits.begin() + firstHits.size() / 2, firstHits.end());
			median = firstHits[firstHits.size() / 2];
			if (!(firstHits.size() % 2)) {
				std::nth_element(firstHits.begin(), firstHits.begin() + firstHits.size() / 2 - 1, firstHits.end());
				median += firstHits[firstHits.size() / 2 - 1];
				median /= 2;
			}
		}
		firstAvrgs.push_back(std::pair<double, double>(((artihemticMiddle) ? sumOfFirsts / z : 0), median));
	}
	analasysFile << "There were " << settings[NUM] << " messages generated " << z << " times (total: " << settings[NUM] * z << ")\nAverage amount of generated messages needed to find a collision:\n";
	std::cout << "There were " << settings[NUM] << " messages generated " << z << " times (total: " << settings[NUM] * z << ")\nAverage amount of generated messages needed to find a collision:\n";
	int i = 0;
	for (std::pair<int, std::vector<std::vector<int>>> alg : hitCollection) {
		std::cout << GetAlgName(alg.first) << std::endl;
		std::cout << "Arithmetic mean: " << ((firstAvrgs[i].first) ? std::to_string(firstAvrgs[i].first) : "can not calculate.") << std::endl;
		std::cout << "Median: " << firstAvrgs[i].second << std::endl << std::endl;

		analasysFile << GetAlgName(alg.first) << std::endl;
		analasysFile << "Arithmetic mean: " << ((firstAvrgs[i].first) ? std::to_string(firstAvrgs[i].first) : "can not calculate.") << std::endl;
		analasysFile << "Median: " << firstAvrgs[i++].second << std::endl << std::endl;
	}
	std::cout << "Analasys of the amount of collisions per amount of messages:\n";
	analasysFile << "Analasys of the amount of collisions per amount of messages:\n";
	std::vector<std::pair<int, std::vector<std::pair<int, int>>>> milestones;
	for (std::pair<int, std::vector<std::vector<int>>> hAlg : hitCollection) {
		std::vector<std::pair<int, int>> temp;
		for (std::vector<int> c : hAlg.second) {
			int hit = 0;
			if(c.size()) for (long m = 5000; m <= settings[NUM]; m+=5000) {
				for (int i = hit; (i < c.size()) && (m >= c[i]); i++, hit++) {}
				temp.push_back(std::pair<int, int>(m, hit));
			}
		}
		milestones.push_back(std::pair<int, std::vector<std::pair<int, int>>>(hAlg.first, temp));
	}
	for (std::pair<int, std::vector<std::pair<int, int>>> hAlg : milestones) {
		std::cout << GetAlgName(hAlg.first) << std::endl;
		analasysFile << GetAlgName(hAlg.first) << std::endl;
		if (!hAlg.second.size()) {
			std::cout << "\tThere were no collisions." << std::endl;
			analasysFile << "\tThere were no collisions." << std::endl;
		}
		else {
			n = 1;
			int diff = 0;
			for (std::pair<int, int> m : hAlg.second) {
				if (m.first == 1000) {
					std::cout << n++ << ". set:" << std::endl;
					analasysFile << n << ". set:\n";
					diff = 0;
				}
				std::cout << "\t" << m.first << ": " << m.second << "(" << m.second - diff << ")" << std::endl;
				analasysFile << "\t" << m.first << ": " << m.second << "(" << m.second - diff << ")\n";
				diff = m.second;
			}
		}
	}
	analasysFile.close();
	std::cout << "\a";
}

Menu* Display(Menu* node, int nthChild, bool disp) {
	if(nthChild) {
		node = node->child;
		while (--nthChild && node->neighbour) node = node->neighbour;
	}
	if(disp) std::cout << node->menu;
	return node;
}

void GenTypeSizeString() {
	std::string type;
	switch (settings[TYPE]) {
	case 0: type = "PassLike";
		break;
	case 1: type = "All ASCII";
		break;
	case 2: type = "Custom";
	}
	men->child->neighbour->neighbour->child->menu = "1. Type (" + type + ")\n2. Size (" + std::to_string(settings[SIZE]) + ")" + ender;
}

void GenConfString() {
	men->child->neighbour->neighbour->menu = "1. Type and size of messages\n2. Number of messages ("+std::to_string(settings[NUM])+")\n3. HASHes\n4. Weakenings" + ender;
}

void GenCustMsgString() {
	men->child->child->menu = "1. First part\n2. Dynamic part\n3. Second part\n4. Minimum ("+std::to_string(settings[MIN])+")\n5. Maximum ("+std::to_string(settings[MAX])+")" + ender;
}

void GenHashesString() {
	men->child->neighbour->neighbour->child->neighbour->neighbour->menu = "1. SHA1   (" + std::to_string(CheckIfUsingHashAlg(SHA_1)) + ")\n2. SHA2   (" + std::to_string(CheckIfUsingHashAlg(SHA_2)) + ")\n3. SHA3   (" + std::to_string(CheckIfUsingHashAlg(SHA_3)) + ")\n4. KECCAK (" + std::to_string(CheckIfUsingHashAlg(KEccAK)) + ")\n5. MD5    (" + std::to_string(CheckIfUsingHashAlg(MD_5)) + ")\n6. CRC32  (" + std::to_string(CheckIfUsingHashAlg(CRC_32)) + ")" + ender;
}

void GenWeakeningString() {
	men->child->neighbour->neighbour->child->neighbour->neighbour->neighbour->menu = 
		"1. SHA1   (" + std::to_string(settings[SHA_1]) +
		")\n2. SHA2   (" + std::to_string(settings[SHA_2]) +
		")\n3. SHA3   (" + std::to_string(settings[SHA_3]) + 
		")\n4. KECCAK (" + std::to_string(settings[KEccAK]) + 
		")\n5. MD5    (" + std::to_string(settings[MD_5]) + 
		")\n6. CRC32  (" + std::to_string(settings[CRC_32]) + ")" + ender;
}

int GetHashSize(int alg) {
	int size;
	alg += SHA_1 - 1;
	switch (alg) {
	case SHA_1:
		size = 40;
		break;
	case MD_5:
		size = 32;
		break;
	case CRC_32:
		size = 8;
		break;
	default: size = 64;
	}
	return size;
}

void GenWeakeningOpt(int alg) {
	std::string m;
	int size = GetHashSize(alg);
	int j = 1;
	for (int i = 1; i <= (size/2); i++) {
		if (!(size % i)) m += std::to_string(j++) + ". " + std::to_string(i) + "\n";
	}
	m += std::to_string(j++) + ". " + std::to_string(size);
	men->child->neighbour->neighbour->child->neighbour->neighbour->neighbour->child->menu = m + ender;
}

int tempChoice;

void UI(Menu* m) {
	std::string odabir;
	bool collider = false;
	int choice = 0;
	do {
		if(!collider) system("cls");
		if (m->id == GENMSG && settings[TYPE]==2) m = m->child; //Radi strukture stabla, preskace na child ako se radi o prilagodenom tipu poruke
		if ((m->id == GENMSG || m->id == CUSTOMMSG) && !msg.empty()) std::cout << "MSG: " << msg << std::endl << std::endl << WriteHashes(mainHash);
		else if(m->id == COLLIDE && msg.empty()) std::cout << "Message is not yet generated!" << std::endl;
		Display(m, 0, 1);
		std::getline(std::cin, odabir);
		if (odabir[0] == 'x') return;
		choice = odabir[0] - 48;
		switch (m->id) {
		case GENMSG:
			if (choice == 1) {
				if (!settings[TYPE]) msg = GenPassLikeMsg();
				else msg = GenAllASCIIMsg();
				mainHash = GenHashes(msg);
			}
			break;
		case FIRSTPRT:
			msg.replace(0, settings[FIRST], odabir);
			settings[FIRST] = odabir.length();
			return;
		case DYNAMICPRT:
			msg.replace(settings[FIRST], settings[DYNAM], odabir);
			settings[DYNAM] = odabir.length();
			return;
		case SECONDPRT:
			msg.replace(settings[FIRST] + settings[DYNAM], -1, odabir);
			return;
		case DYNAMIN:
			settings[MIN] = stoi(odabir);
			GenCustMsgString();
			return;
		case DYNAMAX:
			settings[MAX] = stoi(odabir);
			GenCustMsgString();
			return;
		case COLLIDE:
			if ((choice == 1) && !msg.empty()) {
				Collide(true);
				collider = true;
			}
			else if (choice == 2) UI(m->child);
			break;
		case NCOLLIDE:
			CollideNTimes(stoi(odabir));
			collider = true;
			break;
		case MSGTYPE: {
			int prevType = settings[TYPE];
			settings[TYPE] = odabir[0] - 49;
			if (settings[TYPE] != prevType) msg.clear();
			GenTypeSizeString();
			return;
		}
		case MSGSIZE:
			settings[SIZE] = stoi(odabir);
			GenTypeSizeString();
			return;
		case MHASHES:
			settings[HASHES] ^= (1 << --choice);
			GenHashesString();
			break;
		case MSGNUM:
			settings[NUM] = stoi(odabir);
			GenConfString();
			return;
		case HASHWOPT:
			tempChoice = choice;
			return;
		case HASHWEAK: {
			GenWeakeningOpt(choice);
			UI(m->child);
			int size = GetHashSize(choice);
			for (int i = 1; i <= size; i++) {
				if (!(size % i) && !(--tempChoice)) {
					settings[choice + SHA_1-1] = i;
					break;
				}
			}
			GenWeakeningString();
			break;
		}
		default: UI(Display(m, choice, 0));
		}
		Config(1);
		if(m->id == CONFIG) mainHash = GenHashes(msg);
	} while (1);
}

int main() {
	Config(0);
	men->menu = "1. Generate message\n2. Search for collisions\n3. Configuration" + ender;
	InsertMenu(men, GENMSG,"1. Generate message" + ender);
	InsertMenu(men->child, CUSTOMMSG, "");
	GenCustMsgString();
	InsertMenu(men->child->child, FIRSTPRT, "First part: ");
	InsertMenu(men->child->child, DYNAMICPRT, "Dynamic part: ");
	InsertMenu(men->child->child, SECONDPRT, "Second part: ");
	InsertMenu(men->child->child, DYNAMIN, "Minimum: ");
	InsertMenu(men->child->child, DYNAMAX, "Maximum: ");
	InsertMenu(men, COLLIDE, "1. Search for collisions\n2. Run N times" + ender);
	InsertMenu(men->child->neighbour, NCOLLIDE, "Times: ");
	InsertMenu(men, CONFIG, "");
	GenConfString();
	InsertMenu(men->child->neighbour->neighbour, TYPESIZE, "");
	GenTypeSizeString();
	InsertMenu(men->child->neighbour->neighbour->child, MSGTYPE, "1. PassLike\n2. All ASCII\n3. Custom" + ender);
	InsertMenu(men->child->neighbour->neighbour->child, MSGSIZE, "Size of messages: ");
	InsertMenu(men->child->neighbour->neighbour, MSGNUM, "Number of messages: ");
	InsertMenu(men->child->neighbour->neighbour, MHASHES, "");
	GenHashesString();
	InsertMenu(men->child->neighbour->neighbour, HASHWEAK, "");
	GenWeakeningString();
	InsertMenu(men->child->neighbour->neighbour->child->neighbour->neighbour->neighbour, HASHWOPT, "");
	UI(men);
	return 1;
}