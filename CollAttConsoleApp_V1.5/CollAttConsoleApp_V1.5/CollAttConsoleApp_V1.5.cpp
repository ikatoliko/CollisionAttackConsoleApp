#include <iostream>
#include <string>
#include <random>
#include <bitset>
#include <map>
#include <fstream>
#include "hash-library/sha1.h"
#include "hash-library/sha1.cpp"
#include "hash-library/sha256.h"
#include "hash-library/sha256.cpp"
#include <sstream>

std::random_device rd;
std::mt19937_64 gen(rd());
std::uniform_int_distribution<> dis(1, 60); // Random interval (a, b ili c)
std::uniform_int_distribution<> intDis(48, 57); // a) Znakovi [0, 9]
std::uniform_int_distribution<> upCDis(65, 90); // b) Znakovi [A, Z]
std::uniform_int_distribution<> lowCDis(97, 122); // c) Znakovi [a, z]
std::uniform_int_distribution<> allASCII(32, 126); //Svi ASCII znakovi

enum menuTypes {MAIN, GENMSG, CUSTOMMSG, COLLIDE, CONFIG, TYPESIZE, MSGTYPE, MSGSIZE, MSGNUM, FIRSTPRT, DYNAMICPRT, SECONDPRT, MHASHES, HASHWEAK, DYNAMIN, DYNAMAX, HASHWOPT};
enum settTypes {TYPE, SIZE, NUM, FIRST, DYNAM, MIN, MAX, HASHES, SHA_1, SHA_2, SHA_3, KEccAK, MD_5, CRC_32};

struct Menu {
	menuTypes id=MAIN;
	std::string menu;
	Menu* dijete = NULL;
	Menu* susjed = NULL;
};

class Hashes {
public:
	std::string sha_1, sha_2, sha_3, kecak, md_5, crc_32;
	std::string sha_1H, sha_2H, sha_3H, kecakH, md_5H, crc_32H;
	std::string sha_1B, sha_2B, sha_3B, kecakB, md_5B, crc_32B;
	/*Hashes(std::string s1, std::string s2, std::string s3, std::string k, std::string m, std::string c,
		std::string s1H, std::string s2H, std::string s3H, std::string kH, std::string mH, std::string cH,
		std::string s1B, std::string s2B, std::string s3B, std::string kB, std::string mB, std::string cB) {
		this->sha_1 = s1;
		this->sha_1B = s1B;
		this->sha_1H = s1H;
		this->sha_2 = s2;
		this->sha_2B = s2B;
		this->sha_2H = s2H;
		this->sha_3 = s3;
		this->sha_3B = s3B;
		this->sha_3H = s3H;
		this->kecak = k;
		this->kecakB = kB;
		this->kecakH = kH;
		this->md_5 = m;
		this->md_5B = mB;
		this->md_5H = mH;
		this->crc_32 = c;
		this->crc_32B = cB;
		this->crc_32H = cH;
	}*/
	Hashes() {
		this->sha_1= "";
		this->sha_1B = "";
		this->sha_1H = "";
		this->sha_2= "";
		this->sha_1B = "";
		this->sha_1H = "";
		this->sha_3= "";
		this->sha_3B = "";
		this->sha_3H = "";
		this->kecak = "";
		this->kecakB = "";
		this->kecakH = "";
		this->md_5 = "";
		this->md_5B = "";
		this->md_5H = "";
		this->crc_32 = "";
		this->crc_32B = "";
		this->crc_32H = "";
	}
};

Menu* men = new Menu;
Hashes mainHash;
const std::string ender = "\nx. Povratak\n>>";

std::map<std::string, Hashes> mapa;
std::vector<std::string> collisions;

std::string msg;
int settings[] = { 0, 1024, 2000, 0, 0, 2, 5, 1, 20, 1, 1, 1, 1, 1};

bool CheckIfUsingHashAlg(int alg) {
	return ((settings[HASHES] >> (alg - SHA_1)) & 1) ? true : false;
}

std::pair<std::string, std::string> WeakenHash40(std::string hash, int alg) {
	int bin, limiter = 40 / settings[alg];
	std::bitset<160> bits, set;
	for (int i = 1; i <= 40; i++) {
		std::stringstream ss;
		ss << std::hex << hash[i - 1];
		ss >> bin;
		std::bitset<160> b(bin);
		set |= b;
		if (!(i % limiter)) {
			bits ^= set;
			set.reset();
		}
		else set <<= 4;
	}
	std::string weakHash, wh;
	if (settings[alg] < 4) {
		std::bitset<160> bitsPartialCpy;
		for (int i = 0; i < 4; i++) {
			std::stringstream ss;
			bitsPartialCpy = bits << (40 * i);
			bitsPartialCpy >>= 120;
			ss << std::hex << bitsPartialCpy.to_ullong();
			ss >> wh;
			if(wh!="0")weakHash += wh;
		}
	}
	else {
		std::stringstream ss;
		ss << std::hex << bits.to_ullong();
		ss >> weakHash;
	}
	while (weakHash.length() < limiter) weakHash.insert(0, "0");
	return std::pair<std::string, std::string>(weakHash, bits.to_string().substr(160-limiter * 4));
}

std::pair<std::string, std::string> WeakenHash64(std::string hash, int alg) {
	int bin, limiter = 64 / settings[alg];
	std::bitset<256> bits, set;
	for (int i = 1; i <= 64; i++) {
		std::stringstream ss;
		ss << std::hex << hash[i - 1];
		ss >> bin;
		std::bitset<256> b(bin);
		set |= b;
		if (!(i % limiter)) {
			bits ^= set;
			set.reset();
		}
		else set <<= 4;
	}
	std::string weakHash, wh;
	if (settings[alg] < 4) {
		std::bitset<256> bitsPartialCpy;
		for (int i = 0; i < 4; i++) {
			std::stringstream ss;
			bitsPartialCpy = bits << (64 * i);
			bitsPartialCpy >>= 192;
			ss << std::hex << bitsPartialCpy.to_ullong();
			ss >> wh;
			if (wh != "0")weakHash += wh;
		}
	}
	else {
		std::stringstream ss;
		ss << std::hex << bits.to_ullong();
		ss >> weakHash;
	}
	while (weakHash.length() < limiter) weakHash.insert(0, "0");
	return std::pair<std::string, std::string>(weakHash, bits.to_string().substr(256 - limiter * 4));
}

Hashes GenHashes(std::string toHash) {
	int bin, settSize = sizeof(settings)/sizeof(*settings);
	Hashes hashes;
	std::pair<std::string, std::string> weakHash;
	for (int i = SHA_1; i <= settSize; i++) {
		if (CheckIfUsingHashAlg(i)) {
			if (i == SHA_1) {
				SHA1 sha1;
				hashes.sha_1 = sha1(toHash);
				weakHash = WeakenHash40(hashes.sha_1, i);
				hashes.sha_1H = weakHash.first;
				hashes.sha_1B = weakHash.second;
			}
			if (i == SHA_2) {
				SHA256 sha256;
				hashes.sha_2 = sha256(toHash);
				weakHash = WeakenHash64(hashes.sha_2, i);
				hashes.sha_2H = weakHash.first;
				hashes.sha_2B = weakHash.second;
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
		configuration << "VRSTA_PORUKA: " + std::to_string(settings[TYPE]) + "|" + std::to_string(settings[FIRST]) + "," + std::to_string(settings[DYNAM]) + "." + std::to_string(settings[MIN]) + "-" + std::to_string(settings[MAX])
			+ "\nVELICINA_PORUKA: " + std::to_string(settings[SIZE])
			+ "\nBROJ_PORUKA: " + std::to_string(settings[NUM])
			+ "\nHASH: " + std::to_string(settings[HASHES])
			+ "\nOSLABLJENJA: " + std::to_string(settings[SHA_1]) + "," + std::to_string(settings[SHA_2]) + "," + std::to_string(settings[SHA_3]) + ","
								+ std::to_string(settings[KEccAK]) + "," + std::to_string(settings[MD_5]) + "," + std::to_string(settings[CRC_32])
			+ "\nPORUKA: "+msg+"\n";
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
	int i = 0;
	if (dis(gen) <= 30) {
		nMsg = "-";
		i = 1;
	}
	for (int j = d(gen); i < j; i++) {
		nMsg += (char)intDis(gen);
	}
	return nMsg;
}

void InsertMenu(Menu* node, menuTypes i, std::string m) {
	if (!node->dijete) {
		node->dijete = new Menu;
		node->dijete->menu = m;
		node->dijete->id = i;
	}
	else {
		node = node->dijete;
		while (node->susjed) node = node->susjed;
		node->susjed = new Menu;
		node->susjed->menu=m;
		node->susjed->id = i;
	}
}

void Collide() {
	mapa.clear();
	mapa[msg] = GenHashes(msg);
	collisions.clear();
	std::string wHash = GenHashes(msg).sha_1B;
	for (int i = 0; i < settings[NUM]; i++) {
		if (i % 100 == 0) std::cout << i << std::endl;
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
		std::pair<std::map<std::string, Hashes>::iterator, bool> rez = mapa.insert(std::pair<std::string, Hashes>(nMsg, nHash));
		if (!rez.second) i--; // ako je generirana poruka koja je vec ranije generirana, brojac for petlje se smanjuje za 1 kako bi se generirala nova poruka
		else if (wHash.compare(nHash.sha_1B) == 0) {
			collisions.push_back(nMsg);
		}
	}
	std::map<std::string, Hashes>::iterator itr;
	for (itr = mapa.begin(); itr != mapa.end(); itr++) {
		if (itr->first.compare(msg) != 0) std::cout << "MSG: "<<itr->first << "\nHASH: " << itr->second.sha_1 <<"\nwHASH (hex): "<<itr->second.sha_1H<<"\nwHASH (bin): "<<itr->second.sha_1B<<std::endl << std::endl;
	}
	std::cout << "-------Pocetna Poruka----------\n" << msg << "\nHASH: " << mainHash.sha_1 << "\nwHASH (hex): " << mainHash.sha_1H << "\nwHASH (bin): " << mainHash.sha_1B << "\n------------------------------\n" << std::endl;
	int j = 0;
	if (!collisions.empty()) std::cout << "Kolizije (" << collisions.size() << "):\n\n";
	for (std::string hit : collisions) std::cout << "(" << ++j << ") "<<hit << std::endl << "HASH: " << GenHashes(hit).sha_1 << std::endl << std::endl;
	if (!collisions.empty()) std::cout << "Kolizije (" << collisions.size() << ")\n\n";
}

Menu* Display(Menu* node, int nthChild, bool disp) {
	if(nthChild) {
		node = node->dijete;
		while (--nthChild && node->susjed) node = node->susjed;
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
	men->dijete->susjed->susjed->dijete->menu = "1. Tip (" + type + ")\n2. Velicina (" + std::to_string(settings[SIZE]) + ")" + ender;
}

void GenConfString() {
	men->dijete->susjed->susjed->menu = "1. Vrsta i velicina poruka\n2. Broj poruka ("+std::to_string(settings[NUM])+")\n3. HASHevi\n4. Oslabljenja" + ender;
}

void GenCustMsgString() {
	men->dijete->dijete->menu = "1. Prvi dio\n2. Dinamicki dio\n3. Drugi dio\n4. Minimum("+std::to_string(settings[MIN])+")\n5. Maksimum ("+std::to_string(settings[MAX])+")" + ender;
}

void GenHashesString() {
	men->dijete->susjed->susjed->dijete->susjed->susjed->menu = "1. SHA1   (" + std::to_string(CheckIfUsingHashAlg(SHA_1)) + ")\n2. SHA2   (" + std::to_string(CheckIfUsingHashAlg(SHA_2)) + ")\n3. SHA3   (" + std::to_string(CheckIfUsingHashAlg(SHA_3)) + ")\n4. KECCAK (" + std::to_string(CheckIfUsingHashAlg(KEccAK)) + ")\n5. MD5    (" + std::to_string(CheckIfUsingHashAlg(MD_5)) + ")\n2. CRC32  (" + std::to_string(CheckIfUsingHashAlg(CRC_32)) + ")" + ender;
}
void GenWeakeningString() {
	men->dijete->susjed->susjed->dijete->susjed->susjed->susjed->menu = 
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
	men->dijete->susjed->susjed->dijete->susjed->susjed->susjed->dijete->menu = m + ender;
}

int tempChoice;

void UI(Menu* m) {
	std::string odabir;
	bool collider = false;
	int choice = 0;
	do {
		if(!collider) system("cls");
		if (m->id == GENMSG && settings[TYPE]==2) m = m->dijete; //Radi strukture stabla, preskace na dijete ako se radi o prilagodenom tipu poruke
		if ((m->id == GENMSG || m->id == CUSTOMMSG) && !msg.empty()) std::cout <<"MSG: "<<msg << std::endl << "HASH: " << mainHash.sha_1 << std::endl << "wHASH (hex): " << mainHash.sha_1H << std::endl << "wHAHS (bin): " << mainHash.sha_1B << std::endl;
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
			if (choice == 1) {
				Collide();
				collider = true;
			}
			break;
		case MSGTYPE:
			settings[TYPE] = odabir[0] - 49;
			GenTypeSizeString();
			return;
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
			UI(m->dijete);
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
	} while (1);
}

int main() {
	Config(0);
	men->menu = "1. Generiraj poruku\n2. Trazi kolizije\n3. Konfiguracija" + ender;
	InsertMenu(men, GENMSG,"1. Generiraj poruku" + ender);
	InsertMenu(men->dijete, CUSTOMMSG, "");
	GenCustMsgString();
	InsertMenu(men->dijete->dijete, FIRSTPRT, "Prvi dio: ");
	InsertMenu(men->dijete->dijete, DYNAMICPRT, "Dinamicki dio: ");
	InsertMenu(men->dijete->dijete, SECONDPRT, "Drugi dio: ");
	InsertMenu(men->dijete->dijete, DYNAMIN, "Minimum: ");
	InsertMenu(men->dijete->dijete, DYNAMAX, "Maksimum: ");
	InsertMenu(men, COLLIDE, "1. Trazi kolizije" + ender);
	InsertMenu(men, CONFIG, "");
	GenConfString();
	InsertMenu(men->dijete->susjed->susjed, TYPESIZE, "");
	GenTypeSizeString();
	InsertMenu(men->dijete->susjed->susjed->dijete, MSGTYPE, "1. PassLike\n2. All ASCII\n3. Custom" + ender);
	InsertMenu(men->dijete->susjed->susjed->dijete, MSGSIZE, "Velicina poruka: ");
	InsertMenu(men->dijete->susjed->susjed, MSGNUM, "Broj poruka: ");
	InsertMenu(men->dijete->susjed->susjed, MHASHES, "");
	GenHashesString();
	InsertMenu(men->dijete->susjed->susjed, HASHWEAK, "");
	GenWeakeningString();
	InsertMenu(men->dijete->susjed->susjed->dijete->susjed->susjed->susjed, HASHWOPT, "");
	UI(men);
	return 1;
}