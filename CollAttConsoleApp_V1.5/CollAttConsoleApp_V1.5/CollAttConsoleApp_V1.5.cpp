#include <iostream>
#include <string>
#include <random>
#include <bitset>
#include <map>
#include <fstream>
#include "hash-library/sha1.h"
#include "hash-library/sha1.cpp"
#include <sstream>

std::random_device rd;
std::mt19937_64 gen(rd());
std::uniform_int_distribution<> dis(1, 60); // Random interval (a, b ili c)
std::uniform_int_distribution<> intDis(48, 57); // a) Znakovi [0, 9]
std::uniform_int_distribution<> upCDis(65, 90); // b) Znakovi [A, Z]
std::uniform_int_distribution<> lowCDis(97, 122); // c) Znakovi [a, z]
std::uniform_int_distribution<> allASCII(32, 126); //Svi ASCII znakovi

//char settings[] = "0000000001";

enum menuTypes {MAIN, GENMSG, CUSTOMMSG, COLLIDE, CONFIG, TYPESIZE, MSGTYPE, MSGSIZE, MSGNUM, FIRSTPRT, DYNAMICPRT, SECONDPRT, HASHWEAK, DYNAMIN, DYNAMAX};
enum settTypes {TYPE, SIZE, NUM, WEAK, FIRST, DYNAM, MIN, MAX};

struct Menu {
	menuTypes id=MAIN;
	std::string menu;
	Menu* dijete = NULL;
	Menu* susjed = NULL;
};

class Hashes {
public:
	std::string hash, hashH, hashB;
	Hashes(std::string h, std::string hH, std::string hB) {
		this->hash = h;
		this->hashH = hH;
		this->hashB = hB;
	}
	Hashes() {
		this->hash = "";
		this->hashH = "";
		this->hashB = "";
	}
};

Menu* men = new Menu;
Hashes mainHash;
const std::string ender = "\nx. Povratak\n>>";

std::map<std::string, Hashes> mapa;
std::vector<std::string> collisions;

std::string msg;
int settings[] = { 0, 1024, 2000, 20, 0, 0, 2, 5};

Hashes GenHashes(std::string toHash) {
	SHA1 sha1;
	std::string hash = sha1(toHash);
	int limiter = 40 / settings[WEAK];
	std::bitset<160> bits, set;
	int bin;
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
	std::string weakHash;
	std::stringstream ss;
	ss << std::hex << bits.to_ulong();
	ss >> weakHash;
	if (weakHash.length() < limiter) weakHash.insert(0, "0");
	return Hashes(hash, weakHash, bits.to_string().substr(160-limiter*4));
}

void Config(int i) {
	std::fstream configuration;
	configuration.open("CollAttConf.txt", std::fstream::in | std::fstream::out);
	if (!configuration || i == 1) {
		configuration.close();
		configuration.open("CollAttConf.txt", std::fstream::out | std::fstream::trunc);
		configuration << "VRSTA_PORUKA: " + std::to_string(settings[TYPE]) + "|" + std::to_string(settings[FIRST]) + "," + std::to_string(settings[DYNAM]) + "." + std::to_string(settings[MIN]) + "-" + std::to_string(settings[MAX]) + "\nVELICINA_PORUKA: " + std::to_string(settings[SIZE]) + "\nBROJ_PORUKA: " + std::to_string(settings[NUM]) + "\nOSLABLJENJE: " + std::to_string(settings[WEAK]) + "\nPORUKA: "+msg+"\n";
	}
	else {
		std::string confLine, value;
		for (int j = 0; std::getline(configuration, confLine); j++) {
			value = value = confLine.substr(confLine.find(' ') + 1);
			switch (j) {
			case TYPE:
				if ((settings[TYPE] = value[0] - 48) == 2) {
					settings[FIRST] = stoi(value.substr(2, value.find(',') - 2));
					settings[DYNAM] = stoi(value.substr(value.find(',') + 1));
					settings[MIN] = stoi(value.substr(value.find('.') + 1));
					settings[MAX] = stoi(value.substr(value.find('-') + 1));
				}
				break;
			case 4:
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
	std::string wHash = GenHashes(msg).hashB;
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
		else if (wHash.compare(nHash.hashB) == 0) {
			collisions.push_back(nMsg);
		}
	}
	std::map<std::string, Hashes>::iterator itr;
	for (itr = mapa.begin(); itr != mapa.end(); itr++) {
		if (itr->first.compare(msg) != 0) std::cout << "MSG: "<<itr->first << "\nHASH: " << itr->second.hash <<"\nwHASH (hex): "<<itr->second.hashH<<"\nwHASH (bin): "<<itr->second.hashB<<std::endl << std::endl;
	}
	std::cout << "-------Pocetna Poruka----------\n" << msg << "\nHASH: " << mainHash.hash << "\nwHASH (hex): " << mainHash.hashH << "\nwHASH (bin): " << mainHash.hashB << "\n------------------------------\n" << std::endl;
	int j = 0;
	if (!collisions.empty()) std::cout << "Kolizije (" << collisions.size() << "):\n\n";
	for (std::string hit : collisions) std::cout << "(" << ++j << ") "<<hit << std::endl << "HASH: " << GenHashes(hit).hash << std::endl << std::endl;
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
	men->dijete->susjed->susjed->menu = "1. Vrsta i velicina poruka\n2. Oslabljenje HASH-a ("+std::to_string(settings[WEAK])+")\n3. Broj poruka ("+std::to_string(settings[NUM])+")" + ender;
}

void GenCustMsgString() {
	men->dijete->dijete->menu = "1. Prvi dio\n2. Dinamicki dio\n3. Drugi dio\n4. Minimum("+std::to_string(settings[MIN])+")\n5. Maksimum ("+std::to_string(settings[MAX])+")" + ender;
}

void UI(Menu* m) {
	std::string odabir;
	bool collider = false;
	do {
		if(!collider) system("cls");
		if (m->id == GENMSG && settings[TYPE]==2) m = m->dijete; //Radi strukture stabla, preskace na dijete ako se radi o prilagodenom tipu poruke
		if ((m->id == GENMSG || m->id == CUSTOMMSG) && !msg.empty()) std::cout <<"MSG: "<<msg << std::endl << "HASH: " << mainHash.hash << std::endl << "wHASH (hex): " << mainHash.hashH << std::endl << "wHAHS (bin): " << mainHash.hashB << std::endl;
		Display(m, 0, 1);
		std::getline(std::cin, odabir);
		if (odabir[0] == 'x') return;
		int choice = odabir[0] - 48;
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
		case HASHWEAK: {
			int weak[] = { 1,2,4,5,8,10,20,40 };
			settings[WEAK] = weak[odabir[0] - 49];
			GenConfString();
			return;
		}
		case MSGNUM:
			settings[NUM] = stoi(odabir);
			GenConfString();
			return;
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
	InsertMenu(men->dijete->susjed->susjed, HASHWEAK, "1. 1\n2. 2\n3. 4\n4. 5\n5. 8\n6. 10\n7. 20\n8. 40" + ender);
	InsertMenu(men->dijete->susjed->susjed, MSGNUM, "Broj poruka: ");
	UI(men);
	return 1;
}