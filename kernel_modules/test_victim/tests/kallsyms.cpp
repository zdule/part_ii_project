#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <algorithm>
#include <iostream>
#include <stdio.h>
#include <string.h>
using namespace std;

vector<pair<unsigned long long, string>> syms;

extern "C" {
#include "kallsyms.h"
}
void init_kallsyms() {
	fstream in("/proc/kallsyms", ifstream::in);

	string line;
	for (string line; getline(in, line); ) {
		int successful = 0;
		string str_addr, type, namef;
		stringstream ss(line);
		successful += (bool) getline(ss, str_addr,' ');
		successful += (bool) getline(ss, type,' ');
		successful += (bool) getline(ss, namef,' ');
		if (successful == 3 && (type == "t" || type == "T")) {
			unsigned long long addr = stoull(str_addr, NULL, 16);
			stringstream ss(namef);
			string name;
			getline(ss, name, '\t');
			syms.push_back({addr, name});
		}
    }
	sort(syms.begin(), syms.end());
}

char *lookup(unsigned long long addr) {	
	string ch = "}";
	auto it = upper_bound(syms.begin(), syms.end(), make_pair(addr, ch ));
	it--;
	if (it == syms.end()) return NULL;
	string res = it->second;
	char *result = (char *)malloc(res.size()+1);
	strcpy(result, res.c_str());
	return result;
}

/*
int main() {
	init_kallsyms();
	char *str =lookup(18446744072653571250ULL);
	printf("== %s\n",str);
	free(str);
}
*/
