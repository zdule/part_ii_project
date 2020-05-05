#ifndef KALLSYMS_H
#define KALLSYMS_H
void init_kallsyms();
char *lookup(unsigned long long addr);
#endif
