#include "netfilter.h"
#include "APC.h"
#include <stdlib.h>
int main()
{
	netfilter filter = netfilter("true", filter_type_sniff);
	system("pause");
	return 0;
}