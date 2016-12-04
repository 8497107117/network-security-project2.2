#include <stdio.h>
#include <stdlib.h>

int main (int argc, char *argv[]) {
	if(argc != 2)
		return 0;
	int seed = atoi(argv[1]);
	srand(seed);
	for(int i = 0;i < 1000;i++) {
		int r = rand()%4;
		r = r == 0 ? 4 : r;
		printf("%d ", r);
	}
}
