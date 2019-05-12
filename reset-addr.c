#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>

int main(int argc, char* argv[])
{
	if (argc < 2) {
		printf("No filename specified\n");
		return 1;
	}
	int fd = open(argv[1], O_RDONLY);
	if (fd < 0) {
		printf("Error opening file '%s'\n", argv[1]);
		return 1;
	}
	uint32_t addrs[2];
	read(fd, &addrs, 8);
	printf("reset vector:  0x%08x\n"
	       "stack pointer: 0x%08x\n",
		addrs[1], addrs[0]);
  	return 0;
}
