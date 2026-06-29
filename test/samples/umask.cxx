#include <sys/stat.h>

int main() {
	umask(0027);
	umask(0077);
}
