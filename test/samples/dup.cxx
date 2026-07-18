#include <unistd.h>
#include <fcntl.h>

int main() {
	int new_stdin = dup(0);
	int new_stdin2 = dup2(new_stdin, 50);
	int new_stdin3 = dup3(new_stdin, 100, O_CLOEXEC);
	close(new_stdin);
	close(new_stdin2);
	close(new_stdin3);
}
