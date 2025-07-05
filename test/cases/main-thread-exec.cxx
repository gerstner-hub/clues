#include <iostream>
#include <pthread.h>
#include <unistd.h>

void* thread_entry(void *) {
	std::cout << "other thread pid is " << gettid() << std::endl;
	sleep(1000);
	return nullptr;
}

int main() {
	std::cout << "main thread pid is " << getpid() << std::endl;
	pthread_t thread;
	if (pthread_create(&thread, nullptr, thread_entry, nullptr) != 0) {
		std::cerr << "failed to start thread\n";
		return 1;
	}

	std::cerr << "press enter to execve()\n";
	bool ready;
	std::cin >> ready;

	const char *const argv[] = {"/bin/true", nullptr};
	execve("/bin/true", const_cast<char *const*>(argv), environ);
	std::cerr << " a life post-exec?!\n";

	if (pthread_join(thread, nullptr) != 0) {
		std::cerr << "failed to join thread\n";
		return 2;
	}
}
