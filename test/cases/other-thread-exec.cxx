#include <iostream>
#include <pthread.h>
#include <unistd.h>

void* thread_entry(void *par) {
	std::cout << "other thread PID is " << gettid() << std::endl;
	const char *const argv[] = {"/bin/true", nullptr};
	std::cerr << "press enter to execve()\n";
	bool ready;
	std::cin >> ready;
	execve("/bin/true", const_cast<char *const*>(argv), environ);
	std::cerr << " a life post-exec?!\n";
	return nullptr;
}

int main() {
	std::cout << "main thread PID is " << getpid() << std::endl;
	pthread_t thread;
	if (pthread_create(&thread, nullptr, thread_entry, nullptr) != 0) {
		std::cerr << "failed to start thread\n";
		return 1;
	}

	if (pthread_join(thread, nullptr) != 0) {
		std::cerr << "failed to join thread\n";
		return 2;
	}
}
