#include <iostream>
#include <pthread.h>
#include <unistd.h>

void* thread_entry(void *par) {
	(void)par;
	std::cout << "other thread PID is " << gettid() << std::endl;
	std::cout << "press ENTER to exit thread\n";
	bool ready;
	std::cin >> ready;
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
