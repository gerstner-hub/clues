#include <iostream>
#include <pthread.h>
#include <unistd.h>
#include <sys/wait.h>

void* thread_entry(void *par) {
	(void)par;
	std::cout << "other thread PID is " << gettid() << std::endl;

	if (fork() == 0) {
		const char *const argv[] = {"/usr//bin/sleep", "30", nullptr};
		execve("/usr/bin/sleep", const_cast<char *const*>(argv), environ);
		std::cerr << " a life post-exec?!\n";
	} else {
		wait(NULL);
		std::cout << "child finished\n";
	}

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

