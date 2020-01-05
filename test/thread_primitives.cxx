// Clues
#include "clues/threading/Mutex.hxx"
#include "clues/threading/Condition.hxx"

// C++
#include <iostream>

int main()
{
	try
	{
		/*
		 * lacking actualy threads yet this is a bit of a over
		 * simplified test, but still better than nothing.
		 */
		clues::Mutex lock;

		lock.lock();
		lock.unlock();

		clues::Condition cond(lock);
		cond.signal();
		cond.broadcast();
	}
	catch( const clues::CluesError &ex )
	{
		std::cerr << ex.what() << std::endl;
		return 1;
	}

}

