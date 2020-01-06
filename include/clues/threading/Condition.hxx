#ifndef CLUES_CONDITION_HXX
#define CLUES_CONDITION_HXX

// Linux
#include <pthread.h>
#include <assert.h>

// Clues
#include "clues/errors/ApiError.hxx"
#include "clues/threading/Mutex.hxx"

namespace clues
{

/**
 * \brief
 * 	A class to represent a pthread condition
 * \details
 * 	The current implementation only provides the most basic condition
 * 	operations. Refer to the POSIX man pages for more information.
 **/
class Condition
{
	// disallow copy-assignment
	Condition(const Condition&) = delete;
	Condition& operator=(const Condition&) = delete;

public: // functions

	/**
	 * \brief
	 * 	Create a condition coupled with \c lock
	 * \details
	 *	The given lock will be associated with the Condition for the
	 *	complete lifetime of the object. You need to make sure that
	 *	\c lock is never destroyed before the associated Condition
	 *	object is destroyed.
	 **/
	explicit Condition(Mutex &lock) :
		m_lock(lock)
	{
		auto res = ::pthread_cond_init(&m_pcond, nullptr);

		if( res != 0 )
		{
			clues_throw( ApiError(res) );
		}
	}

	~Condition()
	{
		const int destroy_res = ::pthread_cond_destroy(&m_pcond);

		assert( ! destroy_res );
	}

	//! The associated lock must already be locked at entry
	void wait()
	{
		auto res = ::pthread_cond_wait(&m_pcond, &(m_lock.m_pmutex));

		if( res != 0 )
		{
			clues_throw( ApiError(res) );
		}
	}

	void signal()
	{
		auto res = ::pthread_cond_signal(&m_pcond);

		if( res != 0 )
		{
			clues_throw( ApiError(res) );
		}
	}

	void broadcast()
	{
		auto res = ::pthread_cond_broadcast(&m_pcond);

		if( res != 0 )
		{
			clues_throw( ApiError(res) );
		}
	}

	Mutex& getMutex() { return m_lock; }

protected: // data

	pthread_cond_t m_pcond;
	Mutex &m_lock;
};

/**
 * \brief
 *	An aggregate of a Mutex and a Condition coupled together for typical
 *	usage
 **/
class ConditionMutex :
	public Mutex,
	public Condition
{
public: // functions

	ConditionMutex() :
		Condition(static_cast<Mutex&>(*this))
	{}
};

} // end ns

#endif // inc. guard

