// Clues
#include "clues/SubProc.hxx"
#include "clues/StreamAdaptor.hxx"
#include "clues/Pipe.hxx"
#include "clues/errors/CluesError.hxx"
#include "clues/errors/InternalError.hxx"
#include "clues/errors/ApiError.hxx"
#include "clues/types.hxx"

// C++
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>

// C
#include <stdlib.h>
#include <fcntl.h>

class RedirectOutputTestBase
{
public:
	RedirectOutputTestBase() :
		m_cat_path("/bin/cat")
	{}

	~RedirectOutputTestBase()
	{
		if( unlink(m_tmp_file_path.c_str()) != 0 )
		{
			std::cerr << "Failed to remove " << m_tmp_file_path << std::endl;
		}
	}

	clues::FileDesc getTempFile()
	{
		m_tmp_file_path = "/tmp/subproc_test.XXXXXX";
		auto ret = mkostemp(&m_tmp_file_path[0], O_CLOEXEC);

		if( ret == clues::INVALID_FILE_DESC )
		{
			clues_throw( clues::ApiError() );
		}

		std::cout << "Using temporary file: " << m_tmp_file_path << std::endl;

		return ret;
	}

protected:

	std::string m_tmp_file_path;
	const std::string m_cat_path;
	clues::SubProc m_proc;
};

class RedirectStdoutTest :
	public RedirectOutputTestBase
{
public:
	RedirectStdoutTest() :
		m_cat_file("/etc/fstab")
	{}

	void run()
	{
		clues::InputStreamAdaptor file(getTempFile());

		/*
		 * the test case is:
		 *
		 * cat /etc/fstab >/tmp/somefile
		 *
		 * and check afterwards that the file contains the right
		 * stuff.
		 */
		m_proc.setStdout(file.fileDesc());
		m_proc.setArgs({m_cat_path, m_cat_file});
		m_proc.run();
		auto res = m_proc.wait();

		if( ! res.exitedSuccessfully() )
		{
			clues_throw( clues::InternalError("Child process with redirected stdout failed") );
		}

		compareFiles(file);
	}

	void compareFiles(std::istream &copy)
	{
		std::ifstream orig(m_cat_file);
		// we share the open file description with the child, thus we
		// need to rewind
		copy.seekg(0);

		if( ! copy.good() || !orig.good() )
		{
			clues_throw( clues::InternalError("bad stream state(s)") );
		}

		std::string line1, line2;

		while(true)
		{
			std::getline(orig, line1);
			std::getline(copy, line2);

			if( orig.eof() && copy.eof() )
				break;
			else if( orig.fail() || copy.fail() )
			{
				std::cout << "orig.fail(): " << orig.fail() << std::endl;
				std::cout << "copy.fail(): " << copy.fail() << std::endl;
				clues_throw( clues::InternalError("inconsistent stream state(s)") );
			}
			else if( line1 != line2 )
			{
				std::cerr
					<< "output file doesn't match input file\n"
					<< line1 << " != " << line2 << std::endl;
				clues_throw( clues::InternalError("file comparison failed") );
			}

			//std::cout << line1 << " == " << line2 << "\n";
		}

		std::cout << "File comparison successful" << std::endl;
	}

protected:

	const std::string m_cat_file;
};

class RedirectStderrTest :
	public RedirectOutputTestBase
{
public:
	RedirectStderrTest() :
		m_nonexisting_file("/non/existing/file")
	{}

	void run()
	{
		clues::InputStreamAdaptor file(getTempFile());

		/*
		 * the test case is:
		 *
		 * cat /non/existing/file 2>/tmp/somefile
		 *
		 * and check afterwards that an error message is
		 * contained in the stderr file.
		 */
		m_proc.setStderr(file.fileDesc());
		m_proc.setArgs({m_cat_path, m_nonexisting_file});
		m_proc.run();
		auto res = m_proc.wait();

		if( ! res.exited() || res.exitStatus() != 1 )
		{
			clues_throw( clues::InternalError("Child process with redirected stderr ended in unexpected state") );
		}

		checkErrorMessage(file);
	}

	void checkErrorMessage(std::istream &errfile)
	{
		errfile.seekg(0);

		std::string line;
		std::getline(errfile, line);

		if( errfile.fail() )
		{
			clues_throw( clues::InternalError("Failed to read back cat error message") );
		}

		// TODO: be aware of locale settings that might change the
		// error message content
		const std::string errmsg("No such file or directory");
		for( const auto &item: {m_nonexisting_file, m_cat_path, errmsg} )
		{
			if( line.find(item) != line.npos )
				continue;

			std::cerr << "Couldn't find '" << item << "' in error message: '" << line << "'\n";
			clues_throw( clues::InternalError("Couldn't find expected item in error message") );
		}

		std::cout << "error message contains expected elements" << std::endl;
	}

protected:

	const std::string m_nonexisting_file;
};

class PipeInTest
{
public:
	explicit PipeInTest() :
		m_head_path("/usr/bin/head"),
		m_test_file("/etc/services")
	{}

	void run()
	{
		std::stringstream ss;
		ss << m_expected_lines;
		/*
		 * the test case is:
		 *
		 * ech "stuff" | head -n 5 | our_test
		 *
		 * and we check whether the expected number of lines can be
		 * read from the pipe
		 */
		m_proc.setArgs({m_head_path, "-n", ss.str()});
		m_proc.setStdout(m_pipe_from_head.writeEnd());
		m_proc.setStdin(m_pipe_to_head.readEnd());
		m_proc.run();

		// we need to close the write-end to successfully receive an
		// EOF indication on the read end when the sub process
		// finishes.
		m_pipe_from_head.closeWriteEnd();
		// same here vice-versa
		m_pipe_to_head.closeReadEnd();

		try
		{
			performPipeIO();
		}
		catch(...)
		{
			m_proc.kill(clues::Signal(SIGTERM));
			m_proc.wait();
			throw;
		}

		auto res = m_proc.wait();

		if( ! res.exitedSuccessfully() )
		{
			clues_throw( clues::InternalError("Child process with redirected stdin failed") );
		}
	}

	void performPipeIO()
	{
		clues::StringVector test_lines;
		for(size_t i = 0; i < m_expected_lines * 2; i++ )
		{
			std::stringstream ss;
			ss << "Test line " << i << "\n";
			test_lines.push_back(ss.str());
		}

		clues::InputStreamAdaptor from_head(m_pipe_from_head);
		clues::OutputStreamAdaptor to_head(m_pipe_to_head);

		for(const auto &line: test_lines)
		{
			to_head.write(line.c_str(), line.size());

			if( to_head.fail() )
				// probably head exited after the maximum
				// number of lines
				break;
		}

		to_head << std::flush;

		std::string copy_line;
		size_t received_lines = 0;

		while(true)
		{
			std::getline(from_head, copy_line);

			if( from_head.eof() )
				break;
			else if( from_head.fail() )
			{
				clues_throw( clues::InternalError("bad stream state") );
			}

			// re-add the newline for comparison
			copy_line += "\n";

			if( test_lines.at(received_lines) != copy_line )
			{
				std::cerr << "'" << copy_line << "' != '" << test_lines[received_lines] << "'" << std::endl;
				clues_throw( clues::InternalError("received bad line copy") );
			}
			else
			{
				//std::cout << "line nr. " << received_lines << " is correct" << std::endl;
			}

			++received_lines;
		}

		if( received_lines != m_expected_lines )
		{
			clues_throw( clues::InternalError("Didn't receive back the expected amount of lines") );
		}

		from_head.close();
		to_head.close();

		std::cout << "Received the correct amount and content of lines back" << std::endl;
	}

protected:

	clues::Pipe m_pipe_to_head;
	clues::Pipe m_pipe_from_head;
	clues::SubProc m_proc;
	const std::string m_head_path;
	const std::string m_test_file;
	const size_t m_expected_lines = 5;
};

int main()
{
	try
	{
		/*
		 * test redirection of each std. file descriptor
		 */
		{
			RedirectStdoutTest out_test;
			out_test.run();
		}

		std::cout << "\n\n";

		{
			RedirectStderrTest err_test;
			err_test.run();
		}

		std::cout << "\n\n";

		{
			PipeInTest in_test;
			in_test.run();
		}

		return 0;
	}
	catch( const clues::CluesError &ex )
	{
		std::cerr << ex.what() << std::endl;
		return 1;
	}
}

