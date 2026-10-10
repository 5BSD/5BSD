/* SPDX-License-Identifier: BSD-2-Clause */
/* Kernel NFSv3 server coverage of the FUSE READDIRPLUS cookie array. */
#include <sys/param.h>
#include <sys/mount.h>
#include <sys/wait.h>
#include <dirent.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <atomic>
#include "mockfs.hh"
#include "utils.hh"
#include "nfs_cookie_client.hh"

using namespace testing;

class NfsReaddir: public FuseTest {
	pid_t server = -1;
protected:
	std::vector<nfs_cookie::Entry> entries;
	std::atomic<unsigned> plus_calls{0}, plain_calls{0};
	bool fallback = false;

	void SetUp() override {
		const char *enabled = getenv("FUSE_NFS_LOOPBACK");
		if (enabled == nullptr || strcmp(enabled, "1") != 0)
			GTEST_SKIP() << "Requires opt-in disposable VM and rpcbind";
		ASSERT_EQ(0U, geteuid());
		m_init_flags = FUSE_EXPORT_SUPPORT | FUSE_DO_READDIRPLUS;
		m_allow_other = true;
		m_default_permissions = true;
		FuseTest::SetUp();
		ASSERT_FALSE(HasFatalFailure());
		for (unsigned i = 0; i < 12; i++)
			entries.push_back({100 + i, std::to_string(i) +
			    std::string(120, 'a' + i), (1ULL << 33) + 107 + i * 37});
		EXPECT_CALL(*m_mock, process(ResultOf([](auto in) {
			return in.header.opcode == FUSE_GETATTR;
		}, Eq(true)), _)).Times(AnyNumber())
		.WillRepeatedly(Invoke(ReturnImmediate([](auto in, auto &out) {
			SET_OUT_HEADER_LEN(out, attr);
			out.body.attr.attr.ino = in.header.nodeid;
			out.body.attr.attr.mode = S_IFDIR | 0755;
			out.body.attr.attr.nlink = 2;
			out.body.attr.attr_valid = UINT64_MAX;
		})));
		EXPECT_CALL(*m_mock, process(ResultOf([](auto in) {
			return in.header.opcode == FUSE_STATFS;
		}, Eq(true)), _)).Times(AnyNumber())
		.WillRepeatedly(Invoke(ReturnImmediate([](auto, auto &out) {
			SET_OUT_HEADER_LEN(out, statfs);
			out.body.statfs.st.bsize = 4096;
			out.body.statfs.st.frsize = 4096;
			out.body.statfs.st.namelen = 255;
		})));
		EXPECT_CALL(*m_mock, process(ResultOf([](auto in) {
			return in.header.opcode == FUSE_FORGET;
		}, Eq(true)), _)).Times(AnyNumber())
		.WillRepeatedly(Invoke([](auto, auto &) {}));
		EXPECT_LOOKUP(FUSE_ROOT_ID, "dir")
		.WillRepeatedly(Invoke(ReturnImmediate([](auto, auto &out) {
			SET_OUT_HEADER_LEN(out, entry);
			out.body.entry.nodeid = 42;
			out.body.entry.generation = 1;
			out.body.entry.attr.ino = 42;
			out.body.entry.attr.mode = S_IFDIR | 0755;
			out.body.entry.attr.nlink = 2;
			out.body.entry.attr_valid = UINT64_MAX;
			out.body.entry.entry_valid = UINT64_MAX;
		})));
		EXPECT_CALL(*m_mock, process(ResultOf([](auto in) {
			return in.header.opcode == FUSE_OPENDIR;
		}, Eq(true)), _)).WillOnce(Invoke(ReturnErrno(ENOSYS)));
		/* Establish the no-OPENDIR contract before exporting the mount. */
		int fd = open("mountpoint/dir", O_RDONLY | O_DIRECTORY);
		ASSERT_GE(fd, 0) << strerror(errno);
		ASSERT_EQ(0, close(fd));
		EXPECT_CALL(*m_mock, process(ResultOf([](auto in) {
			return in.header.nodeid == 42 &&
			    (in.header.opcode == FUSE_READDIRPLUS ||
			    in.header.opcode == FUSE_READDIR);
		}, Eq(true)), _)).Times(AtLeast(1))
		.WillRepeatedly(Invoke(ReturnImmediate([this](auto in, auto &out) {
			bool plus = in.header.opcode == FUSE_READDIRPLUS;
			if (plus) plus_calls++; else plain_calls++;
			if (plus && fallback) {
				out.header.error = -ENOSYS;
				out.header.len = sizeof(out.header);
				return;
			}
			size_t first = 0, used = 0;
			uint64_t off = in.body.readdir.offset;
			if (off != 0) {
				while (first < entries.size() && entries[first].cookie != off)
					first++;
				ASSERT_LT(first, entries.size()) << "Unknown FUSE cookie";
				first++;
			}
			for (size_t i = first; i < entries.size(); i++) {
				const auto &e = entries[i];
				struct fuse_direntplus d{};
				d.entry_out.nodeid = e.fileid;
				d.entry_out.attr.ino = e.fileid;
				d.entry_out.attr.mode = S_IFREG | 0644;
				d.entry_out.attr.nlink = 1;
				d.dirent.ino = e.fileid;
				d.dirent.off = e.cookie;
				d.dirent.type = DT_REG;
				d.dirent.namelen = e.name.size();
				size_t len = plus ? FUSE_DIRENTPLUS_SIZE(&d) :
				    FUSE_DIRENT_SIZE(&d.dirent);
				size_t prefix = plus ? FUSE_NAME_OFFSET_DIRENTPLUS :
				    FUSE_NAME_OFFSET;
				if (used + len > in.body.readdir.size) break;
				memset(out.body.bytes + used, 0, len);
				memcpy(out.body.bytes + used, plus ? (void *)&d :
				    (void *)&d.dirent, prefix);
				memcpy(out.body.bytes + used + prefix, e.name.data(),
				    e.name.size());
				used += len;
			}
			out.header.error = 0;
			out.header.len = sizeof(out.header) + used;
		})));
	}

	void export_mount() {
		struct statfs fs;
		ASSERT_EQ(0, statfs("mountpoint", &fs));
		struct export_args ex{};
		gid_t gid = 65534;
		sockaddr_in addr{};
		addr.sin_len = sizeof(addr);
		addr.sin_family = AF_INET;
		addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		ex.ex_flags = MNT_EXPORTED;
		ex.ex_uid = 65534;
		ex.ex_ngroups = 1;
		ex.ex_groups = &gid;
		ex.ex_addr = reinterpret_cast<sockaddr *>(&addr);
		ex.ex_addrlen = sizeof(addr);
		ex.ex_numsecflavors = 1;
		ex.ex_secflavors[0] = AUTH_SYS;
		char error[256]{};
		struct iovec iov[] = {
#define OPT(k, v, n) {const_cast<char *>(k), sizeof(k)}, {v, n}
			OPT("fstype", fs.f_fstypename, strlen(fs.f_fstypename) + 1),
			OPT("fspath", fs.f_mntonname, strlen(fs.f_mntonname) + 1),
			OPT("from", fs.f_mntfromname, strlen(fs.f_mntfromname) + 1),
			OPT("export", &ex, sizeof(ex)),
			OPT("errmsg", error, sizeof(error)),
#undef OPT
		};
		ASSERT_EQ(0, nmount(iov, nitems(iov), fs.f_flags | MNT_UPDATE))
		    << strerror(errno) << ": " << error;
	}

	void start_server() {
		int pipefd[2];
		ASSERT_EQ(0, pipe2(pipefd, O_CLOEXEC));
		server = ::fork();
		if (server == 0) {
			close(pipefd[1]);
			char ready;
			ssize_t n;
			do { n = read(pipefd[0], &ready, 1); } while (n < 0 && errno == EINTR);
			close(pipefd[0]);
			if (n != 1) _exit(126);
			execl("/usr/sbin/nfsd", "nfsd", "--debug", "-u", "-h",
			    "127.0.0.1", "--minthreads", "1", "--maxthreads", "1",
			    (char *)nullptr);
			_exit(127);
		}
		close(pipefd[0]);
		if (server < 0) { close(pipefd[1]); FAIL() << strerror(errno); }
		m_mock->m_child_pid = server;
		ssize_t n = write(pipefd[1], "x", 1);
		close(pipefd[1]);
		ASSERT_EQ(1, n);
	}

	void TearDown() override {
		if (server > 0) {
			kill(server, SIGUSR1);
			int status = 0;
			pid_t done = 0;
			for (int i = 0; i < 100 && done == 0; i++) {
				done = waitpid(server, &status, WNOHANG);
				if (done == 0) usleep(100000);
			}
			if (done == 0) {
				kill(server, SIGKILL);
				while (waitpid(server, &status, 0) < 0 && errno == EINTR) {}
				ADD_FAILURE() << "nfsd failed to stop";
			} else {
				EXPECT_EQ(server, done);
				EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
			}
		}
		FuseTest::TearDown();
	}

	void check_cookies() {
		nfs_cookie::Request request;
		ASSERT_EQ(0, getfh("mountpoint/dir", &request.handle));
		export_mount();
		ASSERT_FALSE(HasFatalFailure());
		start_server();
		ASSERT_FALSE(HasFatalFailure());
		nfs_cookie::Client client;
		ASSERT_TRUE(client.connect());
		bool ready = false;
		for (int i = 0; i < 50 && !ready; i++) {
			ready = client.ready() == RPC_SUCCESS;
			if (!ready) usleep(100000);
		}
		ASSERT_TRUE(ready) << "NFS server startup";
		size_t seen = 0;
		unsigned pages = 0;
		bool eof = false;
		while (!eof && pages++ < 32) {
			nfs_cookie::Reply reply;
			ASSERT_EQ(RPC_SUCCESS, client.readdir(request, reply));
			ASSERT_EQ(0U, reply.status);
			ASSERT_TRUE(reply.eof || !reply.entries.empty());
			for (const auto &e : reply.entries) {
				ASSERT_LT(seen, entries.size());
				EXPECT_EQ(entries[seen].name, e.name);
				EXPECT_EQ(entries[seen].fileid, e.fileid);
				EXPECT_EQ(entries[seen].cookie, e.cookie);
				request.cookie = e.cookie;
				seen++;
			}
			request.verifier = reply.verifier;
			eof = reply.eof;
		}
		EXPECT_TRUE(eof);
		EXPECT_EQ(entries.size(), seen);
		EXPECT_GT(pages, 1U);
		EXPECT_GT(plus_calls.load(), 0U);
		if (fallback) {
			EXPECT_EQ(1U, plus_calls.load());
			EXPECT_GT(plain_calls.load(), 0U);
		} else {
			EXPECT_EQ(0U, plain_calls.load());
		}
	}
};

TEST_F(NfsReaddir, plus_cookie_resume) { check_cookies(); }
TEST_F(NfsReaddir, enosys_cookie_resume) { fallback = true; check_cookies(); }
