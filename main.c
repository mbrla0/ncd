/* For now, I'll just break compat. for systems whose libc
 * doesn't comform to POSIX.1-2008, so I can use scandir(),
 * which greatly simplifies the code in ncd_iface_up().
 * 
 * TODO: Implement a path for POSIX.1-2001 libraries in
 * the subdirectory scanning routine, in ncd_iface_up(),
 * and then change this back to 600.
 */
#define _XOPEN_SOURCE 700

/* See readdir(3), enables DT_* macros needed by
 * _ncd_iface_up_dir_filter() in order to filter
 * files out. */
#define _DEFAULT_SOURCE 1

#include <stdio.h>
#include <stdlib.h>

/* System-related headers */
#include <sys/types.h>	/* For general POSIX types		*/
#include <sys/wait.h>	/* For waitpid()				*/
#include <sys/stat.h>	/* For stat() 					*/
#include <sys/select.h>	/* For select() and fd_set		*/
#include <sys/socket.h>	/* Required by rtnetlink.		*/
#include <signal.h>		/* For everything signals 		*/
#include <errno.h>		/* For errno and error codes	*/
#include <fcntl.h>		/* For open()					*/
#include <dirent.h>		/* For opendir() and readdir()	*/
#include <unistd.h>		/* For general POSIX functions	*/

/* Netlink-related headers */
#include <netlink/netlink.h>	/* For general libnl 				*/
#include <netlink/socket.h>		/* For socket handling in libnl 	*/
#include <netlink/msg.h>		/* For message handling in libnl 	*/
#include <linux/netlink.h>		/* For Linux-related netlink 		*/
#include <linux/rtnetlink.h>	/* For rtnetlink					*/
#include <net/if.h>				/* For interface information		*/
#include <linux/if.h>

#define RETVAL_OK 0
#define RET_OK(ret) (ret == RETVAL_OK)
#define EXPECT(fn, msg) if(fn != RETVAL_OK) { fprintf(stderr, msg); exit(1); }

/* Maximum number of characters to be allowed in a network interface name.
 * TODO: Consider moving NCD_IFNAME_MAX to ncd_settings.
 */
#define NCD_IFNAME_MAX 256

/* If an interface name contains any of these characters, it will
 * be considered invalid by ncd_iface_up(), as a security measure against
 * directory back-traversal, especially. Change this according to your needs,
 * if you find this to be too conservative or too permissive, or  if any of
 * your interfaces happen to have one of these characters in its name.
 *
 * Note that only values in the range ]0x20;0x7E] are effective here, since
 * chars outside of it are allways considered invalid.
 *
 * TODO: Consider moving NCD_IFNAME_INVALID to ncd_settings.
 */
static const char* NCD_IFNAME_INVALID = "\"\'?<>:;`,./\\+=[]{|}!@#$%&*()~^";

/* When netconfd sets an interface up, it will create a link to the */
static const char* NCD_RUNNING_LINK = "active";

/* Structure for holding global netconfd settings */
struct{
	/* Directory parent to all interface script directories */
	const char *catalog;
	/* Directory for storing the current state of the program */
	const char *runtime;
	/* Default timeout for scripts, in seconds */
	int timeout;
} ncd_settings;

/* Loads default values into ndc_settings */
void ncd_settings_load_defaults(){
	ncd_settings.catalog = "/var/netconfd/scripts/";
	ncd_settings.timeout = 10;
}


pid_t ncd_spawn(const char *program, char *const argv[], char *const envp[]){
	pid_t pid = fork();
	switch(pid){
	case 0:{
		/* In child process */
		int ret = execve(program, argv, envp);
		if(ret == -1)
			perror("ncd_spawn(): execve():");

		exit(ret);
		return 0;
	}case -1:
		/* Failed */
		perror("ncd_spawn(): fork():");
		return -1;
	default:
		/* In parent */
		fprintf(stderr, "ncd_spawn(): successfuly spawned \"%s\", with pid %d\n", program, pid);
		return pid;
	}
}

struct ncd_runinfo{
	/* Process ID of the child, or -1 on failure */
	pid_t pid;
	/* Whether or not this process is to be kept alive
	 * until the end of its execution. */
	int keepalive;
	/* Did the process time out? */
	int timed_out;
	/* Was the process terminated by a signal? */
	int signaled;
	/* Exit code, valid only when `keepalive`, `signaled`
	 * and `timed_out` are all set to 0 */
	int exit_code; 
};

/* Spawns a subprocess and wait at most timeout
 * seconds for it to end, killing it otherwise. */
struct ncd_runinfo ncd_timedrun(unsigned int timeout, const char *program, char *const argv[], char *const envp[]){
	pid_t pid = ncd_spawn(program, argv, envp);
	struct ncd_runinfo info = {0, 0, 0, 0, 0};
	info.pid = pid;

	if(pid == -1)
		return info;

	if(timeout > 0){
		info.keepalive = 0;

		static sigset_t sset;
		sigemptyset(&sset);
		sigaddset(&sset, SIGCHLD);
		sigaddset(&sset, SIGALRM);

		sigset_t old_sset;
		sigprocmask(SIG_BLOCK, &sset, &old_sset);

		alarm(ncd_settings.timeout);
		while(1){
			int status;
			if(waitpid(pid, &status, WNOHANG) == pid){
				if(WIFEXITED(status)){
					fprintf(stderr, "ncd_timedrun(): child exited with code %d\n", WEXITSTATUS(status));
					info.exit_code = WEXITSTATUS(status);
					break;
				}else if(WIFSIGNALED(status)){
					fprintf(stderr, "ncd_timedrun(): child was signaled to death\n");
					info.signaled = 1;
					break;
				}
			}
			
			int sig;
			if(sigwait(&sset, &sig) != 0)
				perror("ncd_waitrun(): sigwait():");

			if(sig == SIGALRM){
				/* TIMED OUT! TIME TO KILL */
				kill(pid, SIGKILL);
				info.timed_out = 1;
				break;
			}
		}
		
		alarm(0);
		sigprocmask(SIG_SETMASK, &old_sset, NULL);
	}else
		info.keepalive = 1;

	return info;
}

/* Describes the script catalog this program is working with.
 * 
 * A catalog is a directory whose subdirectories are named after
 * a given link name, and contain zero or more script subdirs,
 * each with startup and finishing scripts. */
struct{
	const char *directory;
	int locked;
} ncd_catalog;

/* Changes the cwd to ncd_catalog.directory */
int ncd_catalog_cwd_reset(){
	if(chdir(ncd_catalog.directory) == -1){
		perror("ncd_catalog_cwd_reset()");
		return 1;
	}

	return RETVAL_OK;
}

/* Change catalog into the given directory */
int ncd_catalog_cd(const char* target){
	/* Since we're moving into a new directory, this program
	 * we can't have a lock guarantee. Even if it has been
	 * locked by this same execution before, ncd_lock() must
	 * be called again.
	 */
	ncd_catalog.locked = 0;

	/* Check whether target is a valid directory */
	struct stat st;
	if(stat(target, &st) == -1){
		perror("ncd_catalog_cd(): could not stat target directory");
		return 1;
	}else if(!S_ISDIR(st.st_mode)){
		fprintf(stderr, "ncd_catalog_cd(): target %s is not a directory\n", target);
		return 1;
	}

	/* Change into it and return OK */
	ncd_catalog.directory = target;
	return ncd_catalog_cwd_reset();
}

/* Tries to lock the catalog */
int ncd_catalog_lock(){
	if(ncd_catalog_cwd_reset() != 0)
		return 1;
		
	int fd = open("./lock.pid", O_RDWR | O_CREAT | O_EXCL);
	if(fd == -1){
		/* There are two possibilities here: either the file can't
		 * be created by this process (doesn't have enough permissions,
		 * I/O error, etc.) or it already exists, in which case we might
		 * still own it if the contents of the file match getpid().
		 */
		fd = open("./lock.pid", O_RDONLY);
		if(fd == -1){
			/* We REEEEALLY cannot access this file D= */
			perror("ncd_catalog_lock(): open()");
			return 1;
		}

		/* Check the contents of the file against getpid() */
		pid_t fpid;
		if(read(fd, &fpid, sizeof(pid_t)) < sizeof(pid_t)){
			perror("ncd_catalog_lock(): read()");
			return 1;
		}

		if(fpid != getpid()){
			fprintf(stderr, "ncd_catalog_lock(): lock is owned by another process, with id %d\n", fpid);
			return 1;
		}else{
			/* The lock is already ours! */
			ncd_catalog.locked = 1;
			return RETVAL_OK;
		}
	}else{
		/* Write the current process ID into the file,
		 * TODO: Maybe turn this into text later.
		 **/
		pid_t pid = getpid();
		if(write(fd, &pid, sizeof(pid_t)) < sizeof(pid_t)){
			perror("ncd_catalog_lock(): write()");
			return 1;
		}
		close(fd);

		ncd_catalog.locked = 1;
		return RETVAL_OK;
	}
}

int ncd_catalog_unlock(){
	if(!ncd_catalog.locked){
		fprintf(stderr, "ncd_catalog_unlock(): catalog is not locked\n");
		return 1;
	}
	if(ncd_catalog_cwd_reset() != 0)
		return 1;

	return remove("./lock.pid");
}

/* Describes the currently selected interface */
struct{
	/* Name of the interface */
	const char *ifname;
	/* Whether this interface is up */
	int up;
	/* Name of the running script (if up) */
	const char *script;
	/* PID of the 'run' program. Note that it
	 * might have already exited even when
	 * the state is still up, which happens for
	 * scripts that just set things up and rely on
	 * 'stop' to clean up after them, in which case
	 * this number is not valid. Therefore, it must
	 * not be assumed to always be valid.*/
	int script_pid;
	/* If set, ignore this interface */
	int invalid;
} ncd_iface;

/* Simmilar to ncd_catalog_cwd_reset(), except that this
 * changes directory to the base interface directory instead
 * of the catalog directory */
int ncd_iface_cwd_reset(){
	/* First, change back to the base catalog directory */
	if(ncd_catalog_cwd_reset() != 0)
		return 1;

	/* Then, change into the interface directory */
	if(chdir(ncd_iface.ifname) == -1){
		perror("ncd_iface_cwd_reset(): chdir()");
		return 1;
	}

	return RETVAL_OK;
}

/* Changes into the given interface */
int ncd_iface_change(const char* ifname){
	if(ncd_catalog_cwd_reset() != 0)
		return 1;

	/* Check for input sanity:
	 *	- Make sure it doesn't hang execution by being too long.
	 *
	 * 	- We'll be changing directories, and, although highly discouraged,
	 * netconfd might be running as root and outside a chroot jail, we need
	 * to make sure the interface name does not contain malitious input, such
	 * as one that would make it change into a folder containing malitious
	 * scripts written by an attacker. (For example: with no sanity check in place,
	 * having the ifname be "../../../home/totally-not-an-attacker/malitious_script"
	 * would trick netconfd to change into that directory and execute its scripts as
	 * root! And we can't have that)
	 */
	if(strlen(ifname) > NCD_IFNAME_MAX){
		fprintf(stderr, "ncd_iface_change(): exceeded maximum interface name size, if you're sure "
						"this is a valid interface, consider changing NCD_IFNAME_MAX to a higher value\n");
		return 1;
	}
	
	int i;
	for(i = 0; i < strlen(ifname); ++i){
		if(ifname[i] > 0x7e || ifname[i] <= 0x20){
			fprintf(stderr, "ncd_iface_change(): interface contains characters outside the ]0x20;0x7e] range");
			return 1;
		}
	}

	char *invalid = strpbrk(ifname, NCD_IFNAME_INVALID);
	if(invalid != NULL){
		fprintf(stderr, "ncd_iface_change(): interface \"%s\" contains the invalid character \'%c\', if "
						"you're sure this is a valid interface, consider removing the character from "
						"NCD_IFNAME_INVALID\n", ifname, *invalid);
		return 1;
	}

	/* Change to its directory */
	if(chdir(ifname) == -1){
		perror("ncd_iface_change(): chdir()");
		return 1;
	}

	/* Update ncd_iface */
	ncd_iface.ifname		= ifname;
	ncd_iface.up 			= 0;
	ncd_iface.script_pid		= 0;
	ncd_iface.invalid		= 0;
	ncd_iface.script		= NULL;

	return 0;
}

int ncd_iface_down(){
	if(ncd_iface.invalid){
		fprintf(stderr, "ncd_iface_down(): interface has been marked invalid\n");
		return 1;
	}

	if(ncd_iface_cwd_reset() != 0)
		return 1;

	/* Check if there's anything running */
	if(chdir(NCD_RUNNING_LINK) == -1){
		int err = errno;
		perror("ncd_iface_down(): chdir()");

		switch(err){
		case ENOENT:
			/* The folder does not exist: wasn't really setup to
			 * begin with, so we don't need to worry about a thing.
			 */
			return 0;
		case EACCES:
			/* We cannot access the folder: This is grave, yell at
			 * the sysadmin to go fix his permission issues and flag
			 * this interface as not being valid, so we don't run the
			 * risk of breaking something down the line. */
			fprintf(stderr, "ncd_iface_down(): permission issues encountered when processing interface! "
							"please clean up after yourself, especially when dealing with permissions. " 
							"this interface will be marked as invalid and no op. will be permitted on it.\n");
			ncd_iface.invalid = 1;
			return 1;
		default:
			/* The folder is invalid, just delete it */
			fprintf(stderr, "ncd_iface_down(): the status folder is invalid, cannot determine interface status correctly. "
					"the interface will be marked invalid, so as to prevent unintended damage, please look into "
				       	"%s%s in order to correct to make sure %s either exists and is a valid folder, or does not exist.\n",
				       	ncd_catalog.directory, ncd_iface.ifname, NCD_RUNNING_LINK);
			ncd_iface.invalid = 1;
			return 1;
		}
	}

	/* Stop the PID in keepalive, if any */
	int keepalive_fd = open("./keepalive", O_RDONLY);
	if(keepalive_fd >= 0){
		int pid;
		if(read(keepalive_fd, &pid, sizeof(int)) == sizeof(int))
			/* Terminate the child process */
			kill(pid, SIGTERM);

		close(keepalive_fd);
		if(remove("./keepalive") == -1)
			perror("ncd_iface_down(): remove(\"./keepalive\"):");
	}

	/* Run the stop script, if any */
	int result = 0;
	struct stat st;
	if(stat("./stop", &st) == 0 && st.st_mode & S_IXUSR){
		struct ncd_runinfo info = ncd_timedrun(ncd_settings.timeout, "./stop", NULL, NULL);
		if(!info.timed_out && !info.keepalive && !info.signaled)
			result = info.exit_code;
		else
			result = 1;
	}
	
	if(ncd_iface_cwd_reset() != 0){
		fprintf(stderr, "ncd_iface_down(): cannot change directory.\n");
		return 1;
	}
	
	fprintf(stderr, "ncd_iface_down(): done\n");

	if(remove(NCD_RUNNING_LINK) != 0){
		perror("ncd_iface_down(): remove():");
		return 1;
	}

	return result;
}

int _ncd_iface_up_dir_filter(const struct dirent* dir){
	return dir->d_type == DT_DIR 
		&& strcmp(dir->d_name, NCD_RUNNING_LINK) != 0 
		&& strcmp(dir->d_name, ".")  != 0
		&& strcmp(dir->d_name, "..") != 0;
}

int _ncd_iface_up_dir_cmp(struct dirent** a, struct dirent** b){
	/* Any character not in this list will be treated as coming first */
	static const char *SORTING_ORDER = 
			"-0123456789AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz";

	char *an = (*a)->d_name;
	char *bn = (*b)->d_name;
	while(strchr(SORTING_ORDER, *an) == strchr(SORTING_ORDER, *bn)
		&& *an != 0 && *bn != 0){

		if(an - (*a)->d_name >= sizeof((*a)->d_name)) return 0;
		++an;
		++bn;
	}

	return (int) (strchr(SORTING_ORDER, *bn) - strchr(SORTING_ORDER, *an));
}

/* Tries to setup an interface name from the catalog */
int ncd_iface_up(){
	if(ncd_iface.invalid){
		fprintf(stderr, "ncd_iface_up(): interface has been marked invalid\n");
		return 1;
	}
	
	if(ncd_iface_cwd_reset() != 0){
		fprintf(stderr, "ncd_iface_up(): could not change directory");
		return 1;
	}

	/* Make sure this interface is down */
	struct stat st;
	if(stat(NCD_RUNNING_LINK, &st) == 0){
		fprintf(stderr, "ncd_iface_up(): iface is already up\n");
		return 1;
	}

	if(ncd_iface_cwd_reset() != 0){
		fprintf(stderr, "ncd_iface_up(): could not change directory");
		return 1;
	}

	int dircount;
	struct dirent **dirs;

#if _POSIX_C_SOURCE < 200809L
#error "Support is limited to POSIX.1-2008, please enable it."
#else
	/* Sort script folders using alphasort */
	dircount = scandir(".", &dirs, _ncd_iface_up_dir_filter, alphasort);
	if(dircount < 0){
		perror("ncd_iface_up(): scandir():");
		return 0;
	}else if(dircount == 0){
		fprintf(stderr, "ncd_iface_up(): scandir found no suitable folder\n");
	}
#endif
	int i, done, diri;
	for(i = 0, done = 0; i < dircount && !done; ++i){
		/* Save the current directory as a file descriptor,
		 * so we can return to it later, without having to
		 * mess aroung with string buffers.
		 */
		int basedir_fd = open(".", O_RDONLY);
		if(basedir_fd == -1){
			perror("ncd_iface_up(): open():");
			return 1;
		}

		if(chdir(dirs[i]->d_name) == -1){
			perror("ncd_iface_up(): chdir():");
			continue;
		}
		
		/* Figure out the lifetime of this script */
		int keepalive = 0;
		int timeout;
		{
			int tofd = open("./timeout", O_RDONLY);
			if(tofd == -1){
				perror("ncd_iface_up(): open(\"./timeout\"):");
				timeout = ncd_settings.timeout;
			}else if(read(tofd, &timeout, sizeof(int)) != sizeof(int)){
				perror("ncd_iface_up(): read():");
				keepalive = 1;
				timeout   = 0;
			}
		}

		if(keepalive){
			struct ncd_runinfo ri;
			ri = ncd_timedrun(0, "run", NULL, NULL);
			
			/* Stop right here */
			if(ri.pid != -1 && ri.keepalive){
				int kafd = open("./keepalive", O_RDONLY);
				if(kafd >= 0 && write(kafd, &ri.pid, sizeof(pid_t)) != sizeof(pid_t))
					perror("ncd_iface_up(): write() to keepalivie:");

				if(kafd >=0)
					close(kafd);

				diri = i;
				done = 1;
			}
		}else{
			struct ncd_runinfo ri;
			ri = ncd_timedrun(timeout, "run", NULL, NULL);

			/* Found a valid config */
			if(!ri.timed_out && !ri.signaled && !ri.keepalive){
				diri = i;
				done = ri.exit_code + 1;
			}else{
				diri = i;
				done = 2;
			}
		}

		if(fchdir(basedir_fd) == -1){
			perror("ncd_iface_up(): fchdir():");
			return 1;
		}
		close(basedir_fd);
	}

	/* Create a symlink for the running script if successful */
	if(done && symlink(dirs[diri]->d_name, NCD_RUNNING_LINK) != 0){
		perror("ncd_iface_up(): symlink():");
		return 1;
	}

	/* Returns 1 on no valid option found, 0 otherwise */
	return 1 - done;
}

/* Clears all runtime information from the catalog */
int ncd_runtime_clear(){
	if(ncd_catalog_cwd_reset() != 0){
		fprintf(stderr, "ncd_runtime_clear(): could not change directory\n");
		return 1;
	}

	DIR *dir = opendir(".");
	if(dir == NULL){
		perror("ncd_runtime_clear(): opendir():");
		return 1;
	}

	struct dirent *e;
	for(e = readdir(dir); e != NULL; e = readdir(dir)){
		if(!_ncd_iface_up_dir_filter(e))
			continue;

		ncd_iface_change(e->d_name);
		if(ncd_iface_cwd_reset() != 0){
			fprintf(stderr, "ncd_runtime_clear(): could not change into interface directory\n");
			return 1;
		}
		
		// Delete the running link
		if(remove(NCD_RUNNING_LINK) != 0){
			fprintf(stderr, "ncd_runtime_clear(): could not remove running link of interface %s:", ncd_iface.ifname);
			perror("");
		}
	};

	return 0;
}

/* Tries to stop all interfaces. Does not preserve the state of ncd_iface. */
int ncd_runtime_shutdown(){
	if(ncd_catalog_cwd_reset() != 0){
		fprintf(stderr, "ncd_runtime_shutdown(): could not change directory\n");
		return 1;
	}

	DIR *dir = opendir(".");
	if(dir == NULL){
		perror("ncd_runtime_shutdown(): opendir():");
		return 1;
	}

	struct dirent *e;
	for(e = readdir(dir); e != NULL; e = readdir(dir)){
		if(!_ncd_iface_up_dir_filter(e))
			continue;

		ncd_iface_change(e->d_name);
		ncd_iface_down();
	};

	return 0;
}

int ncd_nl_handle_message(struct nl_msg* message, void* args){
	struct nlmsghdr *header;
	header = nlmsg_hdr(message);
	
	int datalen = nlmsg_datalen(header);
	if(datalen < sizeof(struct ifinfomsg)){
		fprintf(stderr, "ncd_nl_handle_message(): message is not big enough\n");
		return 1;
	}

	struct ifinfomsg *ifhdr;
	ifhdr = nlmsg_data(header);

	/* Determine interface name */
	const char *ifname = NULL;
	{
		int attrlen = datalen - sizeof(struct ifinfomsg);
		struct rtattr* i = (struct rtattr*) (ifhdr + 1);
		while(i && RTA_OK(i, i->rta_len) && attrlen >= i->rta_len){
			fprintf(stderr, "ncd_nl_handle_message(): found attribute of type %d, looking for type %d. "
				"attrlen: %d, datalen: %d, i->rta_len: %d\n", i->rta_type, IFLA_IFNAME, attrlen, datalen, i->rta_len);
			if(i->rta_type == IFLA_IFNAME){
				ifname = RTA_DATA(i);
				break;
			}
			
			attrlen -= i->rta_len;
			i = RTA_NEXT(i, i->rta_len);
		}
	}

	if(ifname == NULL){
		fprintf(stderr, "ncd_nl_handle_message(): unable to determine interface name\n");
		return 1;
	}

	/* Print some debug info */
	fprintf(stderr, "Interface %s changed state to: %x\n", ifname, ifhdr->ifi_flags);

	/* Trigger interface code */
	ncd_iface_change(ifname);
	if(ifhdr->ifi_flags & (IFF_RUNNING | IFF_LOWER_UP))
		ncd_iface_up();
	else
		ncd_iface_down();

	return 0;
}

/* Netlink socket that will be used to listen to changes
 * on network interfaces (links), such as one of them going
 * UP or DOWN. */
struct nl_sock *ncd_nl_socket;
int ncd_nl_socket_setup(){
	/* Allocate the new socket */
	ncd_nl_socket = nl_socket_alloc();
	if(!ncd_nl_socket){
		fprintf(stderr, "ncd_nl_socket_setup(): could not allocate socket\n");
		return 1;
	}

	/* Setup a callback function for messages, disable sequence checking,
	 * since broadcasts are never multi-part, all of which can be done
	 * before the socket has been connected.
	 */
	nl_socket_modify_cb(ncd_nl_socket,
					NL_CB_VALID,	/* Only really care about valid messages */
					NL_CB_CUSTOM,
					ncd_nl_handle_message,
					NULL);
	nl_socket_disable_seq_check(ncd_nl_socket);

	int conn_result = nl_connect(ncd_nl_socket, NETLINK_ROUTE);
	if(conn_result != 0){
		fprintf(stderr, "ncd_nl_socket_setup(): could not connect to netlink (%d)\n", conn_result);
		return 1;
	}

	/* Configure this socket to listen to messages in the LINK group,
	 * along with making it nonblocking, ascynchronous, which will
	 * be useful later for proper signal handling. */
	nl_socket_add_memberships(ncd_nl_socket, RTNLGRP_LINK, 0);
	nl_socket_set_nonblocking(ncd_nl_socket);

	return 0;
}

/* Reverses ncd_nl_socket_setup() */
void ncd_nl_socket_dispose(){
	nl_close(ncd_nl_socket);
	nl_socket_free(ncd_nl_socket);
	ncd_nl_socket = NULL;
}

/* Handles signal-originated termination requests */
static int ncd_terminate_requested = 0;
void ncd_signal_req_termination(){
	ncd_terminate_requested = 1;
}

int main(){
	ncd_settings_load_defaults();

	EXPECT(ncd_nl_socket_setup(), "could not setup netlink socket\n");
	EXPECT(ncd_catalog_cd(ncd_settings.catalog), "could not get catalog\n");
	EXPECT(ncd_catalog_lock(), "unable to acquire lock\n");
	EXPECT(ncd_runtime_clear(), "unable to clear runtime data\n");

	/* Setup signal handlers */
	signal(SIGTERM, ncd_signal_req_termination);
	signal(SIGCONT, ncd_signal_req_termination);
	signal(SIGINT,  ncd_signal_req_termination);

	/* Process events */
	while(!ncd_terminate_requested){
		int sockfd = nl_socket_get_fd(ncd_nl_socket);

		/* Wait for either the socket to become available
		 * or for a signal to be received. */

		fd_set fdset;
		FD_ZERO(&fdset);
		FD_SET(sockfd, &fdset);

		int result = select(sockfd + 1, &fdset, NULL, NULL, NULL);
		switch(result){
		case 0:
			/* *should* never be reached, test for it just in case */
			fprintf(stderr, "bug! main(): select should not arrive here without a timeout!\n");
			break;
		case -1:
			/* forced to stop by something else, log it */
			perror("main(): select()");
			break;
		default:
			/* a new message should be available now */
			nl_recvmsgs_default(ncd_nl_socket);
			break;
		}
	}

	/* Cleanup */
	ncd_runtime_shutdown();
	ncd_catalog_unlock();
	ncd_nl_socket_dispose();
	
	return 0;
}
