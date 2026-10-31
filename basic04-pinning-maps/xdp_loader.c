/* SPDX-License-Identifier: GPL-2.0 */
static const char *__doc__ = "XDP loader\n"
	" - Allows selecting BPF program --progname name to XDP-attach to --dev\n";

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

#include <locale.h>
#include <unistd.h>
#include <time.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <xdp/libxdp.h>

#include <net/if.h>
#include <linux/if_link.h> /* depend on kernel-headers installed */

#include "../common/common_params.h"
#include "../common/common_user_bpf_xdp.h"
#include "../common/common_libbpf.h"

static const char *default_filename = "xdp_prog_kern.o";

static const struct option_wrapper long_options[] = {

	{{"help",        no_argument,		NULL, 'h' },
	 "Show help", false},

	{{"dev",         required_argument,	NULL, 'd' },
	 "Operate on device <ifname>", "<ifname>", true},

	{{"skb-mode",    no_argument,		NULL, 'S' },
	 "Install XDP program in SKB (AKA generic) mode"},

	{{"native-mode", no_argument,		NULL, 'N' },
	 "Install XDP program in native mode"},

	{{"auto-mode",   no_argument,		NULL, 'A' },
	 "Auto-detect SKB or native mode"},

	{{"force",       no_argument,		NULL, 'F' },
	 "Force install, replacing existing program on interface"},

	{{"unload",      required_argument,	NULL, 'U' },
	 "Unload XDP program <id> instead of loading", "<id>"},

	{{"quiet",       no_argument,		NULL, 'q' },
	 "Quiet mode (no output)"},

	{{"filename",    required_argument,	NULL,  1  },
	 "Load program from <file>", "<file>"},

	{{"progname",    required_argument,	NULL,  2  },
	 "Load program from function <name> in the ELF file", "<name>"},

	{{0, 0, NULL,  0 }, NULL, false}
};

#ifndef PATH_MAX
#define PATH_MAX	4096
#endif

const char *pin_basedir =  "/sys/fs/bpf";
const char *map_name    =  "xdp_stats_map";

/* Pinning maps under /sys/fs/bpf */
int pin_maps_in_bpf_object(struct bpf_object *bpf_obj, struct config *cfg)
{
	char map_filename[PATH_MAX];
	int err, len;

	len = snprintf(map_filename, PATH_MAX, "%s/%s", cfg->pin_dir, map_name);
	if (len < 0) {
		fprintf(stderr, "ERR: creating map_name\n");
		return EXIT_FAIL_OPTION;
	}

	/* Existing/previous XDP prog might not have cleaned up */
	if (access(map_filename, F_OK) != -1 ) {
		if (verbose)
			printf(" - Unpinning (remove) prev maps in %s/\n",
			       cfg->pin_dir);

		/* Basically calls unlink(3) on map_filename */
		err = bpf_object__unpin_maps(bpf_obj, cfg->pin_dir);
		if (err) {
			fprintf(stderr, "ERR: UNpinning maps in %s\n", cfg->pin_dir);
			return EXIT_FAIL_BPF;
		}
	}
	if (verbose)
		printf(" - Pinning maps in %s/\n", cfg->pin_dir);

	/* This will pin all maps in our bpf_object */
	err = bpf_object__pin_maps(bpf_obj, cfg->pin_dir);
	if (err) {
		fprintf(stderr, "ERR: Pinning maps in %s\n", cfg->pin_dir);
		return EXIT_FAIL_BPF;
	}

	return 0;
}

/* Unpinning map under /sys/fs/bpf */
void unpin_map(struct config *cfg)
{
	char map_path[PATH_MAX];
	int len;

	len = snprintf(map_path, PATH_MAX, "%s/%s", cfg->pin_dir, map_name);
	if (len < 0) {
		fprintf(stderr, "ERR: creating map filename for unpin\n");
		return;
	}

	/* If the map file exists, unpin it */
	if (access(map_path, F_OK) == 0) {
		if (verbose)
			printf(" - Unpinning map %s\n", map_path);

		/* Use unlink to remove the pinned map file */
		if (unlink(map_path)) {
			fprintf(stderr, "ERR: Failed to unpin map %s: %s\n",
				map_path, strerror(errno));
		}
	}
}

int main(int argc, char **argv)
{
	struct xdp_program *prog;
	int err, len;

	struct config cfg = {
		.attach_mode = XDP_MODE_NATIVE,
		.ifindex     = -1,
		.do_unload   = false,
	};
	/* Set default BPF-ELF object file and BPF program name */
	strncpy(cfg.filename, default_filename, sizeof(cfg.filename));
	/* Cmdline options can change progname */
	parse_cmdline_args(argc, argv, long_options, &cfg, __doc__);

	/* Required option */
	if (cfg.ifindex == -1) {
		fprintf(stderr, "ERR: required option --dev missing\n\n");
		usage(argv[0], __doc__, long_options, (argc == 1));
		return EXIT_FAIL_OPTION;
	}

	/* Initialize the pin_dir configuration */
	len = snprintf(cfg.pin_dir, 512, "%s/%s", pin_basedir, cfg.ifname);
	if (len < 0) {
		fprintf(stderr, "ERR: creating pin dirname\n");
		return EXIT_FAIL_OPTION;
	}

	if (cfg.do_unload) {
		unpin_map(&cfg);

		/* unload the program */
		err = do_unload(&cfg);
		if (err) {
			char errmsg[1024];
			libxdp_strerror(err, errmsg, sizeof(errmsg));
			fprintf(stderr, "Couldn't unload XDP program: %s\n", errmsg);
			return err;
		}

		printf("Success: Unloaded XDP program\n");
		return EXIT_OK;
	}

	int prog_fd = -1;
	DECLARE_LIBBPF_OPTS(bpf_object_open_opts, opts);
	DECLARE_LIBXDP_OPTS(xdp_program_opts, xdp_opts, 0);

	xdp_opts.open_filename = cfg.filename;
	xdp_opts.prog_name = cfg.progname;
	xdp_opts.opts = &opts;

	prog = xdp_program__create(&xdp_opts);
	err = libxdp_get_error(prog);
	if (err) {
		char errmsg[1024];
		libxdp_strerror(err, errmsg, sizeof(errmsg));
		fprintf(stderr, "ERR: loading program: %s\n", errmsg);
		exit(EXIT_FAIL_BPF);
	}

	struct bpf_object *bpf_obj = xdp_program__bpf_obj(prog);
	if (!bpf_obj) {
		exit(EXIT_FAIL_BPF);
	}


	struct bpf_map *map = bpf_object__find_map_by_name(bpf_obj, "xdp_stats_map");
	int prev_pinned_map_fd = -1;
	bool reused_map = false;
	char map_filename[PATH_MAX];

	len = snprintf(map_filename, PATH_MAX, "%s/%s", cfg.pin_dir, map_name);
	prev_pinned_map_fd = bpf_obj_get(map_filename);

	if (map && !(prev_pinned_map_fd < 0)) {
		if (bpf_map__reuse_fd(map, prev_pinned_map_fd) < 0) {
			/* upon failure to reuse map, fallback to the original logic of unpinning and repinning */
			fprintf(stderr, "failed to reuse previous map\n");
		} else {
			fprintf(stdout, "reusing same map\n");
			reused_map = true;
		}

		if (prev_pinned_map_fd != -1) close(prev_pinned_map_fd);
	}

	err = xdp_program__attach(prog, cfg.ifindex, cfg.attach_mode, 0);
	if (err)
		exit(err);

	prog_fd = xdp_program__fd(prog);
	if (prog_fd < 0) {
		fprintf(stderr, "ERR: xdp_program__fd failed: %s\n", strerror(errno));
		exit(EXIT_FAIL_BPF);
	}

	// program = load_bpf_and_xdp_attach(&cfg);
	if (!prog) {
		err = EXIT_FAIL_BPF;
		goto out;
	}

	if (verbose) {
		printf("Success: Loaded BPF-object(%s) and used program(%s)\n",
		       cfg.filename, cfg.progname);
		printf(" - XDP prog attached on device:%s(ifindex:%d)\n",
		       cfg.ifname, cfg.ifindex);
	}

	/* Use the --dev name as subdir for exporting/pinning maps */
	if (!reused_map) {
		err = pin_maps_in_bpf_object(xdp_program__bpf_obj(prog), &cfg);
		if (err) {
			fprintf(stderr, "ERR: pinning maps\n");
			goto out;
		}
	}

	err = EXIT_OK;

out:
	xdp_program__close(prog);
	return err;
}
