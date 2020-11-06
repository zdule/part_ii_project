/*
    This file is part of the kambpf project (https://github.com/zdule/part_ii_project).
    It is file is offered under two licenses GPLv2 and Apache License Version 2.
    For more information see the LICENSE file at the root of the project.

    Copyright 2020 Dusan Zivanovic
*/

#include <bpf/libbpf.h>
struct bpf_object *load_obj_or_exit(char *path);
struct bpf_program *find_program_by_name_or_exit(struct bpf_object *obj, char *name);
struct perf_buffer *setup_perf_events_cb(struct bpf_object *obj, 
					char *map_name, size_t buff_pages, struct perf_buffer_opts *opts);
int find_map_fd_by_name_or_exit(struct bpf_object *obj, const char *map_name);

#define passert(exp,format,args...) \
	do { \
		if (!(exp)) { \
			fprintf(stderr, "Assertion error: %s at line %d\n%s\n", __FILE__, __LINE__, #exp); \
			fprintf(stderr, format"\n", ##args);  /* ## is a hack to handle no arguments case */ \
			exit(EXIT_FAILURE); \
		} \
	} while (false)
